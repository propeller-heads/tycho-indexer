//! Module for Handling Relative Balance Changes.
//!
//! This module facilitates the conversion of relative balance changes into absolute balances,
//! employing a structured approach to ensure the accurate representation of balance data.
//!
//! Process Overview:
//!
//! 1. **Mapping (User-Implemented)**: The initial step requires the user to implement a mapping
//!    function that extracts `BlockBalanceDeltas` messages. It's crucial that `BalanceDelta`
//!    messages within these messages have strictly increasing ordinals, which guarantees the order
//!    of balance changes is preserved and unambiguous. This step is not provided by the SDK and
//!    must be custom-implemented to suit the specific protocol.
//!
//! 2. **Storing Changes**: Utilize the `store_balance_changes` function to apply relative balance
//!    changes. This function handles changes additively, preparing them for final aggregation.
//!
//! 3. **Aggregation**: Use the `aggregate_balance_changes` function to compile the processed
//!    changes into a detailed map of absolute balances. This final step produces the comprehensive
//!    balance data ready for output modules or further analysis.
//!
//! Through this sequence, the module ensures the transformation from relative to absolute
//! balances is conducted with high fidelity, upholding the integrity of transactional data.

use crate::{
    abi,
    pb::tycho::evm::v1::{BalanceChange, BlockBalanceDeltas, Transaction},
    prelude::BalanceDelta,
};
use itertools::Itertools;
use std::{collections::HashMap, str::FromStr};
use substreams::{
    key,
    pb::substreams::StoreDeltas,
    prelude::{BigInt, StoreAdd},
};
use substreams_ethereum::{pb::eth::v2::TransactionTrace, Event};

/// Stores relative balance changes in an additive manner.
///
/// Aggregates the relative balance changes from a `BlockBalanceDeltas` message into the store
/// in an additive way. This function ensures that balance changes are applied correctly
/// according to the order specified by their ordinal values. Each token's balance changes
/// must have strictly increasing ordinals; otherwise, the function will panic.
///
/// This method is designed to work in conjunction with `aggregate_balances_changes`,
/// which consumes the data stored by this function. The stored data is intended for use
/// in a "deltas mode" processing pattern, as described in the
/// [Substreams documentation](https://substreams.streamingfast.io/documentation/develop/manifest-modules/types#deltas-mode).
///
/// ## Arguments
/// * `deltas` - A `BlockBalanceDeltas` message containing the relative balance changes. It is
///   crucial that the relative balance deltas for each token address have strictly increasing
///   ordinals; the function will panic otherwise.
/// * `store` - An implementation of the `StoreAdd` trait that will be used to add relative balance
///   changes. This store should support the addition of `BigInt` values.
///
/// ## Panics
/// This function will panic if:
/// - The `component_id` of any delta is not valid UTF-8.
/// - The ordinals for any given token address are not strictly increasing.
pub fn store_balance_changes(deltas: BlockBalanceDeltas, store: impl StoreAdd<BigInt>) {
    let mut previous_ordinal = HashMap::<String, u64>::new();
    deltas
        .balance_deltas
        .iter()
        .for_each(|delta| {
            let balance_key = format!(
                "{0}:{1}",
                String::from_utf8(delta.component_id.clone())
                    .expect("delta.component_id is not valid utf-8!"),
                hex::encode(&delta.token)
            );
            let current_ord = delta.ord;
            previous_ordinal
                .entry(balance_key.clone())
                .and_modify(|ord| {
                    // ordinals must arrive in increasing order
                    if *ord >= current_ord {
                        panic!(
                            "Invalid ordinal sequence for {}: {} >= {}",
                            balance_key, *ord, current_ord
                        );
                    }
                    *ord = current_ord;
                })
                .or_insert(delta.ord);
            store.add(delta.ord, balance_key, BigInt::from_signed_bytes_be(&delta.delta));
        });
}

type TxAggregatedBalances = HashMap<Vec<u8>, (Transaction, HashMap<Vec<u8>, BalanceChange>)>;

/// Aggregates absolute balances per transaction and token.
///
/// ## Arguments
/// * `balance_store` - A `StoreDeltas` with all changes that occured in the source store module.
/// * `deltas` - A `BlockBalanceDeltas` message containing the relative balances changes.
///
/// This function reads absolute balance values from an additive store (see `store_balance_changes`
/// for how to create such a store). It zips these values with the relative balance deltas to
/// associate balance values with tokens and components, ensuring the last balance change per token
/// per transaction is kept if there are multiple changes. Negative balances are set to 0, adhering
/// to the expectation that absolute balances must be non-negative.
///
/// Will keep the last balance change per token per transaction if there are multiple
/// changes. In case a balance ends up being negative, it will be clipped to 0 since
/// absolute balances are expected to be either zero or positive.
///
/// ## Panics
/// May panic if the store deltas values are not in the correct format. Values are
/// expected to be utf-8 encoded string integers, which is the default behaviour
/// for substreams stores.
///
/// ## Returns
/// A map of transactions hashes to a tuple of `Transaction` and aggregated
/// absolute balance changes.
pub fn aggregate_balances_changes(
    balance_store: StoreDeltas,
    deltas: BlockBalanceDeltas,
) -> TxAggregatedBalances {
    balance_store
        .deltas
        .into_iter()
        .zip(deltas.balance_deltas)
        .map(|(store_delta, balance_delta)| {
            let component_id = key::segment_at(&store_delta.key, 0);
            let token_id = key::segment_at(&store_delta.key, 1);
            // store_delta.new_value is an ASCII string representing an integer
            let ascii_string =
                String::from_utf8(store_delta.new_value.clone()).expect("Invalid UTF-8 sequence");
            let balance = BigInt::from_str(&ascii_string).expect("Failed to parse integer");

            // If the absolute balance is negative, we set it to zero.
            let big_endian_bytes_balance = if balance < BigInt::zero() {
                BigInt::zero().to_bytes_be().1
            } else {
                balance.to_bytes_be().1
            };

            (
                balance_delta
                    .tx
                    .expect("Missing transaction on delta"),
                BalanceChange {
                    token: hex::decode(token_id).expect("Token ID not valid hex"),
                    balance: big_endian_bytes_balance,
                    component_id: component_id.as_bytes().to_vec(),
                },
            )
        })
        // We need to group the balance changes by tx hash for the `TransactionContractChanges` agg
        .group_by(|(tx, _)| tx.hash.clone())
        .into_iter()
        .map(|(txh, group)| {
            let (mut transactions, balance_changes): (Vec<_>, Vec<_>) = group.into_iter().unzip();

            let balances = balance_changes
                .into_iter()
                .map(|balance_change| (balance_change.token.clone(), balance_change))
                .collect();
            (txh, (transactions.pop().unwrap(), balances))
        })
        .collect()
}

/// Extracts balance deltas from a transaction trace based on a given address predicate.
///
/// This function processes the logs within a transaction trace to identify ERC-20 token transfer
/// events. It applies the given predicate to determine which addresses are of interest and extracts
/// the balance changes (deltas) for those addresses. The balance deltas are then returned as a
/// vector.
///
/// # Arguments
///
/// * `tx` - A reference to a `TransactionTrace` which contains the transaction logs and other
///   details.
/// * `address_predicate` - A predicate function that takes two byte slices representing a token and
///   a component and returns a boolean. This function is used to filter which addresses' balance
///   changes should be extracted.
///
/// # Returns
///
/// A vector of `BalanceDelta` structs, each representing a change in balance for a specific address
/// within the transaction.
///
/// # Example
///
/// ```
/// let predicate = |log_address: &[u8], transfer_address: &[u8]| -> bool {
///     // Your predicate logic here, e.g., checking if the address matches a specific pattern.
///     true
/// };
///
/// let balance_deltas = extract_balance_deltas_from_tx(&tx, predicate);
/// ```
///
/// # Notes
///
/// - It is assumed that the transactor is the component. If the protocol follows a different
///   design, this function may not be applicable.
/// - The `address_predicate` is applied to both the log address and the `from`/`to` addresses in
///   the transfer event.
pub fn extract_balance_deltas_from_tx<F: Fn(&[u8], &[u8]) -> bool>(
    tx: &TransactionTrace,
    address_predicate: F,
) -> Vec<BalanceDelta> {
    let mut balance_deltas = vec![];

    tx.logs_with_calls()
        .for_each(|(log, _)| {
            if let Some(transfer) = abi::erc20::events::Transfer::match_and_decode(log) {
                let mut create_balance_delta = |transactor: &[u8], delta: BigInt| {
                    balance_deltas.push(BalanceDelta {
                        ord: log.ordinal,
                        tx: Some(tx.into()),
                        token: log.address.clone(),
                        delta: delta.to_signed_bytes_be(),
                        component_id: hex::encode(transactor).into(),
                    });
                };

                if address_predicate(&log.address, &transfer.from) {
                    create_balance_delta(&transfer.from, transfer.value.neg());
                }
                if address_predicate(&log.address, &transfer.to) {
                    create_balance_delta(&transfer.to, transfer.value);
                }
            }
        });

    balance_deltas
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{mock_store::MockStore, pb::tycho::evm::v1::BalanceDelta};
    use substreams::{
        pb::substreams::StoreDelta,
        prelude::{StoreGet, StoreNew},
    };

    fn block_balance_deltas() -> BlockBalanceDeltas {
        let comp_id = "0x42c0ffee"
            .to_string()
            .as_bytes()
            .to_vec();
        let token_0 = hex::decode("bad999").unwrap();
        let token_1 = hex::decode("babe00").unwrap();
        BlockBalanceDeltas {
            balance_deltas: vec![
                BalanceDelta {
                    ord: 0,
                    tx: Some(Transaction {
                        hash: vec![0, 1],
                        from: vec![9, 9],
                        to: vec![8, 8],
                        index: 0,
                    }),
                    token: token_0.clone(),
                    delta: BigInt::from_str("+1000")
                        .unwrap()
                        .to_signed_bytes_be(),
                    component_id: comp_id.clone(),
                },
                BalanceDelta {
                    ord: 2,
                    tx: Some(Transaction {
                        hash: vec![0, 1],
                        from: vec![9, 9],
                        to: vec![8, 8],
                        index: 0,
                    }),
                    token: token_1.clone(),
                    delta: BigInt::from_str("+100")
                        .unwrap()
                        .to_signed_bytes_be(),
                    component_id: comp_id.clone(),
                },
                BalanceDelta {
                    ord: 3,
                    tx: Some(Transaction {
                        hash: vec![0, 1],
                        from: vec![9, 9],
                        to: vec![8, 8],
                        index: 0,
                    }),
                    token: token_1.clone(),
                    delta: BigInt::from_str("50")
                        .unwrap()
                        .to_signed_bytes_be(),
                    component_id: comp_id.clone(),
                },
                BalanceDelta {
                    ord: 10,
                    tx: Some(Transaction {
                        hash: vec![0, 1],
                        from: vec![9, 9],
                        to: vec![8, 8],
                        index: 0,
                    }),
                    token: token_0.clone(),
                    delta: BigInt::from_str("-1")
                        .unwrap()
                        .to_signed_bytes_be(),
                    component_id: comp_id.clone(),
                },
            ],
        }
    }
    fn store_deltas() -> StoreDeltas {
        let comp_id = "0x42c0ffee"
            .to_string()
            .as_bytes()
            .to_vec();
        let token_0 = hex::decode("bad999").unwrap();
        let token_1 = hex::decode("babe00").unwrap();

        let t0_key =
            format!("{}:{}", String::from_utf8(comp_id.clone()).unwrap(), hex::encode(token_0));
        let t1_key =
            format!("{}:{}", String::from_utf8(comp_id.clone()).unwrap(), hex::encode(token_1));
        StoreDeltas {
            deltas: vec![
                StoreDelta {
                    operation: 0,
                    ordinal: 0,
                    key: t0_key.clone(),
                    old_value: BigInt::from(0)
                        .to_string()
                        .as_bytes()
                        .to_vec(),
                    new_value: BigInt::from(1000)
                        .to_string()
                        .as_bytes()
                        .to_vec(),
                },
                StoreDelta {
                    operation: 0,
                    ordinal: 2,
                    key: t1_key.clone(),
                    old_value: BigInt::from(0)
                        .to_string()
                        .as_bytes()
                        .to_vec(),
                    new_value: BigInt::from(100)
                        .to_string()
                        .as_bytes()
                        .to_vec(),
                },
                StoreDelta {
                    operation: 0,
                    ordinal: 3,
                    key: t1_key.clone(),
                    old_value: BigInt::from(100)
                        .to_string()
                        .as_bytes()
                        .to_vec(),
                    new_value: BigInt::from(150)
                        .to_string()
                        .as_bytes()
                        .to_vec(),
                },
                StoreDelta {
                    operation: 0,
                    ordinal: 10,
                    key: t0_key.clone(),
                    old_value: BigInt::from(1000)
                        .to_string()
                        .as_bytes()
                        .to_vec(),
                    new_value: BigInt::from(999)
                        .to_string()
                        .as_bytes()
                        .to_vec(),
                },
            ],
        }
    }

    #[test]
    fn test_store_balances() {
        let comp_id = "0x42c0ffee"
            .to_string()
            .as_bytes()
            .to_vec();
        let token_0 = hex::decode("bad999").unwrap();
        let token_1 = hex::decode("babe00").unwrap();
        let deltas = block_balance_deltas();
        let store = <MockStore as StoreNew>::new();

        store_balance_changes(deltas, store.clone());
        let res_0 = store.get_last(format!(
            "{}:{}",
            String::from_utf8(comp_id.clone()).unwrap(),
            hex::encode(token_0)
        ));
        let res_1 = store.get_last(format!(
            "{}:{}",
            String::from_utf8(comp_id.clone()).unwrap(),
            hex::encode(token_1)
        ));

        assert_eq!(res_0, Some(BigInt::from_str("+999").unwrap()));
        assert_eq!(res_1, Some(BigInt::from_str("+150").unwrap()));
    }

    #[test]
    fn test_aggregate_balances_changes() {
        let store_deltas = store_deltas();
        let balance_deltas = block_balance_deltas();
        let comp_id = "0x42c0ffee"
            .to_string()
            .as_bytes()
            .to_vec();
        let token_0 = hex::decode("bad999").unwrap();
        let token_1 = hex::decode("babe00").unwrap();

        let exp = [(
            vec![0, 1],
            (
                Transaction { hash: vec![0, 1], from: vec![9, 9], to: vec![8, 8], index: 0 },
                [
                    (
                        token_0.clone(),
                        BalanceChange {
                            token: token_0,
                            balance: BigInt::from(999)
                                .to_signed_bytes_be()
                                .to_vec(),
                            component_id: comp_id.clone(),
                        },
                    ),
                    (
                        token_1.clone(),
                        BalanceChange {
                            token: token_1,
                            balance: vec![150],
                            component_id: comp_id.clone(),
                        },
                    ),
                ]
                .into_iter()
                .collect::<HashMap<_, _>>(),
            ),
        )]
        .into_iter()
        .collect::<HashMap<_, _>>();

        let res = aggregate_balances_changes(store_deltas, balance_deltas);
        assert_eq!(res, exp);
    }
}
