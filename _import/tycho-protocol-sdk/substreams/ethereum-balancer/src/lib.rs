use std::collections::HashMap;

use anyhow::Result;
use substreams::pb::substreams::StoreDeltas;
use substreams::store::{
    StoreAdd, StoreAddBigInt, StoreGet, StoreGetBigInt, StoreGetProto, StoreNew,
    StoreSetIfNotExists, StoreSetIfNotExistsProto,
};
use substreams::{hex, log};

use substreams::key;
use substreams::scalar::BigInt;
use substreams_ethereum::block_view::{CallView, LogView};
use substreams_ethereum::pb::eth;
use substreams_ethereum::pb::eth::v2::{balance_change, Call, Log, TransactionTrace};
use substreams_ethereum::{Event, Function};

use itertools::Itertools;
use pb::tycho::evm::v1::{self as tycho};

mod abi;
mod pb;

const VAULT_ADDRESS: &[u8] = &hex!("BA12222222228d8Ba445958a75a0704d566BF2C8");

/// This trait defines some helpers for serializing and deserializing `Vec<BigInt` which is needed
///  to be able to encode the `normalized_weights` and `weights` `Attribute`s. This should also be
///  handled by any downstream application.
trait SerializableVecBigInt {
    fn serialize_bytes(&self) -> Vec<u8>;
    fn deserialize_bytes(bytes: &[u8]) -> Vec<BigInt>;
}

impl SerializableVecBigInt for Vec<BigInt> {
    fn serialize_bytes(&self) -> Vec<u8> {
        self.iter()
            .flat_map(|big_int| big_int.to_signed_bytes_be())
            .collect()
    }
    fn deserialize_bytes(bytes: &[u8]) -> Vec<BigInt> {
        bytes
            .chunks_exact(32)
            .map(|chunk| BigInt::from_signed_bytes_be(chunk))
            .collect::<Vec<BigInt>>()
    }
}

/// This struct purely exists to spoof the `PartialEq` trait for `Transaction` so we can use it in
///  a later groupby operation.
struct TransactionWrapper(tycho::Transaction);

impl PartialEq for TransactionWrapper {
    fn eq(&self, other: &Self) -> bool {
        self.0.hash == other.0.hash
    }
}

/// This is the main function that handles the creation of `ProtocolComponent`s with `Attribute`s
///  based on the specific factory address. There's 3 factory groups that are represented here:
///  - Weighted Pool Factories
///  - Linear Pool Factories
///  - Stable Pool Factories
/// (Balancer does have a bit more (esp. in the deprecated section) that could be implemented as
///  desired.)
/// We use the specific ABIs to decode both the log event and cooresponding call to gather
///  `PoolCreated` event information alongside the `Create` calldata that provide us details to
///  fufill both the required details + any extra `Attributes`
/// Ref: https://docs.balancer.fi/reference/contracts/deployment-addresses/mainnet.html
fn pool_factory_map(pool_addr: &[u8], log: &Log, call: &Call) -> Option<tycho::ProtocolComponent> {
    match pool_addr {
        &hex!("897888115Ada5773E02aA29F775430BFB5F34c51") => {
            let create_call =
                abi::weighted_pool_factory::functions::Create::match_and_decode(call)?;
            let pool_created =
                abi::weighted_pool_factory::events::PoolCreated::match_and_decode(log)?;

            Some(tycho::ProtocolComponent {
                id: hex::encode(&pool_created.pool),
                tokens: create_call.tokens,
                contracts: vec![pool_addr.into(), pool_created.pool],
                static_att: vec![
                    tycho::Attribute {
                        name: "pool_type".into(),
                        value: "WeightedPoolFactory".into(),
                        change: tycho::ChangeType::Creation.into(),
                    },
                    tycho::Attribute {
                        name: "swap_fee_percentage".into(),
                        value: create_call.swap_fee_percentage.to_signed_bytes_be(),
                        change: tycho::ChangeType::Creation.into(),
                    },
                    tycho::Attribute {
                        name: "normalized_weights".into(),
                        value: create_call.normalized_weights.serialize_bytes(),
                        change: tycho::ChangeType::Creation.into(),
                    },
                ],
                change: tycho::ChangeType::Creation.into(),
            })
        }
        &hex!("DB8d758BCb971e482B2C45f7F8a7740283A1bd3A") => {
            let create_call =
                abi::composable_stable_pool_factory::functions::Create::match_and_decode(call)?;
            let pool_created =
                abi::composable_stable_pool_factory::events::PoolCreated::match_and_decode(log)?;

            Some(tycho::ProtocolComponent {
                id: hex::encode(&pool_created.pool),
                tokens: create_call.tokens,
                contracts: vec![pool_addr.into(), pool_created.pool],
                static_att: vec![
                    tycho::Attribute {
                        name: "pool_type".into(),
                        value: "ComposableStablePoolFactory".into(),
                        change: tycho::ChangeType::Creation.into(),
                    },
                    tycho::Attribute {
                        name: "swap_fee_percentage".into(),
                        value: create_call.swap_fee_percentage.to_signed_bytes_be(),
                        change: tycho::ChangeType::Creation.into(),
                    },
                    tycho::Attribute {
                        name: "amplification_parameter".into(),
                        value: create_call.amplification_parameter.to_signed_bytes_be(),
                        change: tycho::ChangeType::Creation.into(),
                    },
                ],
                change: tycho::ChangeType::Creation.into(),
            })
        }
        &hex!("813EE7a840CE909E7Fea2117A44a90b8063bd4fd") => {
            let create_call =
                abi::erc_linear_pool_factory::functions::Create::match_and_decode(call)?;
            let pool_created =
                abi::erc_linear_pool_factory::events::PoolCreated::match_and_decode(log)?;

            Some(tycho::ProtocolComponent {
                id: hex::encode(&pool_created.pool),
                tokens: vec![create_call.main_token, create_call.wrapped_token],
                contracts: vec![pool_addr.into(), pool_created.pool],
                static_att: vec![
                    tycho::Attribute {
                        name: "pool_type".into(),
                        value: "ERC4626LinearPoolFactory".into(),
                        change: tycho::ChangeType::Creation.into(),
                    },
                    tycho::Attribute {
                        name: "swap_fee_percentage".into(),
                        value: create_call.swap_fee_percentage.to_signed_bytes_be(),
                        change: tycho::ChangeType::Creation.into(),
                    },
                    tycho::Attribute {
                        name: "upper_target".into(),
                        value: create_call.upper_target.to_signed_bytes_be(),
                        change: tycho::ChangeType::Creation.into(),
                    },
                    // Note, `lower_target` is generally hardcoded for all pools, not located in call data
                    // Note, rate provider might be provided as `create.protocol_id`, but as a BigInt. needs investigation
                ],
                change: tycho::ChangeType::Creation.into(),
            })
        }
        &hex!("5F43FBa61f63Fa6bFF101a0A0458cEA917f6B347") => {
            let create_call =
                abi::euler_linear_pool_factory::functions::Create::match_and_decode(call)?;
            let pool_created =
                abi::euler_linear_pool_factory::events::PoolCreated::match_and_decode(log)?;

            Some(tycho::ProtocolComponent {
                id: hex::encode(&pool_created.pool),
                tokens: vec![create_call.main_token, create_call.wrapped_token],
                contracts: vec![pool_addr.into(), pool_created.pool],
                static_att: vec![
                    tycho::Attribute {
                        name: "pool_type".into(),
                        value: "EulerLinearPoolFactory".into(),
                        change: tycho::ChangeType::Creation.into(),
                    },
                    tycho::Attribute {
                        name: "swap_fee_percentage".into(),
                        value: create_call.swap_fee_percentage.to_signed_bytes_be(),
                        change: tycho::ChangeType::Creation.into(),
                    },
                    tycho::Attribute {
                        name: "upper_target".into(),
                        value: create_call.upper_target.to_signed_bytes_be(),
                        change: tycho::ChangeType::Creation.into(),
                    },
                ],
                change: tycho::ChangeType::Creation.into(),
            })
        }
        &hex!("39A79EB449Fc05C92c39aA6f0e9BfaC03BE8dE5B") => {
            let create_call =
                abi::gearbox_linear_pool_factory::functions::Create::match_and_decode(call)?;
            let pool_created =
                abi::gearbox_linear_pool_factory::events::PoolCreated::match_and_decode(log)?;

            Some(tycho::ProtocolComponent {
                id: hex::encode(&pool_created.pool),
                tokens: vec![create_call.main_token, create_call.wrapped_token],
                contracts: vec![pool_addr.into(), pool_created.pool],
                static_att: vec![
                    tycho::Attribute {
                        name: "pool_type".into(),
                        value: "GearboxLinearPoolFactory".into(),
                        change: tycho::ChangeType::Creation.into(),
                    },
                    tycho::Attribute {
                        name: "swap_fee_percentage".into(),
                        value: create_call.swap_fee_percentage.to_signed_bytes_be(),
                        change: tycho::ChangeType::Creation.into(),
                    },
                    tycho::Attribute {
                        name: "upper_target".into(),
                        value: create_call.upper_target.to_signed_bytes_be(),
                        change: tycho::ChangeType::Creation.into(),
                    },
                ],
                change: tycho::ChangeType::Creation.into(),
            })
        }
        // The `ManagedPoolFactory` is a bit ✨ unique ✨, so we'll leave it commented out for now
        // Take a look at it's `Create` call to see how the params are structured.
        // &hex!("BF904F9F340745B4f0c4702c7B6Ab1e808eA6b93") => {
        //     let create_call = abi::managed_pool_factory::functions::Create::match_and_decode(call)?;
        //     let pool_created =
        //         abi::managed_pool_factory::events::PoolCreated::match_and_decode(log)?;

        //     Some(tycho::ProtocolComponent {
        //         id: hex::encode(&pool_created.pool),
        //         tokens: create_call.tokens,
        //         contracts: vec![pool_addr.into(), pool_created.pool],
        //         static_att: vec![
        //             tycho::Attribute {
        //                 name: "pool_type".into(),
        //                 value: "ManagedPoolFactory".into(),
        //                 change: tycho::ChangeType::Creation.into(),
        //             },
        //             tycho::Attribute {
        //                 name: "swap_fee_percentage".into(),
        //                 value: create_call.swap_fee_percentage.to_signed_bytes_be(),
        //                 change: tycho::ChangeType::Creation.into(),
        //             },
        //         ],
        //         change: tycho::ChangeType::Creation.into(),
        //     })
        // }
        &hex!("4E11AEec21baF1660b1a46472963cB3DA7811C89") => {
            let create_call =
                abi::silo_linear_pool_factory::functions::Create::match_and_decode(call)?;
            let pool_created =
                abi::silo_linear_pool_factory::events::PoolCreated::match_and_decode(log)?;

            Some(tycho::ProtocolComponent {
                id: hex::encode(&pool_created.pool),
                tokens: vec![create_call.main_token, create_call.wrapped_token],
                contracts: vec![pool_addr.into(), pool_created.pool],
                static_att: vec![
                    tycho::Attribute {
                        name: "pool_type".into(),
                        value: "SiloLinearPoolFactory".into(),
                        change: tycho::ChangeType::Creation.into(),
                    },
                    tycho::Attribute {
                        name: "swap_fee_percentage".into(),
                        value: create_call.swap_fee_percentage.to_signed_bytes_be(),
                        change: tycho::ChangeType::Creation.into(),
                    },
                    tycho::Attribute {
                        name: "upper_target".into(),
                        value: create_call.upper_target.to_signed_bytes_be(),
                        change: tycho::ChangeType::Creation.into(),
                    },
                ],
                change: tycho::ChangeType::Creation.into(),
            })
        }
        &hex!("5F5222Ffa40F2AEd6380D022184D6ea67C776eE0") => {
            let create_call =
                abi::yearn_linear_pool_factory::functions::Create::match_and_decode(call)?;
            let pool_created =
                abi::yearn_linear_pool_factory::events::PoolCreated::match_and_decode(log)?;

            Some(tycho::ProtocolComponent {
                id: hex::encode(&pool_created.pool),
                tokens: vec![create_call.main_token, create_call.wrapped_token],
                contracts: vec![pool_addr.into(), pool_created.pool],
                static_att: vec![
                    tycho::Attribute {
                        name: "pool_type".into(),
                        value: "YearnLinearPoolFactory".into(),
                        change: tycho::ChangeType::Creation.into(),
                    },
                    tycho::Attribute {
                        name: "swap_fee_percentage".into(),
                        value: create_call.swap_fee_percentage.to_signed_bytes_be(),
                        change: tycho::ChangeType::Creation.into(),
                    },
                    tycho::Attribute {
                        name: "upper_target".into(),
                        value: create_call.upper_target.to_signed_bytes_be(),
                        change: tycho::ChangeType::Creation.into(),
                    },
                ],
                change: tycho::ChangeType::Creation.into(),
            })
        }
        // The `WeightedPool2TokenFactory` is a deprecated contract but we've included it since one
        //  of the highest TVL pools, 80BAL-20WETH, is able to be tracked.
        &hex!("A5bf2ddF098bb0Ef6d120C98217dD6B141c74EE0") => {
            let create_call =
                abi::weighted_pool_tokens_factory::functions::Create::match_and_decode(call)?;
            let pool_created =
                abi::weighted_pool_tokens_factory::events::PoolCreated::match_and_decode(log)?;

            Some(tycho::ProtocolComponent {
                id: hex::encode(&pool_created.pool),
                tokens: create_call.tokens,
                contracts: vec![pool_addr.into(), pool_created.pool],
                static_att: vec![
                    tycho::Attribute {
                        name: "pool_type".into(),
                        value: "WeightedPool2TokensFactory".into(),
                        change: tycho::ChangeType::Creation.into(),
                    },
                    tycho::Attribute {
                        name: "swap_fee_percentage".into(),
                        value: create_call.swap_fee_percentage.to_signed_bytes_be(),
                        change: tycho::ChangeType::Creation.into(),
                    },
                    // TODO
                    tycho::Attribute {
                        name: "weights".into(),
                        value: create_call.weights.serialize_bytes(),
                        change: tycho::ChangeType::Creation.into(),
                    },
                ],
                change: tycho::ChangeType::Creation.into(),
            })
        }
        _ => None,
    }
}

/// Since the `PoolBalanceChanged` events administer only deltas, we need to leverage a map and a
///  store to be able to tally up final balances for tokens in a pool.
#[substreams::handlers::map]
pub fn map_balance_deltas(block: eth::v2::Block) -> Result<tycho::BalanceDeltas, anyhow::Error> {
    Ok(tycho::BalanceDeltas {
        balance_deltas: block
            .events::<abi::vault::events::PoolBalanceChanged>(&[&VAULT_ADDRESS])
            .flat_map(|(event, log)| {
                event
                    .tokens
                    .iter()
                    .zip(event.deltas.iter())
                    .map(|(token, delta)| tycho::BalanceDelta {
                        ord: log.log.ordinal,
                        tx: Some(tycho::Transaction {
                            hash: log.receipt.transaction.hash.clone(),
                            from: log.receipt.transaction.from.clone(),
                            to: log.receipt.transaction.to.clone(),
                            index: Into::<u64>::into(log.receipt.transaction.index).clone(),
                        }),
                        token: token.clone(),
                        delta: delta.to_signed_bytes_be(),
                        component_id: event.pool_id.into(),
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>(),
    })
}

/// It's significant to include both the `pool_id` and the `token_id` for each balance delta as the
///  store key to ensure that there's a unique balance being tallied for each.
#[substreams::handlers::store]
pub fn store_balance_changes(deltas: tycho::BalanceDeltas, store: StoreAddBigInt) {
    deltas.balance_deltas.iter().for_each(|delta| {
        store.add(
            delta.ord,
            format!(
                "pool:{0}:token:{1}",
                hex::encode(&delta.component_id),
                hex::encode(&delta.token)
            ),
            BigInt::from_signed_bytes_be(&delta.delta),
        );
    });
}

/// This is the main map that handles most of the indexing of this substream.
#[substreams::handlers::map]
pub fn map_changes(
    block: eth::v2::Block,
    deltas: tycho::BalanceDeltas,
    store: StoreDeltas,  // Note, this map module is using the `deltas` mode for the store.
) -> Result<tycho::BlockContractChanges> {
    // Gather contract changes by indexing `PoolCreated` events and analysing the `Create` call
    // We store these as a hashmap by tx hash since we need to agg by tx hash later
    let mut transaction_contract_changes = block
        .transactions()
        .flat_map(|tx| {
            tx.logs_with_calls()
                .filter(|(_, call)| !call.call.state_reverted)
                .filter_map(|(log, call)| {
                    let pool_factory_address = call.call.address.as_slice();

                    Some((
                        tx.hash.clone(),
                        tycho::TransactionContractChanges {
                            tx: Some(tycho::Transaction {
                                hash: tx.hash.clone(),
                                from: tx.from.clone(),
                                to: tx.to.clone(),
                                index: Into::<u64>::into(tx.index).clone(),
                            }),
                            contract_changes: vec![],
                            balance_changes: vec![],
                            component_changes: vec![pool_factory_map(
                                pool_factory_address,
                                &log,
                                &call.call,
                            )?],
                        },
                    ))
                })
        })
        .collect::<HashMap<_, _>>();

    // Balance changes are gathered by the `StoreDelta` based on `PoolBalanceChanged` creating `BalanceDeltas`
    // We essentially just process the changes that occured to the `store` this block
    // Then, these balance changes are merged onto the existing map of tx contract changes,
    //  inserting a new one if it doesn't exist.
    store
        .deltas
        .into_iter()
        .zip(deltas.balance_deltas)
        .map(|(store_delta, balance_delta)| {
            let pool_id = key::segment_at(&store_delta.key, 1);
            let token_id = key::segment_at(&store_delta.key, 3);
            (
                balance_delta.tx.unwrap(),
                tycho::BalanceChange {
                    token: hex::decode(token_id).expect("Token ID not valid hex"),
                    balance: store_delta.new_value,
                    component_id: hex::decode(pool_id).expect("Token ID not valid hex"),
                },
            )
        })
        // We need to group the balance changes by tx hash for the `TransactionContractChanges` agg
        .group_by(|(tx, _)| TransactionWrapper(tx.clone()))
        .into_iter()
        .for_each(|(tx_wrapped, group)| {
            let tx = tx_wrapped.0;

            if let Some(tx_change) = transaction_contract_changes.get_mut(&tx.hash) {
                tx_change
                    .balance_changes
                    .extend(group.map(|(_, change)| change.clone()));
            } else {
                transaction_contract_changes.insert(
                    tx.hash.clone(),
                    tycho::TransactionContractChanges {
                        tx: Some(tx),
                        contract_changes: vec![],
                        component_changes: vec![],
                        balance_changes: group
                            .map(|(_, change)| change.clone())
                            .collect::<Vec<_>>(),
                    },
                );
            }
        });

    Ok(tycho::BlockContractChanges {
        block: Some(tycho::Block {
            number: block.number,
            hash: block.hash.clone(),
            parent_hash: block
                .header
                .as_ref()
                .expect("Block header not present")
                .parent_hash
                .clone(),
            ts: block.timestamp_seconds(),
        }),
        changes: transaction_contract_changes
            .into_iter()
            .map(|(_, v)| v)
            .sorted_unstable_by_key(|tx_change| tx_change.tx.clone().unwrap().index)
            .collect::<Vec<_>>(),
    })
}
