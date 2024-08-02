use std::collections::HashMap;

use anyhow::Result;
use itertools::Itertools;
use substreams::{
    pb::substreams::StoreDeltas,
    scalar::BigInt,
    store::{
        StoreAddBigInt, StoreGet, StoreGetInt64, StoreGetString, StoreNew, StoreSet, StoreSetInt64,
        StoreSetString,
    },
};
use substreams_ethereum::pb::eth;

use crate::{
    consts::{CRYPTO_SWAP_NG_FACTORY, NEW_SUSD, OLD_SUSD, TRICRYPTO_FACTORY},
    pool_changes::emit_eth_deltas,
    pool_factories,
    pools::emit_specific_pools,
};
use tycho_substreams::{
    balances::{extract_balance_deltas_from_tx, store_balance_changes},
    contract::extract_contract_changes,
    prelude::*,
};

/// This struct purely exists to spoof the `PartialEq` trait for `Transaction` so we can use it in
///  a later groupby operation.
#[derive(Debug)]
struct TransactionWrapper(Transaction);

impl PartialEq for TransactionWrapper {
    fn eq(&self, other: &Self) -> bool {
        self.0.hash == other.0.hash
    }
}

#[substreams::handlers::map]
pub fn map_components(
    params: String,
    block: eth::v2::Block,
) -> Result<BlockTransactionProtocolComponents> {
    // Gather contract changes by indexing `PoolCreated` events and analysing the `Create` call
    // We store these as a hashmap by tx hash since we need to agg by tx hash later
    Ok(BlockTransactionProtocolComponents {
        tx_components: block
            .transactions()
            .filter_map(|tx| {
                let mut components = tx
                    .logs_with_calls()
                    .filter(|(_, call)| !call.call.state_reverted)
                    .filter_map(|(log, call)| {
                        pool_factories::address_map(
                            call.call
                                .address
                                .as_slice()
                                .try_into()
                                .ok()?, // this shouldn't fail
                            log,
                            call.call,
                            tx,
                        )
                    })
                    .collect::<Vec<_>>();

                if let Some(component) = emit_specific_pools(&params, tx).expect(
                    "An unexpected error occured when parsing params for emitting specific pools",
                ) {
                    components.push(component)
                }

                if !components.is_empty() {
                    Some(TransactionProtocolComponents {
                        tx: Some(Transaction {
                            hash: tx.hash.clone(),
                            from: tx.from.clone(),
                            to: tx.to.clone(),
                            index: Into::<u64>::into(tx.index),
                        }),
                        components,
                    })
                } else {
                    None
                }
            })
            .collect::<Vec<_>>(),
    })
}

/// Simply stores the `ProtocolComponent`s with the pool id as the key and tokens as the value
#[substreams::handlers::store]
pub fn store_component_tokens(map: BlockTransactionProtocolComponents, store: StoreSetString) {
    map.tx_components
        .iter()
        .flat_map(|tx_components| &tx_components.components)
        .for_each(|component| {
            store.set(
                0,
                format!("pool:{0}", component.id),
                &component
                    .tokens
                    .iter()
                    .map(hex::encode)
                    .join(":"),
            );
        });
}

/// Stores contracts required by components, for example LP tokens if they are different from the
/// pool.
/// This is later used to index them with `extract_contract_changes`
#[substreams::handlers::store]
pub fn store_non_component_accounts(map: BlockTransactionProtocolComponents, store: StoreSetInt64) {
    map.tx_components
        .iter()
        .flat_map(|tx_components| &tx_components.components)
        .for_each(|component| {
            // Crypto pool factory creates LP token separated from the pool, we need to index it so
            // we add it to the store if the new protocol component comes from this factory
            if component.has_attributes(&[
                ("pool_type", "crypto_pool".into()),
                ("factory_name", "crypto_pool_factory".into()),
            ]) {
                let lp_token = component
                    .get_attribute_value("lp_token")
                    .expect("didn't find lp_token attribute");
                store.set(0, hex::encode(lp_token), &1);
            }
        });
}

/// Since the `PoolBalanceChanged` events administer only deltas, we need to leverage a map and a
///  store to be able to tally up final balances for tokens in a pool.
#[substreams::handlers::map]
pub fn map_relative_balances(
    block: eth::v2::Block,
    tokens_store: StoreGetString,
) -> Result<BlockBalanceDeltas, anyhow::Error> {
    Ok(BlockBalanceDeltas {
        balance_deltas: {
            let mut deltas: Vec<_> = block
                .transactions()
                .flat_map(|tx| {
                    emit_eth_deltas(tx, &tokens_store)
                        .into_iter()
                        .chain(
                            extract_balance_deltas_from_tx(tx, |token, transactor| {
                                let pool_key = format!("pool:{}", hex::encode(transactor));
                                if let Some(tokens) = tokens_store.get_last(pool_key) {
                                    let token_id;
                                    if token == OLD_SUSD {
                                        token_id = hex::encode(NEW_SUSD);
                                    } else {
                                        token_id = hex::encode(token);
                                    }
                                    tokens.split(':').any(|t| t == token_id)
                                } else {
                                    false
                                }
                            })
                            .into_iter()
                            .map(|mut balance| {
                                if balance.token == OLD_SUSD {
                                    balance.token = NEW_SUSD.into();
                                }
                                balance
                            })
                            .collect::<Vec<_>>(),
                        )
                })
                .collect();

            // Keep it consistent with how it's inserted in the store. This step is important
            // because we use a zip on the store deltas and balance deltas later.
            deltas.sort_unstable_by(|a, b| a.ord.cmp(&b.ord));

            deltas
        },
    })
}

/// It's significant to include both the `pool_id` and the `token_id` for each balance delta as the
///  store key to ensure that there's a unique balance being tallied for each.
#[substreams::handlers::store]
pub fn store_balances(deltas: BlockBalanceDeltas, store: StoreAddBigInt) {
    store_balance_changes(deltas, store)
}

/// This is the main map that handles most of the indexing of this substream.
/// Every change is grouped by transaction index via the `transaction_changes`
///  map. Each block of code will extend the `TransactionChanges` struct with the
///  cooresponding changes (balance, component, contract), inserting a new one if it doesn't exist.
///  At the very end, the map can easily be sorted by index to ensure the final
/// `BlockContractChanges` is ordered by transactions properly.
#[substreams::handlers::map]
pub fn map_protocol_changes(
    block: eth::v2::Block,
    grouped_components: BlockTransactionProtocolComponents,
    deltas: BlockBalanceDeltas,
    components_store: StoreGetString,
    non_component_accounts_store: StoreGetInt64,
    balance_store: StoreDeltas, // Note, this map module is using the `deltas` mode for the store.
) -> Result<BlockChanges> {
    // We merge contract changes by transaction (identified by transaction index) making it easy to
    //  sort them at the very end.
    let mut transaction_changes: HashMap<_, TransactionChanges> = HashMap::new();

    // `ProtocolComponents` are gathered from `map_pools_created` which just need a bit of work to
    //  convert into `TransactionChanges`
    grouped_components
        .tx_components
        .into_iter()
        .for_each(|tx_component| {
            let tx = tx_component.tx.as_ref().unwrap();
            transaction_changes
                .entry(tx.index)
                .or_insert_with(|| TransactionChanges {
                    tx: Some(tx.clone()),
                    contract_changes: vec![],
                    component_changes: vec![],
                    balance_changes: vec![],
                    entity_changes: vec![],
                })
                .component_changes
                .extend_from_slice(
                    &(tx_component
                        .components
                        .into_iter()
                        .map(|mut component| {
                            component.id = format!("0x{}", component.id);
                            component
                        })
                        .collect::<Vec<_>>()),
                );
        });

    // Balance changes are gathered by the `StoreDelta` based on `TokenExchange`, etc. creating
    //  `BalanceDeltas`. We essentially just process the changes that occured to the `store` this
    //  block. Then, these balance changes are merged onto the existing map of tx contract changes,
    //  inserting a new one if it doesn't exist.
    balance_store
        .deltas
        .into_iter()
        .zip(deltas.balance_deltas)
        .map(|(store_delta, balance_delta)| {
            let new_value_string = String::from_utf8(store_delta.new_value)
                .unwrap()
                .to_string();
            (
                balance_delta.tx.unwrap(),
                BalanceChange {
                    token: balance_delta.token,
                    balance: BigInt::try_from(new_value_string)
                        .unwrap()
                        .to_signed_bytes_be(),
                    component_id: format!(
                        "0x{}",
                        String::from_utf8(balance_delta.component_id).unwrap()
                    )
                    .into(),
                },
            )
        })
        // We need to group the balance changes by tx hash for the `TransactionChanges` agg
        .chunk_by(|(tx, _)| TransactionWrapper(tx.clone()))
        .into_iter()
        .for_each(|(tx_wrapped, group)| {
            let tx = tx_wrapped.0;

            transaction_changes
                .entry(tx.index)
                .or_insert_with(|| TransactionChanges {
                    tx: Some(tx.clone()),
                    contract_changes: vec![],
                    component_changes: vec![],
                    balance_changes: vec![],
                    entity_changes: vec![],
                })
                .balance_changes
                .extend(group.map(|(_, change)| change));
        });

    // General helper for extracting contract changes. Uses block, our component store which holds
    //  all of our tracked deployed pool addresses, and the map of tx contract changes which we
    //  output into for final processing later.
    extract_contract_changes(
        &block,
        |addr| {
            components_store
                .get_last(format!("pool:{0}", hex::encode(addr)))
                .is_some() ||
                non_component_accounts_store
                    .get_last(hex::encode(addr))
                    .is_some() ||
                addr.eq(&CRYPTO_SWAP_NG_FACTORY) ||
                addr.eq(&TRICRYPTO_FACTORY)
        },
        &mut transaction_changes,
    );

    for change in transaction_changes.values_mut() {
        for balance_change in change.balance_changes.iter_mut() {
            replace_eth_address(&mut balance_change.token);
        }

        for component_change in change.component_changes.iter_mut() {
            for token in component_change.tokens.iter_mut() {
                replace_eth_address(token);
            }
        }
    }

    // Process all `transaction_changes` for final output in the `BlockContractChanges`,
    //  sorted by transaction index (the key).
    Ok(BlockChanges {
        block: Some(Block {
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
        changes: transaction_changes
            .drain()
            .sorted_unstable_by_key(|(index, _)| *index)
            .filter_map(|(_, change)| {
                if change.contract_changes.is_empty() &&
                    change.component_changes.is_empty() &&
                    change.balance_changes.is_empty()
                {
                    None
                } else {
                    Some(change)
                }
            })
            .collect::<Vec<_>>(),
    })
}

fn replace_eth_address(token: &mut Vec<u8>) {
    let eth_address = [238u8; 20]; // 0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee
    if *token == eth_address {
        *token = [0u8; 20].to_vec();
    }
}
