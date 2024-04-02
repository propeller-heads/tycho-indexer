use std::collections::HashMap;

use anyhow::Result;
use substreams::{
    pb::substreams::StoreDeltas,
    store::{
        StoreAdd, StoreAddBigInt, StoreAddInt64, StoreGet, StoreGetInt64, StoreGetString, StoreNew,
        StoreSet, StoreSetString,
    },
};

use substreams::{hex, key, scalar::BigInt};

use substreams_ethereum::{block_view::LogView, pb::eth};

use itertools::Itertools;

use substreams_ethereum::Event;

use crate::{abi, pb};

use tycho_substreams::{
    balances::store_balance_changes, contract::extract_contract_changes, prelude::*,
};

const FACTORY: [u8; 20] = hex!("Eb6625D65a0553c9dBc64449e56abFe519bd9c9B");

// struct BinDelta {
//     delta_a: BigInt,
//     delta_b: BigInt,
//     delta_lp_balance: BigInt,
//     bin_id: BigInt,
//     kind: BigInt,
//     lower_tick: BigInt,
//     is_active: bool,
// }

/// This struct purely exists to spoof the `PartialEq` trait for `Transaction` so we can use it in
///  a later groupby operation.
#[derive(Debug)]
struct TransactionWrapper(Transaction);

impl PartialEq for TransactionWrapper {
    fn eq(&self, other: &Self) -> bool {
        self.0.hash == other.0.hash
    }
}

fn tx_from_log(log: &LogView) -> Transaction {
    Transaction {
        hash: log.receipt.transaction.hash.clone(),
        from: log.receipt.transaction.from.clone(),
        to: log.receipt.transaction.to.clone(),
        index: Into::<u64>::into(log.receipt.transaction.index),
    }
}

#[substreams::handlers::map]
pub fn map_components(block: eth::v2::Block) -> Result<BlockTransactionProtocolComponents> {
    // Gather contract changes by indexing `PoolCreated` events and analysing the `Create` call
    // We store these as a hashmap by tx hash since we need to agg by tx hash later
    Ok(BlockTransactionProtocolComponents {
        tx_components: block
            .transactions()
            .filter_map(|tx| {
                let components: Vec<ProtocolComponent> = tx
                    .logs_with_calls()
                    .filter(|(_, call)| !call.call.state_reverted)
                    .filter(|(log, _)| log.address == FACTORY)
                    .filter_map(|(log, _)| {
                        let pool_added = abi::factory::events::PoolCreated::match_and_decode(log)?;

                        Some(ProtocolComponent {
                            id: hex::encode(&pool_added.pool_address),
                            tx: Some(Transaction {
                                hash: tx.hash.clone(),
                                from: tx.from.clone(),
                                to: tx.to.clone(),
                                index: Into::<u64>::into(tx.index),
                            }),
                            tokens: vec![pool_added.token_a, pool_added.token_b],
                            contracts: vec![FACTORY.into(), pool_added.pool_address],
                            static_att: vec![
                                Attribute {
                                    name: "activeTick".into(),
                                    value: pool_added
                                        .active_tick
                                        .to_signed_bytes_be(),
                                    change: ChangeType::Creation.into(),
                                },
                                Attribute {
                                    name: "lookback".into(),
                                    value: pool_added.lookback.to_signed_bytes_be(),
                                    change: ChangeType::Creation.into(),
                                },
                            ],
                            change: ChangeType::Creation.into(),
                            ..Default::default()
                        })
                    })
                    .collect::<Vec<_>>();

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

/// Simply stores the `ProtocolComponent`s with the pool id as the key
#[substreams::handlers::store]
pub fn store_components(map: BlockTransactionProtocolComponents, store: StoreAddInt64) {
    store.add_many(
        0,
        &map.tx_components
            .iter()
            .flat_map(|tx_components| &tx_components.components)
            .map(|component| format!("pool:{0}", component.id))
            .collect::<Vec<_>>(),
        1,
    );
}

/// Simply stores the `ProtocolComponent`s with the pool id as the key
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
                    .map(|token| hex::encode(token))
                    .join(":".into()),
            );
        });
}

/// Since the `Swap`, `AddLiquidity`, `RemoveLiuidity` events administer only deltas, we need to
/// leverage a map and a store to be able to tally up final balances for tokens in a pool.
#[substreams::handlers::map]
pub fn map_relative_balances(
    block: eth::v2::Block,
    pools_store: StoreGetInt64,
    tokens_store: StoreGetString,
) -> Result<BlockBalanceDeltas, anyhow::Error> {
    let deltas = block
        .logs()
        .filter(|log| {
            pools_store
                .get_last(format!("pool:{0}", hex::encode(&log.address())))
                .is_some()
        })
        .flat_map(|log| {
            if let Some(event) = abi::pool::events::Swap::match_and_decode(log) {
                let tokens = tokens_store
                    .get_last(format!("pool:{}", hex::encode(log.address())))
                    .unwrap()
                    .split(":")
                    .map(|token| token.to_owned()) // Clone the tokens
                    .collect::<Vec<_>>();
                let (token_a, token_b) = if event.token_a_in {
                    (
                        hex::decode(tokens[0].clone()).unwrap(),
                        hex::decode(tokens[1].clone()).unwrap(),
                    )
                } else {
                    (
                        hex::decode(tokens[1].clone()).unwrap(),
                        hex::decode(tokens[0].clone()).unwrap(),
                    )
                };
                vec![
                    BalanceDelta {
                        ord: log.log.ordinal,
                        tx: Some(tx_from_log(&log)),
                        token: token_a,
                        delta: event.amount_in.to_signed_bytes_be(),
                        component_id: log.address().into(),
                    },
                    BalanceDelta {
                        ord: log.log.ordinal,
                        tx: Some(tx_from_log(&log)),
                        token: token_b,
                        delta: event.amount_out.to_signed_bytes_be(),
                        component_id: log.address().into(),
                    },
                ]
            } else if let Some(event) = abi::pool::events::AddLiquidity::match_and_decode(log) {
                event
                    .bin_deltas
                    .into_iter()
                    .flat_map(
                        |(
                            delta_a,
                            delta_b,
                            delta_lp_balance,
                            bin_id,
                            kind,
                            lower_tick,
                            is_active,
                        )| {
                            let tokens = tokens_store
                                .get_last(format!("pool:{}", hex::encode(log.address())))
                                .unwrap()
                                .split(":")
                                .map(|token| token.to_owned()) // Clone the tokens
                                .collect::<Vec<_>>();
                            vec![
                                BalanceDelta {
                                    ord: log.log.ordinal,
                                    tx: Some(tx_from_log(&log)),
                                    token: hex::decode(tokens[0].clone()).unwrap(),
                                    delta: delta_a.to_signed_bytes_be(),
                                    component_id: log.address().into(),
                                },
                                BalanceDelta {
                                    ord: log.log.ordinal,
                                    tx: Some(tx_from_log(&log)),
                                    token: hex::decode(tokens[1].clone()).unwrap(),
                                    delta: delta_b.to_signed_bytes_be(),
                                    component_id: log.address().into(),
                                },
                            ]
                        },
                    )
                    .collect::<Vec<_>>()
            } else if let Some(event) = abi::pool::events::RemoveLiquidity::match_and_decode(log) {
                event
                    .bin_deltas
                    .into_iter()
                    .flat_map(
                        |(
                            delta_a,
                            delta_b,
                            delta_lp_balance,
                            bin_id,
                            kind,
                            lower_tick,
                            is_active,
                        )| {
                            let tokens = tokens_store
                                .get_last(format!("pool:{}", hex::encode(log.address())))
                                .unwrap()
                                .split(":")
                                .map(|token| token.to_owned()) // Clone the tokens
                                .collect::<Vec<_>>();
                            let neg_delta_a: BigInt = delta_a * -1;
                            let neg_delta_b: BigInt = delta_b * -1;
                            vec![
                                BalanceDelta {
                                    ord: log.log.ordinal,
                                    tx: Some(tx_from_log(&log)),
                                    token: hex::decode(tokens[0].clone()).unwrap(),
                                    delta: neg_delta_a.to_signed_bytes_be(),
                                    component_id: log.address().into(),
                                },
                                BalanceDelta {
                                    ord: log.log.ordinal,
                                    tx: Some(tx_from_log(&log)),
                                    token: hex::decode(tokens[1].clone()).unwrap(),
                                    delta: neg_delta_b.to_signed_bytes_be(),
                                    component_id: log.address().into(),
                                },
                            ]
                        },
                    )
                    .collect::<Vec<_>>()
            } else {
                vec![]
            }
        })
        .collect::<Vec<_>>();

    Ok(BlockBalanceDeltas { balance_deltas: deltas })
}

/// It's significant to include both the `pool_id` and the `token_id` for each balance delta as the
///  store key to ensure that there's a unique balance being tallied for each.
#[substreams::handlers::store]
pub fn store_balances(deltas: BlockBalanceDeltas, store: StoreAddBigInt) {
    store_balance_changes(deltas, store)
}

/// This is the main map that handles most of the indexing of this substream.
/// Every contract change is grouped by transaction index via the `transaction_contract_changes`
///  map. Each block of code will extend the `TransactionContractChanges` struct with the
///  cooresponding changes (balance, component, contract), inserting a new one if it doesn't exist.
///  At the very end, the map can easily be sorted by index to ensure the final
/// `BlockContractChanges`  is ordered by transactions properly.
#[substreams::handlers::map]
pub fn map_protocol_changes(
    block: eth::v2::Block,
    grouped_components: BlockTransactionProtocolComponents,
    deltas: BlockBalanceDeltas,
    components_store: StoreGetInt64,
    balance_store: StoreDeltas, // Note, this map module is using the `deltas` mode for the store.
) -> Result<BlockContractChanges> {
    // We merge contract changes by transaction (identified by transaction index) making it easy to
    //  sort them at the very end.
    let mut transaction_contract_changes: HashMap<_, TransactionContractChanges> = HashMap::new();

    // `ProtocolComponents` are gathered from `map_pools_created` which just need a bit of work to
    //   convert into `TransactionContractChanges`
    grouped_components
        .tx_components
        .iter()
        .for_each(|tx_component| {
            let tx = tx_component.tx.as_ref().unwrap();

            transaction_contract_changes
                .entry(tx.index)
                .or_insert_with(|| TransactionContractChanges {
                    tx: Some(tx.clone()),
                    contract_changes: vec![],
                    component_changes: vec![],
                    balance_changes: vec![],
                })
                .component_changes
                .extend_from_slice(&tx_component.components);
        });

    // Balance changes are gathered by the `StoreDelta` based on transfer and liquidity events
    //  creating `BalanceDeltas`. We essentially just process the changes that occured to the
    //  `store` this block. Then, these balance changes are merged onto the existing map of
    //  tx contract changes, inserting a new one if it doesn't exist.
    balance_store
        .deltas
        .into_iter()
        .zip(deltas.balance_deltas)
        .map(|(store_delta, balance_delta)| {
            let pool_id = key::segment_at(&store_delta.key, 1);
            let token_id = key::segment_at(&store_delta.key, 3);
            (
                balance_delta.tx.unwrap(),
                BalanceChange {
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

            transaction_contract_changes
                .entry(tx.index)
                .or_insert_with(|| TransactionContractChanges {
                    tx: Some(tx.clone()),
                    contract_changes: vec![],
                    component_changes: vec![],
                    balance_changes: vec![],
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
                .get_last(format!("pool:0x{0}", hex::encode(addr)))
                .is_some()
        },
        &mut transaction_contract_changes,
    );

    // Process all `transaction_contract_changes` for final output in the `BlockContractChanges`,
    //  sorted by transaction index (the key).
    Ok(BlockContractChanges {
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
        changes: transaction_contract_changes
            .drain()
            .sorted_unstable_by_key(|(index, _)| index.clone())
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

// #[substreams::handlers::map]
// pub fn debug_block_events(block: eth::v2::Block) -> Result<BlockContractChanges> {
//     log::info!("Block: {:?}", block);

//     Ok(BlockContractChanges {
//         block: Some(Block {
//             number: block.number,
//             hash: block.hash.clone(),
//             parent_hash: block
//                 .header
//                 .as_ref()
//                 .expect("Block header not present")
//                 .parent_hash
//                 .clone(),
//             ts: block.timestamp_seconds(),
//         }),
//         changes: transaction_contract_changes
//             .drain()
//             .sorted_unstable_by_key(|(index, _)| index.clone())
//             .filter_map(|(_, change)| {
//                 if change.contract_changes.is_empty()
//                     && change.component_changes.is_empty()
//                     && change.balance_changes.is_empty()
//                 {
//                     None
//                 } else {
//                     Some(change)
//                 }
//             })
//             .collect::<Vec<_>>(),
//     })
// }
