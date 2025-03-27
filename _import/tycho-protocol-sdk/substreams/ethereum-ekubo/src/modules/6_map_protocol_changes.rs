use std::{collections::HashMap, str::FromStr};

use itertools::Itertools;
use substreams::{key, pb::substreams::StoreDeltas, scalar::BigInt};
use substreams_ethereum::pb::eth;
use substreams_helper::hex::Hexable;
use tycho_substreams::{
    balances::aggregate_balances_changes,
    models::{
        Attribute, BlockBalanceDeltas, BlockChanges, ChangeType, EntityChanges,
        TransactionChangesBuilder,
    },
};

use crate::pb::ekubo::{
    block_transaction_events::transaction_events::pool_log::Event, BlockTransactionEvents,
    LiquidityChanges, TickDeltas,
};

/// Aggregates protocol components and balance changes by transaction.
///
/// This is the main method that will aggregate all changes as well as extract all
/// relevant contract storage deltas.
#[substreams::handlers::map]
fn map_protocol_changes(
    block: eth::v2::Block,
    new_components: BlockChanges,
    block_tx_events: BlockTransactionEvents,
    balances_map_deltas: BlockBalanceDeltas,
    balances_store_deltas: StoreDeltas,
    ticks_map_deltas: TickDeltas,
    ticks_store_deltas: StoreDeltas,
    liquidity_changes: LiquidityChanges,
    liquidity_store_deltas: StoreDeltas,
) -> Result<BlockChanges, substreams::errors::Error> {
    let mut transaction_changes: HashMap<_, TransactionChangesBuilder> = HashMap::new();

    // New components
    new_components
        .changes
        .iter()
        .for_each(|tx_changes| {
            let tx = tx_changes.tx.as_ref().unwrap();
            let builder = transaction_changes
                .entry(tx.index)
                .or_insert_with(|| TransactionChangesBuilder::new(tx));

            tx_changes
                .component_changes
                .iter()
                .for_each(|component| {
                    builder.add_protocol_component(component);
                });

            tx_changes
                .entity_changes
                .iter()
                .for_each(|entity_change| {
                    builder.add_entity_change(entity_change);
                });

            tx_changes
                .balance_changes
                .iter()
                .for_each(|balance_change| {
                    builder.add_balance_change(balance_change);
                });
        });

    // Component balances
    aggregate_balances_changes(balances_store_deltas, balances_map_deltas)
        .into_iter()
        .for_each(|(_, (tx, balances))| {
            let builder = transaction_changes
                .entry(tx.index)
                .or_insert_with(|| TransactionChangesBuilder::new(&tx));

            balances
                .values()
                .for_each(|token_bc_map| {
                    token_bc_map.values().for_each(|bc| {
                        builder.add_balance_change(bc);
                    })
                });
        });

    // Tick liquidities
    ticks_store_deltas
        .deltas
        .into_iter()
        .zip(ticks_map_deltas.deltas)
        .for_each(|(store_delta, tick_delta)| {
            let new_value_bigint = BigInt::from_store_bytes(&store_delta.new_value);

            let is_creation = BigInt::from_store_bytes(&store_delta.old_value).is_zero();

            let attribute = Attribute {
                name: format!("ticks/{}", tick_delta.tick_index),
                value: new_value_bigint.to_signed_bytes_be(),
                change: if is_creation {
                    ChangeType::Creation.into()
                } else if new_value_bigint.is_zero() {
                    ChangeType::Deletion.into()
                } else {
                    ChangeType::Update.into()
                },
            };
            let tx = tick_delta.transaction.unwrap();
            let builder = transaction_changes
                .entry(tx.index)
                .or_insert_with(|| TransactionChangesBuilder::new(&tx.into()));

            builder.add_entity_change(&EntityChanges {
                component_id: tick_delta.pool_id.to_hex(),
                attributes: vec![attribute],
            });
        });

    // Pool liquidities
    liquidity_store_deltas
        .deltas
        .into_iter()
        .zip(liquidity_changes.changes)
        .for_each(|(store_delta, change)| {
            let tx = change.transaction.unwrap();
            let builder = transaction_changes
                .entry(tx.index)
                .or_insert_with(|| TransactionChangesBuilder::new(&tx.into()));

            let new_value_bigint = BigInt::from_str(key::segment_at(
                &String::from_utf8(store_delta.new_value).unwrap(),
                1,
            ))
            .unwrap();

            builder.add_entity_change(&EntityChanges {
                component_id: change.pool_id.to_hex(),
                attributes: vec![Attribute {
                    name: "liquidity".to_string(),
                    value: new_value_bigint.to_signed_bytes_be(),
                    change: ChangeType::Update.into(),
                }],
            });
        });

    // Remaining event changes not subject to special treatment
    block_tx_events
        .block_transaction_events
        .into_iter()
        .flat_map(|tx_events| {
            let tx = tx_events.transaction.unwrap();

            tx_events
                .pool_logs
                .into_iter()
                .flat_map(move |log| {
                    let tx = tx.clone();

                    maybe_attribute_updates(log.event.unwrap()).map(|attrs| {
                        (
                            tx,
                            EntityChanges { component_id: log.pool_id.to_hex(), attributes: attrs },
                        )
                    })
                })
        })
        .for_each(|(tx, entity_changes)| {
            let builder = transaction_changes
                .entry(tx.index)
                .or_insert_with(|| TransactionChangesBuilder::new(&tx.into()));
            builder.add_entity_change(&entity_changes);
        });

    Ok(BlockChanges {
        block: Some((&block).into()),
        changes: transaction_changes
            .drain()
            .sorted_unstable_by_key(|(index, _)| *index)
            .filter_map(|(_, builder)| builder.build())
            .collect(),
    })
}

fn maybe_attribute_updates(ev: Event) -> Option<Vec<Attribute>> {
    match ev {
        Event::Swapped(swapped) => Some(vec![
            Attribute {
                name: "tick".into(),
                value: swapped
                    .tick_after
                    .to_be_bytes()
                    .to_vec(),
                change: ChangeType::Update.into(),
            },
            Attribute {
                name: "sqrt_ratio".into(),
                value: swapped.sqrt_ratio_after,
                change: ChangeType::Update.into(),
            },
        ]),
        _ => None,
    }
}
