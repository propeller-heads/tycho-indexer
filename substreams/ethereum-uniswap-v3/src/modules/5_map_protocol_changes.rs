use std::{collections::HashMap, str::FromStr, usize, vec};
use substreams::{
    pb::substreams::StoreDeltas,
    scalar::BigInt,
    store::{StoreGet, StoreGetBigInt},
};
use substreams_ethereum::pb::eth::v2::{self as eth, TransactionTrace};
use substreams_helper::hex::Hexable;

use crate::pb::{
    tycho::evm::v1::{
        Attribute, BalanceChange, BlockEntityChanges, ChangeType, EntityChanges,
        TransactionEntityChanges,
    },
    uniswap::v3::{
        events::{pool_event, PoolEvent},
        BalanceDeltas, Events, LiquidityChanges, TickDeltas,
    },
};
type TxIndex = u64;
type PoolAddress = Vec<u8>;

#[substreams::handlers::map]
pub fn map_protocol_changes(
    block: eth::Block,
    created_pools: BlockEntityChanges,
    events: Events,
    balances_map_deltas: BalanceDeltas,
    balances_store_deltas: StoreDeltas,
    ticks_map_deltas: TickDeltas,
    ticks_store_deltas: StoreDeltas,
    pool_liquidity_changes: LiquidityChanges,
    pool_liquidity_store_deltas: StoreDeltas,
) -> Result<BlockEntityChanges, substreams::errors::Error> {
    let mut tx_changes_map: HashMap<Vec<u8>, TransactionEntityChanges> = HashMap::new();

    // Add created pools to the tx_changes_map
    for change in created_pools.changes.into_iter() {
        let transaction = change.tx.as_ref().unwrap();
        tx_changes_map
            .entry(transaction.hash.clone())
            .and_modify(|c| {
                c.component_changes
                    .extend(change.component_changes.clone())
            })
            .or_insert(change);
    }

    let mut balance_changes: HashMap<TxIndex, Vec<BalanceChange>> = HashMap::new();
    balances_store_deltas
        .deltas
        .into_iter()
        .zip(balances_map_deltas.deltas)
        .for_each(|(store_delta, balance_delta)| {
            let new_value_bigint =
                BigInt::from_str(&String::from_utf8(store_delta.new_value).unwrap()).unwrap();
            balance_changes
                .entry(balance_delta.transaction.unwrap().index)
                .or_insert_with(Vec::new)
                .push(BalanceChange {
                    component_id: balance_delta
                        .pool_address
                        .to_hex()
                        .into(),
                    token: balance_delta.token_address,
                    balance: new_value_bigint.to_bytes_be().1,
                })
        });

    let mut entity_changes: HashMap<TxIndex, HashMap<PoolAddress, Vec<Attribute>>> = HashMap::new();

    ticks_store_deltas
        .deltas
        .into_iter()
        .zip(ticks_map_deltas.deltas)
        .for_each(|(store_delta, tick_delta)| {
            let new_value_bigint =
                BigInt::from_str(&String::from_utf8(store_delta.new_value).unwrap()).unwrap();
            let attribute_name = format!("ticks/{}/net-liquidity", tick_delta.tick_index);
            let attribute = Attribute {
                name: attribute_name,
                value: new_value_bigint.to_signed_bytes_le(),
                change: if new_value_bigint.is_zero() {
                    ChangeType::Deletion.into()
                } else {
                    ChangeType::Update.into()
                },
            };

            entity_changes
                .entry(tick_delta.transaction.unwrap().index)
                .or_insert_with(HashMap::new)
                .entry(tick_delta.pool_address)
                .or_insert_with(Vec::new)
                .push(attribute);
        });

    pool_liquidity_store_deltas
        .deltas
        .into_iter()
        .zip(pool_liquidity_changes.changes)
        .for_each(|(store_delta, change)| {
            let new_value_bigint = BigInt::from_str(
                &String::from_utf8(store_delta.new_value)
                    .unwrap()
                    .split(':')
                    .nth(1)
                    .unwrap(),
            )
            .unwrap();
            entity_changes
                .entry(change.transaction.unwrap().index)
                .or_insert_with(HashMap::new)
                .entry(change.pool_address)
                .or_insert_with(Vec::new)
                .push(Attribute {
                    name: "liquidity".to_string(),
                    value: new_value_bigint.to_signed_bytes_le(),
                    change: ChangeType::Update.into(),
                });
        });

    events
        .pool_events
        .into_iter()
        .flat_map(event_to_attributes_updates)
        .for_each(|(tx_ix, pool_address, attr)| {
            entity_changes
                .entry(tx_ix)
                .or_insert_with(HashMap::new)
                .entry(pool_address)
                .or_insert_with(Vec::new)
                .push(attr);
        });

    for trx in block.transactions() {
        let entity_c = entity_changes
            .remove(&trx.index.into())
            .unwrap_or_default()
            .into_iter()
            .map(|(c_id, attributes)| EntityChanges { component_id: c_id.to_hex(), attributes })
            .collect::<Vec<_>>();

        let balance_c = balance_changes
            .remove(&trx.index.into())
            .unwrap_or_default();

        if !entity_c.is_empty() || !balance_c.is_empty() {
            update_tx_changes_map(&mut tx_changes_map, entity_c, balance_c, trx);
        }
    }

    Ok(BlockEntityChanges {
        block: Some(block.into()),
        changes: tx_changes_map.into_values().collect(),
    })
}

fn update_tx_changes_map(
    tx_changes_map: &mut HashMap<Vec<u8>, TransactionEntityChanges>,
    entity_changes: Vec<EntityChanges>,
    balance_changes: Vec<BalanceChange>,
    tx_trace: &TransactionTrace,
) {
    // Get the tx hash
    let tx_hash = tx_trace.hash.clone();

    // Get the tx changes from the map
    let tx_changes = tx_changes_map.get_mut(&tx_hash);

    // Update the tx changes
    if let Some(tx_changes) = tx_changes {
        // Merge the entity changes
        tx_changes.entity_changes =
            merge_entity_changes(&tx_changes.entity_changes, &entity_changes);

        // Merge the balance changes
        tx_changes.balance_changes =
            merge_balance_changes(&tx_changes.balance_changes, &balance_changes);
    } else {
        // If the tx is not in the map, add it
        let tx_changes = TransactionEntityChanges {
            tx: Some(tx_trace.into()),
            entity_changes,
            balance_changes,
            component_changes: vec![],
        };
        tx_changes_map.insert(tx_hash, tx_changes);
    }
}

/// Merges new entity changes into an existing collection of entity changes and returns the merged
/// result. For each entity change, if an entity change with the same component_id exists, its
/// attributes are merged. If an attribute with the same name exists, the new attribute replaces the
/// old one.
///
/// Parameters:
/// - `existing_changes`: A reference to a vector of existing entity changes.
/// - `new_changes`: A reference to a vector of new entity changes to be merged.
///
/// Returns:
/// A new `Vec<EntityChanges>` containing the merged entity changes.
fn merge_entity_changes(
    existing_changes: &[EntityChanges],
    new_changes: &Vec<EntityChanges>,
) -> Vec<EntityChanges> {
    let mut changes_map = existing_changes
        .iter()
        .cloned()
        .map(|change| (change.component_id.clone(), change))
        .collect::<HashMap<_, _>>();

    for change in new_changes {
        match changes_map.get_mut(&change.component_id) {
            Some(existing_change) => {
                let mut attributes_map = existing_change
                    .attributes
                    .iter()
                    .cloned()
                    .map(|attr| (attr.name.clone(), attr))
                    .collect::<HashMap<_, _>>();

                for attr in &change.attributes {
                    attributes_map.insert(attr.name.clone(), attr.clone());
                }

                existing_change.attributes = attributes_map.into_values().collect();
            }
            None => {
                changes_map.insert(change.component_id.clone(), change.clone());
            }
        }
    }

    changes_map.into_values().collect()
}

#[derive(Debug, PartialEq, Eq, Hash)]
struct BalanceChangeKey {
    token: Vec<u8>,
    component_id: Vec<u8>,
}

/// Merges two vectors of `BalanceChange` structures into a single vector. If two `BalanceChange`
/// instances have the same combination of `token` and `component_id`, the value from the
/// `new_entries` vector will replace the one from the `current` vector.
///
/// Parameters:
/// - `current`: A reference to a vector of `BalanceChange` instances representing the current
///   balance changes.
/// - `new_entries`: A reference to a vector of `BalanceChange` instances representing new balance
///   changes to be merged.
///
/// Returns:
/// A `Vec<BalanceChange>` that contains the merged balance changes.
fn merge_balance_changes(
    current: &[BalanceChange],
    new_entries: &Vec<BalanceChange>,
) -> Vec<BalanceChange> {
    let mut balances = HashMap::new();

    for balance_change in current.iter().chain(new_entries) {
        let key = BalanceChangeKey {
            token: balance_change.token.clone(),
            component_id: balance_change.component_id.clone(),
        };

        balances.insert(key, balance_change.clone());
    }

    balances.into_values().collect()
}

fn event_to_attributes_updates(event: PoolEvent) -> Vec<(TxIndex, PoolAddress, Attribute)> {
    match event.r#type.as_ref().unwrap() {
        pool_event::Type::Initialize(initalize) => {
            vec![
                (
                    event.transaction.clone().unwrap().index,
                    hex::decode(event.pool_address.clone()).unwrap(),
                    Attribute {
                        name: "sqrt_price_x96".to_string(),
                        value: BigInt::from_str(&initalize.sqrt_price)
                            .unwrap()
                            .to_signed_bytes_le(),
                        change: ChangeType::Update.into(),
                    },
                ),
                (
                    event.transaction.unwrap().index,
                    hex::decode(event.pool_address).unwrap(),
                    Attribute {
                        name: "tick".to_string(),
                        value: BigInt::from(initalize.tick).to_signed_bytes_le(),
                        change: ChangeType::Update.into(),
                    },
                ),
            ]
        }
        pool_event::Type::Swap(swap) => vec![
            (
                event.transaction.clone().unwrap().index,
                hex::decode(event.pool_address.clone()).unwrap(),
                Attribute {
                    name: "sqrt_price_x96".to_string(),
                    value: BigInt::from_str(&swap.sqrt_price)
                        .unwrap()
                        .to_signed_bytes_le(),
                    change: ChangeType::Update.into(),
                },
            ),
            (
                event.transaction.unwrap().index,
                hex::decode(event.pool_address).unwrap(),
                Attribute {
                    name: "tick".to_string(),
                    value: BigInt::from(swap.tick).to_signed_bytes_le(),
                    change: ChangeType::Update.into(),
                },
            ),
        ],
        pool_event::Type::SetFeeProtocol(sfp) => vec![
            (
                event.transaction.clone().unwrap().index,
                hex::decode(event.pool_address.clone()).unwrap(),
                Attribute {
                    name: "protocol_fees/token0".to_string(),
                    value: BigInt::from(sfp.fee_protocol_0_new.clone()).to_signed_bytes_le(),
                    change: ChangeType::Update.into(),
                },
            ),
            (
                event.transaction.unwrap().index,
                hex::decode(event.pool_address).unwrap(),
                Attribute {
                    name: "protocol_fees/token1".to_string(),
                    value: BigInt::from(sfp.fee_protocol_1_new.clone()).to_signed_bytes_le(),
                    change: ChangeType::Update.into(),
                },
            ),
        ],
        _ => vec![],
    }
}
