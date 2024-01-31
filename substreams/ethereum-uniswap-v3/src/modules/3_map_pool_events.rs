use std::{collections::HashMap, vec};
use substreams::{
    log,
    scalar::BigInt,
    store::{StoreGet, StoreGetProto},
};
use substreams_ethereum::{
    pb::eth::v2::{self as eth, Log, StorageChange, TransactionTrace},
    Event,
};

use substreams_helper::hex::Hexable;

use crate::{
    abi::pool::events::{
        Burn, Collect, CollectProtocol, Flash, Initialize, Mint, SetFeeProtocol, Swap,
    },
    pb::tycho::evm::{
        uniswap::v3::Pool,
        v1::{
            Attribute, BalanceChange, Block, BlockEntityChanges, ChangeType, EntityChanges,
            SameTypeTransactionChanges, TransactionEntityChanges,
        },
    },
    storage::uniswap_v3_pool::UniswapPoolStorage,
    store_key::StoreKey,
};

enum EventType {
    Initialize,
    Swap,
    Flash,
    Mint(Mint),
    Burn(Burn),
    Collect,
    SetFeeProtocol,
    CollectProtocol,
    Unknown,
}

#[substreams::handlers::map]
pub fn map_pool_events(
    block: eth::Block,
    created_pairs: SameTypeTransactionChanges,
    pools_store: StoreGetProto<Pool>,
) -> Result<BlockEntityChanges, substreams::errors::Error> {
    let mut tx_changes_map: HashMap<Vec<u8>, TransactionEntityChanges> = HashMap::new();

    // Add created pairs to the tx_changes_map
    for change in &created_pairs.changes {
        let transaction = change.tx.as_ref().unwrap();
        tx_changes_map.insert(transaction.hash.clone(), change.clone());
    }

    for trx in block.transactions() {
        for (log, call_view) in trx.logs_with_calls() {
            // Skip if the log is not from a known uniswapV3 pool.
            if let Some(pool) =
                pools_store.get_last(StoreKey::Pool.get_unique_pool_key(&log.address.to_hex()))
            {
                log::info!("Log from pool address: {}", pool.address.clone().to_hex());

                // Handle events, it will update the tx_changes_map
                handle_pool_events(
                    &mut tx_changes_map,
                    trx,
                    log,
                    &call_view.call.storage_changes,
                    &pool,
                );
            } else {
                continue;
            }
        }
    }

    // Make a list of all HashMap values:
    let tx_entity_changes: Vec<TransactionEntityChanges> = tx_changes_map.into_values().collect();

    let tycho_block: Block = block.into();

    let block_entity_changes =
        BlockEntityChanges { block: Option::from(tycho_block), changes: tx_entity_changes };

    Ok(block_entity_changes)
}

fn handle_pool_events(
    tx_changes_map: &mut HashMap<Vec<u8>, TransactionEntityChanges>,
    tx_trace: &TransactionTrace,
    event: &Log,
    storage_changes: &Vec<StorageChange>,
    pool: &Pool,
) {
    match decode_event(event) {
        EventType::Mint(mint) => {
            handle_mint_or_burn(
                storage_changes,
                pool,
                &mint.tick_upper,
                &mint.tick_lower,
                tx_changes_map,
                tx_trace,
            );
        }
        EventType::Burn(burn) => {
            handle_mint_or_burn(
                storage_changes,
                pool,
                &burn.tick_upper,
                &burn.tick_lower,
                tx_changes_map,
                tx_trace,
            );
        }
        _ => {
            let pool_storage = UniswapPoolStorage::new(storage_changes, &pool.address);

            let changed_attributes = pool_storage.get_changed_attributes();

            // Create entity changes
            let entity_changes: Vec<EntityChanges> = vec![EntityChanges {
                component_id: pool.address.clone().to_hex(),
                attributes: changed_attributes,
            }];

            // TODO: Create balance changes
            let balance_changes: Vec<BalanceChange> = vec![];

            update_tx_changes_map(entity_changes, balance_changes, tx_changes_map, tx_trace);
        }
    }
}

fn handle_mint_or_burn(
    storage_changes: &Vec<StorageChange>,
    pool: &Pool,
    tick_upper_idx: &BigInt,
    tick_lower_idx: &BigInt,
    tx_changes_map: &mut HashMap<Vec<u8>, TransactionEntityChanges>,
    tx_trace: &TransactionTrace,
) {
    let pool_storage = UniswapPoolStorage::new(storage_changes, &pool.address);

    // Get all relevent storage changes
    let mut changed_attributes = pool_storage.get_changed_attributes();

    handle_ticks_changes(pool_storage, tick_upper_idx, tick_lower_idx, &mut changed_attributes);

    // Create entity changes
    let entity_changes: Vec<EntityChanges> = vec![EntityChanges {
        component_id: pool.address.clone().to_hex(),
        attributes: changed_attributes,
    }];

    // TODO: Create balance changes
    let balance_changes: Vec<BalanceChange> = vec![];

    update_tx_changes_map(entity_changes, balance_changes, tx_changes_map, tx_trace);
}

fn handle_ticks_changes(
    pool_storage: UniswapPoolStorage<'_>,
    tick_upper_idx: &BigInt,
    tick_lower_idx: &BigInt,
    changed_attributes: &mut Vec<Attribute>,
) {
    let upper_tick = pool_storage.ticks(tick_upper_idx);
    let lower_tick = pool_storage.ticks(tick_lower_idx);

    // We expect upper_tick and lower_tick net liquidity to change on burn
    if let Some(liq) = upper_tick.net_liquidity() {
        changed_attributes.push(Attribute {
            name: format!("tick/{}/net-liquidity", tick_upper_idx),
            value: liq.1.to_signed_bytes_le(),
            change: ChangeType::Update.into(),
        });
    }

    if let Some(liq) = lower_tick.net_liquidity() {
        changed_attributes.push(Attribute {
            name: format!("tick/{}/net-liquidity", tick_lower_idx),
            value: liq.1.to_signed_bytes_le(),
            change: ChangeType::Update.into(),
        });
    }
}

fn decode_event(event: &Log) -> EventType {
    if Swap::match_log(event) {
        EventType::Swap
    } else if let Some(e) = Mint::match_and_decode(event) {
        EventType::Mint(e)
    } else if let Some(e) = Burn::match_and_decode(event) {
        EventType::Burn(e)
    } else if Initialize::match_log(event) {
        EventType::Initialize
    } else if Flash::match_log(event) {
        EventType::Flash
    } else if Collect::match_log(event) {
        EventType::Collect
    } else if SetFeeProtocol::match_log(event) {
        EventType::SetFeeProtocol
    } else if CollectProtocol::match_log(event) {
        EventType::CollectProtocol
    } else {
        EventType::Unknown
    }
}

fn update_tx_changes_map(
    entity_changes: Vec<EntityChanges>,
    balance_changes: Vec<BalanceChange>,
    tx_changes_map: &mut HashMap<Vec<u8>, TransactionEntityChanges>,
    tx_trace: &TransactionTrace,
) {
    // Get the tx hash
    let tx_hash = tx_trace.hash.clone();

    // Get the tx changes from the map
    let tx_changes = tx_changes_map.get_mut(&tx_hash);

    // Update the tx changes
    if let Some(tx_changes) = tx_changes {
        // Iterate over incoming entity changes
        for change in entity_changes {
            match tx_changes
                .entity_changes
                .iter_mut()
                .find(|e| e.component_id == change.component_id)
            {
                Some(existing_change) => {
                    // If an existing entity change with the same component_id is found, extend its
                    // attributes
                    existing_change
                        .attributes
                        .extend(change.attributes);
                }
                None => {
                    // If no existing entity change with the same component_id, add the new change
                    tx_changes.entity_changes.push(change);
                }
            }
        }

        tx_changes
            .balance_changes
            .extend(balance_changes);
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
