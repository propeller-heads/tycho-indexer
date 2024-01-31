use std::{collections::HashMap, usize, vec};
use substreams::{
    log,
    store::{StoreGet, StoreGetProto},
};
use substreams_ethereum::pb::eth::v2::{self as eth, Log, StorageChange, TransactionTrace};

use substreams_helper::hex::Hexable;

use crate::{
    events::get_log_changed_attribute,
    pb::tycho::evm::{
        uniswap::v3::Pool,
        v1::{
            BalanceChange, Block, BlockEntityChanges, EntityChanges, SameTypeTransactionChanges,
            TransactionEntityChanges,
        },
    },
    store_key::StoreKey,
};

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

                // Handle Uniswap V3 events, it will update the tx_changes_map
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
    storage_changes: &[StorageChange],
    pool: &Pool,
) {
    let changed_attributes = get_log_changed_attribute(event, storage_changes, pool);

    // Create entity changes
    let entity_changes: Vec<EntityChanges> = vec![EntityChanges {
        component_id: pool.address.clone().to_hex(),
        attributes: changed_attributes,
    }];

    update_tx_changes_map(entity_changes, vec![], tx_changes_map, tx_trace);
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
                    // If an existing entity change with the same component_id is found, add the new
                    // attributes to the existing entity change.

                    // Create a hashmap to ensure each attribute name is unique.
                    let mut attributes = HashMap::new();

                    // Insert elements from existing_change.
                    for attr in existing_change.attributes.clone() {
                        attributes
                            .entry(attr.name.clone())
                            .or_insert(attr);
                    }

                    // Insert elements from change. If an attribute with the same name is already
                    // present, it replaces it.
                    for attr in change.attributes {
                        attributes.insert(attr.name.clone(), attr);
                    }

                    existing_change.attributes = attributes.into_values().collect();
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
