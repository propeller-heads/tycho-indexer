use std::{collections::HashMap, vec};
use substreams::store::{StoreGet, StoreGetProto};
use substreams_ethereum::pb::eth::v2::{self as eth};

use substreams_helper::{event_handler::EventHandler, hex::Hexable};

use crate::{
    abi::pool::events::Sync,
    pb::tycho::evm::{
        uniswap::v2::Pool,
        v1::{
            Attribute, BalanceChange, Block, BlockEntityChanges, ChangeType, EntityChanges,
            SameTypeTransactionChanges, Transaction, TransactionEntityChanges,
        },
    },
    store_key::StoreKey,
    traits::PoolAddresser,
};

#[substreams::handlers::map]
pub fn map_pool_events(
    block: eth::Block,
    created_pairs: SameTypeTransactionChanges,
    pools_store: StoreGetProto<Pool>,
) -> Result<BlockEntityChanges, substreams::errors::Error> {
    // Sync event is sufficient for our use-case. Since it's emitted on
    // every reserve-altering function call, we can use it as the only event
    // to update the reserves of a pool.
    let mut tx_changes_map: HashMap<Vec<u8>, TransactionEntityChanges> = HashMap::new();

    handle_sync(&block, &mut created_pairs.clone(), &mut tx_changes_map, &pools_store);

    // Make a list of all HashMap values:
    let tx_entity_changes: Vec<TransactionEntityChanges> = tx_changes_map.into_values().collect();

    let tycho_block: Block = block.into();

    let block_entity_changes =
        BlockEntityChanges { block: Option::from(tycho_block), changes: tx_entity_changes };

    Ok(block_entity_changes)
}

fn handle_sync(
    block: &eth::Block,
    created_pairs: &mut SameTypeTransactionChanges,
    tx_changes_map: &mut HashMap<Vec<u8>, TransactionEntityChanges>,
    store: &StoreGetProto<Pool>,
) {
    // Create a HashMap of tx hashes to TransactionEntityChanges to allow for fast lookup
    // on transactions that created a pool and later add liquidity

    for change in &created_pairs.changes {
        let transaction = change.tx.as_ref().unwrap(); // get reference instead of value
        tx_changes_map.insert(transaction.hash.clone(), change.clone()); // clone because we're
                                                                         // working with references
    }

    let mut on_sync = |event: Sync, _tx: &eth::TransactionTrace, _log: &eth::Log| {
        let pool_address = _log.address.to_hex();

        let pool = store.must_get_last(StoreKey::Pool.get_unique_pool_key(pool_address.as_str()));
        // Convert reserves to hex
        let reserve0: Vec<u8> = event.reserve0.to_signed_bytes_le();
        let reserve1: Vec<u8> = event.reserve1.to_signed_bytes_le();

        // Create entity changes
        let entity_changes: Vec<EntityChanges> = vec![EntityChanges {
            component_id: pool_address.clone(),
            attributes: vec![
                Attribute {
                    name: "reserve0".to_string(),
                    value: reserve0.clone(),
                    change: ChangeType::Update.into(),
                },
                Attribute {
                    name: "reserve1".to_string(),
                    value: reserve1.clone(),
                    change: ChangeType::Update.into(),
                },
            ],
        }];

        // Create balance changes
        let balance_changes: Vec<BalanceChange> = vec![
            BalanceChange {
                token: pool.token0,
                balance: reserve0,
                component_id: Vec::from(pool_address.clone()),
            },
            BalanceChange {
                token: pool.token1,
                balance: reserve1,
                component_id: Vec::from(pool_address.clone()),
            },
        ];

        // Check if tx.hash is in map
        // Overrides entity_changes and balance_changes because logs
        // are ordered so, in case of multiple sync events, the last one will
        // be the most up-to-date
        match tx_changes_map.get_mut(&_tx.hash) {
            Some(change) => {
                // Found a transaction that created a pool
                change.entity_changes = entity_changes;
                change.balance_changes = balance_changes;
            }
            None => {
                // This transaction did not create a pool
                let tycho_tx: Transaction = _tx.into();
                let change: TransactionEntityChanges = TransactionEntityChanges {
                    tx: Option::from(tycho_tx),
                    component_changes: vec![],
                    entity_changes,
                    balance_changes,
                };
                // Events
                tx_changes_map.insert(_tx.hash.clone(), change);
            }
        }
    };

    let mut eh = EventHandler::new(block);
    eh.filter_by_address(PoolAddresser { store });
    eh.on::<Sync, _>(&mut on_sync);
    eh.handle_events();
}
