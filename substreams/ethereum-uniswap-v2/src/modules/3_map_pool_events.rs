use std::vec;
use substreams::store::{StoreGet, StoreGetProto};
use substreams_ethereum::pb::eth::v2::{self as eth};

use substreams_helper::{event_handler::EventHandler, hex::Hexable};

use crate::{
    abi::pool::events::Sync,
    pb::tycho::evm::{
        uniswap::v2::Pool,
        v1::{
            Attribute, ChangeType, EntityChanges, SameTypeTransactionChanges,
            TransactionEntityChanges,
        },
    },
    traits::{PoolAddresser},
};
use crate::pb::tycho::evm::v1::Transaction;

#[substreams::handlers::map]
pub fn map_pool_events(
    block: eth::Block,
    pools_store: StoreGetProto<Pool>,
) -> Result<SameTypeTransactionChanges, substreams::errors::Error> {
    let mut events = vec![];

    // Sync event is sufficient for our use-case. Since it's emitted on
    // every reserve-altering function call, we can use it as the only event
    // to update the reserves of a pool.
    handle_sync(&block, &pools_store, &mut events);

    Ok(SameTypeTransactionChanges { changes: events })
}

fn handle_sync(
    block: &eth::Block,
    store: &StoreGetProto<Pool>,
    events: &mut Vec<TransactionEntityChanges>,
) {
    let mut on_sync = |event: Sync, tx: &eth::TransactionTrace, log: &eth::Log| {
        let pool_address = log.address.to_hex();

        // Convert reserves to hex
        let reserve0: Vec<u8> = event.reserve0.to_signed_bytes_le();
        let reserve1: Vec<u8> = event.reserve1.to_signed_bytes_le();

        let tycho_tx: Transaction = tx.into();
        // Events
        events.push(TransactionEntityChanges {
            tx: Option::from(tycho_tx),
            entity_changes: vec![EntityChanges {
                component_id: pool_address.clone(),
                attributes: vec![
                    Attribute {
                        name: "reserve0".to_string(),
                        value: reserve0,
                        change: ChangeType::Update.into(),
                    },
                    Attribute {
                        name: "reserve1".to_string(),
                        value: reserve1,
                        change: ChangeType::Update.into(),
                    },
                ],
            }],
            component_changes: vec![],
            balance_changes: vec![],
        })
    };

    let mut eh = EventHandler::new(&block);
    eh.filter_by_address(PoolAddresser { store });
    eh.on::<Sync, _>(&mut on_sync);
    eh.handle_events();
}
