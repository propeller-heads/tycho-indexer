use substreams::store::{DeltaBigInt, Deltas, StoreGet};
use substreams::store::StoreGetProto;
use substreams_ethereum::pb::eth::v2::{self as eth};

use substreams_helper::event_handler::EventHandler;
use substreams_helper::hex::Hexable;

use crate::abi::pool::events::Sync;
use crate::pb::tycho::evm::uniswap::v2::{Event, Events, Pool};
use crate::pb::tycho::evm::uniswap::v2::event::Type::SyncType;
use crate::pb::tycho::evm::uniswap::v2::SyncEvent;
use crate::traits::PoolAddresser;

#[substreams::handlers::map]
pub fn map_pool_events(
    block: eth::Block,
    pools_store: StoreGetProto<Pool>,
) -> Result<Events, substreams::errors::Error> {
    let mut events = vec![];

    // Since we only need updated reserves,
    // Sync event is sufficient for our use-case
    handle_sync(&block, &pools_store, &mut events);

    Ok(Events { events })
}

fn handle_sync(block: &eth::Block, store: &StoreGetProto<Pool>, events: &mut Vec<Event>) {
    let mut on_sync = |event: Sync, tx: &eth::TransactionTrace, log: &eth::Log| {
        let pool_address = log.address.to_hex();

        events.push(Event {
            hash: tx.hash.to_hex(),
            log_index: log.index,
            log_ordinal: log.ordinal,
            to: tx.to.to_hex(),
            from: tx.from.to_hex(),
            block_number: block.number,
            timestamp: block.timestamp_seconds(),
            pool: pool_address,
            r#type: Some(SyncType(SyncEvent {
                reserve0: event.reserve0.to_string(),
                reserve1: event.reserve1.to_string(),
            })),
        });
    };

    let mut eh = EventHandler::new(&block);
    eh.filter_by_address(PoolAddresser { store });
    eh.on::<Sync, _>(&mut on_sync);
    eh.handle_events();
}

