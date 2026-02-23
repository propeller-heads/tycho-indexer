use substreams::store::{StoreGet, StoreGetProto, StoreNew, StoreSet, StoreSetInt64};
use substreams_helper::hex::Hexable;

use crate::{
    details_store::is_pool_tracked,
    pb::ekubo::{
        block_transaction_events::transaction_events::pool_log::Event, BlockTransactionEvents,
        PoolDetails,
    },
};

#[substreams::handlers::store]
pub fn store_active_ticks(
    block_tx_events: BlockTransactionEvents,
    tick_store: StoreSetInt64,
    details_store: StoreGetProto<PoolDetails>,
) {
    block_tx_events
        .block_transaction_events
        .into_iter()
        .flat_map(|tx_events| tx_events.pool_logs)
        .filter_map(|log| {
            let tick = maybe_tick(log.event.unwrap())?;
            let pool_id = log.pool_id.to_hex();

            is_pool_tracked(&details_store, &pool_id).then_some((pool_id, log.ordinal, tick))
        })
        .for_each(|(pool, ordinal, new_tick_index)| {
            tick_store.set(ordinal, pool, &new_tick_index.into())
        });
}

fn maybe_tick(ev: Event) -> Option<i32> {
    match ev {
        Event::PoolInitialized(pool_initialized) => Some(pool_initialized.tick),
        Event::Swapped(swapped) => Some(swapped.tick_after),
        _ => None,
    }
}
