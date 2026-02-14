use substreams::store::{StoreGet, StoreGetProto};
use substreams_helper::hex::Hexable;
use tycho_substreams::models::{BalanceDelta, BlockBalanceDeltas, Transaction};

use crate::{
    pb::ekubo::{
        block_transaction_events::transaction_events::pool_log::Event, BlockTransactionEvents,
        PoolDetails,
    },
    store::get_pool_details,
};

#[substreams::handlers::map]
fn map_balance_changes(
    block_tx_events: BlockTransactionEvents,
    store: StoreGetProto<PoolDetails>,
) -> BlockBalanceDeltas {
    BlockBalanceDeltas {
        balance_deltas: block_tx_events
            .block_transaction_events
            .into_iter()
            .flat_map(|tx_events| {
                let tx: Transaction = tx_events.transaction.unwrap().into();

                let store = &store;

                tx_events
                    .pool_logs
                    .into_iter()
                    .flat_map(move |log| {
                        let component_id = log.pool_id.to_hex();
                        let pool_details = get_pool_details(store, &component_id);

                        let component_id_bytes = component_id.into_bytes();
                        let tx = tx.clone();

                        balance_deltas(log.event.unwrap(), pool_details)
                            .into_iter()
                            .map(move |reduced| BalanceDelta {
                                ord: log.ordinal,
                                tx: Some(tx.clone()),
                                token: reduced.token,
                                delta: reduced.delta,
                                component_id: component_id_bytes.clone(),
                            })
                    })
            })
            .collect(),
    }
}

struct ReducedBalanceDelta {
    token: Vec<u8>,
    delta: Vec<u8>,
}

fn balance_deltas(ev: Event, pool_details: PoolDetails) -> Vec<ReducedBalanceDelta> {
    let (delta0, delta1) = match ev {
        Event::Swapped(ev) => (ev.delta0, ev.delta1),
        Event::PositionUpdated(ev) => (ev.delta0, ev.delta1),
        _ => return vec![],
    };

    vec![
        ReducedBalanceDelta { token: pool_details.token0, delta: delta0 },
        ReducedBalanceDelta { token: pool_details.token1, delta: delta1 },
    ]
}
