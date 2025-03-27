use substreams::{
    hex,
    scalar::BigInt,
    store::{StoreGet, StoreGetProto},
};
use substreams_helper::hex::Hexable;
use tycho_substreams::models::{BalanceDelta, BlockBalanceDeltas, Transaction};

use crate::pb::ekubo::{
    block_transaction_events::transaction_events::pool_log::Event, BlockTransactionEvents,
    PoolDetails,
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
    match ev {
        Event::Swapped(swapped) => {
            vec![
                ReducedBalanceDelta { token: pool_details.token0, delta: swapped.delta0 },
                ReducedBalanceDelta { token: pool_details.token1, delta: swapped.delta1 },
            ]
        }
        Event::PositionUpdated(position_updated) => {
            vec![
                ReducedBalanceDelta {
                    token: pool_details.token0,
                    delta: adjust_delta_by_fee(
                        BigInt::from_signed_bytes_be(&position_updated.delta0),
                        pool_details.fee,
                    )
                    .to_signed_bytes_be(),
                },
                ReducedBalanceDelta {
                    token: pool_details.token1,
                    delta: adjust_delta_by_fee(
                        BigInt::from_signed_bytes_be(&position_updated.delta1),
                        pool_details.fee,
                    )
                    .to_signed_bytes_be(),
                },
            ]
        }
        Event::PositionFeesCollected(position_fees_collected) => {
            vec![
                ReducedBalanceDelta {
                    token: pool_details.token0,
                    delta: BigInt::from_unsigned_bytes_be(&position_fees_collected.amount0)
                        .neg()
                        .to_signed_bytes_be(),
                },
                ReducedBalanceDelta {
                    token: pool_details.token1,
                    delta: BigInt::from_unsigned_bytes_be(&position_fees_collected.amount1)
                        .neg()
                        .to_signed_bytes_be(),
                },
            ]
        }
        Event::FeesAccumulated(fees_accumulated) => {
            vec![
                ReducedBalanceDelta { token: pool_details.token0, delta: fees_accumulated.amount0 },
                ReducedBalanceDelta { token: pool_details.token1, delta: fees_accumulated.amount1 },
            ]
        }
        _ => vec![],
    }
}

// Negative deltas don't include the fees paid by the position owner, thus we need to add it back
// here (i.e. subtract from the component's balance)
fn adjust_delta_by_fee(delta: BigInt, fee: u64) -> BigInt {
    if delta < BigInt::zero() {
        let denom = BigInt::from_signed_bytes_be(&hex!("0100000000000000000000000000000000"));
        (delta * denom.clone()) / (denom - fee)
    } else {
        delta
    }
}

fn get_pool_details(store: &StoreGetProto<PoolDetails>, component_id: &str) -> PoolDetails {
    store
        .get_at(0, component_id)
        .expect("pool id should exist in store")
}
