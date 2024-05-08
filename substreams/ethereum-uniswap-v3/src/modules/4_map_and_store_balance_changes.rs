use std::str::FromStr;

use anyhow::Ok;

use crate::pb::uniswap::v3::{
    events::{pool_event, PoolEvent},
    BalanceDelta, BalanceDeltas, Events,
};
use num_bigint::Sign;
use substreams::{
    scalar::BigInt,
    store::{StoreAdd, StoreAddBigInt, StoreNew},
};

#[substreams::handlers::map]
pub fn map_balance_changes(events: Events) -> Result<BalanceDeltas, anyhow::Error> {
    let balances_deltas = events
        .pool_events
        .into_iter()
        .flat_map(event_to_balance_deltas)
        .collect();

    Ok(BalanceDeltas { deltas: balances_deltas })
}

#[substreams::handlers::store]
pub fn store_pools_balances(balances_deltas: BalanceDeltas, store: StoreAddBigInt) {
    let mut deltas = balances_deltas.deltas.clone();

    deltas.sort_unstable_by_key(|delta| delta.ordinal);

    deltas.iter().for_each(|delta| {
        store.add(
            delta.ordinal,
            format!(
                "pool:{0}:token:{1}",
                hex::encode(&delta.pool_address),
                hex::encode(&delta.token_address)
            ),
            BigInt::from_bytes_le(
                if delta.sign { Sign::Plus } else { Sign::Minus },
                delta.amount.as_slice(),
            ),
        );
    });
}

fn event_to_balance_deltas(event: PoolEvent) -> Vec<BalanceDelta> {
    match event.r#type.unwrap() {
        pool_event::Type::Mint(e) => vec![
            BalanceDelta {
                token_address: hex::decode(event.token0.clone()).unwrap(),
                amount: BigInt::from_str(&e.amount_0)
                    .unwrap()
                    .to_bytes_le()
                    .1,
                sign: true,
                pool_address: hex::decode(event.pool_address.clone()).unwrap(),
                ordinal: event.log_ordinal,
                transaction: event.transaction.clone(),
            },
            BalanceDelta {
                token_address: hex::decode(event.token1.clone()).unwrap(),
                amount: BigInt::from_str(&e.amount_1)
                    .unwrap()
                    .to_bytes_le()
                    .1,
                sign: true,
                pool_address: hex::decode(event.pool_address.clone()).unwrap(),
                ordinal: event.log_ordinal,
                transaction: event.transaction,
            },
        ],
        pool_event::Type::Collect(e) => vec![
            BalanceDelta {
                token_address: hex::decode(event.token0.clone()).unwrap(),
                amount: BigInt::from_str(&e.amount_0)
                    .unwrap()
                    .to_bytes_le()
                    .1,
                sign: false,
                pool_address: hex::decode(event.pool_address.clone()).unwrap(),
                ordinal: event.log_ordinal,
                transaction: event.transaction.clone(),
            },
            BalanceDelta {
                token_address: hex::decode(event.token1.clone()).unwrap(),
                amount: BigInt::from_str(&e.amount_1)
                    .unwrap()
                    .to_bytes_le()
                    .1,
                sign: false,
                pool_address: hex::decode(event.pool_address.clone()).unwrap(),
                ordinal: event.log_ordinal,
                transaction: event.transaction,
            },
        ],
        //Burn balance changes are accounted for in the Collect event.
        pool_event::Type::Burn(_) => vec![],
        pool_event::Type::Swap(e) => {
            let token0_amount = BigInt::from_str(&e.amount_0).unwrap();
            let (token0_amount_sign, token0_amount_bytes) = token0_amount.to_bytes_le();

            let token1_amount = BigInt::from_str(&e.amount_1).unwrap();
            let (token1_amount_sign, token1_amount_bytes) = token1_amount.to_bytes_le();

            vec![
                BalanceDelta {
                    token_address: hex::decode(event.token0.clone()).unwrap(),
                    amount: token0_amount_bytes,
                    sign: token0_amount_sign == Sign::Plus,
                    pool_address: hex::decode(event.pool_address.clone()).unwrap(),
                    ordinal: event.log_ordinal,
                    transaction: event.transaction.clone(),
                },
                BalanceDelta {
                    token_address: hex::decode(event.token1.clone()).unwrap(),
                    amount: token1_amount_bytes,
                    sign: token1_amount_sign == Sign::Plus,
                    pool_address: hex::decode(event.pool_address.clone()).unwrap(),
                    ordinal: event.log_ordinal,
                    transaction: event.transaction,
                },
            ]
        }
        pool_event::Type::Flash(e) => vec![
            BalanceDelta {
                token_address: hex::decode(event.token0).unwrap(),
                amount: BigInt::from_str(&e.paid_0)
                    .unwrap()
                    .clone()
                    .to_bytes_le()
                    .1,
                sign: true,
                pool_address: hex::decode(event.pool_address.clone()).unwrap(),
                ordinal: event.log_ordinal,
                transaction: event.transaction.clone(),
            },
            BalanceDelta {
                token_address: hex::decode(event.token1).unwrap(),
                amount: BigInt::from_str(&e.paid_1)
                    .unwrap()
                    .clone()
                    .to_bytes_le()
                    .1,
                sign: true,
                pool_address: hex::decode(event.pool_address.clone()).unwrap(),
                ordinal: event.log_ordinal,
                transaction: event.transaction,
            },
        ],
        pool_event::Type::CollectProtocol(e) => {
            vec![
                BalanceDelta {
                    token_address: hex::decode(event.token0).unwrap(),
                    amount: BigInt::from_str(&e.amount_0)
                        .unwrap()
                        .clone()
                        .to_bytes_le()
                        .1,
                    sign: false,
                    pool_address: hex::decode(event.pool_address.clone()).unwrap(),
                    ordinal: event.log_ordinal,
                    transaction: event.transaction.clone(),
                },
                BalanceDelta {
                    token_address: hex::decode(event.token1).unwrap(),
                    amount: BigInt::from_str(&e.amount_1)
                        .unwrap()
                        .clone()
                        .to_bytes_le()
                        .1,
                    sign: false,
                    pool_address: hex::decode(event.pool_address.clone()).unwrap(),
                    ordinal: event.log_ordinal,
                    transaction: event.transaction,
                },
            ]
        }
        _ => vec![],
    }
}
