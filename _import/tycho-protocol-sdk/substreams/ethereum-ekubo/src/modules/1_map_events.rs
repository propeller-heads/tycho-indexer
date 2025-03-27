use ethabi::Address;
use itertools::Itertools;
use substreams::scalar::BigInt;
use substreams_ethereum::{
    pb::eth::{self, v2::Log},
    Event as _,
};

use crate::{
    abi::core::events as abi_events,
    deployment_config::DeploymentConfig,
    pb::ekubo::{
        block_transaction_events::{
            transaction_events::{
                pool_log::{
                    pool_initialized::Extension, Event, FeesAccumulated, PoolInitialized,
                    PositionFeesCollected, PositionUpdated, Swapped,
                },
                PoolLog,
            },
            TransactionEvents,
        },
        BlockTransactionEvents,
    },
    pool_config::PoolConfig,
    sqrt_ratio::float_sqrt_ratio_to_fixed,
};

#[substreams::handlers::map]
fn map_events(params: String, block: eth::v2::Block) -> BlockTransactionEvents {
    let config: DeploymentConfig = serde_qs::from_str(&params).unwrap();

    BlockTransactionEvents {
        block_transaction_events: block
            .transactions()
            .flat_map(|trace| {
                let pool_logs = trace
                    .logs_with_calls()
                    .filter_map(|(log, _)| maybe_pool_log(log, &config))
                    .collect_vec();

                (!pool_logs.is_empty())
                    .then(|| TransactionEvents { transaction: Some(trace.into()), pool_logs })
            })
            .collect(),
    }
}

fn maybe_pool_log(log: &Log, config: &DeploymentConfig) -> Option<PoolLog> {
    if log.address != config.core {
        return None;
    }

    let (pool_id, ev) = if log.topics.is_empty() {
        let data = &log.data;

        assert!(data.len() == 116, "swap event data length mismatch");

        (
            data[20..52].to_vec(),
            Event::Swapped(Swapped {
                delta0: data[52..68].to_vec(),
                delta1: data[68..84].to_vec(),
                liquidity_after: data[84..100].to_vec(),
                sqrt_ratio_after: float_sqrt_ratio_to_fixed(BigInt::from_unsigned_bytes_be(
                    &data[100..112],
                )),
                tick_after: i32::from_be_bytes(data[112..116].try_into().unwrap()),
            }),
        )
    } else if let Some(ev) = abi_events::PositionUpdated::match_and_decode(log) {
        (
            ev.pool_id.to_vec(),
            Event::PositionUpdated(PositionUpdated {
                lower: ev.params.1 .0.to_i32(),
                upper: ev.params.1 .1.to_i32(),
                liquidity_delta: ev.params.2.to_signed_bytes_be(),
                delta0: ev.delta0.to_signed_bytes_be(),
                delta1: ev.delta1.to_signed_bytes_be(),
            }),
        )
    } else if let Some(ev) = abi_events::PositionFeesCollected::match_and_decode(log) {
        (
            ev.pool_id.to_vec(),
            Event::PositionFeesCollected(PositionFeesCollected {
                amount0: ev.amount0.to_bytes_be().1,
                amount1: ev.amount1.to_bytes_be().1,
            }),
        )
    } else if let Some(ev) = abi_events::PoolInitialized::match_and_decode(log) {
        let pool_config = PoolConfig::from(ev.pool_key.2);

        let extension = {
            let extension = pool_config.extension;

            if extension == Address::zero().as_bytes() {
                Extension::Base
            } else if extension == config.oracle {
                Extension::Oracle
            } else {
                Extension::Unknown
            }
        };

        (
            ev.pool_id.to_vec(),
            Event::PoolInitialized(PoolInitialized {
                token0: ev.pool_key.0,
                token1: ev.pool_key.1,
                config: ev.pool_key.2.to_vec(),
                tick: ev.tick.to_i32(),
                sqrt_ratio: float_sqrt_ratio_to_fixed(ev.sqrt_ratio),
                extension: extension.into(),
            }),
        )
    } else if let Some(ev) = abi_events::FeesAccumulated::match_and_decode(log) {
        (
            ev.pool_id.to_vec(),
            Event::FeesAccumulated(FeesAccumulated {
                amount0: ev.amount0.to_bytes_be().1,
                amount1: ev.amount1.to_bytes_be().1,
            }),
        )
    } else {
        return None;
    };

    Some(PoolLog { ordinal: log.ordinal, pool_id, event: Some(ev) })
}
