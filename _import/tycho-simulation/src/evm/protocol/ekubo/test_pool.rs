use std::collections::HashMap;

use evm_ekubo_sdk::{
    math::uint::U256,
    quoting::{
        base_pool::BasePoolState,
        types::{Config, NodeKey, Tick},
    },
};
use num_bigint::BigUint;
use tycho_common::{dto::ProtocolComponent, Bytes};

use super::{pool::base::BasePool, state::EkuboState};
use crate::models::Token;

pub const POOL_KEY: NodeKey = NodeKey {
    token0: U256([1, 0, 0, 0]),
    token1: U256([2, 0, 0, 0]),
    config: Config { fee: 0, tick_spacing: 10, extension: U256::zero() },
};

pub fn token0() -> Token {
    Token {
        address: POOL_KEY.token0.to_big_endian().into(),
        decimals: 0,
        symbol: "TOKEN0".to_string(),
        gas: BigUint::default(),
    }
}

pub fn token1() -> Token {
    Token {
        address: POOL_KEY.token1.to_big_endian().into(),
        decimals: 0,
        symbol: "TOKEN1".to_string(),
        gas: BigUint::default(),
    }
}

pub const LOWER_TICK: Tick = Tick { index: -10, liquidity_delta: 100_000_000 };

pub const UPPER_TICK: Tick =
    Tick { index: -LOWER_TICK.index, liquidity_delta: -LOWER_TICK.liquidity_delta };

pub const TICK_INDEX_BETWEEN: i32 = 0;
pub const SQRT_RATIO_BETWEEN: U256 = U256([0, 0, 1, 0]);
pub const LIQUIDITY_BETWEEN: u128 = LOWER_TICK.liquidity_delta as u128;

pub fn component() -> ProtocolComponent {
    ProtocolComponent {
        static_attributes: HashMap::from([
            ("extension_id".to_string(), 1_i32.to_be_bytes().into()), // Base pool
            ("token0".to_string(), POOL_KEY.token0.to_big_endian().into()),
            ("token1".to_string(), POOL_KEY.token1.to_big_endian().into()),
            ("fee".to_string(), POOL_KEY.config.fee.into()),
            ("tick_spacing".to_string(), POOL_KEY.config.tick_spacing.into()),
            (
                "extension".to_string(),
                POOL_KEY
                    .config
                    .extension
                    .to_big_endian()
                    .into(),
            ),
        ]),
        ..Default::default()
    }
}

pub fn attributes() -> HashMap<String, Bytes> {
    HashMap::from([
        ("liquidity".to_string(), LIQUIDITY_BETWEEN.to_be_bytes().into()),
        (
            "sqrt_ratio".to_string(),
            SQRT_RATIO_BETWEEN
                .to_big_endian()
                .into(),
        ),
        ("tick".to_string(), TICK_INDEX_BETWEEN.to_be_bytes().into()),
        (
            format!("ticks/{index}", index = LOWER_TICK.index),
            LOWER_TICK
                .liquidity_delta
                .to_be_bytes()
                .into(),
        ),
        (
            format!("ticks/{index}", index = UPPER_TICK.index),
            UPPER_TICK
                .liquidity_delta
                .to_be_bytes()
                .into(),
        ),
    ])
}

pub fn state() -> EkuboState {
    EkuboState::Base(
        BasePool::new(
            POOL_KEY,
            BasePoolState {
                sqrt_ratio: SQRT_RATIO_BETWEEN,
                liquidity: LIQUIDITY_BETWEEN,
                active_tick_index: Some(0),
            },
            vec![LOWER_TICK, UPPER_TICK].into(),
            TICK_INDEX_BETWEEN,
        )
        .unwrap(),
    )
}
