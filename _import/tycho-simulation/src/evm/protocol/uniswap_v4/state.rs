use alloy_primitives::U256;

use crate::evm::protocol::utils::uniswap::tick_list::{TickInfo, TickList};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UniswapV4State {
    liquidity: u128,
    sqrt_price: U256,
    lp_fee: i32,
    protocol_fees: UniswapV4ProtocolFees,
    tick: i32,
    ticks: TickList,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UniswapV4ProtocolFees {
    zero2one: i32,
    one2zero: i32,
}

impl UniswapV4ProtocolFees {
    pub fn new(zero2one: i32, one2zero: i32) -> Self {
        Self { zero2one, one2zero }
    }
}

impl UniswapV4State {
    /// Creates a new `UniswapV4State` with specified values.
    pub fn new(
        liquidity: u128,
        sqrt_price: U256,
        lp_fee: i32,
        protocol_fees: UniswapV4ProtocolFees,
        tick: i32,
        tick_spacing: i32,
        ticks: Vec<TickInfo>,
    ) -> Self {
        let tick_list = TickList::from(
            tick_spacing
                .try_into()
                // even though it's given as int24, tick_spacing must be positive, see here:
                // https://github.com/Uniswap/v4-core/blob/a22414e4d7c0d0b0765827fe0a6c20dfd7f96291/src/libraries/TickMath.sol#L25-L28
                .expect("tick_spacing should always be positive"),
            ticks,
        );
        UniswapV4State { liquidity, sqrt_price, lp_fee, protocol_fees, tick, ticks: tick_list }
    }
}
