use alloy_primitives::{I256, U256};

pub(crate) mod liquidity_math;
mod solidity_math;
pub(crate) mod sqrt_price_math;
pub(crate) mod swap_math;
pub(crate) mod tick_list;
pub(crate) mod tick_math;

#[derive(Debug)]
pub(crate) struct SwapState {
    pub(crate) amount_remaining: I256,
    pub(crate) amount_calculated: I256,
    pub(crate) sqrt_price: U256,
    pub(crate) tick: i32,
    pub(crate) liquidity: u128,
}

#[derive(Debug)]
pub(crate) struct StepComputation {
    pub(crate) sqrt_price_start: U256,
    pub(crate) tick_next: i32,
    pub(crate) initialized: bool,
    pub(crate) sqrt_price_next: U256,
    pub(crate) amount_in: U256,
    pub(crate) amount_out: U256,
    pub(crate) fee_amount: U256,
}

#[derive(Debug)]
pub(crate) struct SwapResults {
    pub(crate) amount_calculated: I256,
    pub(crate) sqrt_price: U256,
    pub(crate) liquidity: u128,
    pub(crate) tick: i32,
    pub(crate) gas_used: U256,
}
