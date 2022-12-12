use ethers::types::{I256, U256};

use crate::models::ERC20Token;

use super::tick_math;

pub struct TradeSimulationError {}

pub struct UniswapV3State {
    liquidity: U256,
    sqrt_price: U256,
    fee: u32,
    tick: i32,
    current_pos: usize,
}

struct SwapState {
    amount_remaining: I256,
    amount_calulated: I256,
    sqrt_price: U256,
    tick: i32,
    liquidity: U256,
}

struct StepComputation {
    sqrt_price_start: U256,
    amount_calculated: I256,
    sqrt_price: U256,
    tick: i32,
    liquidity: U256,
}

impl UniswapV3State {
    pub fn get_amount_out(
        &self,
        amount_in: U256,
        token_a: &ERC20Token,
        token_b: &ERC20Token,
    ) -> Result<U256, TradeSimulationError> {
        let zero_for_one = token_a < token_b;

        Ok(U256::zero())
    }

    fn swap(&self, zero_for_one: bool, amount_specified: I256, sqrt_price_limit: Option<U256>) {
        let price_limit = if sqrt_price_limit.is_none() {
            if zero_for_one {
                tick_math::MIN_SQRT_RATIO + 1
            } else {
                tick_math::MAX_SQRT_RATIO - 1
            }
        } else {
            sqrt_price_limit.unwrap()
        };

        if zero_for_one {
            assert!(price_limit > tick_math::MIN_SQRT_RATIO);
            assert!(price_limit < self.sqrt_price);
        } else {
            assert!(price_limit < tick_math::MAX_SQRT_RATIO);
            assert!(price_limit > self.sqrt_price);
        }

        let exact_input = amount_specified > I256::zero();

        let state = SwapState {
            amount_remaining: amount_specified,
            amount_calulated: I256::zero(),
            sqrt_price: self.sqrt_price,
            tick: self.tick,
            liquidity: self.liquidity,
        };
        let n_ticks_crossed = 0u32;

        while state.amount_remaining != I256::zero() && state.sqrt_price != price_limit {}
    }
}
