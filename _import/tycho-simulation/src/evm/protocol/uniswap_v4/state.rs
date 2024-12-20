#![allow(dead_code)] //TODO: remove when used

use alloy_primitives::{Sign, I256, U256};

use crate::{
    evm::protocol::{
        safe_math::{safe_add_u256, safe_sub_u256},
        u256_num::u256_to_biguint,
        utils::uniswap::{
            liquidity_math, swap_math,
            tick_list::{TickInfo, TickList, TickListErrorKind},
            tick_math::{
                get_sqrt_ratio_at_tick, get_tick_at_sqrt_ratio, MAX_SQRT_RATIO, MAX_TICK,
                MIN_SQRT_RATIO, MIN_TICK,
            },
            StepComputation, SwapResults, SwapState,
        },
    },
    protocol::{errors::SimulationError, models::GetAmountOutResult, state::ProtocolSim},
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UniswapV4State {
    liquidity: u128,
    sqrt_price: U256,
    fees: UniswapV4Fees,
    tick: i32,
    ticks: TickList,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UniswapV4Fees {
    // Protocol fees in the zero for one direction
    zero_for_one: u32,
    // Protocol fees in the one for zero direction
    one_for_zero: u32,
    // Liquidity providers fees
    lp_fee: u32,
}

impl UniswapV4Fees {
    pub fn new(zero_for_one: u32, one_for_zero: u32, lp_fee: u32) -> Self {
        Self { zero_for_one, one_for_zero, lp_fee }
    }

    fn calculate_swap_fees_pips(&self, zero_for_one: bool) -> u32 {
        let protocol_fees = if zero_for_one { self.zero_for_one } else { self.one_for_zero };
        protocol_fees + self.lp_fee
    }
}

impl UniswapV4State {
    /// Creates a new `UniswapV4State` with specified values.
    pub fn new(
        liquidity: u128,
        sqrt_price: U256,
        fees: UniswapV4Fees,
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
        UniswapV4State { liquidity, sqrt_price, fees, tick, ticks: tick_list }
    }

    fn swap(
        &self,
        zero_for_one: bool,
        amount_specified: I256,
        sqrt_price_limit: Option<U256>,
    ) -> Result<SwapResults, SimulationError> {
        if self.liquidity == 0 {
            return Err(SimulationError::RecoverableError("No liquidity".to_string()));
        }
        let price_limit = if let Some(limit) = sqrt_price_limit {
            limit
        } else if zero_for_one {
            safe_add_u256(MIN_SQRT_RATIO, U256::from(1u64))?
        } else {
            safe_sub_u256(MAX_SQRT_RATIO, U256::from(1u64))?
        };

        if zero_for_one {
            assert!(price_limit > MIN_SQRT_RATIO);
            assert!(price_limit < self.sqrt_price);
        } else {
            assert!(price_limit < MAX_SQRT_RATIO);
            assert!(price_limit > self.sqrt_price);
        }

        let exact_input = amount_specified > I256::from_raw(U256::from(0u64));

        let mut state = SwapState {
            amount_remaining: amount_specified,
            amount_calculated: I256::from_raw(U256::from(0u64)),
            sqrt_price: self.sqrt_price,
            tick: self.tick,
            liquidity: self.liquidity,
        };
        let mut gas_used = U256::from(130_000);

        while state.amount_remaining != I256::from_raw(U256::from(0u64)) &&
            state.sqrt_price != price_limit
        {
            let (mut next_tick, initialized) = match self
                .ticks
                .next_initialized_tick_within_one_word(state.tick, zero_for_one)
            {
                Ok((tick, init)) => (tick, init),
                Err(tick_err) => match tick_err.kind {
                    TickListErrorKind::TicksExeeded => {
                        let mut new_state = self.clone();
                        new_state.liquidity = state.liquidity;
                        new_state.tick = state.tick;
                        new_state.sqrt_price = state.sqrt_price;
                        return Err(SimulationError::InvalidInput(
                            "Ticks exceeded".into(),
                            Some(GetAmountOutResult::new(
                                u256_to_biguint(state.amount_calculated.abs().into_raw()),
                                u256_to_biguint(gas_used),
                                Box::new(new_state),
                            )),
                        ));
                    }
                    _ => return Err(SimulationError::FatalError("Unknown error".to_string())),
                },
            };

            next_tick = next_tick.clamp(MIN_TICK, MAX_TICK);

            let sqrt_price_next = get_sqrt_ratio_at_tick(next_tick)?;
            let (sqrt_price, amount_in, amount_out, fee_amount) = swap_math::compute_swap_step(
                state.sqrt_price,
                UniswapV4State::get_sqrt_ratio_target(sqrt_price_next, price_limit, zero_for_one),
                state.liquidity,
                state.amount_remaining,
                self.fees
                    .calculate_swap_fees_pips(zero_for_one),
            )?;
            state.sqrt_price = sqrt_price;

            let step = StepComputation {
                sqrt_price_start: state.sqrt_price,
                tick_next: next_tick,
                initialized,
                sqrt_price_next,
                amount_in,
                amount_out,
                fee_amount,
            };
            if exact_input {
                state.amount_remaining -= I256::checked_from_sign_and_abs(
                    Sign::Positive,
                    safe_add_u256(step.amount_in, step.fee_amount)?,
                )
                .unwrap();
                state.amount_calculated -=
                    I256::checked_from_sign_and_abs(Sign::Positive, step.amount_out).unwrap();
            } else {
                state.amount_remaining +=
                    I256::checked_from_sign_and_abs(Sign::Positive, step.amount_out).unwrap();
                state.amount_calculated += I256::checked_from_sign_and_abs(
                    Sign::Positive,
                    safe_add_u256(step.amount_in, step.fee_amount)?,
                )
                .unwrap();
            }
            if state.sqrt_price == step.sqrt_price_next {
                if step.initialized {
                    let liquidity_raw = self
                        .ticks
                        .get_tick(step.tick_next)
                        .unwrap()
                        .net_liquidity;
                    let liquidity_net = if zero_for_one { -liquidity_raw } else { liquidity_raw };
                    state.liquidity =
                        liquidity_math::add_liquidity_delta(state.liquidity, liquidity_net);
                }
                state.tick = if zero_for_one { step.tick_next - 1 } else { step.tick_next };
            } else if state.sqrt_price != step.sqrt_price_start {
                state.tick = get_tick_at_sqrt_ratio(state.sqrt_price)?;
            }
            gas_used = safe_add_u256(gas_used, U256::from(2000))?;
        }
        Ok(SwapResults {
            amount_calculated: state.amount_calculated,
            sqrt_price: state.sqrt_price,
            liquidity: state.liquidity,
            tick: state.tick,
            gas_used,
        })
    }

    fn get_sqrt_ratio_target(
        sqrt_price_next: U256,
        sqrt_price_limit: U256,
        zero_for_one: bool,
    ) -> U256 {
        let cond1 = if zero_for_one {
            sqrt_price_next < sqrt_price_limit
        } else {
            sqrt_price_next > sqrt_price_limit
        };

        if cond1 {
            sqrt_price_limit
        } else {
            sqrt_price_next
        }
    }
}

#[allow(unused_variables)] //TODO: remove when implemented
impl ProtocolSim for UniswapV4State {
    fn fee(&self) -> f64 {
        todo!()
    }

    fn spot_price(
        &self,
        base: &crate::models::Token,
        quote: &crate::models::Token,
    ) -> Result<f64, SimulationError> {
        todo!()
    }

    fn get_amount_out(
        &self,
        amount_in: num_bigint::BigUint,
        token_in: &crate::models::Token,
        token_out: &crate::models::Token,
    ) -> Result<GetAmountOutResult, SimulationError> {
        todo!()
    }

    fn delta_transition(
        &mut self,
        delta: tycho_core::dto::ProtocolStateDelta,
        tokens: &std::collections::HashMap<tycho_core::Bytes, crate::models::Token>,
    ) -> Result<(), crate::protocol::errors::TransitionError<String>> {
        todo!()
    }

    fn clone_box(&self) -> Box<dyn ProtocolSim> {
        todo!()
    }

    fn as_any(&self) -> &dyn std::any::Any {
        todo!()
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        todo!()
    }

    fn eq(&self, other: &dyn ProtocolSim) -> bool {
        todo!()
    }
}
