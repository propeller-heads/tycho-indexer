use std::{any::Any, collections::HashMap};

use alloy_primitives::{Sign, I256, U256};
use num_bigint::BigUint;
use tracing::trace;
use tycho_core::{dto::ProtocolStateDelta, Bytes};

use crate::{
    evm::protocol::{
        safe_math::{safe_add_u256, safe_sub_u256},
        u256_num::u256_to_biguint,
        utils::uniswap::{
            i24_be_bytes_to_i32, liquidity_math,
            sqrt_price_math::sqrt_price_q96_to_f64,
            swap_math,
            tick_list::{TickInfo, TickList, TickListErrorKind},
            tick_math::{
                get_sqrt_ratio_at_tick, get_tick_at_sqrt_ratio, MAX_SQRT_RATIO, MAX_TICK,
                MIN_SQRT_RATIO, MIN_TICK,
            },
            StepComputation, SwapResults, SwapState,
        },
    },
    models::Token,
    protocol::{
        errors::{SimulationError, TransitionError},
        models::GetAmountOutResult,
        state::ProtocolSim,
    },
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

impl ProtocolSim for UniswapV4State {
    // Not possible to implement correctly with the current interface because we need to know the
    // swap direction.
    fn fee(&self) -> f64 {
        todo!()
    }

    fn spot_price(&self, base: &Token, quote: &Token) -> Result<f64, SimulationError> {
        if base < quote {
            Ok(sqrt_price_q96_to_f64(self.sqrt_price, base.decimals as u32, quote.decimals as u32))
        } else {
            Ok(1.0f64 /
                sqrt_price_q96_to_f64(
                    self.sqrt_price,
                    quote.decimals as u32,
                    base.decimals as u32,
                ))
        }
    }

    fn get_amount_out(
        &self,
        amount_in: BigUint,
        token_in: &Token,
        token_out: &Token,
    ) -> Result<GetAmountOutResult, SimulationError> {
        let zero_for_one = token_in < token_out;
        let amount_specified = I256::checked_from_sign_and_abs(
            Sign::Positive,
            U256::from_be_slice(&amount_in.to_bytes_be()),
        )
        .expect("UniswapV4 I256 overflow");

        let result = self.swap(zero_for_one, amount_specified, None)?;

        trace!(?amount_in, ?token_in, ?token_out, ?zero_for_one, ?result, "V4 SWAP");
        let mut new_state = self.clone();
        new_state.liquidity = result.liquidity;
        new_state.tick = result.tick;
        new_state.sqrt_price = result.sqrt_price;

        Ok(GetAmountOutResult::new(
            u256_to_biguint(
                result
                    .amount_calculated
                    .abs()
                    .into_raw(),
            ),
            u256_to_biguint(result.gas_used),
            Box::new(new_state),
        ))
    }

    fn delta_transition(
        &mut self,
        delta: ProtocolStateDelta,
        _tokens: &HashMap<Bytes, Token>,
    ) -> Result<(), TransitionError<String>> {
        // Apply attribute changes
        if let Some(liquidity) = delta
            .updated_attributes
            .get("liquidity")
        {
            // This is a hotfix because if the liquidity has never been updated after creation, it's
            // currently encoded as H256::zero(), therefore, we can't decode this as u128.
            // We can remove this once it has been fixed on the tycho side.
            let liq_16_bytes = if liquidity.len() == 32 {
                // Make sure it only happens for 0 values, otherwise error.
                if liquidity == &Bytes::zero(32) {
                    Bytes::from([0; 16])
                } else {
                    return Err(TransitionError::DecodeError(format!(
                        "Liquidity bytes too long for {}, expected 16",
                        liquidity
                    )));
                }
            } else {
                liquidity.clone()
            };

            self.liquidity = u128::from(liq_16_bytes);
        }
        if let Some(sqrt_price) = delta
            .updated_attributes
            .get("sqrt_price_x96")
        {
            self.sqrt_price = U256::from_be_slice(sqrt_price);
        }
        if let Some(tick) = delta.updated_attributes.get("tick") {
            // This is a hotfix because if the tick has never been updated after creation, it's
            // currently encoded as H256::zero(), therefore, we can't decode this as i32.
            // We can remove this once it has been fixed on the tycho side.
            let ticks_4_bytes = if tick.len() == 32 {
                // Make sure it only happens for 0 values, otherwise error.
                if tick == &Bytes::zero(32) {
                    Bytes::from([0; 4])
                } else {
                    return Err(TransitionError::DecodeError(format!(
                        "Tick bytes too long for {}, expected 4",
                        tick
                    )));
                }
            } else {
                tick.clone()
            };
            self.tick = i24_be_bytes_to_i32(&ticks_4_bytes);
        }
        if let Some(zero2one_protocol_fee) = delta
            .updated_attributes
            .get("protocol_fees/zero2one")
        {
            self.fees.zero_for_one = u32::from(zero2one_protocol_fee.clone());
        }
        if let Some(one2zero_protocol_fee) = delta
            .updated_attributes
            .get("protocol_fees/one2zero")
        {
            self.fees.one_for_zero = u32::from(one2zero_protocol_fee.clone());
        }

        // apply tick changes
        for (key, value) in delta.updated_attributes.iter() {
            // tick liquidity keys are in the format "tick/{tick_index}/net_liquidity"
            if key.starts_with("ticks/") {
                let parts: Vec<&str> = key.split('/').collect();
                self.ticks.set_tick_liquidity(
                    parts[1]
                        .parse::<i32>()
                        .map_err(|err| TransitionError::DecodeError(err.to_string()))?,
                    i128::from(value.clone()),
                )
            }
        }
        // delete ticks - ignores deletes for attributes other than tick liquidity
        for key in delta.deleted_attributes.iter() {
            // tick liquidity keys are in the format "tick/{tick_index}/net_liquidity"
            if key.starts_with("tick/") {
                let parts: Vec<&str> = key.split('/').collect();
                self.ticks.set_tick_liquidity(
                    parts[1]
                        .parse::<i32>()
                        .map_err(|err| TransitionError::DecodeError(err.to_string()))?,
                    0,
                )
            }
        }

        Ok(())
    }

    fn clone_box(&self) -> Box<dyn ProtocolSim> {
        Box::new(self.clone())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn eq(&self, other: &dyn ProtocolSim) -> bool {
        if let Some(other_state) = other
            .as_any()
            .downcast_ref::<UniswapV4State>()
        {
            self.liquidity == other_state.liquidity &&
                self.sqrt_price == other_state.sqrt_price &&
                self.fees == other_state.fees &&
                self.tick == other_state.tick &&
                self.ticks == other_state.ticks
        } else {
            false
        }
    }
}
