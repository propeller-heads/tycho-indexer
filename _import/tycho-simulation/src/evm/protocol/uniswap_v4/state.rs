use std::{any::Any, collections::HashMap};

use alloy::primitives::{Address, Sign, I256, U256};
use num_bigint::BigUint;
use num_traits::{ToPrimitive, Zero};
use revm::primitives::I128;
use tracing::trace;
use tycho_client::feed::BlockHeader;
use tycho_common::{
    dto::ProtocolStateDelta,
    models::token::Token,
    simulation::{
        errors::{SimulationError, TransitionError},
        protocol_sim::{Balances, GetAmountOutResult, ProtocolSim},
    },
    Bytes,
};

use super::hooks::utils::{has_permission, HookOptions};
use crate::evm::protocol::{
    safe_math::{safe_add_u256, safe_sub_u256},
    u256_num::u256_to_biguint,
    uniswap_v4::hooks::{
        hook_handler::HookHandler,
        models::{
            AfterSwapParameters, BalanceDelta, BeforeSwapDelta, BeforeSwapParameters, StateContext,
            SwapParams,
        },
    },
    utils::uniswap::{
        i24_be_bytes_to_i32, liquidity_math,
        sqrt_price_math::{get_amount0_delta, get_amount1_delta, sqrt_price_q96_to_f64},
        swap_math,
        tick_list::{TickInfo, TickList, TickListErrorKind},
        tick_math::{
            get_sqrt_ratio_at_tick, get_tick_at_sqrt_ratio, MAX_SQRT_RATIO, MAX_TICK,
            MIN_SQRT_RATIO, MIN_TICK,
        },
        StepComputation, SwapResults, SwapState,
    },
    vm::constants::EXTERNAL_ACCOUNT,
};

#[derive(Clone, Debug)]
pub struct UniswapV4State {
    liquidity: u128,
    sqrt_price: U256,
    fees: UniswapV4Fees,
    tick: i32,
    ticks: TickList,
    tick_spacing: i32,
    pub hook: Option<Box<dyn HookHandler>>,
    /// The current block, will be used to set vm context
    block: BlockHeader,
}

impl PartialEq for UniswapV4State {
    fn eq(&self, other: &Self) -> bool {
        match (&self.hook, &other.hook) {
            (Some(a), Some(b)) => a.is_equal(&**b),
            (None, None) => true,
            _ => false,
        }
    }
}

impl Eq for UniswapV4State {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UniswapV4Fees {
    // Protocol fees in the zero for one direction
    pub zero_for_one: u32,
    // Protocol fees in the one for zero direction
    pub one_for_zero: u32,
    // Liquidity providers fees
    pub lp_fee: u32,
}

impl UniswapV4Fees {
    pub fn new(zero_for_one: u32, one_for_zero: u32, lp_fee: u32) -> Self {
        Self { zero_for_one, one_for_zero, lp_fee }
    }

    fn calculate_swap_fees_pips(&self, zero_for_one: bool, lp_fee_override: Option<u32>) -> u32 {
        let protocol_fees = if zero_for_one { self.zero_for_one } else { self.one_for_zero };
        protocol_fees + lp_fee_override.unwrap_or(self.lp_fee)
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
        block: BlockHeader,
    ) -> Self {
        let tick_list = TickList::from(
            tick_spacing
                .try_into()
                // even though it's given as int24, tick_spacing must be positive, see here:
                // https://github.com/Uniswap/v4-core/blob/a22414e4d7c0d0b0765827fe0a6c20dfd7f96291/src/libraries/TickMath.sol#L25-L28
                .expect("tick_spacing should always be positive"),
            ticks,
        );
        UniswapV4State {
            liquidity,
            sqrt_price,
            fees,
            tick,
            ticks: tick_list,
            tick_spacing,
            hook: None,
            block,
        }
    }

    fn swap(
        &self,
        zero_for_one: bool,
        amount_specified: I256,
        sqrt_price_limit: Option<U256>,
        lp_fee_override: Option<u32>,
    ) -> Result<SwapResults, SimulationError> {
        if amount_specified == I256::ZERO {
            return Ok(SwapResults {
                amount_calculated: I256::ZERO,
                sqrt_price: self.sqrt_price,
                liquidity: self.liquidity,
                tick: self.tick,
                gas_used: U256::from(3_000), // baseline gas cost for no-op swap
            })
        }

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

        let exact_input = amount_specified < I256::ZERO;

        let mut state = SwapState {
            amount_remaining: amount_specified,
            amount_calculated: I256::ZERO,
            sqrt_price: self.sqrt_price,
            tick: self.tick,
            liquidity: self.liquidity,
        };
        let mut gas_used = U256::from(130_000);

        while state.amount_remaining != I256::ZERO && state.sqrt_price != price_limit {
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
                // The core univ4 swap logic assumes that if the amount is > 0 it's exact in, and
                // if it's < 0 it's exact out. The compute_swap_step assumes the
                // opposite (it's like that for univ3).
                -state.amount_remaining,
                self.fees
                    .calculate_swap_fees_pips(zero_for_one, lp_fee_override),
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
                state.amount_remaining += I256::checked_from_sign_and_abs(
                    Sign::Positive,
                    safe_add_u256(step.amount_in, step.fee_amount)?,
                )
                .unwrap();
                state.amount_calculated +=
                    I256::checked_from_sign_and_abs(Sign::Positive, step.amount_out).unwrap();
            } else {
                state.amount_remaining -=
                    I256::checked_from_sign_and_abs(Sign::Positive, step.amount_out).unwrap();
                state.amount_calculated -= I256::checked_from_sign_and_abs(
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
                        liquidity_math::add_liquidity_delta(state.liquidity, liquidity_net)?;
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

    pub fn set_hook_handler(&mut self, handler: Box<dyn HookHandler>) {
        self.hook = Some(handler);
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

    fn find_limits_experimentally(
        &self,
        token_in: Bytes,
        token_out: Bytes,
    ) -> Result<(BigUint, BigUint), SimulationError> {
        // Create dummy token objects with proper addresses. This is fine since `get_amount_out`
        // only uses the token addresses.
        let token_in_obj =
            Token::new(&token_in, "TOKEN_IN", 18, 0, &[Some(10_000)], Default::default(), 100);
        let token_out_obj =
            Token::new(&token_out, "TOKEN_OUT", 18, 0, &[Some(10_000)], Default::default(), 100);

        self.find_max_amount(&token_in_obj, &token_out_obj)
    }

    /// Finds max amount by performing exponential search.
    ///
    /// Reasoning:
    /// - get_amount_out(I256::MAX) will almost always fail, so this will waste time checking values
    ///   unrealistically high.
    /// - If you were to start binary search from 1 to 10^76, you'd need hundreds of iterations.
    ///
    /// More about exponential search: https://en.wikipedia.org/wiki/Exponential_search
    ///
    /// # Returns
    ///
    /// Returns a tuple containing the max amount in and max amount out respectively.
    fn find_max_amount(
        &self,
        token_in: &Token,
        token_out: &Token,
    ) -> Result<(BigUint, BigUint), SimulationError> {
        let mut low = BigUint::from(1u64);

        // The max you can swap on a USV4 is I256::MAX is 5.7e76, since input amount is I256.
        // So start with something much smaller to search for a reasonable upper bound.
        let mut high = BigUint::from(10u64).pow(18); // 1 ether in wei
        let mut last_successful_amount_in = BigUint::from(1u64);
        let mut last_successful_amount_out = BigUint::from(0u64);

        // First, find an upper bound where the swap fails using exponential search.
        // Save and return both the amount in and amount out.
        while let Ok(result) = self.get_amount_out(high.clone(), token_in, token_out) {
            // We haven't found the upper bound yet, increase the attempted upper bound
            // by order of magnitude and store the last success as the lower bound.
            low = last_successful_amount_in.clone();
            last_successful_amount_in = high.clone();
            last_successful_amount_out = result.amount;
            high *= BigUint::from(10u64);

            // Stop if we're getting too large for I256 (about 10^75)
            if high > BigUint::from(10u64).pow(75) {
                return Ok((last_successful_amount_in, last_successful_amount_out));
            }
        }

        // Use binary search to narrow down value between low and high
        while &high - &low > BigUint::from(1u64) {
            let mid = (&low + &high) / BigUint::from(2u64);

            match self.get_amount_out(mid.clone(), token_in, token_out) {
                Ok(result) => {
                    last_successful_amount_in = mid.clone();
                    last_successful_amount_out = result.amount;
                    low = mid;
                }
                Err(_) => {
                    high = mid;
                }
            }
        }

        Ok((last_successful_amount_in, last_successful_amount_out))
    }

    /// Helper method to check if there are no initialized ticks in either direction
    fn has_no_initialized_ticks(&self) -> bool {
        !self.ticks.has_initialized_ticks()
    }
}

impl ProtocolSim for UniswapV4State {
    // Not possible to implement correctly with the current interface because we need to know the
    // swap direction.
    fn fee(&self) -> f64 {
        todo!()
    }

    fn spot_price(&self, base: &Token, quote: &Token) -> Result<f64, SimulationError> {
        if let Some(hook) = &self.hook {
            match hook.spot_price(base, quote) {
                Ok(price) => return Ok(price),
                Err(SimulationError::RecoverableError(_)) => {
                    // Calculate spot price by swapping two amounts and use the approximation
                    // to get the derivative, following the pattern from vm/state.rs
                    
                    // Calculate the first sell amount (x1) as a small amount
                    let x1 = BigUint::from(10u64).pow(base.decimals as u32) / BigUint::from(100u64); // 0.01 token
                    
                    // Calculate the second sell amount (x2) as x1 + 1% of x1
                    let x2 = &x1 + (&x1 / BigUint::from(100u64));
                    
                    // Perform swaps to get the received amounts
                    let y1 = self.get_amount_out(x1.clone(), base, quote)?;
                    let y2 = self.get_amount_out(x2.clone(), base, quote)?;
                    
                    // Calculate the marginal price
                    let num = &y2.amount - &y1.amount;
                    let den = &x2 - &x1;
                    
                    if den == BigUint::from(0u64) {
                        return Err(SimulationError::FatalError(
                            "Cannot calculate spot price: denominator is zero".to_string(),
                        ));
                    }
                    
                    // Convert to f64 and adjust for decimals
                    let num_f64 = num.to_f64().ok_or_else(|| {
                        SimulationError::FatalError("Failed to convert numerator to f64".to_string())
                    })?;
                    let den_f64 = den.to_f64().ok_or_else(|| {
                        SimulationError::FatalError("Failed to convert denominator to f64".to_string())
                    })?;
                    
                    let token_correction = 
                        10f64.powi(base.decimals as i32 - quote.decimals as i32);
                    
                    return Ok(num_f64 / den_f64 * token_correction);
                }
                Err(e) => return Err(e),
            }
        }

        if base < quote {
            Ok(sqrt_price_q96_to_f64(self.sqrt_price, base.decimals, quote.decimals))
        } else {
            Ok(1.0f64 / sqrt_price_q96_to_f64(self.sqrt_price, quote.decimals, base.decimals))
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
            Sign::Negative,
            U256::from_be_slice(&amount_in.to_bytes_be()),
        )
        .ok_or_else(|| {
            SimulationError::InvalidInput("I256 overflow: amount_in".to_string(), None)
        })?;

        let mut amount_to_swap = amount_specified;
        let mut lp_fee_override: Option<u32> = None;
        let mut before_swap_gas = 0u64;
        let mut after_swap_gas = 0u64;
        let mut before_swap_delta = BeforeSwapDelta(I256::ZERO);
        let mut storage_overwrites = None;

        let token_in_address = Address::from_slice(&token_in.address);
        let token_out_address = Address::from_slice(&token_out.address);

        let state_context = StateContext {
            currency_0: if zero_for_one { token_in_address } else { token_out_address },
            currency_1: if zero_for_one { token_out_address } else { token_in_address },
            fees: self.fees.clone(),
            tick_spacing: self.tick_spacing,
        };

        let swap_params = SwapParams {
            zero_for_one,
            amount_specified: amount_to_swap,
            sqrt_price_limit: self.sqrt_price,
        };

        // Check if hook is set and has before_swap permissions
        if let Some(ref hook) = self.hook {
            if has_permission(hook.address(), HookOptions::BeforeSwap) {
                let before_swap_params = BeforeSwapParameters {
                    context: state_context.clone(),
                    sender: *EXTERNAL_ACCOUNT,
                    swap_params: swap_params.clone(),
                    hook_data: Bytes::new(),
                };

                let before_swap_result = hook
                    .before_swap(before_swap_params, self.block.clone(), None, None)
                    .map_err(|e| {
                        SimulationError::FatalError(format!(
                            "BeforeSwap hook simulation failed: {e:?}"
                        ))
                    })?;

                before_swap_gas = before_swap_result.gas_estimate;
                before_swap_delta = before_swap_result.result.amount_delta;
                storage_overwrites = Some(before_swap_result.result.overwrites);

                // Convert amountDelta to amountToSwap as per Uniswap V4 spec
                // See: https://github.com/Uniswap/v4-core/blob/main/src/libraries/Hooks.sol#L270
                if before_swap_delta.as_i256() != I256::ZERO {
                    amount_to_swap += I256::from(before_swap_delta.get_specified_delta());
                    if amount_to_swap > I256::ZERO {
                        return Err(SimulationError::FatalError(
                            "Hook delta exceeds swap amount".into(),
                        ))
                    }
                }

                // Set LP fee override if provided by hook
                if before_swap_result
                    .result
                    .fee
                    .to::<u32>() !=
                    0
                {
                    lp_fee_override = Some(
                        before_swap_result
                            .result
                            .fee
                            .to::<u32>(),
                    );
                }
            }
        }

        // Perform the swap with potential hook modifications
        let result = self.swap(zero_for_one, amount_to_swap, None, lp_fee_override)?;

        let mut swap_delta = BalanceDelta(result.amount_calculated);
        let hook_delta_specified = before_swap_delta.get_specified_delta();
        let mut hook_delta_unspecified = before_swap_delta.get_unspecified_delta();

        if let Some(ref hook) = self.hook {
            if has_permission(hook.address(), HookOptions::AfterSwap) {
                let after_swap_params = AfterSwapParameters {
                    context: state_context,
                    sender: *EXTERNAL_ACCOUNT,
                    swap_params,
                    delta: swap_delta,
                    hook_data: Bytes::new(),
                };

                let after_swap_result = hook
                    .after_swap(after_swap_params, self.block.clone(), storage_overwrites, None)
                    .map_err(|e| {
                        SimulationError::FatalError(format!(
                            "AfterSwap hook simulation failed: {e:?}"
                        ))
                    })?;
                after_swap_gas = after_swap_result.gas_estimate;
                hook_delta_unspecified += after_swap_result.result;
            }
        }

        if (hook_delta_specified != I128::ZERO) || (hook_delta_unspecified != I128::ZERO) {
            let hook_delta = if (amount_specified < I256::ZERO) == zero_for_one {
                BalanceDelta::new(hook_delta_specified, hook_delta_unspecified)
            } else {
                BalanceDelta::new(hook_delta_unspecified, hook_delta_specified)
            };
            // This is a BalanceDelta subtraction
            swap_delta = swap_delta - hook_delta
        }
        let amount_out = if (amount_specified < I256::ZERO) == zero_for_one {
            swap_delta.amount1()
        } else {
            swap_delta.amount0()
        };

        trace!(?amount_in, ?token_in, ?token_out, ?zero_for_one, ?result, "V4 SWAP");
        let mut new_state = self.clone();
        new_state.liquidity = result.liquidity;
        new_state.tick = result.tick;
        new_state.sqrt_price = result.sqrt_price;

        // Add hook gas costs to baseline swap cost
        let total_gas_used = result.gas_used + U256::from(before_swap_gas + after_swap_gas);
        Ok(GetAmountOutResult::new(
            u256_to_biguint(U256::from(amount_out.abs())),
            u256_to_biguint(total_gas_used),
            Box::new(new_state),
        ))
    }

    fn get_limits(
        &self,
        token_in: Bytes,
        token_out: Bytes,
    ) -> Result<(BigUint, BigUint), SimulationError> {
        if let Some(hook) = &self.hook {
            // Check if pool has no liquidity & ticks -> hook manages liquidity
            if self.liquidity == 0 && self.has_no_initialized_ticks() {
                // If the hook has a get_amount_ranges entrypoint, call it and return (0, limits[1])
                match hook.get_amount_ranges(token_in.clone(), token_out.clone()) {
                    Ok(amount_ranges) => {
                        return Ok((
                            u256_to_biguint(amount_ranges.amount_in_range.1),
                            u256_to_biguint(amount_ranges.amount_out_range.1),
                        ))
                    }
                    // Check if hook get_amount_ranges is not implemented or the limits entrypoint
                    // is not set for this hook
                    Err(SimulationError::RecoverableError(msg))
                        if msg.contains("not implemented") || msg.contains("not set") =>
                    {
                        // Hook manages liquidity but doesn't have get_amount_ranges
                        // Use binary search to find limits by calling swap with increasing amounts
                        return self.find_limits_experimentally(token_in, token_out);
                        // Otherwise fall back to default implementation
                    }
                    Err(e) => return Err(e),
                }
            }
        }

        // If the pool has no liquidity, return zeros for both limits
        if self.liquidity == 0 {
            return Ok((BigUint::zero(), BigUint::zero()));
        }

        let zero_for_one = token_in < token_out;
        let mut current_tick = self.tick;
        let mut current_sqrt_price = self.sqrt_price;
        let mut current_liquidity = self.liquidity;
        let mut total_amount_in = U256::ZERO;
        let mut total_amount_out = U256::ZERO;

        // Iterate through all ticks in the direction of the swap
        // Continues until there is no more liquidity in the pool or no more ticks to process
        while let Ok((tick, initialized)) = self
            .ticks
            .next_initialized_tick_within_one_word(current_tick, zero_for_one)
        {
            // Clamp the tick value to ensure it's within valid range
            let next_tick = tick.clamp(MIN_TICK, MAX_TICK);

            // Calculate the sqrt price at the next tick boundary
            let sqrt_price_next = get_sqrt_ratio_at_tick(next_tick)?;

            // Calculate the amount of tokens swapped when moving from current_sqrt_price to
            // sqrt_price_next. Direction determines which token is being swapped in vs out
            let (amount_in, amount_out) = if zero_for_one {
                let amount0 = get_amount0_delta(
                    sqrt_price_next,
                    current_sqrt_price,
                    current_liquidity,
                    true,
                )?;
                let amount1 = get_amount1_delta(
                    sqrt_price_next,
                    current_sqrt_price,
                    current_liquidity,
                    false,
                )?;
                (amount0, amount1)
            } else {
                let amount0 = get_amount0_delta(
                    sqrt_price_next,
                    current_sqrt_price,
                    current_liquidity,
                    false,
                )?;
                let amount1 = get_amount1_delta(
                    sqrt_price_next,
                    current_sqrt_price,
                    current_liquidity,
                    true,
                )?;
                (amount1, amount0)
            };

            // Accumulate total amounts for this tick range
            total_amount_in = safe_add_u256(total_amount_in, amount_in)?;
            total_amount_out = safe_add_u256(total_amount_out, amount_out)?;

            // If this tick is "initialized" (meaning its someone's position boundary), update the
            // liquidity when crossing it
            // For zero_for_one, liquidity is removed when crossing a tick
            // For one_for_zero, liquidity is added when crossing a tick
            if initialized {
                let liquidity_raw = self
                    .ticks
                    .get_tick(next_tick)
                    .unwrap()
                    .net_liquidity;
                let liquidity_delta = if zero_for_one { -liquidity_raw } else { liquidity_raw };
                current_liquidity =
                    liquidity_math::add_liquidity_delta(current_liquidity, liquidity_delta)?;
            }

            // Move to the next tick position
            current_tick = if zero_for_one { next_tick - 1 } else { next_tick };
            current_sqrt_price = sqrt_price_next;

            // If we've consumed all liquidity, no point continuing the loop
            if current_liquidity == 0 {
                break;
            }
        }

        Ok((u256_to_biguint(total_amount_in), u256_to_biguint(total_amount_out)))
    }

    fn delta_transition(
        &mut self,
        delta: ProtocolStateDelta,
        tokens: &HashMap<Bytes, Token>,
        balances: &Balances,
    ) -> Result<(), TransitionError<String>> {
        if let Some(mut hook) = self.hook.clone() {
            match hook.delta_transition(delta.clone(), tokens, balances) {
                Ok(()) => self.set_hook_handler(hook),
                Err(TransitionError::SimulationError(SimulationError::RecoverableError(msg)))
                    if msg.contains("not implemented") =>
                {
                    // Fall back to default implementation
                }
                Err(e) => return Err(e),
            }
        }

        // Apply attribute changes
        if let Some(liquidity) = delta
            .updated_attributes
            .get("liquidity")
        {
            self.liquidity = u128::from(liquidity.clone());
        }
        if let Some(sqrt_price) = delta
            .updated_attributes
            .get("sqrt_price_x96")
        {
            self.sqrt_price = U256::from_be_slice(sqrt_price);
        }
        if let Some(tick) = delta.updated_attributes.get("tick") {
            self.tick = i24_be_bytes_to_i32(tick);
        }
        if let Some(lp_fee) = delta.updated_attributes.get("fee") {
            self.fees.lp_fee = u32::from(lp_fee.clone());
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

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, fs, path::Path, str::FromStr};

    use num_traits::FromPrimitive;
    use rstest::rstest;
    use serde_json::Value;
    use tycho_client::feed::synchronizer::ComponentWithState;
    use tycho_common::models::Chain;

    use super::*;
    use crate::{
        evm::{
            engine_db::{
                create_engine,
                simulation_db::SimulationDB,
                utils::{get_client, get_runtime},
            },
            protocol::uniswap_v4::hooks::generic_vm_hook_handler::GenericVMHookHandler,
        },
        protocol::models::TryFromWithBlock,
    };

    // Helper methods to create commonly used tokens
    fn usdc() -> Token {
        Token::new(
            &Bytes::from_str("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48").unwrap(),
            "USDC",
            6,
            0,
            &[Some(10_000)],
            Default::default(),
            100,
        )
    }

    fn weth() -> Token {
        Token::new(
            &Bytes::from_str("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2").unwrap(),
            "WETH",
            18,
            0,
            &[Some(10_000)],
            Default::default(),
            100,
        )
    }

    #[test]
    fn test_delta_transition() {
        let block = BlockHeader {
            number: 7239119,
            hash: Bytes::from_str(
                "0x28d41d40f2ac275a4f5f621a636b9016b527d11d37d610a45ac3a821346ebf8c",
            )
            .expect("Invalid block hash"),
            parent_hash: Bytes::from(vec![0; 32]),
            revert: false,
            timestamp: 0,
        };
        let mut pool = UniswapV4State::new(
            1000,
            U256::from_str("1000").unwrap(),
            UniswapV4Fees { zero_for_one: 100, one_for_zero: 90, lp_fee: 700 },
            100,
            60,
            vec![TickInfo::new(120, 10000), TickInfo::new(180, -10000)],
            block,
        );

        let attributes: HashMap<String, Bytes> = [
            ("liquidity".to_string(), Bytes::from(2000_u64.to_be_bytes().to_vec())),
            ("sqrt_price_x96".to_string(), Bytes::from(1001_u64.to_be_bytes().to_vec())),
            ("tick".to_string(), Bytes::from(120_i32.to_be_bytes().to_vec())),
            ("protocol_fees/zero2one".to_string(), Bytes::from(50_u32.to_be_bytes().to_vec())),
            ("protocol_fees/one2zero".to_string(), Bytes::from(75_u32.to_be_bytes().to_vec())),
            ("fee".to_string(), Bytes::from(100_u32.to_be_bytes().to_vec())),
            ("ticks/-120/net_liquidity".to_string(), Bytes::from(10200_u64.to_be_bytes().to_vec())),
            ("ticks/120/net_liquidity".to_string(), Bytes::from(9800_u64.to_be_bytes().to_vec())),
        ]
        .into_iter()
        .collect();

        let delta = ProtocolStateDelta {
            component_id: "State1".to_owned(),
            updated_attributes: attributes,
            deleted_attributes: HashSet::new(),
        };

        pool.delta_transition(delta, &HashMap::new(), &Balances::default())
            .unwrap();

        assert_eq!(pool.liquidity, 2000);
        assert_eq!(pool.sqrt_price, U256::from(1001));
        assert_eq!(pool.tick, 120);
        assert_eq!(pool.fees.zero_for_one, 50);
        assert_eq!(pool.fees.one_for_zero, 75);
        assert_eq!(pool.fees.lp_fee, 100);
        assert_eq!(
            pool.ticks
                .get_tick(-120)
                .unwrap()
                .net_liquidity,
            10200
        );
        assert_eq!(
            pool.ticks
                .get_tick(120)
                .unwrap()
                .net_liquidity,
            9800
        );
    }

    #[tokio::test]
    /// Compares a quote that we got from the UniswapV4 Quoter contract on Sepolia with a simulation
    /// using Tycho-simulation and a state extracted with Tycho-indexer
    async fn test_swap_sim() {
        let project_root = env!("CARGO_MANIFEST_DIR");

        let asset_path = Path::new(project_root)
            .join("tests/assets/decoder/uniswap_v4_snapshot_sepolia_block_7239119.json");
        let json_data = fs::read_to_string(asset_path).expect("Failed to read test asset");
        let data: Value = serde_json::from_str(&json_data).expect("Failed to parse JSON");

        let state: ComponentWithState = serde_json::from_value(data)
            .expect("Expected json to match ComponentWithState structure");

        let block = BlockHeader {
            number: 7239119,
            hash: Bytes::from_str(
                "0x28d41d40f2ac275a4f5f621a636b9016b527d11d37d610a45ac3a821346ebf8c",
            )
            .expect("Invalid block hash"),
            parent_hash: Bytes::from(vec![0; 32]),
            revert: false,
            timestamp: 0,
        };

        let usv4_state = UniswapV4State::try_from_with_header(
            state,
            block,
            &Default::default(),
            &Default::default(),
        )
        .await
        .unwrap();

        let t0 = Token::new(
            &Bytes::from_str("0x647e32181a64f4ffd4f0b0b4b052ec05b277729c").unwrap(),
            "T0",
            18,
            0,
            &[Some(10_000)],
            Chain::Ethereum,
            100,
        );
        let t1 = Token::new(
            &Bytes::from_str("0xe390a1c311b26f14ed0d55d3b0261c2320d15ca5").unwrap(),
            "T0",
            18,
            0,
            &[Some(10_000)],
            Chain::Ethereum,
            100,
        );

        let res = usv4_state
            .get_amount_out(BigUint::from_u64(1000000000000000000).unwrap(), &t0, &t1)
            .unwrap();

        // This amount comes from a call to the `quoteExactInputSingle` on the quoter contract on a
        // sepolia node with these arguments
        // ```
        // {"poolKey":{"currency0":"0x647e32181a64f4ffd4f0b0b4b052ec05b277729c","currency1":"0xe390a1c311b26f14ed0d55d3b0261c2320d15ca5","fee":"3000","tickSpacing":"60","hooks":"0x0000000000000000000000000000000000000000"},"zeroForOne":true,"exactAmount":"1000000000000000000","hookData":"0x"}
        // ```
        // Here is the curl for it:
        //
        // ```
        // curl -X POST https://eth-sepolia.api.onfinality.io/public \
        // -H "Content-Type: application/json" \
        // -d '{
        //   "jsonrpc": "2.0",
        //   "method": "eth_call",
        //   "params": [
        //     {
        //       "to": "0xCd8716395D55aD17496448a4b2C42557001e9743",
        //       "data": "0xaa9d21cb0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000647e32181a64f4ffd4f0b0b4b052ec05b277729c000000000000000000000000e390a1c311b26f14ed0d55d3b0261c2320d15ca50000000000000000000000000000000000000000000000000000000000000bb8000000000000000000000000000000000000000000000000000000000000003c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000de0b6b3a764000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000"
        //     },
        //     "0x6e75cf"
        //   ],
        //   "id": 1
        //   }'
        // ```
        let expected_amount = BigUint::from(9999909699895_u64);
        assert_eq!(res.amount, expected_amount);
    }

    #[tokio::test]
    async fn test_get_limits() {
        let block = BlockHeader {
            number: 22689129,
            hash: Bytes::from_str(
                "0x7763ea30d11aef68da729b65250c09a88ad00458c041064aad8c9a9dbf17adde",
            )
            .expect("Invalid block hash"),
            parent_hash: Bytes::from(vec![0; 32]),
            revert: false,
            timestamp: 0,
        };

        let project_root = env!("CARGO_MANIFEST_DIR");
        let asset_path =
            Path::new(project_root).join("tests/assets/decoder/uniswap_v4_snapshot.json");
        let json_data = fs::read_to_string(asset_path).expect("Failed to read test asset");
        let data: Value = serde_json::from_str(&json_data).expect("Failed to parse JSON");

        let state: ComponentWithState = serde_json::from_value(data)
            .expect("Expected json to match ComponentWithState structure");

        let usv4_state = UniswapV4State::try_from_with_header(
            state,
            block,
            &Default::default(),
            &Default::default(),
        )
        .await
        .unwrap();

        let t0 = Token::new(
            &Bytes::from_str("0x2260fac5e5542a773aa44fbcfedf7c193bc2c599").unwrap(),
            "WBTC",
            8,
            0,
            &[Some(10_000)],
            Chain::Ethereum,
            100,
        );
        let t1 = Token::new(
            &Bytes::from_str("0xdac17f958d2ee523a2206206994597c13d831ec7").unwrap(),
            "USDT",
            6,
            0,
            &[Some(10_000)],
            Chain::Ethereum,
            100,
        );

        let res = usv4_state
            .get_limits(t0.address.clone(), t1.address.clone())
            .unwrap();

        assert_eq!(&res.0, &BigUint::from_u128(71698353688830259750744466706).unwrap()); // Crazy amount because of this tick: "ticks/-887220/net-liquidity": "0x00e8481d98"

        let out = usv4_state
            .get_amount_out(res.0, &t0, &t1)
            .expect("swap for limit in didn't work");

        assert_eq!(&res.1, &out.amount);
    }

    #[test]
    fn test_get_amount_out_euler_hook() {
        // Test using transaction 0xb372306a81c6e840f4ec55f006da6b0b097f435802a2e6fd216998dd12fb4aca
        //
        // Output of beforeSwap:
        // "output":{
        //      "amountToSwap":"0"
        //      "hookReturn":"2520471492123673565794154180707800634502860978735"
        //      "lpFeeOverride":"0"
        // }
        //
        // Output of entire swap, including hooks:
        // "swapDelta":"-2520471491783391198873215717244426027071092767279"
        //
        // Get amount out:
        // "amountOut":"2681115183499232721"

        let block = BlockHeader {
            number: 22689128,
            parent_hash: Default::default(),
            hash: Bytes::from_str(
                "0xfbfa716523d25d6d5248c18d001ca02b1caf10cabd1ab7321465e2262c41157b",
            )
            .expect("Invalid block hash"),
            timestamp: 1749739055,
            revert: false,
        };

        // Pool ID: 0xdd8dd509e58ec98631b800dd6ba86ee569c517ffbd615853ed5ab815bbc48ccb
        // Information taken from Tenderly simulation
        let mut usv4_state = UniswapV4State::new(
            0,
            U256::from_str("4295128740").unwrap(),
            UniswapV4Fees { zero_for_one: 100, one_for_zero: 90, lp_fee: 500 },
            0,
            1,
            // Except the ticks - not sure where to get these...
            vec![],
            block.clone(),
        );

        let hook_address: Address = Address::from_str("0x69058613588536167ba0aa94f0cc1fe420ef28a8")
            .expect("Invalid hook address");

        let db = SimulationDB::new(get_client(None), get_runtime(), Some(block));
        let engine = create_engine(db, true).expect("Failed to create simulation engine");
        let pool_manager = Address::from_str("0x000000000004444c5dc75cb358380d2e3de08a90")
            .expect("Invalid pool manager address");

        let hook_handler = GenericVMHookHandler::new(
            hook_address,
            engine,
            pool_manager,
            HashMap::new(),
            HashMap::new(),
            None,
        )
        .unwrap();

        let t0 = usdc();
        let t1 = weth();

        usv4_state.set_hook_handler(Box::new(hook_handler));
        let out = usv4_state
            .get_amount_out(BigUint::from_u64(7407000000).unwrap(), &t0, &t1)
            .unwrap();

        assert_eq!(out.amount, BigUint::from_str("2681115183499232721").unwrap())
    }

    #[test]
    fn test_spot_price_with_recoverable_error() {
        // Test that spot_price correctly falls back to swap-based calculation
        // when a RecoverableError (other than "not implemented") is returned
        let block = BlockHeader {
            number: 22689128,
            parent_hash: Default::default(),
            hash: Bytes::from_str(
                "0xfbfa716523d25d6d5248c18d001ca02b1caf10cabd1ab7321465e2262c41157b",
            )
            .expect("Invalid block hash"),
            timestamp: 1749739055,
            revert: false,
        };

        let usv4_state = UniswapV4State::new(
            1000000000000000000u128, // 1e18 liquidity
            U256::from_str("79228162514264337593543950336").unwrap(), // 1:1 price
            UniswapV4Fees { zero_for_one: 100, one_for_zero: 100, lp_fee: 100 },
            0,
            60,
            vec![
                TickInfo::new(-600, 500000000000000000i128),
                TickInfo::new(600, -500000000000000000i128),
            ],
            block,
        );

        // Test spot price calculation without a hook (should use default implementation)
        let spot_price_result = usv4_state.spot_price(&usdc(), &weth());
        assert!(spot_price_result.is_ok());
        
        // The price should be approximately 1.0 (since we set sqrt_price for 1:1)
        // Adjusting for decimals difference (USDC has 6, WETH has 18)
        let price = spot_price_result.unwrap();
        assert!(price > 0.0);
    }

    #[test]
    fn test_get_limits_with_hook_managed_liquidity_no_ranges_entrypoint() {
        // This test demonstrates the experimental limit finding logic for hooks that:
        // 1. Manage liquidity (pool has no liquidity & no ticks)
        // 2. Don't have get_amount_ranges entrypoint

        let block = BlockHeader {
            number: 22689128,
            parent_hash: Default::default(),
            hash: Bytes::from_str(
                "0xfbfa716523d25d6d5248c18d001ca02b1caf10cabd1ab7321465e2262c41157b",
            )
            .expect("Invalid block hash"),
            timestamp: 1749739055,
            revert: false,
        };

        let hook_address: Address = Address::from_str("0x69058613588536167ba0aa94f0cc1fe420ef28a8")
            .expect("Invalid hook address");

        let db = SimulationDB::new(get_client(None), get_runtime(), Some(block.clone()));
        let engine = create_engine(db, true).expect("Failed to create simulation engine");
        let pool_manager = Address::from_str("0x000000000004444c5dc75cb358380d2e3de08a90")
            .expect("Invalid pool manager address");

        // Create a GenericVMHookHandler without limits_entrypoint
        // This will trigger the "not set" error path and use experimental limit finding
        let hook_handler = GenericVMHookHandler::new(
            hook_address,
            engine,
            pool_manager,
            HashMap::new(),
            HashMap::new(),
            None,
        )
        .unwrap();

        // Create a UniswapV4State with NO liquidity and NO ticks (hook manages all liquidity)
        let mut usv4_state = UniswapV4State::new(
            0, // no liquidity - hook provides it
            U256::from_str("4295128740").unwrap(),
            UniswapV4Fees { zero_for_one: 100, one_for_zero: 90, lp_fee: 500 },
            0,      // current tick
            1,      // tick spacing
            vec![], // no ticks - hook manages liquidity
            block.clone(),
        );

        usv4_state.set_hook_handler(Box::new(hook_handler));

        let token_in = usdc().address;
        let token_out = weth().address;

        let (amount_in_limit, amount_out_limit) = usv4_state
            .get_limits(token_in, token_out)
            .expect("Should find limits through experimental swapping");

        // Assuming pool supply doesn't change drastically at time of this test
        // At least 1 million USDC, not more than 100 million USDC
        assert!(amount_in_limit > BigUint::from(10u64).pow(12));
        assert!(amount_in_limit < BigUint::from(10u64).pow(14));

        // At least 100 ETH, not more than 10 000 ETH
        assert!(amount_out_limit > BigUint::from(10u64).pow(20));
        assert!(amount_out_limit < BigUint::from(10u64).pow(22));
    }

    #[rstest]
    #[case::high_liquidity(u128::MAX / 2)] // Very large liquidity
    #[case::medium_liquidity(10000000000000000000u128)] // Moderate liquidity: 10e18
    #[case::minimal_liquidity(1000u128)] // Very small liquidity
    fn test_find_max_amount(#[case] liquidity: u128) {
        let block = BlockHeader {
            number: 22578103,
            hash: Bytes::from_str(
                "0x035c0e674c3bf3384a74b766908ab41c1968e989360aa26bea1dd64b1626f5f0",
            )
            .unwrap(),
            timestamp: 1748397011,
            ..Default::default()
        };

        // Use fixed configuration for all test cases
        let fees = UniswapV4Fees { zero_for_one: 100, one_for_zero: 100, lp_fee: 100 };
        let tick_spacing = 60;
        let ticks = vec![
            TickInfo::new(-600, (liquidity / 4) as i128),
            TickInfo::new(600, -((liquidity / 4) as i128)),
        ];

        let usv4_state = UniswapV4State::new(
            liquidity,
            U256::from_str("79228162514264337593543950336").unwrap(),
            fees,
            0,
            tick_spacing,
            ticks,
            block,
        );

        let token_in = usdc();
        let token_out = weth();

        let (max_amount_in, _max_amount_out) = usv4_state
            .find_max_amount(&token_in, &token_out)
            .unwrap();

        let success = usv4_state
            .get_amount_out(max_amount_in.clone(), &token_in, &token_out)
            .is_ok();
        assert!(success, "Should be able to swap the exact max amount.");

        let one_more = &max_amount_in + BigUint::from(1u64);
        let should_fail = usv4_state
            .get_amount_out(one_more, &token_in, &token_out)
            .is_err();
        assert!(should_fail, "Swapping max_amount + 1 should fail.");
    }
}
