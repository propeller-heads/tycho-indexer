use std::{any::Any, collections::HashMap};

use alloy::primitives::{Address, Sign, I256, U256};
use num_bigint::BigUint;
use num_traits::Zero;
use tracing::trace;
use tycho_common::{dto::ProtocolStateDelta, Bytes};

use super::hooks::utils::{has_permission, HookOptions};
use crate::{
    evm::{
        engine_db::simulation_db::BlockHeader,
        protocol::{
            safe_math::{safe_add_u256, safe_sub_u256},
            u256_num::u256_to_biguint,
            uniswap_v4::hooks::hook_handler::{
                AfterSwapParameters, BeforeSwapParameters, HookHandler, StateContext, SwapParams,
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
        },
    },
    models::{Balances, Token},
    protocol::{
        errors::{SimulationError, TransitionError},
        models::GetAmountOutResult,
        state::ProtocolSim,
    },
};

#[derive(Clone, Debug)]
pub struct UniswapV4State {
    liquidity: u128,
    sqrt_price: U256,
    fees: UniswapV4Fees,
    tick: i32,
    ticks: TickList,
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
        UniswapV4State { liquidity, sqrt_price, fees, tick, ticks: tick_list, hook: None, block }
    }

    fn swap(
        &self,
        zero_for_one: bool,
        amount_specified: I256,
        sqrt_price_limit: Option<U256>,
        lp_fee_override: Option<u32>,
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
            // TODO this is negative in the tenderly simulation. Not sure we can work with that simulation because of this.
            Sign::Positive,
            U256::from_be_slice(&amount_in.to_bytes_be()),
        )
        .ok_or_else(|| {
            SimulationError::InvalidInput("I256 overflow: amount_in".to_string(), None)
        })?;

        let mut amount_to_swap = amount_specified;
        let mut lp_fee_override: Option<u32> = None;
        let mut before_swap_gas = 0u64;
        let mut after_swap_gas = 0u64;

        let token_in_address = Address::from_slice(&token_in.address);
        let token_out_address = Address::from_slice(&token_out.address);

        let state_context = StateContext {
            currency_0: if zero_for_one { token_in_address } else { token_out_address },
            currency_1: if zero_for_one { token_out_address } else { token_in_address },
            fees: self.fees.clone(),
            tick: self.tick,
        };

        let swap_params = SwapParams {
            zero_for_one,
            amount_specified,
            sqrt_price_limit: U256::ZERO, // Will be set to appropriate limit in swap
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
                    .before_swap(before_swap_params, self.block, None, None)
                    .map_err(|e| {
                        SimulationError::FatalError(format!("BeforeSwap hook failed: {e:?}"))
                    })?;

                before_swap_gas = before_swap_result.gas_estimate;
                let before_swap_amount_delta = before_swap_result.result.amount_delta;

                // Convert amountDelta to amountToSwap as per Uniswap V4 spec
                // See: https://github.com/Uniswap/v4-core/blob/main/src/libraries/Hooks.sol#L270
                if before_swap_amount_delta != I256::ZERO {
                    amount_to_swap = amount_specified + before_swap_amount_delta;
                    // TODO check that exact input doesn't change to exact output (see USV4 code)
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

        let mut after_swap_amount_delta: I256 = I256::ZERO;

        if let Some(ref hook) = self.hook {
            if has_permission(hook.address(), HookOptions::AfterSwap) {
                let after_swap_params = AfterSwapParameters {
                    context: state_context,
                    sender: *EXTERNAL_ACCOUNT,
                    swap_params,
                    delta: result.amount_calculated,
                    hook_data: Bytes::new(),
                };

                let after_swap_result = hook
                    // TODO pass storage overwrites here
                    .after_swap(after_swap_params, self.block, None, None)
                    .map_err(|e| {
                        SimulationError::FatalError(format!("AfterSwap hook failed: {e:?}"))
                    })?;
                after_swap_gas = after_swap_result.gas_estimate;
                after_swap_amount_delta = after_swap_result.result;
            }
        }

        trace!(?amount_in, ?token_in, ?token_out, ?zero_for_one, ?result, "V4 SWAP");
        let mut new_state = self.clone();
        new_state.liquidity = result.liquidity;
        new_state.tick = result.tick;
        new_state.sqrt_price = result.sqrt_price;

        // Add hook gas costs to baseline swap cost
        let total_gas_used = result.gas_used + U256::from(before_swap_gas + after_swap_gas);

        Ok(GetAmountOutResult::new(
            u256_to_biguint(
                result
                    .amount_calculated
                    .abs()
                    .into_raw() +
                    after_swap_amount_delta.into_raw(),
            ),
            u256_to_biguint(total_gas_used),
            Box::new(new_state),
        ))
    }

    fn get_limits(
        &self,
        token_in: Bytes,
        token_out: Bytes,
    ) -> Result<(BigUint, BigUint), SimulationError> {
        // If the pool has no liquidity, return zeros for both limits
        if self.liquidity == 0 {
            return Ok((BigUint::zero(), BigUint::zero()));
        }

        let zero_for_one = token_in < token_out;
        let mut current_tick = self.tick;
        let mut current_sqrt_price = self.sqrt_price;
        let mut current_liquidity = self.liquidity;
        let mut total_amount_in = U256::from(0u64);
        let mut total_amount_out = U256::from(0u64);

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
        }

        Ok((u256_to_biguint(total_amount_in), u256_to_biguint(total_amount_out)))
    }

    fn delta_transition(
        &mut self,
        delta: ProtocolStateDelta,
        _tokens: &HashMap<Bytes, Token>,
        _balances: &Balances,
    ) -> Result<(), TransitionError<String>> {
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

    use num_bigint::ToBigUint;
    use num_traits::FromPrimitive;
    use serde_json::Value;
    use tycho_client::feed::{synchronizer::ComponentWithState, Header};

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

    #[test]
    fn test_delta_transition() {
        let block = Header {
            number: 7239119,
            hash: Bytes::from_str(
                "0x28d41d40f2ac275a4f5f621a636b9016b527d11d37d610a45ac3a821346ebf8c",
            )
            .expect("Invalid block hash"),
            parent_hash: Bytes::from(vec![0; 32]),
            revert: false,
        };
        let mut pool = UniswapV4State::new(
            1000,
            U256::from_str("1000").unwrap(),
            UniswapV4Fees { zero_for_one: 100, one_for_zero: 90, lp_fee: 700 },
            100,
            60,
            vec![TickInfo::new(120, 10000), TickInfo::new(180, -10000)],
            block.into(),
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

        let block = Header {
            number: 7239119,
            hash: Bytes::from_str(
                "0x28d41d40f2ac275a4f5f621a636b9016b527d11d37d610a45ac3a821346ebf8c",
            )
            .expect("Invalid block hash"),
            parent_hash: Bytes::from(vec![0; 32]),
            revert: false,
        };

        let usv4_state = UniswapV4State::try_from_with_block(
            state,
            block,
            &Default::default(),
            &Default::default(),
        )
        .await
        .unwrap();

        let t0 = Token::new(
            "0x647e32181a64f4ffd4f0b0b4b052ec05b277729c",
            18,
            "T0",
            10_000.to_biguint().unwrap(),
        );
        let t1 = Token::new(
            "0xe390a1c311b26f14ed0d55d3b0261c2320d15ca5",
            18,
            "T0",
            10_000.to_biguint().unwrap(),
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
        let block = Header {
            number: 22689129,
            hash: Bytes::from_str(
                "0x7763ea30d11aef68da729b65250c09a88ad00458c041064aad8c9a9dbf17adde",
            )
            .expect("Invalid block hash"),
            parent_hash: Bytes::from(vec![0; 32]),
            revert: false,
        };

        let project_root = env!("CARGO_MANIFEST_DIR");
        let asset_path =
            Path::new(project_root).join("tests/assets/decoder/uniswap_v4_snapshot.json");
        let json_data = fs::read_to_string(asset_path).expect("Failed to read test asset");
        let data: Value = serde_json::from_str(&json_data).expect("Failed to parse JSON");

        let state: ComponentWithState = serde_json::from_value(data)
            .expect("Expected json to match ComponentWithState structure");

        let usv4_state = UniswapV4State::try_from_with_block(
            state,
            block,
            &Default::default(),
            &Default::default(),
        )
        .await
        .unwrap();

        let t0 = Token::new(
            "0x2260fac5e5542a773aa44fbcfedf7c193bc2c599",
            8,
            "WBTC",
            10_000.to_biguint().unwrap(),
        );
        let t1 = Token::new(
            "0xdac17f958d2ee523a2206206994597c13d831ec7",
            6,
            "USDT",
            10_000.to_biguint().unwrap(),
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
    fn test_get_amount_out_with_hook() {
        // Test using transaction 0xb372306a81c6e840f4ec55f006da6b0b097f435802a2e6fd216998dd12fb4aca
        //
        // Output of beforeSwap:
        // "output":{
        //      "amountToSwap":"0"
        //      "hookReturn":"2520471492123673565794154180707800634502860978735"
        //      "lpFeeOverride":"2520471492123673565794154180707800634502860978735"
        // }
        //
        // Output of afterSwap:
        // "output":{
        //      "0":"2520471492123673565794154180707800634502860978735" // swapDelta
        //      "1":"-2520471491783391198873215717244426027071092767279" // hookDelta
        // }
        //
        // Output of entire swap, including hooks:
        // "swapDelta":"-2520471491783391198873215717244426027071092767279"

        let block = Header {
            number: 22689129,
            hash: Bytes::from_str(
                "0x7763ea30d11aef68da729b65250c09a88ad00458c041064aad8c9a9dbf17adde",
            )
            .expect("Invalid block hash"),
            parent_hash: Bytes::from(vec![0; 32]),
            revert: false,
            // timestamp: 1749695867,
        };

        // Pool ID: 0xdd8dd509e58ec98631b800dd6ba86ee569c517ffbd615853ed5ab815bbc48ccb
        // Information taken from Tenderly simulation
        let mut usv4_state = UniswapV4State::new(
            0,
            U256::from_str("79228162514264337593543950336").unwrap(),
            UniswapV4Fees { zero_for_one: 100, one_for_zero: 90, lp_fee: 500 },
            0,
            1,
            // Except the ticks - not sure where to get these...
            vec![],
            block.clone().into(),
        );

        // TODO There are two hook addresses in the tx:
        // 0xF5d35536482f62c9031b4d6bD34724671BCE33d1 and 0x69058613588536167ba0aa94f0cc1fe420ef28a8
        // It seems the latter is a proxy though. Not sure which one to use.
        // The former fails with 0x28561ddc LockedHook()
        // and the latter with 0xa7c12499 InsufficientCalldata()
        let hook_address: Address = Address::from_str("0x69058613588536167ba0aa94f0cc1fe420ef28a8")
            .expect("Invalid hook address");

        // Note: get_runtime will fail if this test is async
        let db = SimulationDB::new(get_client(None), get_runtime(), Some(block.into()));
        let engine = create_engine(db, true).expect("Failed to create simulation engine");
        let pool_manager = Address::from_str("0x000000000004444c5dc75cb358380d2e3de08a90")
            .expect("Invalid pool manager address");

        let hook_handler = GenericVMHookHandler::new(
            hook_address,
            engine,
            pool_manager,
            HashMap::new(),
            HashMap::new(),
        )
        .unwrap();

        let t0 = Token::new(
            "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
            6,
            "USDC",
            10_000.to_biguint().unwrap(), // gas
        );
        let t1 = Token::new(
            "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
            18,
            "WETH",
            10_000.to_biguint().unwrap(), // gas
        );

        usv4_state.set_hook_handler(Box::new(hook_handler));
        let _out = usv4_state
            .get_amount_out(BigUint::from_u64(7407000000).unwrap(), &t0, &t1)
            .unwrap();
    }
}
