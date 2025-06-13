use std::{any::Any, collections::HashMap};

use alloy::primitives::{Address, Sign, I256, U256};
use num_bigint::BigUint;
use num_traits::Zero;
use tracing::trace;
use tycho_common::{dto::ProtocolStateDelta, Bytes};

use super::hooks::utils::{has_permission, HookOptions};
use crate::{
    evm::protocol::{
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
    // Hook handler for the pool
    pub hook: Option<Box<dyn HookHandler>>,
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
    ) -> Self {
        let tick_list = TickList::from(
            tick_spacing
                .try_into()
                // even though it's given as int24, tick_spacing must be positive, see here:
                // https://github.com/Uniswap/v4-core/blob/a22414e4d7c0d0b0765827fe0a6c20dfd7f96291/src/libraries/TickMath.sol#L25-L28
                .expect("tick_spacing should always be positive"),
            ticks,
        );
        UniswapV4State { liquidity, sqrt_price, fees, tick, ticks: tick_list, hook: None }
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
                    // TODO is this the right sender? Does this matter?
                    sender: Address::ZERO,
                    swap_params: swap_params.clone(),
                    // TODO what is the hook data?
                    hook_data: Bytes::new(),
                };

                // TODO use block 0 for now - not sure where to get the actual block number
                let before_swap_result = hook
                    .before_swap(before_swap_params, 0)
                    .map_err(|e| {
                        SimulationError::FatalError(format!("BeforeSwap hook failed: {e:?}"))
                    })?;

                before_swap_gas = before_swap_result.gas_estimate;
                let before_swap_amount_delta = before_swap_result.result.amountDelta;

                // Convert amountDelta to amountToSwap as per Uniswap V4 spec
                // See: https://github.com/Uniswap/v4-core/blob/main/src/libraries/Hooks.sol#L270
                if before_swap_amount_delta != I256::ZERO {
                    amount_to_swap = amount_specified + before_swap_amount_delta;
                    // TODO in the USV4 code they check if it's exact input or output, and makes
                    // sure this doesn't change (returns an error if it does). Is that necessary in
                    // our case, or do we just support exact input so this doesn't matter?
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

        if let Some(ref hook) = self.hook {
            if has_permission(hook.address(), HookOptions::AfterSwap) {
                let after_swap_params = AfterSwapParameters {
                    context: state_context,
                    sender: Address::ZERO,
                    swap_params,
                    delta: result.amount_calculated,
                    hook_data: Bytes::new(),
                };

                // TODO again, where to get block number?
                let after_swap_result = hook
                    .after_swap(after_swap_params, 0)
                    .map_err(|e| {
                        SimulationError::FatalError(format!("AfterSwap hook failed: {e:?}"))
                    })?;
                after_swap_gas = after_swap_result.gas_estimate;
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
                // TODO need to add the after swap delta here to this too. Figure out how to get
                // that.
                result
                    .amount_calculated
                    .abs()
                    .into_raw(),
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

    use alloy::primitives::{Bytes as AlloyBytes, B256};
    use num_bigint::ToBigUint;
    use num_traits::FromPrimitive;
    use revm::bytecode::Bytecode;
    use serde_json::Value;
    use tycho_client::feed::synchronizer::ComponentWithState;

    use super::*;
    use crate::{
        evm::{
            engine_db::{
                create_engine,
                simulation_db::{BlockHeader, SimulationDB},
                utils::{get_client, get_runtime},
            },
            protocol::uniswap_v4::hooks::generic_vm_hook_handler::GenericVMHookHandler,
        },
        protocol::models::TryFromWithBlock,
    };

    #[test]
    fn test_delta_transition() {
        let mut pool = UniswapV4State::new(
            1000,
            U256::from_str("1000").unwrap(),
            UniswapV4Fees { zero_for_one: 100, one_for_zero: 90, lp_fee: 700 },
            100,
            60,
            vec![TickInfo::new(120, 10000), TickInfo::new(180, -10000)],
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

        let usv4_state = UniswapV4State::try_from_with_block(
            state,
            Default::default(),
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
        let project_root = env!("CARGO_MANIFEST_DIR");
        let asset_path =
            Path::new(project_root).join("tests/assets/decoder/uniswap_v4_snapshot.json");
        let json_data = fs::read_to_string(asset_path).expect("Failed to read test asset");
        let data: Value = serde_json::from_str(&json_data).expect("Failed to parse JSON");

        let state: ComponentWithState = serde_json::from_value(data)
            .expect("Expected json to match ComponentWithState structure");

        let usv4_state = UniswapV4State::try_from_with_block(
            state,
            Default::default(),
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

        // TODO need to replace this with a snapshot of the USV4 pool state at block 22689129
        let project_root = env!("CARGO_MANIFEST_DIR");
        let asset_path =
            Path::new(project_root).join("tests/assets/decoder/uniswap_v4_snapshot.json");
        let json_data = fs::read_to_string(asset_path).expect("Failed to read test asset");
        let _data: Value = serde_json::from_str(&json_data).expect("Failed to parse JSON");

        let euler_swap_bytecode = Bytecode::new_raw(
            AlloyBytes::from_str(
                "0x608060405234801561000f575f5ffd5b5060043610610179575f3560e01c80637165485d116100d2578063b47b2fb111610088578063dc4c90d311610063578063dc4c90d314610673578063dc98354e1461069a578063e1b4af691461056c575f5ffd5b8063b47b2fb11461051e578063b6a8b0fa1461056c578063c4e833ce1461057f575f5ffd5b80639f063efc116100b85780639f063efc14610409578063a70354a1146104af578063aaed87a3146104f6575f5ffd5b80637165485d146104675780638e0dc28d1461049c575f5ffd5b8063536aeb721161013257806367e4ac2c1161010d57806367e4ac2c146103d45780636c2bbe7e146104095780636fe7e6eb14610454575f5ffd5b8063536aeb7214610356578063575e24b4146103695780635e615a6b146103bf575f5ffd5b8063182148ef11610162578063182148ef146101d257806321d0ee7014610312578063259982e514610312575f5ffd5b8063022c0d9f1461017d5780630902f1ac14610192575b5f5ffd5b61019061018b366004614fd1565b6106ad565b005b61019a610b56565b604080516dffffffffffffffffffffffffffff948516815293909216602084015263ffffffff16908201526060015b60405180910390f35b6102876040805160a0810182525f80825260208201819052918101829052606081018290526080810191909152506040805160a0810182525f5473ffffffffffffffffffffffffffffffffffffffff9081168252600154808216602084015262ffffff740100000000000000000000000000000000000000008204169383019390935277010000000000000000000000000000000000000000000000909204600290810b606083015254909116608082015290565b6040516101c991905f60a08201905073ffffffffffffffffffffffffffffffffffffffff835116825273ffffffffffffffffffffffffffffffffffffffff602084015116602083015262ffffff6040840151166040830152606083015160020b606083015273ffffffffffffffffffffffffffffffffffffffff608084015116608083015292915050565b610325610320366004615056565b610c58565b6040517fffffffff0000000000000000000000000000000000000000000000000000000090911681526020016101c9565b6101906103643660046150b0565b610ce1565b61037c6103773660046150d9565b6114ac565b604080517fffffffff000000000000000000000000000000000000000000000000000000009094168452602084019290925262ffffff16908201526060016101c9565b6103c761153c565b6040516101c99190615133565b6103dc6115a9565b6040805173ffffffffffffffffffffffffffffffffffffffff9384168152929091166020830152016101c9565b61041c610417366004615258565b6116a0565b604080517fffffffff0000000000000000000000000000000000000000000000000000000090931683526020830191909152016101c9565b6103256104623660046152f1565b611730565b61048e7f45756c657253776170207631000000000000000000000000000000000000000081565b6040519081526020016101c9565b61048e6104aa366004615357565b6117ac565b7f0000000000000000000000000c9a3dd6b8f28529d72d7f9ce918d493519ee3835b60405173ffffffffffffffffffffffffffffffffffffffff90911681526020016101c9565b61050961050436600461539c565b61187e565b604080519283526020830191909152016101c9565b61053161052c3660046153d3565b6119fb565b604080517fffffffff000000000000000000000000000000000000000000000000000000009093168352600f9190910b6020830152016101c9565b61032561057a366004615454565b611a89565b610666604080516101c0810182525f80825260208201819052918101829052606081018290526080810182905260a0810182905260c0810182905260e08101829052610100810182905261012081018290526101408101829052610160810182905261018081018290526101a081019190915250604080516101c08101825260018082525f60208301819052928201819052606082018390526080820183905260a0820183905260c0820181905260e0820183905261010082018190526101208201839052610140820152610160810182905261018081018290526101a081019190915290565b6040516101c991906154ae565b6104d17f000000000000000000000000000000000004444c5dc75cb358380d2e3de08a9081565b6103256106a83660046155c8565b611b14565b6106b5611b99565b5f7fae890085f98619e96ae34ba28d74baa4a4f79785b58fd4afcd3dc0338b79df9180549091507c0100000000000000000000000000000000000000000000000000000000900463ffffffff1660011461073b576040517f0f2e5b6c00000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b80547bffffffffffffffffffffffffffffffffffffffffffffffffffffffff167c02000000000000000000000000000000000000000000000000000000001781556dffffffffffffffffffffffffffff86118015906107a857506dffffffffffffffffffffffffffff8511155b6107de576040517f6b2f218300000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b7fae890085f98619e96ae34ba28d74baa4a4f79785b58fd4afcd3dc0338b79df915f610808611c46565b90508715610840576108407f0000000000000000000000000c9a3dd6b8f28529d72d7f9ce918d493519ee38382835f01518b8a611d1d565b8615610877576108777f0000000000000000000000000c9a3dd6b8f28529d72d7f9ce918d493519ee3838283602001518a8a611d1d565b83156108f3578573ffffffffffffffffffffffffffffffffffffffff16638f536f3e6108a16121d0565b8a8a89896040518663ffffffff1660e01b81526004016108c595949392919061560f565b5f604051808303815f87803b1580156108dc575f5ffd5b505af11580156108ee573d5f5f3e3d5ffd5b505050505b5f6109227f0000000000000000000000000c9a3dd6b8f28529d72d7f9ce918d493519ee38383845f01516122c3565b90505f6109547f0000000000000000000000000c9a3dd6b8f28529d72d7f9ce918d493519ee3838485602001516122c3565b84549091505f908b906109789085906dffffffffffffffffffffffffffff166156b3565b61098291906156c6565b85549091505f908b906109b89085906e01000000000000000000000000000090046dffffffffffffffffffffffffffff166156b3565b6109c291906156c6565b90506109cf85838361296a565b610a05576040517fd93c670b00000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b85546dffffffffffffffffffffffffffff9182166e010000000000000000000000000000027fffffffff00000000000000000000000000000000000000000000000000000000909116919092161717845573ffffffffffffffffffffffffffffffffffffffff8816610a756121d0565b855460408051868152602081018690528082018f9052606081018e90526dffffffffffffffffffffffffffff80841660808301526e01000000000000000000000000000090930490921660a08301525173ffffffffffffffffffffffffffffffffffffffff92909216917f4813b0ad1586a6c47f088a07b488c1eadc58e7e7a9c3f1a71b3f33c5379133aa9181900360c00190a3505082547bffffffffffffffffffffffffffffffffffffffffffffffffffffffff167c01000000000000000000000000000000000000000000000000000000001790925550505050505050565b5f8080807fae890085f98619e96ae34ba28d74baa4a4f79785b58fd4afcd3dc0338b79df9180549091507c0100000000000000000000000000000000000000000000000000000000900463ffffffff16600203610bdf576040517f0f2e5b6c00000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b50507fae890085f98619e96ae34ba28d74baa4a4f79785b58fd4afcd3dc0338b79df91546dffffffffffffffffffffffffffff808216946e010000000000000000000000000000830490911693507c010000000000000000000000000000000000000000000000000000000090910463ffffffff169150565b5f3373ffffffffffffffffffffffffffffffffffffffff7f000000000000000000000000000000000004444c5dc75cb358380d2e3de08a901614610cc8576040517fae18210a00000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b610cd58686868686612a9a565b90505b95945050505050565b7fae890085f98619e96ae34ba28d74baa4a4f79785b58fd4afcd3dc0338b79df915f610d0b611c46565b82549091507c0100000000000000000000000000000000000000000000000000000000900463ffffffff1615610d6d576040517fef65161f00000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b81547bffffffffffffffffffffffffffffffffffffffffffffffffffffffff167c0100000000000000000000000000000000000000000000000000000000178255610120810151670de0b6b3a764000011610df4576040517fde17a3af00000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b5f8160a00151118015610e0a57505f8160c00151115b610e40576040517fde17a3af00000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b6a084595161401484a0000008160a0015111158015610e6e57506a084595161401484a0000008160c0015111155b610ea4576040517fde17a3af00000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b670de0b6b3a76400008160e0015111158015610ecd5750670de0b6b3a764000081610100015111155b610f03576040517fde17a3af00000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b5f815f015173ffffffffffffffffffffffffffffffffffffffff166338d52e0f6040518163ffffffff1660e01b8152600401602060405180830381865afa158015610f50573d5f5f3e3d5ffd5b505050506040513d601f19601f82011682018060405250810190610f7491906156d9565b90505f826020015173ffffffffffffffffffffffffffffffffffffffff166338d52e0f6040518163ffffffff1660e01b8152600401602060405180830381865afa158015610fc4573d5f5f3e3d5ffd5b505050506040513d601f19601f82011682018060405250810190610fe891906156d9565b90508073ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff161061104f576040517fd54a47c600000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b8073ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff167fe9944f93cd869a79abb7a39884b29cf3572456b35cd63ac130a2749a0d90d56d60405160405180910390a3506110b990506020840184615711565b82547fffffffffffffffffffffffffffffffffffff0000000000000000000000000000166dffffffffffffffffffffffffffff919091161782556111036040840160208501615711565b82546dffffffffffffffffffffffffffff9182166e0100000000000000000000000000009081027fffffffff0000000000000000000000000000ffffffffffffffffffffffffffff8316811780875561116b948694928116928116929092179290041661296a565b6111a1576040517fd93c670b00000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b81546dffffffffffffffffffffffffffff161561124157815461120a9082906111dc906001906dffffffffffffffffffffffffffff1661572a565b84546dffffffffffffffffffffffffffff918216916e0100000000000000000000000000009091041661296a565b15611241576040517fd93c670b00000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b81546e01000000000000000000000000000090046dffffffffffffffffffffffffffff16156112f05781546112b99082906dffffffffffffffffffffffffffff808216916112a4916001916e01000000000000000000000000000090041661572a565b6dffffffffffffffffffffffffffff1661296a565b156112f0576040517fd93c670b00000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b80516112fb90612acd565b6113088160200151612acd565b604081810151825191517fd44fee5a00000000000000000000000000000000000000000000000000000000815273ffffffffffffffffffffffffffffffffffffffff918216600482015291811660248301527f0000000000000000000000000c9a3dd6b8f28529d72d7f9ce918d493519ee383169063d44fee5a906044015f604051808303815f87803b15801561139d575f5ffd5b505af11580156113af573d5f5f3e3d5ffd5b50505050604081810151602083015191517fd44fee5a00000000000000000000000000000000000000000000000000000000815273ffffffffffffffffffffffffffffffffffffffff918216600482015291811660248301527f0000000000000000000000000c9a3dd6b8f28529d72d7f9ce918d493519ee383169063d44fee5a906044015f604051808303815f87803b15801561144b575f5ffd5b505af115801561145d573d5f5f3e3d5ffd5b5050507f000000000000000000000000000000000004444c5dc75cb358380d2e3de08a9073ffffffffffffffffffffffffffffffffffffffff161590506114a7576114a781612cdd565b505050565b5f80803373ffffffffffffffffffffffffffffffffffffffff7f000000000000000000000000000000000004444c5dc75cb358380d2e3de08a90161461151e576040517fae18210a00000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b61152b88888888886130ba565b925092509250955095509592505050565b60408051610180810182525f80825260208201819052918101829052606081018290526080810182905260a0810182905260c0810182905260e081018290526101008101829052610120810182905261014081018290526101608101919091526115a4611c46565b905090565b5f5f5f6115b4611c46565b9050805f015173ffffffffffffffffffffffffffffffffffffffff166338d52e0f6040518163ffffffff1660e01b8152600401602060405180830381865afa158015611602573d5f5f3e3d5ffd5b505050506040513d601f19601f8201168201806040525081019061162691906156d9565b9250806020015173ffffffffffffffffffffffffffffffffffffffff166338d52e0f6040518163ffffffff1660e01b8152600401602060405180830381865afa158015611675573d5f5f3e3d5ffd5b505050506040513d601f19601f8201168201806040525081019061169991906156d9565b9150509091565b5f803373ffffffffffffffffffffffffffffffffffffffff7f000000000000000000000000000000000004444c5dc75cb358380d2e3de08a901614611711576040517fae18210a00000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b61172089898989898989613806565b9150915097509795505050505050565b5f3373ffffffffffffffffffffffffffffffffffffffff7f000000000000000000000000000000000004444c5dc75cb358380d2e3de08a9016146117a0576040517fae18210a00000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b610cd885858585612a9a565b7fae890085f98619e96ae34ba28d74baa4a4f79785b58fd4afcd3dc0338b79df9180545f91907c0100000000000000000000000000000000000000000000000000000000900463ffffffff16600203611831576040517f0f2e5b6c00000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b5f61183a611c46565b90506118737f0000000000000000000000000c9a3dd6b8f28529d72d7f9ce918d493519ee3838261186c848b8b61383a565b8888613a44565b979650505050505050565b7fae890085f98619e96ae34ba28d74baa4a4f79785b58fd4afcd3dc0338b79df9180545f9182917c0100000000000000000000000000000000000000000000000000000000900463ffffffff16600203611904576040517f0f2e5b6c00000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b5f61190d611c46565b60408181015190517f1647292a00000000000000000000000000000000000000000000000000000000815273ffffffffffffffffffffffffffffffffffffffff91821660048201523060248201529192507f0000000000000000000000000c9a3dd6b8f28529d72d7f9ce918d493519ee3831690631647292a90604401602060405180830381865afa1580156119a5573d5f5f3e3d5ffd5b505050506040513d601f19601f820116820180604052508101906119c99190615750565b6119d9575f5f93509350506119f3565b6119ed816119e883898961383a565b613c9a565b93509350505b509250929050565b5f803373ffffffffffffffffffffffffffffffffffffffff7f000000000000000000000000000000000004444c5dc75cb358380d2e3de08a901614611a6c576040517fae18210a00000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b611a7a888888888888613806565b91509150965096945050505050565b5f3373ffffffffffffffffffffffffffffffffffffffff7f000000000000000000000000000000000004444c5dc75cb358380d2e3de08a901614611af9576040517fae18210a00000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b611b07878787878787612a9a565b90505b9695505050505050565b5f3373ffffffffffffffffffffffffffffffffffffffff7f000000000000000000000000000000000004444c5dc75cb358380d2e3de08a901614611b84576040517fae18210a00000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b611b8f848484612a9a565b90505b9392505050565b7f0000000000000000000000000c9a3dd6b8f28529d72d7f9ce918d493519ee38373ffffffffffffffffffffffffffffffffffffffff81163303611bda5750565b7f1f8b5215000000000000000000000000000000000000000000000000000000005f52306004523360245234604452608060645236608452365f60a4375f3660a401525f5f601f19601f36011660a4015f34855af13d5f5f3e808015611c425760403d036040f35b3d5ffd5b60408051610180810182525f80825260208201819052918101829052606081018290526080810182905260a0810182905260c0810182905260e08101829052610100810182905261012081018290526101408101829052610160810191909152610180361015611ce2576040517fa7c1249900000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b611d10367ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe808101815f61576b565b8101906115a49190615838565b60408085015190517f70a0823100000000000000000000000000000000000000000000000000000000815273ffffffffffffffffffffffffffffffffffffffff91821660048201525f918291908616906370a0823190602401602060405180830381865afa158015611d91573d5f5f3e3d5ffd5b505050506040513d601f19601f82011682018060405250810190611db591906158fb565b90508015611e4f576040517f07a2d13a0000000000000000000000000000000000000000000000000000000081526004810182905273ffffffffffffffffffffffffffffffffffffffff8616906307a2d13a90602401602060405180830381865afa158015611e26573d5f5f3e3d5ffd5b505050506040513d601f19601f82011682018060405250810190611e4a91906158fb565b611e51565b5f5b9150508015611fd1575f818410611e685781611e6a565b835b60408088015190516024810183905273ffffffffffffffffffffffffffffffffffffffff8681166044830152828116606483015292935091891691631f8b52159188915f90608401604080517fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe08184030181529181526020820180517bffffffffffffffffffffffffffffffffffffffffffffffffffffffff167fb460af9400000000000000000000000000000000000000000000000000000000179052517fffffffff0000000000000000000000000000000000000000000000000000000060e087901b168152611f62949392919060040161595e565b5f604051808303815f875af1158015611f7d573d5f5f3e3d5ffd5b505050506040513d5f823e601f3d9081017fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0168201604052611fc291908101906159ae565b50611fcd81856156c6565b9350505b82156121c85760408581015190517fc368516c00000000000000000000000000000000000000000000000000000000815273ffffffffffffffffffffffffffffffffffffffff918216600482015285821660248201529087169063c368516c906044015f604051808303815f87803b15801561204b575f5ffd5b505af115801561205d573d5f5f3e3d5ffd5b505050508573ffffffffffffffffffffffffffffffffffffffff16631f8b52158587604001515f87876040516024016120b692919091825273ffffffffffffffffffffffffffffffffffffffff16602082015260400190565b604080517fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe08184030181529181526020820180517bffffffffffffffffffffffffffffffffffffffffffffffffffffffff167f4b3fd14800000000000000000000000000000000000000000000000000000000179052517fffffffff0000000000000000000000000000000000000000000000000000000060e087901b168152612166949392919060040161595e565b5f604051808303815f875af1158015612181573d5f5f3e3d5ffd5b505050506040513d5f823e601f3d9081017fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe01682016040526121c691908101906159ae565b505b505050505050565b5f3373ffffffffffffffffffffffffffffffffffffffff7f0000000000000000000000000c9a3dd6b8f28529d72d7f9ce918d493519ee3831681036122be576040517f18503a1e0000000000000000000000000000000000000000000000000000000081525f60048201527f0000000000000000000000000c9a3dd6b8f28529d72d7f9ce918d493519ee38373ffffffffffffffffffffffffffffffffffffffff16906318503a1e906024016040805180830381865afa158015612296573d5f5f3e3d5ffd5b505050506040513d601f19601f820116820180604052508101906122ba9190615a60565b5090505b919050565b5f5f8273ffffffffffffffffffffffffffffffffffffffff166338d52e0f6040518163ffffffff1660e01b8152600401602060405180830381865afa15801561230e573d5f5f3e3d5ffd5b505050506040513d601f19601f8201168201806040525081019061233291906156d9565b6040517f70a082310000000000000000000000000000000000000000000000000000000081523060048201529091505f9073ffffffffffffffffffffffffffffffffffffffff8316906370a0823190602401602060405180830381865afa15801561239f573d5f5f3e3d5ffd5b505050506040513d601f19601f820116820180604052508101906123c391906158fb565b9050805f036123d6575f92505050611b92565b5f670de0b6b3a7640000866101200151836123f19190615a8d565b6123fb9190615ad1565b61016087015190915073ffffffffffffffffffffffffffffffffffffffff161561248f575f670de0b6b3a76400008761014001518361243a9190615a8d565b6124449190615ad1565b9050801561248d576101608701516124749073ffffffffffffffffffffffffffffffffffffffff861690836141c2565b61247e81846156c6565b925061248a81836156c6565b91505b505b60408681015190517f47cfdac400000000000000000000000000000000000000000000000000000000815273ffffffffffffffffffffffffffffffffffffffff918216600482015286821660248201525f918916906347cfdac490604401602060405180830381865afa158015612508573d5f5f3e3d5ffd5b505050506040513d601f19601f8201168201806040525081019061252c9190615750565b156127b55760408781015190517fd283e75f00000000000000000000000000000000000000000000000000000000815273ffffffffffffffffffffffffffffffffffffffff91821660048201525f9188169063d283e75f90602401602060405180830381865afa1580156125a2573d5f5f3e3d5ffd5b505050506040513d601f19601f820116820180604052508101906125c691906158fb565b90505f8773ffffffffffffffffffffffffffffffffffffffff1663acb708158387116125f257866125f4565b835b8b604001516040518363ffffffff1660e01b815260040161263592919091825273ffffffffffffffffffffffffffffffffffffffff16602082015260400190565b6020604051808303815f875af1158015612651573d5f5f3e3d5ffd5b505050506040513d601f19601f8201168201806040525081019061267591906158fb565b905061268181866156c6565b945061268d81836156c6565b915061269981846156b3565b9250815f036127b2576040808a0151815160048082526024820184526020820180517bffffffffffffffffffffffffffffffffffffffffffffffffffffffff167f869e50c70000000000000000000000000000000000000000000000000000000017905292517f1f8b521500000000000000000000000000000000000000000000000000000000815273ffffffffffffffffffffffffffffffffffffffff8e1693631f8b521593612750938e9391925f920161595e565b5f604051808303815f875af115801561276b573d5f5f3e3d5ffd5b505050506040513d5f823e601f3d9081017fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe01682016040526127b091908101906159ae565b505b50505b82156129475760408781015190517f6e553f650000000000000000000000000000000000000000000000000000000081526004810185905273ffffffffffffffffffffffffffffffffffffffff918216602482015290871690636e553f65906044016020604051808303815f875af192505050801561286f575060408051601f3d9081017fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe016820190925261286c918101906158fb565b60015b612938573d80801561289c576040519150601f19603f3d011682016040523d82523d5f602084013e6128a1565b606091505b507fca0985cf000000000000000000000000000000000000000000000000000000006128cc82615ae4565b7bffffffffffffffffffffffffffffffffffffffffffffffffffffffff191614819061292e576040517f83428ad40000000000000000000000000000000000000000000000000000000081526004016129259190615b50565b60405180910390fd5b505f93505061293a565b505b61294483826156b3565b90505b818111612954575f61295e565b61295e82826156c6565b98975050505050505050565b5f6dffffffffffffffffffffffffffff83118061299457506dffffffffffffffffffffffffffff82115b156129a057505f611b92565b83606001516dffffffffffffffffffffffffffff168310612a2b5783608001516dffffffffffffffffffffffffffff1682106129de57506001611b92565b612a21828560c001518660a0015187608001516dffffffffffffffffffffffffffff1688606001516dffffffffffffffffffffffffffff16896101000151614243565b8310159050611b92565b83608001516dffffffffffffffffffffffffffff16821015612a4e57505f611b92565b612a90838560a001518660c0015187606001516dffffffffffffffffffffffffffff1688608001516dffffffffffffffffffffffffffff168960e00151614243565b8210159050611b92565b5f6040517f0a85dc2900000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b5f8173ffffffffffffffffffffffffffffffffffffffff166338d52e0f6040518163ffffffff1660e01b8152600401602060405180830381865afa158015612b17573d5f5f3e3d5ffd5b505050506040513d601f19601f82011682018060405250810190612b3b91906156d9565b90505f8273ffffffffffffffffffffffffffffffffffffffff1663c52249836040518163ffffffff1660e01b8152600401602060405180830381865afa158015612b87573d5f5f3e3d5ffd5b505050506040513d601f19601f82011682018060405250810190612bab91906156d9565b905073ffffffffffffffffffffffffffffffffffffffff8116612c09576114a773ffffffffffffffffffffffffffffffffffffffff8316847fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff6142ef565b612c4a73ffffffffffffffffffffffffffffffffffffffff8316827fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff6142ef565b6040517f87517c4500000000000000000000000000000000000000000000000000000000815273ffffffffffffffffffffffffffffffffffffffff838116600483015284811660248301526044820181905265ffffffffffff60648301528216906387517c45906084015f604051808303815f87803b158015612ccb575f5ffd5b505af11580156121c6573d5f5f3e3d5ffd5b612dcd30612dc8604080516101c0810182525f80825260208201819052918101829052606081018290526080810182905260a0810182905260c0810182905260e08101829052610100810182905261012081018290526101408101829052610160810182905261018081018290526101a081019190915250604080516101c08101825260018082525f60208301819052928201819052606082018390526080820183905260a0820183905260c0820181905260e0820183905261010082018190526101208201839052610140820152610160810182905261018081018290526101a081019190915290565b6143cc565b5f815f015173ffffffffffffffffffffffffffffffffffffffff166338d52e0f6040518163ffffffff1660e01b8152600401602060405180830381865afa158015612e1a573d5f5f3e3d5ffd5b505050506040513d601f19601f82011682018060405250810190612e3e91906156d9565b90505f826020015173ffffffffffffffffffffffffffffffffffffffff166338d52e0f6040518163ffffffff1660e01b8152600401602060405180830381865afa158015612e8e573d5f5f3e3d5ffd5b505050506040513d601f19601f82011682018060405250810190612eb291906156d9565b90505f64e8d4a51000846101200151612ecb9190615ad1565b6040805160a0808201835273ffffffffffffffffffffffffffffffffffffffff8781168084528782166020850181905262ffffff8781168688018190526001606088018190523060809098018890525f80547fffffffffffffffffffffffff0000000000000000000000000000000000000000908116871790915581547fffffffffffff000000ffffffffffffffffffffffffffffffffffffffffffffff740100000000000000000000000000000000000000009094027fffffffffffffffffff000000000000000000000000000000000000000000000090911690951794909417918216770100000000000000000000000000000000000000000000001790819055600280549094168817845597517f6276cbbe0000000000000000000000000000000000000000000000000000000081526004810194909452841660248401529386901c909316604482015260b89490941c90910b606484015260848301919091526c0100000000000000000000000060a48301529192507f000000000000000000000000000000000004444c5dc75cb358380d2e3de08a9090911690636276cbbe9060c4016020604051808303815f875af115801561308f573d5f5f3e3d5ffd5b505050506040513d601f19601f820116820180604052508101906130b39190615b62565b5050505050565b5f8080807fae890085f98619e96ae34ba28d74baa4a4f79785b58fd4afcd3dc0338b79df9180549091507c0100000000000000000000000000000000000000000000000000000000900463ffffffff16600114613143576040517f28561ddc00000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b80547bffffffffffffffffffffffffffffffffffffffffffffffffffffffff167c02000000000000000000000000000000000000000000000000000000001790555f61318d611c46565b90505f80808060208b0135811380156131f5576131ad60208d0135615b7d565b91506131ee7f0000000000000000000000000c9a3dd6b8f28529d72d7f9ce918d493519ee383878e5f0160208101906131e69190615bb3565b856001613a44565b935061323d565b8b60200135935061323a7f0000000000000000000000000c9a3dd6b8f28529d72d7f9ce918d493519ee383878e5f0160208101906132339190615bb3565b875f613a44565b91505b806132815761327c61324e85614535565b61325790615bce565b61326084614535565b6fffffffffffffffffffffffffffffffff1660809190911b1790565b61329f565b61329f61328d83614535565b61329686614535565b61326090615bce565b925073ffffffffffffffffffffffffffffffffffffffff7f000000000000000000000000000000000004444c5dc75cb358380d2e3de08a9016630b0d9c096132ea60208f018f615bb3565b613306578e60200160208101906133019190615c0a565b613318565b8e5f0160208101906133189190615c0a565b6040517fffffffff0000000000000000000000000000000000000000000000000000000060e084901b16815273ffffffffffffffffffffffffffffffffffffffff9091166004820152306024820152604481018590526064015f604051808303815f87803b158015613388575f5ffd5b505af115801561339a573d5f5f3e3d5ffd5b505050506133ea7f0000000000000000000000000c9a3dd6b8f28529d72d7f9ce918d493519ee383878e5f0160208101906133d59190615bb3565b6133e35788602001516122c3565b88516122c3565b945073ffffffffffffffffffffffffffffffffffffffff7f000000000000000000000000000000000004444c5dc75cb358380d2e3de08a901663a584119461343560208f018f615bb3565b613450578e5f01602081019061344b9190615c0a565b613463565b8e60200160208101906134639190615c0a565b6040517fffffffff0000000000000000000000000000000000000000000000000000000060e084901b16815273ffffffffffffffffffffffffffffffffffffffff90911660048201526024015f604051808303815f87803b1580156134c6575f5ffd5b505af11580156134d8573d5f5f3e3d5ffd5b5050505061354b7f0000000000000000000000000c9a3dd6b8f28529d72d7f9ce918d493519ee383878e5f0160208101906135139190615bb3565b61351e578851613524565b88602001515b877f000000000000000000000000000000000004444c5dc75cb358380d2e3de08a90611d1d565b7f000000000000000000000000000000000004444c5dc75cb358380d2e3de08a9073ffffffffffffffffffffffffffffffffffffffff166311da60b46040518163ffffffff1660e01b81526004016020604051808303815f875af11580156135b5573d5f5f3e3d5ffd5b505050506040513d601f19601f820116820180604052508101906135d991906158fb565b5050505f6136047fae890085f98619e96ae34ba28d74baa4a4f79785b58fd4afcd3dc0338b79df9190565b90505f61361460208d018d615bb3565b61363a5781546136359085906dffffffffffffffffffffffffffff166156c6565b613657565b81546136579086906dffffffffffffffffffffffffffff166156b3565b90505f61366760208e018e615bb3565b156136a057825461369b9086906e01000000000000000000000000000090046dffffffffffffffffffffffffffff166156c6565b6136cf565b82546136cf9087906e01000000000000000000000000000090046dffffffffffffffffffffffffffff166156b3565b90506136dc87838361296a565b613712576040517fd93c670b00000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b82546dffffffffffffffffffffffffffff9182166e010000000000000000000000000000027fffffffff0000000000000000000000000000000000000000000000000000000090911691909216171790557f575e24b400000000000000000000000000000000000000000000000000000000965094505f93505050505f6137b67fae890085f98619e96ae34ba28d74baa4a4f79785b58fd4afcd3dc0338b79df9190565b80547bffffffffffffffffffffffffffffffffffffffffffffffffffffffff167c010000000000000000000000000000000000000000000000000000000017905550919790965090945092505050565b5f5f6040517f0a85dc2900000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b5f5f845f015173ffffffffffffffffffffffffffffffffffffffff166338d52e0f6040518163ffffffff1660e01b8152600401602060405180830381865afa158015613888573d5f5f3e3d5ffd5b505050506040513d601f19601f820116820180604052508101906138ac91906156d9565b90505f856020015173ffffffffffffffffffffffffffffffffffffffff166338d52e0f6040518163ffffffff1660e01b8152600401602060405180830381865afa1580156138fc573d5f5f3e3d5ffd5b505050506040513d601f19601f8201168201806040525081019061392091906156d9565b90508173ffffffffffffffffffffffffffffffffffffffff168573ffffffffffffffffffffffffffffffffffffffff1614801561398857508073ffffffffffffffffffffffffffffffffffffffff168473ffffffffffffffffffffffffffffffffffffffff16145b156139965760019250613a3b565b8073ffffffffffffffffffffffffffffffffffffffff168573ffffffffffffffffffffffffffffffffffffffff161480156139fc57508173ffffffffffffffffffffffffffffffffffffffff168473ffffffffffffffffffffffffffffffffffffffff16145b15613a09575f9250613a3b565b6040517f4617192b00000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b50509392505050565b5f825f03613a5357505f610cd8565b60408581015190517f1647292a00000000000000000000000000000000000000000000000000000000815273ffffffffffffffffffffffffffffffffffffffff918216600482015230602482015290871690631647292a90604401602060405180830381865afa158015613ac9573d5f5f3e3d5ffd5b505050506040513d601f19601f82011682018060405250810190613aed9190615750565b613b23576040517f715756a900000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b6dffffffffffffffffffffffffffff831115613b6b576040517f7468c7a800000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b6101208501518215613ba157670de0b6b3a7640000613b8a8286615a8d565b613b949190615ad1565b613b9e90856156c6565b93505b5f5f613bad8888613c9a565b915091505f613bbe8988888b61457a565b90508515613c1157828711158015613bd65750818111155b613c0c576040517f7468c7a800000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b613c57565b818711158015613c215750828111155b613c57576040517f7468c7a800000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b85613c8d57613c6e84670de0b6b3a76400006156c6565b613c8082670de0b6b3a7640000615a8d565b613c8a9190615ad1565b90505b9998505050505050505050565b6040820151825160208401515f9283927fae890085f98619e96ae34ba28d74baa4a4f79785b58fd4afcd3dc0338b79df91926dffffffffffffffffffffffffffff92839290918689613cec5781613cee565b825b6040517f402d267d00000000000000000000000000000000000000000000000000000000815273ffffffffffffffffffffffffffffffffffffffff86811660048301529192505f9183169063402d267d90602401602060405180830381865afa158015613d5d573d5f5f3e3d5ffd5b505050506040513d601f19601f82011682018060405250810190613d8191906158fb565b6040517fd283e75f00000000000000000000000000000000000000000000000000000000815273ffffffffffffffffffffffffffffffffffffffff878116600483015284169063d283e75f90602401602060405180830381865afa158015613deb573d5f5f3e3d5ffd5b505050506040513d601f19601f82011682018060405250810190613e0f91906158fb565b613e1991906156b3565b905086811015613e27578096505b50505f89613e465786546dffffffffffffffffffffffffffff16613e6b565b86546e01000000000000000000000000000090046dffffffffffffffffffffffffffff165b905084816dffffffffffffffffffffffffffff161015613e9957806dffffffffffffffffffffffffffff1694505b505f89613ea65782613ea8565b815b90505f8173ffffffffffffffffffffffffffffffffffffffff1663961be3916040518163ffffffff1660e01b8152600401602060405180830381865afa158015613ef4573d5f5f3e3d5ffd5b505050506040513d601f19601f82011682018060405250810190613f1891906158fb565b905085811015613f26578095505b5f8273ffffffffffffffffffffffffffffffffffffffff166318e22d986040518163ffffffff1660e01b81526004016040805180830381865afa158015613f6f573d5f5f3e3d5ffd5b505050506040513d601f19601f82011682018060405250810190613f939190615c36565b9150505f613fa48261ffff166148ba565b9050808473ffffffffffffffffffffffffffffffffffffffff166347bd37186040518163ffffffff1660e01b8152600401602060405180830381865afa158015613ff0573d5f5f3e3d5ffd5b505050506040513d601f19601f8201168201806040525081019061401491906158fb565b11614095578373ffffffffffffffffffffffffffffffffffffffff166347bd37186040518163ffffffff1660e01b8152600401602060405180830381865afa158015614062573d5f5f3e3d5ffd5b505050506040513d601f19601f8201168201806040525081019061408691906158fb565b61409090826156c6565b614097565b5f5b9050878110156141ac576040517f70a0823100000000000000000000000000000000000000000000000000000000815273ffffffffffffffffffffffffffffffffffffffff88811660048301528516906307a2d13a9082906370a0823190602401602060405180830381865afa158015614113573d5f5f3e3d5ffd5b505050506040513d601f19601f8201168201806040525081019061413791906158fb565b6040518263ffffffff1660e01b815260040161415591815260200190565b602060405180830381865afa158015614170573d5f5f3e3d5ffd5b505050506040513d601f19601f8201168201806040525081019061419491906158fb565b61419e90826156b3565b9050878110156141ac578097505b50969950949750505050505050505b9250929050565b60405173ffffffffffffffffffffffffffffffffffffffff8381166024830152604482018390526114a791859182169063a9059cbb906064015b604051602081830303815290604052915060e01b6020820180517bffffffffffffffffffffffffffffffffffffffffffffffffffffffff83818316178352505050506148ff565b5f5f61427088860388028685670de0b6b3a764000003028a8602018a670de0b6b3a764000002600161499e565b90507effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff8111156142cb576040517f35278d1200000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b85600187038201816142df576142df615aa4565b0484019150509695505050505050565b6040805173ffffffffffffffffffffffffffffffffffffffff8416602482015260448082018490528251808303909101815260649091019091526020810180517bffffffffffffffffffffffffffffffffffffffffffffffffffffffff167f095ea7b30000000000000000000000000000000000000000000000000000000017905261437b84826149e0565b6143c65760405173ffffffffffffffffffffffffffffffffffffffff84811660248301525f60448301526143bc91869182169063095ea7b3906064016141fc565b6143c684826148ff565b50505050565b80511515612000831615151415806143f05750602081015115156110008316151514155b806144075750604081015115156108008316151514155b8061441e5750606081015115156104008316151514155b806144355750608081015115156102008316151514155b8061444c575060a081015115156101008316151514155b80614462575060c0810151151560808316151514155b80614478575060e0810151151560408316151514155b8061448f5750610100810151151560208316151514155b806144a65750610120810151151560108316151514155b806144bd5750610140810151151560088316151514155b806144d45750610160810151151560048316151514155b806144eb5750610180810151151560028316151514155b8061450257506101a0810151151560018316151514155b15614531576145317fe65af6a00000000000000000000000000000000000000000000000000000000083614a38565b5050565b5f6f800000000000000000000000000000008210614576576145767f93dafdf100000000000000000000000000000000000000000000000000000000614a5a565b5090565b5f807fae890085f98619e96ae34ba28d74baa4a4f79785b58fd4afcd3dc0338b79df9160a087015160c0880151606089015160808a015160e08b01516101008c01518654969750949593946dffffffffffffffffffffffffffff938416949284169391929091818116916e0100000000000000000000000000009004165f808d1561470c578c1561468c5761461f8f6dffffffffffffffffffffffffffff86166156b3565b915087821161463d57614636828b8b8b8b8b614243565b905061464e565b61464b828a8c8a8c8a614a62565b90505b80836dffffffffffffffffffffffffffff161161466b575f614685565b614685816dffffffffffffffffffffffffffff85166156c6565b9b506148a7565b6146a68f6dffffffffffffffffffffffffffff85166156b3565b90508681116146c4576146bd818a8c8a8c8a614243565b91506146d5565b6146d2818b8b8b8b8b614a62565b91505b81846dffffffffffffffffffffffffffff16116146f2575f614685565b614685826dffffffffffffffffffffffffffff86166156c6565b8c156147db578e836dffffffffffffffffffffffffffff161161475b576040517f7468c7a800000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b6147758f6dffffffffffffffffffffffffffff85166156c6565b90508681116147935761478c818a8c8a8c8a614243565b91506147a4565b6147a1818b8b8b8b8b614a62565b91505b836dffffffffffffffffffffffffffff1682116147c1575f614685565b6146856dffffffffffffffffffffffffffff8516836156c6565b8e846dffffffffffffffffffffffffffff1611614824576040517f7468c7a800000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b61483e8f6dffffffffffffffffffffffffffff86166156c6565b915087821161485c57614855828b8b8b8b8b614243565b905061486d565b61486a828a8c8a8c8a614a62565b90505b826dffffffffffffffffffffffffffff16811161488a575f6148a4565b6148a46dffffffffffffffffffffffffffff8416826156c6565b9b505b5050505050505050505050949350505050565b5f815f036148e957507fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff919050565b6064603f8316600a0a600684901c020492915050565b5f5f60205f8451602086015f885af18061491e576040513d5f823e3d81fd5b50505f513d9150811561493557806001141561494f565b73ffffffffffffffffffffffffffffffffffffffff84163b155b156143c6576040517f5274afe700000000000000000000000000000000000000000000000000000000815273ffffffffffffffffffffffffffffffffffffffff85166004820152602401612925565b5f6149cb6149ab83614c3b565b80156149c657505f84806149c1576149c1615aa4565b868809115b151590565b6149d6868686614c67565b610cd891906156b3565b5f5f5f5f60205f8651602088015f8a5af192503d91505f519050828015614a2c57508115614a115780600114614a2c565b5f8673ffffffffffffffffffffffffffffffffffffffff163b115b93505050505b92915050565b815f5273ffffffffffffffffffffffffffffffffffffffff811660045260245ffd5b805f5260045ffd5b5f5f5f5f5f614a8089670de0b6b3a764000002888d038c600161499e565b90507ffffffffffffffffffffffffffffffffffffffffffffffffff21f494c589c000060028702018802670de0b6b3a7640000818303059450614ada87670de0b6b3a7640000038a8b02670de0b6b3a7640000600161499e565b9350614af48760040285670de0b6b3a7640000600161499e565b925050505f5f841215614b0f57614b0a84615b7d565b614b11565b835b90505f5f5f6ec097ce7bc90715b34b9f1000000000841015614b495783840292508483019150614b42826001614d3c565b9050614ba8565b5f614b5385614d6c565b9050614b6b614b628287615ad1565b8683600161499e565b9350614b778180615a8d565b614b819087615ad1565b614b8b90856156b3565b9250614b98836001614d3c565b9150614ba48183615a8d565b9150505b5f5f8813614bea57614bd8614bbd83876156b3565b670de0b6b3a7640000614bd18d6002615a8d565b600161499e565b614be39060016156b3565b9050614c15565b614c07614bf8886002615a8d565b614c0284886156b3565b614dbb565b614c129060016156b3565b90505b8b8110614c2c578b98505050505050505050611b0a565b9750611b0a9650505050505050565b5f6002826003811115614c5057614c50615c67565b614c5a9190615c94565b60ff166001149050919050565b5f838302817fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff85870982811083820303915050805f03614cba57838281614cb057614cb0615aa4565b0492505050611b92565b808411614cd157614cd16003851502601118614dee565b5f848688095f868103871696879004966002600389028118808a02820302808a02820302808a02820302808a02820302808a02820302808a02909103029181900381900460010186841190950394909402919094039290920491909117919091029150509392505050565b5f5f614d4784614dff565b9050614d64614d5584614c3b565b80156149c65750818002851190565b019392505050565b5f805b8215614d8e5760019290921c9180614d8681615cb5565b915050614d6f565b6080811115614db0575f614da36080836156c6565b6001901b9250614db59050565b600191505b50919050565b5f815f03614dcd57614dcd6012614dee565b816001840381614ddf57614ddf615aa4565b04600101831515029392505050565b634e487b715f52806020526024601cfd5b5f60018211614e0c575090565b8160017001000000000000000000000000000000008210614e325760809190911c9060401b5b680100000000000000008210614e4d5760409190911c9060201b5b6401000000008210614e645760209190911c9060101b5b620100008210614e795760109190911c9060081b5b6101008210614e8d5760089190911c9060041b5b60108210614ea05760049190911c9060021b5b60048210614eac5760011b5b600302600190811c90818581614ec457614ec4615aa4565b048201901c90506001818581614edc57614edc615aa4565b048201901c90506001818581614ef457614ef4615aa4565b048201901c90506001818581614f0c57614f0c615aa4565b048201901c90506001818581614f2457614f24615aa4565b048201901c90506001818581614f3c57614f3c615aa4565b048201901c9050614f5b818581614f5557614f55615aa4565b04821190565b90039392505050565b73ffffffffffffffffffffffffffffffffffffffff81168114614f85575f5ffd5b50565b80356122be81614f64565b5f5f83601f840112614fa3575f5ffd5b50813567ffffffffffffffff811115614fba575f5ffd5b6020830191508360208285010111156141bb575f5ffd5b5f5f5f5f5f60808688031215614fe5575f5ffd5b85359450602086013593506040860135614ffe81614f64565b9250606086013567ffffffffffffffff811115615019575f5ffd5b61502588828901614f93565b969995985093965092949392505050565b5f60a08284031215614db5575f5ffd5b5f60808284031215614db5575f5ffd5b5f5f5f5f5f610160868803121561506b575f5ffd5b853561507681614f64565b94506150858760208801615036565b93506150948760c08801615046565b925061014086013567ffffffffffffffff811115615019575f5ffd5b5f60408284031280156150c1575f5ffd5b509092915050565b5f60608284031215614db5575f5ffd5b5f5f5f5f5f61014086880312156150ee575f5ffd5b85356150f981614f64565b94506151088760208801615036565b93506151178760c088016150c9565b925061012086013567ffffffffffffffff811115615019575f5ffd5b815173ffffffffffffffffffffffffffffffffffffffff16815261018081016020830151615179602084018273ffffffffffffffffffffffffffffffffffffffff169052565b5060408301516151a1604084018273ffffffffffffffffffffffffffffffffffffffff169052565b5060608301516151c360608401826dffffffffffffffffffffffffffff169052565b5060808301516151e560808401826dffffffffffffffffffffffffffff169052565b5060a083015160a083015260c083015160c083015260e083015160e083015261010083015161010083015261012083015161012083015261014083015161014083015261016083015161525161016084018273ffffffffffffffffffffffffffffffffffffffff169052565b5092915050565b5f5f5f5f5f5f5f6101a0888a03121561526f575f5ffd5b873561527a81614f64565b96506152898960208a01615036565b95506152988960c08a01615046565b94506101408801359350610160880135925061018088013567ffffffffffffffff8111156152c4575f5ffd5b6152d08a828b01614f93565b989b979a50959850939692959293505050565b8060020b8114614f85575f5ffd5b5f5f5f5f6101008587031215615305575f5ffd5b843561531081614f64565b935061531f8660208701615036565b925060c085013561532f81614f64565b915060e085013561533f816152e3565b939692955090935050565b8015158114614f85575f5ffd5b5f5f5f5f6080858703121561536a575f5ffd5b843561537581614f64565b9350602085013561538581614f64565b925060408501359150606085013561533f8161534a565b5f5f604083850312156153ad575f5ffd5b82356153b881614f64565b915060208301356153c881614f64565b809150509250929050565b5f5f5f5f5f5f61016087890312156153e9575f5ffd5b86356153f481614f64565b95506154038860208901615036565b94506154128860c089016150c9565b9350610120870135925061014087013567ffffffffffffffff811115615436575f5ffd5b61544289828a01614f93565b979a9699509497509295939492505050565b5f5f5f5f5f5f610120878903121561546a575f5ffd5b863561547581614f64565b95506154848860208901615036565b945060c0870135935060e0870135925061010087013567ffffffffffffffff811115615436575f5ffd5b8151151581526101c0810160208301516154cc602084018215159052565b5060408301516154e0604084018215159052565b5060608301516154f4606084018215159052565b506080830151615508608084018215159052565b5060a083015161551c60a084018215159052565b5060c083015161553060c084018215159052565b5060e083015161554460e084018215159052565b5061010083015161555a61010084018215159052565b5061012083015161557061012084018215159052565b5061014083015161558661014084018215159052565b5061016083015161559c61016084018215159052565b506101808301516155b261018084018215159052565b506101a08301516152516101a084018215159052565b5f5f5f60e084860312156155da575f5ffd5b83356155e581614f64565b92506155f48560208601615036565b915060c084013561560481614f64565b809150509250925092565b73ffffffffffffffffffffffffffffffffffffffff8616815284602082015283604082015260806060820152816080820152818360a08301375f81830160a090810191909152601f9092017fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0160101949350505050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52601160045260245ffd5b80820180821115614a3257614a32615686565b81810381811115614a3257614a32615686565b5f602082840312156156e9575f5ffd5b8151611b9281614f64565b80356dffffffffffffffffffffffffffff811681146122be575f5ffd5b5f60208284031215615721575f5ffd5b611b92826156f4565b6dffffffffffffffffffffffffffff8281168282160390811115614a3257614a32615686565b5f60208284031215615760575f5ffd5b8151611b928161534a565b5f5f85851115615779575f5ffd5b83861115615785575f5ffd5b5050820193919092039150565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52604160045260245ffd5b604051610180810167ffffffffffffffff811182821017156157e3576157e3615792565b60405290565b604051601f82017fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe016810167ffffffffffffffff8111828210171561583057615830615792565b604052919050565b5f61018082840312801561584a575f5ffd5b506158536157bf565b61585c83614f88565b815261586a60208401614f88565b602082015261587b60408401614f88565b604082015261588c606084016156f4565b606082015261589d608084016156f4565b608082015260a0838101359082015260c0808401359082015260e080840135908201526101008084013590820152610120808401359082015261014080840135908201526158ee6101608401614f88565b6101608201529392505050565b5f6020828403121561590b575f5ffd5b5051919050565b5f81518084528060208401602086015e5f6020828601015260207fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0601f83011685010191505092915050565b73ffffffffffffffffffffffffffffffffffffffff8516815273ffffffffffffffffffffffffffffffffffffffff84166020820152826040820152608060608201525f610cd56080830184615912565b5f602082840312156159be575f5ffd5b815167ffffffffffffffff8111156159d4575f5ffd5b8201601f810184136159e4575f5ffd5b805167ffffffffffffffff8111156159fe576159fe615792565b615a2f60207fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0601f840116016157e9565b818152856020838501011115615a43575f5ffd5b8160208401602083015e5f91810160200191909152949350505050565b5f5f60408385031215615a71575f5ffd5b8251615a7c81614f64565b60208401519092506153c88161534a565b8082028115828204841417614a3257614a32615686565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52601260045260245ffd5b5f82615adf57615adf615aa4565b500490565b805160208201517fffffffff00000000000000000000000000000000000000000000000000000000811691906004821015615b49577fffffffff00000000000000000000000000000000000000000000000000000000808360040360031b1b82161692505b5050919050565b602081525f611b926020830184615912565b5f60208284031215615b72575f5ffd5b8151611b92816152e3565b5f7f80000000000000000000000000000000000000000000000000000000000000008203615bad57615bad615686565b505f0390565b5f60208284031215615bc3575f5ffd5b8135611b928161534a565b5f81600f0b7fffffffffffffffffffffffffffffffff800000000000000000000000000000008103615c0257615c02615686565b5f0392915050565b5f60208284031215615c1a575f5ffd5b8135611b9281614f64565b805161ffff811681146122be575f5ffd5b5f5f60408385031215615c47575f5ffd5b615c5083615c25565b9150615c5e60208401615c25565b90509250929050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52602160045260245ffd5b5f60ff831680615ca657615ca6615aa4565b8060ff84160691505092915050565b5f7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff8203615ce557615ce5615686565b506001019056fea2646970667358221220bb015cd6de4a917bfc0e69db8e17a8e26266815bf712da36e29567b3a472ccff64736f6c634300081b0033"
            ).map_err(|_| {
                SimulationError::FatalError(
                    "Invalid pool manager bytecode".to_string(),
                )
            }
        ).unwrap());
        let hook_address: Address = Address::from_str("0xF5d35536482f62c9031b4d6bD34724671BCE33d1")
            .expect("Invalid hook address");

        let block = BlockHeader {
            number: 22689129,
            hash: B256::from_str(
                "0x7763ea30d11aef68da729b65250c09a88ad00458c041064aad8c9a9dbf17adde",
            )
            .unwrap(),
            timestamp: 1749695867,
        };

        // Note: get_runtime will fail if this test is async
        let db = SimulationDB::new(get_client(None), get_runtime(), Some(block));
        let engine = create_engine(db, true).expect("Failed to create simulation engine");
        let pool_manager = Address::from_str("0x000000000004444c5dc75cb358380d2e3de08a90")
            .expect("Invalid pool manager address");

        let _hook_handler =
            GenericVMHookHandler::new(hook_address, euler_swap_bytecode, engine, pool_manager);
    }
}
