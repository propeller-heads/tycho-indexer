#![allow(dead_code)]

use std::{collections::HashMap, fmt::Debug};

use alloy::{
    primitives::{aliases::U24, Address, I256, U256},
    sol,
};
use tycho_common::{dto::ProtocolStateDelta, Bytes};

use crate::{
    evm::{
        engine_db::simulation_db::BlockHeader,
        protocol::uniswap_v4::state::{UniswapV4Fees, UniswapV4State},
    },
    models::{Balances, Token},
    protocol::errors::{SimulationError, TransitionError},
};

#[derive(Debug, Clone)]
pub struct StateContext {
    pub currency_0: Address,
    pub currency_1: Address,
    pub fees: UniswapV4Fees,
    pub tick: i32,
}

#[derive(Debug, Clone)]
pub struct SwapParams {
    pub zero_for_one: bool,
    pub amount_specified: I256,
    pub sqrt_price_limit: U256,
}
pub struct BeforeSwapParameters {
    pub context: StateContext,
    pub sender: Address,
    pub swap_params: SwapParams,
    pub hook_data: Bytes,
}

pub type BeforeSwapDelta = I256;

sol! {
    #[derive(Debug)]
    struct BeforeSwapSolOutput {
        bytes4 selector;
        int256 amountDelta;
        uint24 fee;
    }

    #[derive(Debug)]
    struct AfterSwapSolReturn {
        bytes4 selector;
        int128 delta;
   }
}

pub struct BeforeSwapOutput {
    pub amount_delta: I256,
    pub fee: U24,
    pub overwrites: HashMap<Address, HashMap<U256, U256>>,
    pub transient_storage: HashMap<Address, HashMap<U256, U256>>,
}

impl BeforeSwapOutput {
    pub fn new(
        before_swap_output: BeforeSwapSolOutput,
        overwrites: HashMap<Address, HashMap<U256, U256>>,
        transient_storage: HashMap<Address, HashMap<U256, U256>>,
    ) -> Self {
        Self {
            amount_delta: before_swap_output.amountDelta,
            fee: before_swap_output.fee,
            overwrites,
            transient_storage,
        }
    }
}

pub struct AfterSwapParameters {
    pub context: StateContext,
    pub sender: Address,
    pub swap_params: SwapParams,
    pub delta: BeforeSwapDelta,
    pub hook_data: Bytes,
}

#[derive(Debug, Clone)]
pub struct WithGasEstimate<T> {
    pub gas_estimate: u64,
    pub result: T,
}

pub struct AmountRanges {
    amount_in_range: (U256, U256),
    amount_out_range: (U256, U256),
}

/// Trait for simulating the swap-related behavior of Uniswap V4 hooks.
/// https://github.com/Uniswap/v4-core/blob/main/src/interfaces/IHooks.sol
///
/// Implementations of this trait should encapsulate any custom logic tied to hook execution,
/// including spot price adjustments, swap constraints, and state transitions.
pub trait HookHandler: Debug + Send + Sync + 'static {
    fn address(&self) -> Address;
    /// Simulates the beforeSwap Solidity behaviour
    fn before_swap(
        &self,
        params: BeforeSwapParameters,
        block: BlockHeader,
        overwrites: Option<HashMap<Address, HashMap<U256, U256>>>,
        transient_storage: Option<HashMap<Address, HashMap<U256, U256>>>,
    ) -> Result<WithGasEstimate<BeforeSwapOutput>, SimulationError>;

    /// Simulates the afterSwap Solidity behaviour
    fn after_swap(
        &self,
        params: AfterSwapParameters,
        block: BlockHeader,
        overwrites: Option<HashMap<Address, HashMap<U256, U256>>>,
        transient_storage_params: Option<HashMap<Address, HashMap<U256, U256>>>,
    ) -> Result<WithGasEstimate<BeforeSwapDelta>, SimulationError>;

    // Currently fee is not accessible on v4 pools, this is for future use
    // as soon as we adapt the ProtocolSim interface
    fn fee(&self, context: &UniswapV4State, params: SwapParams) -> Result<f64, SimulationError>;

    /// Hooks will likely modify spot price behaviour this function
    /// allows overriding it.
    fn spot_price(&self, base: &Token, quote: &Token) -> Result<f64, SimulationError>;

    // Advanced version also returning minimum swap amounts for future compatability
    // with updated ProtocolSim interface
    fn get_amount_ranges(
        &self,
        token_in: Address,
        token_out: Address,
    ) -> Result<AmountRanges, SimulationError>;

    // Called on each state update to update the internal state of the HookHandler
    fn delta_transition(
        &mut self,
        delta: ProtocolStateDelta,
        tokens: &HashMap<Bytes, Token>,
        balances: &Balances,
    ) -> Result<(), TransitionError<String>>;
    fn clone_box(&self) -> Box<dyn HookHandler>;

    fn as_any(&self) -> &dyn std::any::Any;

    fn is_equal(&self, other: &dyn HookHandler) -> bool;
}

impl Clone for Box<dyn HookHandler> {
    fn clone(&self) -> Self {
        self.clone_box()
    }
}
