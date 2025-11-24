use std::{any::Any, collections::HashMap, fmt};

use num_bigint::BigUint;

use crate::{
    dto::ProtocolStateDelta,
    models::token::Token,
    simulation::{
        errors::{SimulationError, TransitionError},
        indicatively_priced::IndicativelyPriced,
    },
    Bytes,
};

#[derive(Default)]
pub struct Balances {
    pub component_balances: HashMap<String, HashMap<Bytes, Bytes>>,
    pub account_balances: HashMap<Bytes, HashMap<Bytes, Bytes>>,
}

/// GetAmountOutResult struct represents the result of getting the amount out of a trading pair
///
/// # Fields
///
/// * `amount`: BigUint, the amount of the trading pair
/// * `gas`: BigUint, the gas of the trading pair
#[derive(Debug)]
pub struct GetAmountOutResult {
    pub amount: BigUint,
    pub gas: BigUint,
    pub new_state: Box<dyn ProtocolSim>,
}

impl GetAmountOutResult {
    /// Constructs a new GetAmountOutResult struct with the given amount and gas
    pub fn new(amount: BigUint, gas: BigUint, new_state: Box<dyn ProtocolSim>) -> Self {
        GetAmountOutResult { amount, gas, new_state }
    }

    /// Aggregates the given GetAmountOutResult struct to the current one.
    /// It updates the amount with the other's amount and adds the other's gas to the current one's
    /// gas.
    pub fn aggregate(&mut self, other: &Self) {
        self.amount = other.amount.clone();
        self.gas += &other.gas;
    }
}

impl fmt::Display for GetAmountOutResult {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "amount = {}, gas = {}", self.amount, self.gas)
    }
}

pub struct Price {
    pub numerator: BigUint,
    pub denominator: BigUint,
}

impl Price {
    pub fn new(numerator: BigUint, denominator: BigUint) -> Self {
        Self { numerator, denominator }
    }
}

/// ProtocolSim trait
/// This trait defines the methods that a protocol state must implement in order to be used
/// in the trade simulation.
pub trait ProtocolSim: fmt::Debug + Send + Sync + 'static {
    /// Returns the fee of the protocol as ratio
    ///
    /// E.g. if the fee is 1%, the value returned would be 0.01.
    fn fee(&self) -> f64;

    /// Returns the protocol's current spot price of two tokens
    ///
    /// Currency pairs are meant to be compared against one another in
    /// order to understand how much of the quote currency is required
    /// to buy one unit of the base currency.
    ///
    /// E.g. if ETH/USD is trading at 1000, we need 1000 USD (quote)
    /// to buy 1 ETH (base currency).
    ///
    /// # Arguments
    ///
    /// * `a` - Base Token: refers to the token that is the quantity of a pair. For the pair
    ///   BTC/USDT, BTC would be the base asset.
    /// * `b` - Quote Token: refers to the token that is the price of a pair. For the symbol
    ///   BTC/USDT, USDT would be the quote asset.
    fn spot_price(&self, base: &Token, quote: &Token) -> Result<f64, SimulationError>;

    /// Returns the amount out given an amount in and input/output tokens.
    ///
    /// # Arguments
    ///
    /// * `amount_in` - The amount in of the input token.
    /// * `token_in` - The input token ERC20 token.
    /// * `token_out` - The output token ERC20 token.
    ///
    /// # Returns
    ///
    /// A `Result` containing a `GetAmountOutResult` struct on success or a
    ///  `SimulationError` on failure.
    fn get_amount_out(
        &self,
        amount_in: BigUint,
        token_in: &Token,
        token_out: &Token,
    ) -> Result<GetAmountOutResult, SimulationError>;

    /// Computes the maximum amount that can be traded between two tokens.
    ///
    /// This function calculates the maximum possible trade amount between two tokens,
    /// taking into account the protocol's specific constraints and mechanics.
    /// The implementation details vary by protocol - for example:
    /// - For constant product AMMs (like Uniswap V2), this is based on available reserves
    /// - For concentrated liquidity AMMs (like Uniswap V3), this considers liquidity across tick
    ///   ranges
    ///
    /// Note: if there are no limits, the returned amount will be a "soft" limit,
    ///       meaning that the actual amount traded could be higher but it's advised to not
    ///       exceed it.
    ///
    /// # Arguments
    /// * `sell_token` - The address of the token being sold
    /// * `buy_token` - The address of the token being bought
    ///
    /// # Returns
    /// * `Ok((Option<BigUint>, Option<BigUint>))` - A tuple containing:
    ///   - First element: The maximum input amount
    ///   - Second element: The maximum output amount
    ///
    /// This means that for `let res = get_limits(...)` the amount input domain for `get_amount_out`
    /// would be `[0, res.0]` and the amount input domain for `get_amount_in` would be `[0,
    /// res.1]`
    ///
    /// * `Err(SimulationError)` - If any unexpected error occurs
    fn get_limits(
        &self,
        sell_token: Bytes,
        buy_token: Bytes,
    ) -> Result<(BigUint, BigUint), SimulationError>;

    /// Decodes and applies a protocol state delta to the state
    ///
    /// Will error if the provided delta is missing any required attributes or if any of the
    /// attribute values cannot be decoded.
    ///
    /// # Arguments
    ///
    /// * `delta` - A `ProtocolStateDelta` from the tycho indexer
    ///
    /// # Returns
    ///
    /// * `Result<(), TransitionError<String>>` - A `Result` containing `()` on success or a
    ///   `TransitionError` on failure.
    fn delta_transition(
        &mut self,
        delta: ProtocolStateDelta,
        tokens: &HashMap<Bytes, Token>,
        balances: &Balances,
    ) -> Result<(), TransitionError<String>>;

    /// Calculates the exact amount of token_in required to move the pool's marginal price to a
    /// target price.
    ///
    /// This method computes how much token_in must be swapped to adjust the pool's state such that
    /// its marginal price (the rate at which the next infinitesimal trade would execute) equals
    /// exactly the specified `pool_price`. This is a calculation based on the pool's
    /// curve and current reserves, used to determine liquidity availability at specific price
    /// points.
    ///
    /// # Arguments
    ///
    /// * `token_in` - The address of the token being sold (swapped into the pool)
    /// * `token_out` - The address of the token being bought (swapped out of the pool)
    /// * `pool_price` - The target marginal price as a `Price` struct where:
    ///   - `numerator`: Amount of token_in
    ///   - `denominator`: Amount of token_out
    ///   - Represents the price as token_in per token_out (e.g., Price{numerator: 1000,
    ///     denominator: 1} means 1000 token_in buys 1 token_out)
    ///
    /// # Returns
    ///
    /// * `Ok(BigUint)` - The exact amount of token_in required to reach the target price
    /// * `Err(SimulationError)` - If:
    ///   - The target price is unreachable given the pool's reserves (e.g., would require draining
    ///     the pool beyond available liquidity)
    ///   - The target price represents a worse price than the current pool state (moving in the
    ///     wrong direction)
    ///   - The calculation encounters numerical issues (overflow, division by zero, etc.)
    ///   - The method is not implemented for this protocol
    ///
    /// # Notes
    ///
    /// - The returned amount is the gross input including fees. For a 0.3% fee pool, swapping this
    ///   amount will deduct the fee before applying to reserves.
    /// - This method does not mutate pool state; it only performs calculations
    /// - For most AMMs without discontinuities, this is equivalent to `query_demand` with the same
    ///   parameters
    /// - The price direction matters: swapping token_in→token_out typically increases the price of
    ///   token_in relative to token_out
    #[allow(unused)]
    fn swap_to_price(
        &self,
        token_in: &Bytes,
        token_out: &Bytes,
        pool_price: Price,
    ) -> Result<BigUint, SimulationError> {
        Err(SimulationError::FatalError("swap_to_price not implemented".into()))
    }

    /// Calculates how much token_in a pool can accept when trading at an effective price at or
    /// better than the target.
    ///
    /// This method determines the maximum amount of token_in that can be swapped into the pool
    /// while ensuring the effective (average) execution price remains at or better than the
    /// specified `target_price`. This is used by batch auction solvers to understand the "demand"
    /// a pool has for token_in at a given price level when constructing optimal execution paths.
    ///
    /// The method accounts for the pool's fee structure. The term "demand" reflects the market
    /// microstructure perspective: from the solver's viewpoint, the pool is expressing demand for
    /// token_in at this price point.
    ///
    /// # Arguments
    ///
    /// * `token_in` - The address of the token being sold (swapped into the pool)
    /// * `token_out` - The address of the token being bought (swapped out of the pool)
    /// * `target_price` - The maximum acceptable price as a `Price` struct where:
    ///   - `numerator`: Amount of token_in
    ///   - `denominator`: Amount of token_out
    ///   - Represents the price as token_in per token_out (e.g., Price{numerator: 2000,
    ///     denominator: 1} means willing to pay up to 2000 token_in for 1 token_out)
    ///
    /// # Returns
    ///
    /// * `Ok(BigUint)` - The maximum amount of token_in that can be traded at or better than the
    ///   target price. Swapping this amount will result in an average execution price ≤
    ///   target_price (better or equal from the buyer's perspective).
    /// * `Err(SimulationError)` - If:
    ///   - The current pool price is already worse than the target price (no liquidity available at
    ///     this price point)
    ///   - The pool has insufficient liquidity to provide meaningful quotes
    ///   - The calculation encounters numerical issues
    ///   - The method is not implemented for this protocol
    ///
    /// # Notes
    ///
    /// - The returned amount includes fees. The actual amount applied to pool reserves will be the
    ///   gross amount minus protocol fees.
    /// - This method does not mutate pool state; calculations are read-only
    /// - The interpretation of "better than target price" depends on trade direction: lower prices
    ///   favor the buyer of token_out
    /// - Batch auction solvers use this to aggregate liquidity across multiple pools at specific
    ///   price levels
    ///
    /// # Relationship to swap_to_price
    ///
    /// While these methods often return the same value for continuous AMMs, the semantic difference
    /// is important:
    /// - `swap_to_price`: "What input moves the marginal price to exactly X?"
    /// - `query_demand`: "What's the maximum input tradeable at price X or better?"
    ///
    /// For protocols with discrete price levels or custom mechanics, these may diverge.
    #[allow(unused)]
    fn query_demand(
        &self,
        token_in: &Bytes,
        token_out: &Bytes,
        target_price: Price,
    ) -> Result<BigUint, SimulationError> {
        Err(SimulationError::FatalError("query_demand not implemented".into()))
    }

    /// Clones the protocol state as a trait object.
    /// This allows the state to be cloned when it is being used as a `Box<dyn ProtocolSim>`.
    fn clone_box(&self) -> Box<dyn ProtocolSim>;

    /// Allows downcasting of the trait object to its underlying type.
    fn as_any(&self) -> &dyn Any;

    /// Allows downcasting of the trait object to its mutable underlying type.
    fn as_any_mut(&mut self) -> &mut dyn Any;

    /// Compares two protocol states for equality.
    /// This method must be implemented to define how two protocol states are considered equal
    /// (used for tests).
    fn eq(&self, other: &dyn ProtocolSim) -> bool;

    /// Cast as IndicativelyPriced. This is necessary for RFQ protocols
    fn as_indicatively_priced(&self) -> Result<&dyn IndicativelyPriced, SimulationError> {
        Err(SimulationError::FatalError("Pool State does not implement IndicativelyPriced".into()))
    }
}

impl Clone for Box<dyn ProtocolSim> {
    fn clone(&self) -> Box<dyn ProtocolSim> {
        self.clone_box()
    }
}
