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

/// Represents a price as a fraction in the token_in -> token_out direction. With units
/// [token_out/token_in].
///
/// # Fields
///
/// * `numerator` - The amount of token_out (what you receive), including token decimals
/// * `denominator` - The amount of token_in (what you pay), including token decimals
///
/// In the context of `swap_to_price` and `query_supply`, this represents the pool's price in
/// the **token_out/token_in** direction
///
/// A fraction struct is used for price to have flexibility in precision independent of the
/// decimal precisions of the numerator and denominator tokens. This allows for:
/// - Exact price representation without floating-point errors
/// - Handling tokens with different decimal places without loss of precision
///
/// # Example
/// If we want to represent that token A is worth 2.5 units of token B:
///
/// ```
/// use num_bigint::BigUint;
/// use tycho_common::simulation::protocol_sim::Price;
///
/// let numerator = BigUint::from(25u32); // Represents 25 units of token B
/// let denominator = BigUint::from(10u32); // Represents 10 units of token A
/// let price = Price::new(numerator, denominator);
/// ```
///
/// If you want to define a limit price for a trade, where you expect to get at least 120 T1 for
/// 50 T2:
/// ```
/// use num_bigint::BigUint;
/// use tycho_common::simulation::protocol_sim::Price;
///
/// let min_amount_out = BigUint::from(120u32); // The minimum amount of T1 you expect
/// let amount_in = BigUint::from(50u32); // The amount of T2 you are selling
/// let limit_price = Price::new(min_amount_out, amount_in);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Price {
    pub numerator: BigUint,
    pub denominator: BigUint,
}

impl Price {
    pub fn new(numerator: BigUint, denominator: BigUint) -> Self {
        if denominator == BigUint::ZERO {
            // Division by zero is not possible
            panic!("Price denominator cannot be zero");
        } else if numerator == BigUint::ZERO {
            // Zero pool price is not valid in our context
            panic!("Price numerator cannot be zero");
        }
        Self { numerator, denominator }
    }
}

/// Represents a trade between two tokens at a given price on a pool.
///
/// # Fields
///
/// * `amount_in` - The amount of token_in (what you pay)
/// * `amount_out` - The amount of token_out (what you receive)
///
/// The price of the trade is the ratio of amount_out to amount_in, i.e. amount_out / amount_in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Trade {
    pub amount_in: BigUint,
    pub amount_out: BigUint,
}

impl Trade {
    pub fn new(amount_in: BigUint, amount_out: BigUint) -> Self {
        Self { amount_in, amount_out }
    }
}

/// Represents the parameters for swap_to_price.
///
/// # Fields
///
/// * `token_in` - The token being sold (swapped into the pool)
/// * `token_out` - The token being bought (swapped out of the pool)
/// * `target_price` - The marginal price we want the pool to be after the trade, as a [Price]
///    struct. The pool's price will move down to this level as token_in is sold into it
/// * `tolerance` - The tolerance percentage for the resulting trade price. After trading, the pool's
///    price will decrease to the interval `[target_price, target_price * (1 + tolerance)]`.
#[derive(Debug, Clone, PartialEq)]
pub struct SwapToPriceParams {
    token_in: Token,
    token_out: Token,
    target_price: Price,
    tolerance: f64,
}

impl SwapToPriceParams {
    pub fn new(
        token_in: Token,
        token_out: Token,
        target_price: Price,
        tolerance: f64,
    ) -> Self {
        Self { token_in, token_out, target_price, tolerance }
    }

    /// Returns a reference to the input token (token being sold into the pool)
    pub fn token_in(&self) -> &Token {
        &self.token_in
    }

    /// Returns a reference to the output token (token being bought out of the pool)
    pub fn token_out(&self) -> &Token {
        &self.token_out
    }

    /// Returns a reference to the target price
    pub fn target_price(&self) -> &Price {
        &self.target_price
    }

    /// Returns the tolerance
    pub fn tolerance(&self) -> f64 {
        self.tolerance
    }
}

/// Represents the parameters for query_supply.
///
/// # Fields
///
/// * `token_in` - The token being sold (swapped into the pool)
/// * `token_out` - The token being bought (swapped out of the pool)
/// * `trade_limit_price` - The minimum acceptable price for the resulting trade, as a [Price] struct.
///   The resulting amount_out / amount_in must be >= trade_limit_price
/// * `tolerance` - The tolerance as a percentage to be applied on top of (increasing) the trade
///   limit price. This is used to loosen the acceptance criteria for implementations of this method,
///   but will never allow violating the trade limit price itself.
#[derive(Debug, Clone, PartialEq)]
pub struct QuerySupplyParams {
    token_in: Token,
    token_out: Token,
    trade_limit_price: Price,
    tolerance: f64,
}

impl QuerySupplyParams {
    pub fn new(
        token_in: Token,
        token_out: Token,
        trade_limit_price: Price,
        tolerance: f64,
    ) -> Self {
        Self { token_in, token_out, trade_limit_price, tolerance }
    }

    /// Returns a reference to the input token (token being sold into the pool)
    pub fn token_in(&self) -> &Token {
        &self.token_in
    }

    /// Returns a reference to the output token (token being bought out of the pool)
    pub fn token_out(&self) -> &Token {
        &self.token_out
    }

    /// Returns a reference to the trade price limit
    pub fn trade_limit_price(&self) -> &Price {
        &self.trade_limit_price
    }

    /// Returns the tolerance
    pub fn tolerance(&self) -> f64 {
        self.tolerance
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

    /// Calculates the amount of token_in required to move the pool's marginal price down to
    /// a target price, and the amount of token_out received.
    ///
    /// # Arguments
    ///
    /// * `params` - A `SwapToPriceParams` struct containing:
    ///   - `token_in`: The token being sold (swapped into the pool)
    ///   - `token_out`: The token being bought (swapped out of the pool)
    ///   - `target_price`: The target marginal price
    ///   - `tolerance`: Optional tolerance percentage for marginal price of the resulting trade
    ///     price
    ///
    /// # Returns
    ///
    /// * `Ok(Trade)` - A `Trade` struct containing the amount that needs to be swapped on the pool
    ///   to move its price to the target price.
    /// * `Err(SimulationError)` - If:
    ///   - The calculation encounters numerical issues (overflow, division by zero, etc.)
    ///   - The method is not implemented for this protocol
    ///   - The tolerance condition is not met (i.e., the resulting marginal price does not satisfy
    ///     `(1
    ///     - tolerance) * target_price <= result marginal price <= target_price`)
    ///
    /// # Edge Cases and Limitations
    ///
    /// ## Exact Price Achievement
    ///
    /// It is almost never possible to achieve the target price exactly, only within some
    /// margin of tolerance. This is due to:
    /// - **Discrete liquidity**: For concentrated liquidity protocols (e.g., Uniswap V3), liquidity
    ///   is distributed across discrete price ticks, making exact price targeting impossible. The
    ///   closest achievable trade with target price as lower limit will be returned.
    /// - **Numerical precision**: Integer arithmetic and rounding may prevent exact price matching.
    ///   In case of overflow an error will be returned.
    /// - **Protocol constraints**: Some protocols have minimum trade sizes or other constraints
    ///
    /// ## Tolerance Validation
    ///
    /// The resulting marginal price must satisfy: `(1 - tolerance) * target_price <= result
    /// marginal price <= target_price`. If this condition is not met, implementations return an
    /// error. This ensures that `target_price` remains a hard upper limit that is never
    /// exceeded.
    ///
    /// ## Unreachable Prices
    ///
    /// If the target price is already below the current marginal price (i.e., the price would
    /// need to move in the wrong direction), implementations return an error.
    #[allow(unused)]
    fn swap_to_price(&self, params: &SwapToPriceParams) -> Result<Trade, SimulationError> {
        Err(SimulationError::FatalError("swap_to_price not implemented".into()))
    }

    /// Calculates the maximum amount of token_out (sell token) a pool can supply, and the
    /// corresponding demanded amount of token_in (buy token), while respecting a minimum trade
    /// price.
    ///
    /// # Arguments
    ///
    /// * `params` - A `QuerySupplyParams` struct containing:
    ///   - `token_in`: The token being bought by the pool (the buy token)
    ///   - `token_out`: The token being sold by the pool (the sell token)
    ///   - `trade_price_limit`: The minimum acceptable price for the trade
    ///   - `tolerance`: Optional tolerance percentage for early stopping in iterative algorithms
    ///
    /// # Returns
    ///
    /// * `Ok(Trade)` - A `Trade` struct containing the largest trade that can be executed on this
    ///   pool while respecting the provided trade price limit
    /// * `Err(SimulationError)` - If:
    ///   - The calculation encounters numerical issues
    ///   - The method is not implemented for this protocol
    ///
    /// # Tolerance Usage
    ///
    /// The tolerance parameter can be used for early stopping of iterative algorithms when the
    /// result is within the tolerance of the target trade price.
    #[allow(unused)]
    fn query_supply(&self, params: &QuerySupplyParams) -> Result<Trade, SimulationError> {
        Err(SimulationError::FatalError("query_supply not implemented".into()))
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
