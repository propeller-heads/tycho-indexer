//! Token swapping interface built on the action trait system.
//!
//! This module provides the `Swappable` trait for standardized token swap operations
//! across different DEX protocols and AMM implementations.

pub mod action;
pub mod approximation;

use std::{borrow::Cow, fmt};

use num_bigint::BigUint;

use crate::{
    action::context::ActionContext, models::token::Token, simulation::errors::SimulationError,
};

/// Specifies whether a quote is for a given input amount or desired output amount.
#[derive(Clone)]
pub enum QuoteDirection {
    /// Quote is for a specific input amount, calculate output amount.
    AmountIn,
    /// Quote is for a specific output amount, calculate required input amount.
    AmountOut,
}

/// Parameters for marginal price calculations.
///
/// Contains the token pair and execution context needed to determine
/// the instantaneous exchange rate at the current pool state.
#[derive(Clone)]
pub struct MarginalPriceParameters<'a> {
    /// The input token for the price calculation.
    input: &'a Token,
    /// The output token for the price calculation.
    output: &'a Token,
    /// The execution context for the price calculation.
    context: Cow<'a, ActionContext>,
}

impl<'a> MarginalPriceParameters<'a> {
    /// Create new marginal price parameters with default context.
    pub fn new(input: &'a Token, output: &'a Token) -> Self {
        Self { input, output, context: Cow::Owned(ActionContext::default()) }
    }

    /// Create new marginal price parameters with provided context.
    pub fn with_context(input: &'a Token, output: &'a Token, context: &'a ActionContext) -> Self {
        Self { input, output, context: Cow::Borrowed(context) }
    }

    /// Get the input token.
    pub fn input(&self) -> &Token {
        self.input
    }

    /// Get the output token.
    pub fn output(&self) -> &Token {
        self.output
    }

    /// Get the execution context.
    pub fn context(&self) -> &ActionContext {
        &*self.context
    }

    /// Create inverted parameters by swapping input and output tokens.
    pub fn flip(&self) -> MarginalPriceParameters<'a> {
        Self { input: self.output, output: self.input, context: self.context.clone() }
    }
}

/// Parameters for swap quote calculations.
///
/// Specifies all information needed to calculate the expected outcome
/// of a token swap operation.
pub struct QuoteParameters<'a> {
    /// The amount involved in the swap (interpretation depends on direction).
    amount: BigUint,
    /// Whether the amount represents input or desired output.
    direction: QuoteDirection,
    /// The token being provided as input to the swap.
    input: &'a Token,
    /// The token expected as output from the swap.
    output: &'a Token,
    /// The execution context for the swap.
    context: Cow<'a, ActionContext>,
}

impl<'a> QuoteParameters<'a> {
    /// Create new quote parameters with default context.
    pub fn new(
        amount: BigUint,
        direction: QuoteDirection,
        input: &'a Token,
        output: &'a Token,
    ) -> Self {
        Self { amount, direction, input, output, context: Cow::Owned(ActionContext::default()) }
    }

    /// Create new quote parameters with provided context.
    pub fn with_context(
        amount: BigUint,
        direction: QuoteDirection,
        input: &'a Token,
        output: &'a Token,
        context: &'a ActionContext,
    ) -> Self {
        Self { amount, direction, input, output, context: Cow::Borrowed(context) }
    }

    /// Get the amount involved in the swap.
    pub fn amount(&self) -> &BigUint {
        &self.amount
    }

    /// Get the quote direction.
    pub fn direction(&self) -> &QuoteDirection {
        &self.direction
    }

    /// Get the input token.
    pub fn input(&self) -> &Token {
        self.input
    }

    /// Get the output token.
    pub fn output(&self) -> &Token {
        self.output
    }

    /// Get the execution context.
    pub fn context(&self) -> &ActionContext {
        &*self.context
    }
}

/// Result of a swap quote calculation.
///
/// Contains the calculated swap outcome including amounts, gas costs,
/// and the resulting state after swap execution.
pub struct SwapQuote {
    /// The calculated amount (output if AmountIn, input if AmountOut).
    amount: BigUint,
    /// Estimated gas cost for executing the swap.
    gas: BigUint,
    /// The new pool state after executing the swap.
    new_state: Box<dyn Swappable>,
}

impl SwapQuote {
    /// Create a new swap quote with the given parameters.
    pub fn new(amount: BigUint, gas: BigUint, new_state: Box<dyn Swappable>) -> Self {
        SwapQuote { amount, gas, new_state }
    }

    /// Get the calculated amount.
    pub fn amount(&self) -> &BigUint {
        &self.amount
    }

    /// Get the estimated gas cost.
    pub fn gas(&self) -> &BigUint {
        &self.gas
    }

    /// Get the new pool state after the swap.
    pub fn new_state(&self) -> &Box<dyn Swappable> {
        &self.new_state
    }
}

/// Parameters for determining swap amount limits.
///
/// Used to calculate the practical bounds for swap operations based on
/// liquidity constraints and price impact considerations.
#[derive(Clone)]
pub struct LimitsParameters<'a> {
    /// The input token for the swap.
    input: &'a Token,
    /// The output token for the swap.
    output: &'a Token,
    /// The direction of the swap operation.
    direction: QuoteDirection,
    /// Maximum acceptable price impact as a decimal (e.g., 0.05 for 5%).
    /// If there are no hard limits, this serves as a soft limit for calculating
    /// recommended maximum amounts.
    max_price_impact: f64,
    /// The execution context for the operation.
    context: Cow<'a, ActionContext>,
}

impl<'a> LimitsParameters<'a> {
    /// Create new limits parameters with default context and default 5% maximum price impact.
    pub fn new(input: &'a Token, output: &'a Token, direction: QuoteDirection) -> Self {
        Self {
            input,
            output,
            direction,
            max_price_impact: 0.05, // 5% default
            context: Cow::Owned(ActionContext::default()),
        }
    }

    /// Create new limits parameters with provided context and default 5% maximum price impact.
    pub fn with_context(
        input: &'a Token,
        output: &'a Token,
        direction: QuoteDirection,
        context: &'a ActionContext,
    ) -> Self {
        Self {
            input,
            output,
            direction,
            max_price_impact: 0.05, // 5% default
            context: Cow::Borrowed(context),
        }
    }

    /// Get the input token.
    pub fn input(&self) -> &Token {
        self.input
    }

    /// Get the output token.
    pub fn output(&self) -> &Token {
        self.output
    }

    /// Get the quote direction.
    pub fn direction(&self) -> &QuoteDirection {
        &self.direction
    }

    /// Get the maximum price impact.
    pub fn max_price_impact(&self) -> f64 {
        self.max_price_impact
    }

    /// Get the execution context.
    pub fn context(&self) -> &ActionContext {
        &*self.context
    }

    /// Set the maximum acceptable price impact.
    ///
    /// Returns an error if the price impact is not between 0 and 1 (exclusive of 0, inclusive of
    /// 1).
    pub fn set_max_price_impact(mut self, max_price_impact: f64) -> Result<Self, SimulationError> {
        Self::validate_price_impact(max_price_impact)?;
        self.max_price_impact = max_price_impact;
        Ok(self)
    }

    /// Validate that price impact is > 0 and <= 1.
    fn validate_price_impact(max_price_impact: f64) -> Result<(), SimulationError> {
        if max_price_impact <= 0.0 {
            return Err(SimulationError::InvalidInput(
                format!("Max price impact must be greater than 0, got: {}", max_price_impact),
                None,
            ));
        }
        if max_price_impact > 1.0 {
            return Err(SimulationError::InvalidInput(
                format!(
                    "Max price impact must be less than or equal to 1.0 (100%), got: {}",
                    max_price_impact
                ),
                None,
            ));
        }
        Ok(())
    }
}

/// Defines the practical limits for swap amounts.
///
/// Represents the range of amounts that can be swapped while maintaining
/// reasonable execution characteristics and price impact.
pub struct AmountLimits {
    /// The maximum amount that can be swapped.
    upper_limit: BigUint,
    /// The minimum amount that can be swapped.
    lower_limit: BigUint,
}

impl AmountLimits {
    /// Create new amount limits.
    pub fn new(upper_limit: BigUint, lower_limit: BigUint) -> Self {
        Self { upper_limit, lower_limit }
    }

    /// Get the upper limit.
    pub fn upper_limit(&self) -> &BigUint {
        &self.upper_limit
    }

    /// Get the lower limit.
    pub fn lower_limit(&self) -> &BigUint {
        &self.lower_limit
    }
}

/// Interface for token swapping operations across different DEX protocols.
///
/// Provides standardized methods for price discovery, quote calculation, and limit
/// determination. Implementations handle protocol-specific logic while presenting
/// a uniform interface for swap operations.
pub trait Swappable: fmt::Debug + Send + Sync + 'static {
    /// Calculate the minimum trading fee for the given token pair.
    ///
    /// Returns the spread between bid and ask prices, representing the
    /// minimum cost of a round-trip trade.
    fn minimum_fee(&self, params: &MarginalPriceParameters) -> Result<f64, SimulationError>;

    /// Get the marginal price for the specified token pair.
    ///
    /// Returns the instantaneous exchange rate at the current pool state,
    /// representing the price for an infinitesimally small trade.
    fn marginal_price(&self, params: &MarginalPriceParameters) -> Result<f64, SimulationError>;

    /// Calculate a swap quote for the given parameters.
    ///
    /// Returns the expected outcome of the swap including the calculated amount,
    /// gas cost, and the resulting pool state after execution.
    fn quote(&self, quote_parameters: &QuoteParameters) -> Result<SwapQuote, SimulationError>;

    /// Determine the practical limits for swap amounts.
    ///
    /// Returns the range of amounts that can be swapped while respecting
    /// liquidity constraints and price impact limits.
    fn get_limits(&self, params: &LimitsParameters) -> Result<AmountLimits, SimulationError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{token::Token, Chain};

    fn create_test_token() -> Token {
        Token::new(
            &"0x1234567890123456789012345678901234567890".into(),
            "TEST",
            18,
            0,
            &[Some(21000u64)],
            Chain::Ethereum,
            100,
        )
    }

    #[test]
    fn test_limits_parameters_valid_price_impact() {
        let token = create_test_token();

        // Test valid price impacts
        let valid_values = [0.01, 0.05, 0.1, 0.5, 1.0];
        for &impact in &valid_values {
            let result = LimitsParameters::new(&token, &token, QuoteDirection::AmountIn)
                .set_max_price_impact(impact);
            assert!(result.is_ok(), "Price impact {} should be valid", impact);
            assert_eq!(result.unwrap().max_price_impact(), impact);
        }
    }

    #[test]
    fn test_limits_parameters_invalid_price_impact() {
        let token = create_test_token();

        // Test invalid price impacts
        let invalid_values = [0.0, -0.1, 1.1, 2.0, f64::INFINITY, f64::NEG_INFINITY];
        for &impact in &invalid_values {
            let result = LimitsParameters::new(&token, &token, QuoteDirection::AmountIn)
                .set_max_price_impact(impact);
            assert!(result.is_err(), "Price impact {} should be invalid", impact);
        }
    }

    #[test]
    fn test_limits_parameters_set_max_price_impact() {
        let token = create_test_token();
        let params = LimitsParameters::new(&token, &token, QuoteDirection::AmountIn);

        // Test valid update
        let updated = params.clone().set_max_price_impact(0.1);
        assert!(updated.is_ok());
        assert_eq!(updated.unwrap().max_price_impact(), 0.1);
    }
}
