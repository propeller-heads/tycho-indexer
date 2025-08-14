//! Token swapping interface built on the action trait system.
//!
//! This module provides the `Swappable` trait for standardized token swap operations
//! across different DEX protocols and AMM implementations.

pub mod action;
pub mod approximation;

use std::fmt;

use num_bigint::BigUint;

use crate::{
    action::context::ActionContext, models::token::Token, simulation::errors::SimulationError,
};

/// Specifies whether a quote is for a given input amount or desired output amount.
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
#[derive(Clone, Copy)]
pub struct MarginalPriceParameters<'a> {
    /// The input token for the price calculation.
    input: &'a Token,
    /// The output token for the price calculation.
    output: &'a Token,
    /// The execution context for the price calculation.
    context: &'a ActionContext,
}

impl<'a> MarginalPriceParameters<'a> {
    /// Create inverted parameters by swapping input and output tokens.
    pub fn flip(&self) -> MarginalPriceParameters<'a> {
        Self { input: self.output, output: self.input, context: self.context }
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
    context: &'a ActionContext,
}

/// Result of a swap quote calculation.
///
/// Contains the calculated swap outcome including amounts, gas costs,
/// and the resulting state after swap execution.
pub struct SwapQuote {
    /// The calculated amount (output if AmountIn, input if AmountOut).
    pub amount: BigUint,
    /// Estimated gas cost for executing the swap.
    pub gas: BigUint,
    /// The new pool state after executing the swap.
    pub new_state: Box<dyn Swappable>,
}

impl SwapQuote {
    /// Create a new swap quote with the given parameters.
    pub fn new(amount: BigUint, gas: BigUint, new_state: Box<dyn Swappable>) -> Self {
        SwapQuote { amount, gas, new_state }
    }
}

/// Parameters for determining swap amount limits.
///
/// Used to calculate the practical bounds for swap operations based on
/// liquidity constraints and price impact considerations.
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
    context: &'a ActionContext,
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
    fn minimum_fee(&self, params: MarginalPriceParameters) -> Result<f64, SimulationError>;

    /// Get the marginal price for the specified token pair.
    ///
    /// Returns the instantaneous exchange rate at the current pool state,
    /// representing the price for an infinitesimally small trade.
    fn marginal_price(&self, params: MarginalPriceParameters) -> Result<f64, SimulationError>;

    /// Calculate a swap quote for the given parameters.
    ///
    /// Returns the expected outcome of the swap including the calculated amount,
    /// gas cost, and the resulting pool state after execution.
    fn quote(&self, quote_parameters: QuoteParameters) -> Result<SwapQuote, SimulationError>;

    /// Determine the practical limits for swap amounts.
    ///
    /// Returns the range of amounts that can be swapped while respecting
    /// liquidity constraints and price impact limits.
    fn get_limits(&self, params: LimitsParameters) -> Result<AmountLimits, SimulationError>;
}
