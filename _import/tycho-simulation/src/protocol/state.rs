//! Protocol Simulation
//!
//! This module contains the `ProtocolSim` trait, which defines the methods
//! that a protocol state must implement in order to be used in trade
//! simulations.
//!
//! The `ProtocolSim` trait has several key methods:
//!  - `fee`: Returns the protocol's fee as a ratio.
//!  - `spot_price`: Returns the current spot price between two tokens.
//!  - `get_amount_out`: Returns the amount of output tokens given an amount of input tokens.
//!  - `delta_transition`: Applies a state delta to the simulated protocol.
//!  - `clone_box`: Clones the simulated protocol state as a trait object.
//!  - `as_any`: Allows downcasting of the trait object.
//!  - `as_any_mut`: Allows mutable downcasting of the trait object.
//!  - `eq`: Compares two simulated protocol states for equality.
//!
//!
//! # Examples
//! ```
//! use std::str::FromStr;
//! use alloy_primitives::U256;
//! use num_bigint::ToBigUint;
//! use tycho_simulation::evm::protocol::uniswap_v2::state::UniswapV2State;
//! use tycho_simulation::protocol::state::{ProtocolSim};
//! use tycho_simulation::models::Token;
//! use tycho_simulation::u256_num::u256_to_biguint;
//!
//! // Initialize the UniswapV2 state with token reserves
//! let state: Box<dyn ProtocolSim> = Box::new(UniswapV2State::new(
//!     U256::from_str("36925554990922").unwrap(),
//!     U256::from_str("30314846538607556521556").unwrap(),
//! ));
//!
//! // Define two ERC20 tokens: USDC and WETH
//! let usdc = Token::new(
//!     "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", 6, "USDC", 10_000.to_biguint().unwrap()
//! );
//! let weth = Token::new(
//!     "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2", 18, "WETH", 10_000.to_biguint().unwrap()
//! );
//!
//! // Get the amount out for swapping WETH to USDC
//! let out = state.get_amount_out(u256_to_biguint(weth.one()), &weth, &usdc).unwrap().amount;
//! assert_eq!(state.spot_price(&weth, &usdc).unwrap(), 1218.0683462769755f64);
//! assert_eq!(out, 1214374202.to_biguint().unwrap());
//! ```
use std::any::Any;

use num_bigint::BigUint;

use tycho_core::dto::ProtocolStateDelta;

use crate::{
    models::Token,
    protocol::{
        errors::{SimulationError, TransitionError},
        models::GetAmountOutResult,
    },
};

/// ProtocolSim trait
/// This trait defines the methods that a protocol state must implement in order to be used
/// in the trade simulation.
pub trait ProtocolSim: std::fmt::Debug + Send + Sync + 'static {
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
        tokens: Vec<Token>,
    ) -> Result<(), TransitionError<String>>;

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
}

impl Clone for Box<dyn ProtocolSim> {
    fn clone(&self) -> Box<dyn ProtocolSim> {
        self.clone_box()
    }
}
