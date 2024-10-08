//! Protocol State and Simulation
//!
//! This module contains the `ProtocolSim` trait, which defines the methods
//! that a protocol state must implement in order to be used in the trade
//! simulation. It also contains the `ProtocolState` enum, which represents
//! the different protocol states that can be used in the trade simulation.
//! The `ProtocolSim` trait has three methods: `fee`, `spot_price`, and
//! `get_amount_out`.
//!
//!  * `fee` - returns the fee of the protocol as ratio.
//!  * `spot_price` - returns the protocols current spot price of two tokens.
//!  * `get_amount_out` - returns the amount out given an amount in and input/output tokens.
//!
//! The `ProtocolState` enum has currently two variants:
//! `UniswapV2` and `UniswapV3`.
//!
//!
//! # Examples
//! ```
//! use ethers::types::U256;
//! use protosim::protocol::state::{ProtocolSim, ProtocolSim};
//! use protosim::protocol::uniswap_v2::state::{UniswapV2State};
//! use protosim::models::ERC20Token;
//!
//! let state: ProtocolSim = UniswapV2State::new(
//!     U256::from_dec_str("36925554990922").unwrap(),
//!     U256::from_dec_str("30314846538607556521556").unwrap(),
//! ).into();
//! let usdc = ERC20Token::new("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", 6, "USDC", U256::from(10_000));
//! let weth = ERC20Token::new("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2 ", 18, "WETH", U256::from(10_000));
//!
//! let out = state.get_amount_out(weth.one(), &weth, &usdc).unwrap().amount;
//! assert_eq!(state.spot_price(&weth, &usdc), 1218.0683462769755f64);
//! assert_eq!(out, U256::from(1214374202));
//! ```
use std::any::Any;

use ethers::types::U256;
use tycho_core::dto::ProtocolStateDelta;

use crate::{
    models::ERC20Token,
    protocol::{
        errors::{TradeSimulationError, TransitionError},
        events::{EVMLogMeta, LogIndex},
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

    /// Returns the protocols current spot price of two tokens
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
    fn spot_price(&self, base: &ERC20Token, quote: &ERC20Token) -> f64;

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
    ///  `TradeSimulationError` on failure.
    fn get_amount_out(
        &self,
        amount_in: U256,
        token_in: &ERC20Token,
        token_out: &ERC20Token,
    ) -> Result<GetAmountOutResult, TradeSimulationError>;

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
    ) -> Result<(), TransitionError<String>>;

    fn event_transition(
        &mut self,
        protocol_event: Box<dyn ProtocolEvent>,
        log: &EVMLogMeta,
    ) -> Result<(), TransitionError<LogIndex>>;

    fn clone_box(&self) -> Box<dyn ProtocolSim>;
    fn as_any(&self) -> &dyn Any;

    fn eq(&self, other: &dyn ProtocolSim) -> bool;
}

impl Clone for Box<dyn ProtocolSim> {
    fn clone(&self) -> Box<dyn ProtocolSim> {
        self.clone_box()
    }
}

pub trait ProtocolEvent: std::fmt::Debug {
    fn as_any(&self) -> &dyn Any;
    fn clone_box(&self) -> Box<dyn ProtocolEvent>;
}

impl Clone for Box<dyn ProtocolEvent> {
    fn clone(&self) -> Box<dyn ProtocolEvent> {
        self.clone_box()
    }
}
