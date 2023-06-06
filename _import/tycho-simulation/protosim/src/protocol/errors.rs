//! Protocol generic errors
use std::fmt;

use ethers::types::H160;

use super::models::GetAmountOutResult;

/// Enumeration of possible errors that can occur during a trade simulation.
#[derive(Debug, PartialEq)]
pub enum TradeSimulationErrorKind {
    /// Error indicating that there is insufficient data to perform the simulation.
    InsufficientData,
    /// Error indicating that there is no liquidity in the venue to complete the trade.
    NoLiquidity,
    /// Error indicating that an unknown error occurred during the simulation.
    Unkown,
    /// Error indicating that the amount provided for the trade is insufficient.
    InsufficientAmount,
    // Error indicating that an arithmetic operation got an U256 to overflow
    U256Overflow,
}

/// Struct representing a trade simulation error.
#[derive(Debug)]
pub struct TradeSimulationError {
    /// The kind of error that occurred.
    pub kind: TradeSimulationErrorKind,
    /// The partial result of the simulation, if any.
    pub partial_result: Option<GetAmountOutResult>,
}

impl TradeSimulationError {
    /// Creates a new trade simulation error with the given kind and partial result.
    pub fn new(kind: TradeSimulationErrorKind, partial_result: Option<GetAmountOutResult>) -> Self {
        TradeSimulationError {
            kind,
            partial_result,
        }
    }
}

#[derive(Debug)]
pub enum TransitionError<T> {
    OutOfOrder { state: T, event: T },
}

#[derive(Debug)]
pub struct UnknownTokenError {
    /// The unknown token's address
    pub address: H160,
}

impl UnknownTokenError {
    /// Creates a new unknown token error with the given token address.
    pub fn new(address: H160) -> Self {
        UnknownTokenError { address }
    }
}

impl fmt::Display for UnknownTokenError {
    /// Formats the string representation of the unknown token error
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Unknown token: {:?}", self.address)
    }
}
