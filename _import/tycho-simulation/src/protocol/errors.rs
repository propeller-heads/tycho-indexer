//! Protocol generic errors
use crate::protocol::vm::errors::VMError;
use thiserror::Error;

use super::models::GetAmountOutResult;

/// Enumeration of possible errors that can occur during a trade simulation.
#[derive(Debug, PartialEq)]
pub enum TradeSimulationErrorKind {
    /// Error indicating that there is insufficient data to perform the simulation.
    InsufficientData,
    /// Error indicating that there is no liquidity in the venue to complete the trade.
    NoLiquidity,
    /// Error indicating that an unknown error occurred during the simulation.
    Unknown,
    /// Error indicating that the amount provided for the trade is insufficient.
    InsufficientAmount,
    // Error indicating that an arithmetic operation got an U256 to overflow
    U256Overflow,
}

/// Struct representing a native simulation error.
#[derive(Debug)]
pub struct NativeSimulationError {
    /// The kind of error that occurred.
    pub kind: TradeSimulationErrorKind,
    /// The partial result of the simulation, if any.
    pub partial_result: Option<GetAmountOutResult>,
}

impl NativeSimulationError {
    /// Creates a new trade simulation error with the given kind and partial result.
    pub fn new(kind: TradeSimulationErrorKind, partial_result: Option<GetAmountOutResult>) -> Self {
        NativeSimulationError { kind, partial_result }
    }
}

use std::fmt;

impl fmt::Display for TradeSimulationErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            TradeSimulationErrorKind::InsufficientData => {
                write!(f, "Insufficient data to perform the simulation")
            }
            TradeSimulationErrorKind::NoLiquidity => {
                write!(f, "No liquidity in the venue to complete the trade")
            }
            TradeSimulationErrorKind::Unknown => {
                write!(f, "An unknown error occurred during the simulation")
            }
            TradeSimulationErrorKind::InsufficientAmount => {
                write!(f, "Insufficient amount provided for the trade")
            }
            TradeSimulationErrorKind::U256Overflow => {
                write!(f, "Arithmetic operation resulted in a U256 overflow")
            }
        }
    }
}

impl fmt::Display for NativeSimulationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Native simulation error: {}", self.kind)?;

        if let Some(partial_result) = &self.partial_result {
            write!(
                f,
                " | Partial result: amount = {}, gas = {}",
                partial_result.amount, partial_result.gas
            )?;
        }

        Ok(())
    }
}

impl fmt::Display for GetAmountOutResult {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "amount = {}, gas = {}", self.amount, self.gas)
    }
}

#[derive(Debug)]
pub enum TransitionError<T> {
    OutOfOrder { state: T, event: T },
    MissingAttribute(String),
    DecodeError(String),
    InvalidEventType(),
}

#[derive(Debug, PartialEq, Error)]
pub enum InvalidSnapshotError {
    #[error("Missing attributes {0}")]
    MissingAttribute(String),
    #[error("Value error {0}")]
    ValueError(String),
}

/// Represents the outer-level, user-facing errors of the tycho-simulation package.
///
/// `TychoSimulationError` encompasses all possible errors that can occur in the package,
/// wrapping lower-level errors in a user-friendly way for easier handling and display.
#[derive(Error, Debug)]
pub enum TychoSimulationError {
    #[error("VM simulation error: {0}")]
    VMError(VMError),
    #[error("Native simulation error: {0}")]
    NativeSimulationError(NativeSimulationError),
}

impl From<VMError> for TychoSimulationError {
    fn from(err: VMError) -> Self {
        TychoSimulationError::VMError(err)
    }
}

impl From<NativeSimulationError> for TychoSimulationError {
    fn from(err: NativeSimulationError) -> Self {
        TychoSimulationError::NativeSimulationError(err)
    }
}
