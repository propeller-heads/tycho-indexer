//! Protocol generic errors
use crate::{
    evm::simulation::SimulationError,
    protocol::{
        errors::TychoSimulationError::VMError,
        vm::errors::{FileError, RpcError, VMError},
    },
};
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
