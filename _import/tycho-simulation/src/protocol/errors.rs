//! Protocol generic errors
use std::fmt;

use thiserror::Error;

use crate::protocol::vm::errors::FileError;

use super::models::GetAmountOutResult;

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
    SimulationError(SimulationError),
}

#[derive(Debug, Error)]
pub enum InvalidSnapshotError {
    #[error("Missing attributes {0}")]
    MissingAttribute(String),
    #[error("Value error {0}")]
    ValueError(String),
    #[error("Unable to set up vm state on the engine: {0}")]
    VMError(SimulationError),
}

impl From<SimulationError> for InvalidSnapshotError {
    fn from(error: SimulationError) -> Self {
        InvalidSnapshotError::VMError(error)
    }
}

/// Represents the outer-level, user-facing errors of the tycho-simulation package.
///
/// `SimulationError` encompasses all possible errors that can occur in the package,
/// wrapping lower-level errors in a user-friendly way for easier handling and display.
/// Variants:
/// - `RecoverableError`: Indicates that the simulation has failed with a recoverable error.
///   Retrying at a later time may succeed. It may have failed due to a temporary issue, such as a
///   network problem.
/// - `InvalidInput`: Indicates that the simulation has failed due to bad input parameters.
/// - `FatalError`: There is a bug with this pool or protocol - do not attempt simulation again.
#[derive(Error, Debug)]
pub enum SimulationError {
    #[error("Fatal error: {0}")]
    FatalError(String),
    #[error("Invalid input: {0}")]
    InvalidInput(String, Option<GetAmountOutResult>),
    #[error("Recoverable error: {0}")]
    RecoverableError(String),
}

impl<T> From<SimulationError> for TransitionError<T> {
    fn from(error: SimulationError) -> Self {
        TransitionError::SimulationError(error)
    }
}

impl From<FileError> for SimulationError {
    fn from(error: FileError) -> Self {
        SimulationError::FatalError(error.to_string())
    }
}
