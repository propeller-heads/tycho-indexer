use thiserror::Error;

use crate::{
    action::swap::approximation::ApproximationError,
    simulation::protocol_sim::GetAmountOutResult,
};

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
    #[error("Approximation failed")]
    ApproximationError(#[from] ApproximationError),
}

#[derive(Debug)]
pub enum TransitionError<T> {
    OutOfOrder { state: T, event: T },
    MissingAttribute(String),
    DecodeError(String),
    InvalidEventType(),
    SimulationError(SimulationError),
}

impl<T> From<SimulationError> for TransitionError<T> {
    fn from(error: SimulationError) -> Self {
        TransitionError::SimulationError(error)
    }
}
