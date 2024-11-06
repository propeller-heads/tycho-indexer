//! Protocol generic errors
use crate::protocol::vm::errors::{FileError, RpcError};
use thiserror::Error;

use super::models::GetAmountOutResult;

use crate::evm::simulation::SimulationEngineError;
use std::fmt;

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
/// - `AbiError`: Represents an error when loading the ABI file, encapsulating a `FileError`.
/// - `EncodingError`: Denotes an error in encoding data.
/// - `SimulationFailure`: Wraps errors that occur during simulation, containing a
///   `SimulationEngineError`.
/// - `DecodingError`: Indicates an error in decoding data.
/// - `RPCError`: Indicates an error related to RPC interaction.
/// - `NotFound`: Indicates that something was not found (could be a capability, spot price, etc.)
/// - `NotInitialized`: Indicates that something was not initialized before trying to use it (could
///   be engine or adapter contract)
/// - `InsufficientData`: Error indicating that there is insufficient data to perform the
///   simulation. It returns a partial result of the simulation.
/// - `NoLiquidity`: Error indicating that there is no liquidity in the venue to complete the trade.
/// - `InsufficientAmount`: Error indicating that the amount provided for the trade is too low.
/// - `ArithmeticOverflow`: Error indicating that an arithmetic operation got an U256 to overflow
/// - `Unknown`: Error indicating that an unknown error occurred during the simulation.
#[derive(Error, Debug)]
pub enum SimulationError {
    #[error("ABI loading error: {0}")]
    AbiError(#[from] FileError),
    #[error("Encoding error: {0}")]
    EncodingError(String),
    #[error("Simulation failure error: {0}")]
    SimulationEngineError(SimulationEngineError),
    #[error("Decoding error: {0}")]
    DecodingError(String),
    #[error("RPC related error: {0}")]
    RpcError(#[from] RpcError),
    #[error("Not found: {0}")]
    NotFound(String),
    #[error("Not initialized: {0}")]
    NotInitialized(String),
    #[error("Insufficient data")]
    InsufficientData(GetAmountOutResult),
    #[error("No liquidity")]
    NoLiquidity(),
    #[error("Insufficient amount")]
    InsufficientAmount(),
    #[error("U256 overflow")]
    ArithmeticOverflow(),
    #[error("Unknown error")]
    Unknown(),
}
