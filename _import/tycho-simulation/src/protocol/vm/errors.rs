// TODO: remove skips for clippy

use std::io;

use ethers::prelude::ProviderError;
use serde_json::Error as SerdeError;
use thiserror::Error;

use crate::evm::simulation::SimulationError;

/// VM specific errors.
/// Variants:
/// - `AbiError`: Represents an error when loading the ABI file, encapsulating a `FileError`.
/// - `EncodingError`: Denotes an error in encoding data.
/// - `SimulationFailure`: Wraps errors that occur during simulation, containing a
///   `SimulationError`.
/// - `DecodingError`: Indicates an error in decoding data.
/// - `RPCError`: Indicates an error related to RPC interaction.
/// - `UnsupportedCapability`: Denotes an error when a pool state does not support a necessary
///   capability.
/// - `UninitializedAdapter`: Indicates an error when trying to use the Adapter before initializing
///   it.
/// - `CapabilityRetrievalFailure`: Indicates an error when trying to retrieve capabilities.
/// - `EngineNotSet`: Indicates an error when trying to use the engine before setting it.
//   the adapter.
#[derive(Error, Debug)]
pub enum VMError {
    #[error("ABI loading error: {0}")]
    AbiError(FileError),
    #[error("Encoding error: {0}")]
    EncodingError(String),
    #[error("Simulation failure error: {0}")]
    SimulationFailure(SimulationError),
    #[error("Decoding error: {0}")]
    DecodingError(String),
    #[error("RPC related error {0}")]
    RpcError(RpcError),
    #[error("Unsupported Capability: {0}")]
    UnsupportedCapability(String),
    #[error("Adapter not initialized: {0}")]
    UninitializedAdapter(String),
    #[error("Engine not set")]
    EngineNotSet(),
}

#[derive(Debug, Error)]
pub enum FileError {
    /// Occurs when the ABI file cannot be read
    #[error("Malformed ABI error: {0}")]
    MalformedABI(String),
    /// Occurs when the parent directory of the current file cannot be retrieved
    #[error("Structure error {0}")]
    Structure(String),
    /// Occurs when a bad file path was given, which cannot be converted to string.
    #[error("File path conversion error {0}")]
    FilePath(String),
    #[error("I/O error {0}")]
    Io(io::Error),
    #[error("Json parsing error {0}")]
    Parse(SerdeError),
}

impl From<io::Error> for FileError {
    fn from(err: io::Error) -> Self {
        FileError::Io(err)
    }
}

impl From<SerdeError> for FileError {
    fn from(err: SerdeError) -> Self {
        FileError::Parse(err)
    }
}

#[derive(Debug, Error)]
pub enum RpcError {
    #[error("Invalid Request: {0}")]
    InvalidRequest(String),
    #[error("Invalid Response: {0}")]
    InvalidResponse(ProviderError),
    #[error("Empty Response")]
    EmptyResponse(),
}

impl From<RpcError> for VMError {
    fn from(err: RpcError) -> Self {
        VMError::RpcError(err)
    }
}

impl From<FileError> for VMError {
    fn from(err: FileError) -> Self {
        VMError::AbiError(err)
    }
}

impl From<ethers::abi::Error> for VMError {
    fn from(err: ethers::abi::Error) -> Self {
        VMError::DecodingError(err.to_string())
    }
}
