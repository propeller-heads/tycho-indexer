// TODO: remove skips for clippy

use std::io;

use ethers::prelude::ProviderError;
use serde_json::Error as SerdeError;
use thiserror::Error;

use crate::protocol::errors::SimulationError;

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

impl From<RpcError> for SimulationError {
    fn from(err: RpcError) -> Self {
        SimulationError::RpcError(err)
    }
}

impl From<FileError> for SimulationError {
    fn from(err: FileError) -> Self {
        SimulationError::AbiError(err)
    }
}

impl From<ethers::abi::Error> for SimulationError {
    fn from(err: ethers::abi::Error) -> Self {
        SimulationError::DecodingError(err.to_string())
    }
}
