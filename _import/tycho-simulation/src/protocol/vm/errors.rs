// TODO: remove skips for clippy

use crate::evm::simulation::SimulationError;
use serde_json::Error as SerdeError;
use std::io;
use thiserror::Error;

/// Represents the outer-level, user-facing errors of the Protosim package.
///
/// `ProtosimError` encompasses all possible errors that can occur in the package,
/// wrapping lower-level errors in a user-friendly way for easier handling and display.
///
/// Variants:
/// - `AbiError`: Represents an error when loading the ABI file, encapsulating a `FileError`.
/// - `EncodingError`: Denotes an error in encoding data.
/// - `SimulationFailure`: Wraps errors that occur during simulation, containing a
///   `SimulationError`.
/// - `DecodingError`: Indicates an error in decoding data.
#[derive(Error, Debug)]
pub enum ProtosimError {
    #[error("ABI loading error: {0}")]
    AbiError(FileError),
    #[error("Encoding error: {0}")]
    EncodingError(String),
    #[error("Simulation failure error: {0}")]
    SimulationFailure(SimulationError),
    #[error("Decoding error: {0}")]
    DecodingError(String),
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

impl From<FileError> for ProtosimError {
    fn from(err: FileError) -> Self {
        ProtosimError::AbiError(err)
    }
}
impl From<SimulationError> for ProtosimError {
    fn from(err: SimulationError) -> Self {
        ProtosimError::SimulationFailure(err)
    }
}
