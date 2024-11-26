use std::io;

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

impl From<FileError> for String {
    fn from(error: FileError) -> Self {
        match error {
            FileError::MalformedABI(msg) => format!("Malformed ABI error: {}", msg),
            FileError::Structure(msg) => format!("Structure error: {}", msg),
            FileError::FilePath(msg) => format!("File path conversion error: {}", msg),
            FileError::Io(err) => format!("I/O error: {}", err),
            FileError::Parse(err) => format!("Json parsing error: {}", err),
        }
    }
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

impl From<ethers::abi::Error> for SimulationError {
    fn from(err: ethers::abi::Error) -> Self {
        SimulationError::FatalError(err.to_string())
    }
}
