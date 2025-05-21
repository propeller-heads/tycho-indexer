use std::{io, str::Utf8Error};

use thiserror::Error;

/// Represents the outer-level, user-facing errors of the tycho-execution encoding package.
///
/// `EncodingError` encompasses all possible errors that can occur in the package,
/// wrapping lower-level errors in a user-friendly way for easier handling and display.
/// Variants:
/// - `InvalidInput`: Indicates that the encoding has failed due to bad input parameters.
/// - `FatalError`: There is problem with the application setup.
/// - `RecoverableError`: Indicates that the encoding has failed with a recoverable error. Retrying
///   at a later time may succeed. It may have failed due to a temporary issue, such as a network
///   problem.
#[derive(Error, Debug, PartialEq)]
pub enum EncodingError {
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    #[error("Fatal error: {0}")]
    FatalError(String),
    #[error("Recoverable error: {0}")]
    RecoverableError(String),
}

impl From<io::Error> for EncodingError {
    fn from(err: io::Error) -> Self {
        EncodingError::FatalError(err.to_string())
    }
}

impl From<serde_json::Error> for EncodingError {
    fn from(err: serde_json::Error) -> Self {
        EncodingError::FatalError(err.to_string())
    }
}

impl From<Utf8Error> for EncodingError {
    fn from(err: Utf8Error) -> Self {
        EncodingError::FatalError(err.to_string())
    }
}
