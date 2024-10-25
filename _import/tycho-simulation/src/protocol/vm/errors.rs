// TODO: remove skips for clippy

use thiserror::Error;

#[derive(Error, Debug)]
#[allow(unused)]
pub enum ProtosimError {
    #[error("Runtime Error: {0}")]
    RuntimeError(String),

    #[error("Revert Error: {0}")]
    RevertError(String),

    #[error("Decoding error: {0}")]
    DecodingError(String),

    #[error("ABI loading error: {0}")]
    AbiError(String),

    #[error("Encoding error: {0}")]
    EncodingError(String),

    #[error("Simulation failure error: {0}")]
    SimulationFailure(String),
}

impl From<std::io::Error> for ProtosimError {
    fn from(err: std::io::Error) -> ProtosimError {
        ProtosimError::AbiError(err.to_string())
    }
}
