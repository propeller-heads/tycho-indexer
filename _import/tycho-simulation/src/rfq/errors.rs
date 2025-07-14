use thiserror::Error;
use tycho_common::simulation::errors::SimulationError;

#[derive(Debug, Error)]
pub enum RFQError {
    #[error("RFQ connection error: {0}")]
    ConnectionError(String),
    #[error("RFQ parsing error: {0}")]
    ParsingError(String),
}
impl From<reqwest::Error> for RFQError {
    fn from(err: reqwest::Error) -> Self {
        RFQError::ConnectionError(err.to_string())
    }
}

impl From<RFQError> for SimulationError {
    fn from(err: RFQError) -> Self {
        SimulationError::FatalError(err.to_string())
    }
}
