use thiserror::Error;

// TODO: is this necessary?
#[derive(Debug, Error)]
pub enum ModelError {
    #[error("Conversion error: {0}")]
    ConversionError(String),
    #[error("Missing required data: {0}")]
    MissingData(String),
}
