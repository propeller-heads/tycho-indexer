use std::error::Error;
use std::fmt::{Display, Formatter, Result as FmtResult};

#[derive(Debug)]
pub struct StorageDecodingError {
    message: String,
}

impl StorageDecodingError {
    pub fn new(message: String) -> Self {
        StorageDecodingError { message }
    }
}

impl Error for StorageDecodingError {}

impl Display for StorageDecodingError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "Storage decoding error occurred: {}", self.message)
    }
}
