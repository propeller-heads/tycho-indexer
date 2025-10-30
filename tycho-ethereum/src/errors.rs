use std::{error::Error, fmt::Display};

use alloy::transports::http::reqwest;
use thiserror::Error;

#[derive(Error, Debug)]
pub struct SerdeJsonError {
    pub msg: String,
    #[source]
    pub source: serde_json::Error,
}

impl Display for SerdeJsonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.msg, self.source)
    }
}

#[derive(Error, Debug)]
pub struct ReqwestError {
    pub msg: String,
    #[source]
    pub source: reqwest::Error,
}

impl Display for ReqwestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.msg, self.source)
    }
}

#[derive(Error, Debug)]
pub enum RequestError {
    Reqwest(ReqwestError),
    Other(String),
}

impl Display for RequestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RequestError::Reqwest(e) => write!(f, "{}: {}", e.msg, e.source),
            RequestError::Other(e) => write!(f, "{e}"),
        }
    }
}

#[derive(Error, Debug)]
pub enum RPCError {
    #[error("RPC setup error: {0}")]
    SetupError(String),
    #[error("Request error: {0}")]
    RequestError(RequestError),
    #[error("Tracing failure: {0}")]
    TracingFailure(String),
    #[error("Serialize error: {0}")]
    SerializeError(SerdeJsonError),
    #[error("Unknown error: {0}")]
    UnknownError(String),
}

impl RPCError {
    pub fn should_retry(&self) -> bool {
        matches!(self, Self::RequestError(_))
    }
}

/// Helper function to extract the full error chain including source errors
pub(crate) fn extract_error_chain(error: &dyn Error) -> String {
    let mut chain = vec![error.to_string()];
    let mut source = error.source();

    while let Some(err) = source {
        chain.push(err.to_string());
        source = err.source();
    }

    if chain.len() == 1 {
        chain[0].clone()
    } else {
        format!("{} (caused by: {})", chain[0], chain[1..].join(" -> "))
    }
}
