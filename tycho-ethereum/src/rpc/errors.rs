use std::fmt::Display;

use alloy::transports::{RpcError as AlloyRpcError, TransportErrorKind};
use thiserror::Error;

#[derive(Error, Debug)]
pub struct ReqwestError {
    pub msg: String,
    #[source]
    pub source: AlloyRpcError<TransportErrorKind>,
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
    #[error("Unknown error: {0}")]
    UnknownError(String),
}

impl RPCError {
    pub(super) fn from_alloy<S: ToString>(
        msg: S,
        error: AlloyRpcError<TransportErrorKind>,
    ) -> Self {
        RPCError::RequestError(RequestError::Reqwest(ReqwestError {
            msg: msg.to_string(),
            source: error,
        }))
    }

    pub fn should_retry(&self) -> bool {
        matches!(self, Self::RequestError(_))
    }
}
