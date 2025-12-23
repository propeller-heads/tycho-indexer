use std::fmt::Display;

use alloy::transports::{RpcError as AlloyRpcError, TransportErrorKind};
use thiserror::Error;

/// Alloy RPC error type alias for convenience.
pub(crate) type AlloyError = AlloyRpcError<TransportErrorKind>;

#[derive(Error, Debug)]
pub struct ReqwestError {
    pub msg: String,
    #[source]
    pub source: AlloyError,
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
    pub(super) fn from_alloy<S: ToString>(msg: S, error: AlloyError) -> Self {
        RPCError::RequestError(RequestError::Reqwest(ReqwestError {
            msg: msg.to_string(),
            source: error,
        }))
    }
}

/// Extension trait for adding RPC context to Results containing Alloy errors.
///
/// Similar to `anyhow::Context`, this trait provides ergonomic error wrapping
/// that converts Alloy RPC errors into `RPCError` with contextual messages.
///
/// # Example
/// ```ignore
/// use crate::rpc::errors::RpcResultExt;
///
/// // Instead of:
/// result.map_err(|e| RPCError::from_alloy(format!("Failed to get block {block}"), e))?;
///
/// // You can write:
/// result.rpc_context(format!("Failed to get block {block}"))?;
///
/// // Or with lazy evaluation (avoids format! on success path):
/// result.with_rpc_context(|| format!("Failed to get block {block}"))?;
/// ```
pub(crate) trait RpcResultExt<T> {
    /// Wraps the error with context, converting it to an `RPCError`.
    fn rpc_context<C: Display>(self, context: C) -> Result<T, RPCError>;

    /// Wraps the error with lazily-evaluated context.
    /// Use this when the context message is expensive to compute.
    fn with_rpc_context<C: Display, F: FnOnce() -> C>(self, f: F) -> Result<T, RPCError>;
}

impl<T> RpcResultExt<T> for Result<T, AlloyError> {
    fn rpc_context<C: Display>(self, context: C) -> Result<T, RPCError> {
        self.map_err(|e| RPCError::from_alloy(context.to_string(), e))
    }

    fn with_rpc_context<C: Display, F: FnOnce() -> C>(self, f: F) -> Result<T, RPCError> {
        self.map_err(|e| RPCError::from_alloy(f().to_string(), e))
    }
}
