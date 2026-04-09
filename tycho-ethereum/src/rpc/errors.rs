use std::fmt::Display;

use alloy::transports::{RpcError as AlloyRpcError, TransportErrorKind};
use thiserror::Error;

/// Redacts the path component of any URLs in `s`.
///
/// Prevents API keys embedded in URL paths (e.g. `/6da0db2d2bfcd644f87e6f75db0a0d3b`) from
/// leaking into logs or error messages.
fn redact_url_paths(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut pos = 0;

    while pos < s.len() {
        let Some(idx) = s[pos..].find("://") else {
            result.push_str(&s[pos..]);
            break;
        };

        let abs = pos + idx;
        result.push_str(&s[pos..abs + 3]); // include "://"
        pos = abs + 3;

        // Find end of URL token (whitespace or closing delimiter)
        let token_end = s[pos..]
            .find(|c: char| c.is_whitespace() || matches!(c, '(' | ')' | '"' | '\''))
            .map(|i| pos + i)
            .unwrap_or(s.len());

        // If there's a path component, replace it with /***
        if let Some(slash) = s[pos..token_end].find('/') {
            result.push_str(&s[pos..pos + slash]); // host only
            result.push_str("/***");
        } else {
            result.push_str(&s[pos..token_end]); // host with no path
        }
        pos = token_end;
    }

    result
}

#[derive(Error, Debug)]
pub struct ReqwestError {
    pub msg: String,
    #[source]
    pub source: AlloyRpcError<TransportErrorKind>,
}

impl Display for ReqwestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.msg, redact_url_paths(&self.source.to_string()))
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
            RequestError::Reqwest(e) => write!(f, "{e}"),
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
}
