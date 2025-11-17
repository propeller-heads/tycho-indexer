//! RPC retry logic and error classification
//!
//! This module contains retry logic for RPC requests, including exponential backoff
//! and intelligent error classification to determine which errors should be retried.

use std::time::Duration;

use alloy::{
    primitives::private::serde::Deserialize,
    rpc::json_rpc::ErrorPayload,
    transports::{RpcError, TransportErrorKind},
};
use backoff::{exponential::ExponentialBackoffBuilder, ExponentialBackoff};
use serde_json::value::RawValue;

/// Extension trait to implement retry logic for [`RpcError<TransportErrorKind>`].
///
/// This trait provides methods to analyze RPC errors and determine whether they should
/// be retried, as well as extract backoff hints from error responses.
///
/// # Attribution
/// Adapted from alloy-transport:
/// https://github.com/alloy-rs/alloy/blob/a3899575fbc0c789275f95661516b99e9a92838d/crates/transport/src/error.rs#L156
/// License: MIT OR Apache-2.0
pub(crate) trait RpcErrorExt {
    /// Analyzes whether to retry the request depending on the error.
    ///
    /// Returns `true` for transient errors that are likely to succeed on retry:
    /// - Rate limiting (429) errors
    /// - Service unavailable (503) errors
    /// - Missing batch responses
    /// - Null responses
    /// - Certain JSON-RPC error codes
    ///
    /// Returns `false` for permanent errors that won't succeed on retry:
    /// - Serialization/deserialization errors
    /// - Invalid request errors
    /// - Backend gone errors
    fn is_retryable(&self) -> bool;

    /// Fetches the backoff hint from the error message if present.
    ///
    /// Some RPC providers (e.g., Infura) include a suggested backoff duration
    /// in their rate limit error responses under `data.rate.backoff_seconds`.
    /// This method extracts that hint if available.
    fn backoff_hint(&self) -> Option<Duration>;

    /// Classifies errors into transient or permanent for backoff retry logic.
    ///
    /// Transient errors are retried with exponential backoff, potentially with a
    /// provider-specified backoff hint. Permanent errors fail immediately.
    fn classify_error(self) -> backoff::Error<Self>
    where
        Self: Sized;
}

impl<E: std::borrow::Borrow<RawValue>> RpcErrorExt for RpcError<TransportErrorKind, E> {
    fn is_retryable(&self) -> bool {
        match self {
            Self::Transport(err) => err.is_retry_err(),
            Self::SerError(_) => false,
            Self::DeserError { text, .. } => {
                if let Ok(resp) = serde_json::from_str::<ErrorPayload>(text) {
                    return resp.is_retry_err();
                }

                // some providers send invalid JSON RPC in the error case (no `id:u64`), but the
                // text should be a `JsonRpcError`
                #[derive(Deserialize)]
                struct Resp {
                    error: ErrorPayload,
                }

                if let Ok(resp) = serde_json::from_str::<Resp>(text) {
                    return resp.error.is_retry_err();
                }

                false
            }
            Self::ErrorResp(err) => err.is_retry_err(),
            Self::NullResp => true,
            _ => false,
        }
    }

    fn backoff_hint(&self) -> Option<Duration> {
        if let Self::ErrorResp(resp) = self {
            let data = resp.try_data_as::<serde_json::Value>();
            if let Some(Ok(data)) = data {
                let backoff_seconds = &data["rate"]["backoff_seconds"];
                // Try u64 first (whole numbers)
                if let Some(seconds) = backoff_seconds.as_u64() {
                    return Some(Duration::from_secs(seconds));
                }
                // Then try f64 (decimals) - round up for safety
                if let Some(seconds) = backoff_seconds.as_f64() {
                    return Some(Duration::from_secs(seconds.ceil() as u64));
                }
            }
        }
        None
    }

    fn classify_error(self) -> backoff::Error<Self> {
        if self.is_retryable() {
            if let Some(hint) = self.backoff_hint() {
                backoff::Error::retry_after(self, hint)
            } else {
                backoff::Error::transient(self)
            }
        } else {
            backoff::Error::permanent(self)
        }
    }
}

/// Configuration for RPC retry behavior with exponential backoff.
#[derive(Clone, Debug)]
pub struct RetryPolicy(ExponentialBackoff);

impl Default for RetryPolicy {
    /// Creates a new retry policy with default values:
    /// - Initial interval: 250ms
    /// - Multiplier: 1.75x
    /// - Max interval: 30s
    /// - Max elapsed time: 125s
    fn default() -> Self {
        Self(
            ExponentialBackoffBuilder::new()
                .with_initial_interval(Duration::from_millis(250))
                .with_multiplier(1.75)
                .with_max_interval(Duration::from_secs(30))
                .with_max_elapsed_time(Some(Duration::from_secs(125)))
                .build(),
        )
    }
}

impl RetryPolicy {
    pub fn new(policy: ExponentialBackoff) -> Self {
        Self(policy)
    }

    /// Creates a retry policy with custom configuration.
    pub fn with_config(
        initial_interval: Duration,
        multiplier: f64,
        max_interval: Duration,
        max_elapsed_time: Duration,
    ) -> Self {
        let policy = ExponentialBackoffBuilder::new()
            .with_initial_interval(initial_interval)
            .with_multiplier(multiplier)
            .with_max_interval(max_interval)
            .with_max_elapsed_time(Some(max_elapsed_time))
            .build();

        Self(policy)
    }

    /// Creates a retry policy optimized for testing (very short intervals).
    #[cfg(test)]
    pub fn for_testing() -> Self {
        let policy = ExponentialBackoffBuilder::new()
            .with_initial_interval(Duration::from_millis(1))
            .with_multiplier(1.1)
            .with_max_interval(Duration::from_millis(5))
            .with_max_elapsed_time(Some(Duration::from_millis(50)))
            .build();

        Self(policy)
    }

    /// Executes an RPC request with automatic retry on transient failures.
    ///
    /// This function wraps an RPC operation with exponential backoff retry logic.
    /// It automatically retries requests that fail with transient errors (rate limiting,
    /// connection issues, etc.) while immediately failing on permanent errors.
    pub(crate) async fn retry_request<F, Fut, T>(
        &self,
        mut operation: F,
    ) -> Result<T, RpcError<TransportErrorKind>>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = Result<T, RpcError<TransportErrorKind>>>,
    {
        backoff::future::retry(self.policy(), || {
            let fut = operation();
            async move {
                fut.await
                    .map_err(RpcError::classify_error)
            }
        })
        .await
    }

    /// Gets a clone of the underlying backoff policy.
    fn policy(&self) -> ExponentialBackoff {
        // TODO: consider if we should share state for concurrent retries from multiple tasks
        self.0.clone()
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
        time::Instant,
    };

    use alloy::{rpc::client::ClientBuilder, transports::HttpError};
    use mockito::{Mock, ServerGuard};
    use rstest::rstest;
    use serde::de::Error;

    use super::*;

    async fn mock_success(server: &mut ServerGuard) -> Mock {
        server
            .mock("POST", "/")
            .match_body(mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"jsonrpc":"2.0","id":1,"result":"0xabc"}"#)
            .expect(1)
            .create_async()
            .await
    }

    async fn mock_rate_limited(server: &mut ServerGuard) -> Mock {
        server
            .mock("POST", "/")
            .match_body(mockito::Matcher::Any)
            .with_status(429)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"jsonrpc":"2.0","id":1,"error":{"code":429,"message":"Too Many Requests"}}"#,
            )
            .expect(3)
            .create_async()
            .await
    }

    #[test]
    fn test_retry_policy_custom() {
        let policy = RetryPolicy::with_config(
            Duration::from_millis(100),
            2.0,
            Duration::from_secs(10),
            Duration::from_secs(60),
        );

        let backoff = policy.policy();
        assert_eq!(backoff.initial_interval, Duration::from_millis(100));
        assert_eq!(backoff.multiplier, 2.0);
        assert_eq!(backoff.max_interval, Duration::from_secs(10));
        assert_eq!(backoff.max_elapsed_time, Some(Duration::from_secs(60)));
    }

    #[test]
    fn test_error_classification_retryable() {
        // Test that 429 errors are retryable
        let rate_limit_err =
            RpcError::<TransportErrorKind>::Transport(TransportErrorKind::HttpError(HttpError {
                status: 429,
                body: "".to_string(),
            }));
        assert!(rate_limit_err.is_retryable());

        // Test that 503 errors are retryable
        let unavailable_err =
            RpcError::<TransportErrorKind>::Transport(TransportErrorKind::HttpError(HttpError {
                status: 503,
                body: "".to_string(),
            }));
        assert!(unavailable_err.is_retryable());

        // Test that null responses are retryable
        let null_err = RpcError::<TransportErrorKind>::NullResp;
        assert!(null_err.is_retryable());
    }

    #[test]
    fn test_error_classification_non_retryable() {
        // Test that serialization errors are not retryable
        let ser_err =
            RpcError::<TransportErrorKind>::SerError(serde_json::Error::custom("test error"));
        assert!(!ser_err.is_retryable());

        // Test that backend gone is not retryable
        let backend_gone =
            RpcError::<TransportErrorKind>::Transport(TransportErrorKind::BackendGone);
        assert!(!backend_gone.is_retryable());

        // Test that pubsub unavailable is not retryable
        let pubsub_unavailable =
            RpcError::<TransportErrorKind>::Transport(TransportErrorKind::PubsubUnavailable);
        assert!(!pubsub_unavailable.is_retryable());
    }

    #[rstest]
    #[case::integer(10_f64, Duration::from_secs(10))]
    #[case::float(5.7, Duration::from_secs(6))]
    #[test]
    fn test_backoff_hint_extraction(#[case] backoff_value: f64, #[case] duration: Duration) {
        use alloy::rpc::json_rpc::ErrorPayload;

        // Create a mock error response with backoff hint
        // Need to create Box<RawValue> to satisfy trait bounds
        let data_json = serde_json::json!({
            "rate": {
                "backoff_seconds": backoff_value
            }
        });
        let data = serde_json::value::to_raw_value(&data_json).unwrap();

        let error_payload =
            ErrorPayload { code: -32005, message: "Rate limited".into(), data: Some(data) };

        let err = RpcError::ErrorResp(error_payload);
        let hint = err.backoff_hint();

        assert_eq!(hint, Some(duration));
    }

    #[test]
    fn test_backoff_hint_missing() {
        use alloy::rpc::json_rpc::ErrorPayload;

        // Create a mock error response without backoff hint
        let error_payload = ErrorPayload { code: -32005, message: "Some error".into(), data: None };

        let err = RpcError::<TransportErrorKind>::ErrorResp(error_payload);
        let hint = err.backoff_hint();

        assert_eq!(hint, None);
    }

    /// Test that transient errors (429) are retried and eventually succeed
    #[tokio::test]
    async fn test_retry_on_rate_limit_then_succeed() {
        let mut server = mockito::Server::new_async().await;
        let request_count = Arc::new(AtomicUsize::new(0));
        let request_count_clone = request_count.clone();

        // First 3 requests: 429 rate limit
        let _mock_rate_limit = mock_rate_limited(&mut server).await;

        // 4th request: success
        let _mock_success = mock_success(&mut server).await;

        let client = ClientBuilder::default().http(server.url().parse().unwrap());
        let policy = RetryPolicy::for_testing();

        let result = policy
            .retry_request(|| async {
                request_count_clone.fetch_add(1, Ordering::SeqCst);
                client
                    .request_noparams::<String>("eth_blockNumber")
                    .await
            })
            .await;

        assert!(result.is_ok(), "Expected eventual success after retries");
        assert_eq!(result.unwrap(), "0xabc");
        assert_eq!(
            request_count.load(Ordering::SeqCst),
            4,
            "Expected 4 requests (3 failures + 1 success)"
        );
    }

    /// Test that permanent errors (400) fail immediately without retry
    #[tokio::test]
    async fn test_no_retry_on_permanent_error() {
        let mut server = mockito::Server::new_async().await;
        let request_count = Arc::new(AtomicUsize::new(0));
        let request_count_clone = request_count.clone();

        // 400 Bad Request - should NOT be retried
        let _mock = server
            .mock("POST", "/")
            .match_body(mockito::Matcher::Any)
            .with_status(400)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32600,"message":"Invalid Request"}}"#,
            )
            .expect(1) // Should only be called once!
            .create_async()
            .await;

        let client = ClientBuilder::default().http(server.url().parse().unwrap());
        let policy = RetryPolicy::for_testing();

        let result = policy
            .retry_request(|| async {
                request_count_clone.fetch_add(1, Ordering::SeqCst);
                client
                    .request_noparams::<String>("eth_blockNumber")
                    .await
            })
            .await;

        assert!(result.is_err(), "Expected immediate failure on non-retryable error");
        assert_eq!(
            request_count.load(Ordering::SeqCst),
            1,
            "Expected only 1 request (no retries for permanent errors)"
        );
    }

    /// Test that backoff hints from the server are respected
    #[tokio::test]
    async fn test_backoff_hint_respected() {
        let mut server = mockito::Server::new_async().await;
        let start_time = Instant::now();

        // First request: rate limited with 2-second backoff hint
        let _mock_rate_limit = server
            .mock("POST", "/")
            .match_body(mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{
                    "jsonrpc":"2.0",
                    "id":1,
                    "error":{
                        "code":-32005,
                        "message":"Rate limited",
                        "data":{"rate":{"backoff_seconds":2}}
                    }
                }"#,
            )
            .expect(1)
            .create_async()
            .await;

        // Second request: success
        let _mock_success = mock_success(&mut server).await;

        let client = ClientBuilder::default().http(server.url().parse().unwrap());
        let policy = RetryPolicy::for_testing();

        let result = policy
            .retry_request(|| async {
                client
                    .request_noparams::<String>("eth_blockNumber")
                    .await
            })
            .await;

        let elapsed = start_time.elapsed();

        assert!(result.is_ok(), "Expected eventual success after backoff");
        assert!(
            elapsed >= Duration::from_secs(2),
            "Expected at least 2 seconds delay due to backoff hint, got {:?}",
            elapsed
        );
    }

    /// Test that max elapsed time is enforced
    #[tokio::test]
    async fn test_exponential_backoff() {
        let mut server = mockito::Server::new_async().await;
        let request_count = Arc::new(AtomicUsize::new(0));
        let request_count_clone = request_count.clone();
        let start_time = Instant::now();

        // First request: rate limited
        let _mock_rate_limit = mock_rate_limited(&mut server).await;

        // Second request: success
        let _mock_success = mock_success(&mut server).await;

        let client = ClientBuilder::default().http(server.url().parse().unwrap());
        // Very short max elapsed time for testing
        let start_interval = 100;
        let multiplier = 2.0;
        let policy = RetryPolicy::with_config(
            Duration::from_millis(start_interval),
            multiplier,
            Duration::from_millis(1000),
            Duration::from_millis(2000), // Give up after 200ms
        );

        let result = policy
            .retry_request(|| async {
                request_count_clone.fetch_add(1, Ordering::SeqCst);
                println!("Elapsed: {:?}", start_time.elapsed());
                client
                    .request_noparams::<String>("eth_blockNumber")
                    .await
            })
            .await;

        println!("Result: {:?}", result);
        assert!(result.is_ok(), "Expected eventual success after retries");

        let elapsed = start_time.elapsed();
        // Calculate expected minimum elapsed time due-to-backoff
        // Note that there is a default 50% jitter applied by backoff crate
        let expected_min = 0.5 *
            (start_interval as f64 +
                (start_interval as f64 * multiplier) +
                (start_interval as f64 * multiplier * multiplier));
        assert!(
            elapsed >= Duration::from_millis(expected_min as u64),
            "Expected at least {}ms elapsed time due to backoff, got {:?}",
            expected_min,
            elapsed
        );

        let count = request_count.load(Ordering::SeqCst);
        assert_eq!(
            count, 4,
            "Should have retried {} times before timeout, got {} requests",
            4, count
        );
    }
}
