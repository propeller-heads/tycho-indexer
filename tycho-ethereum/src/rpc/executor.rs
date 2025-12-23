use std::marker::PhantomData;

use alloy::{
    rpc::client::ReqwestClient,
    transports::{RpcError, TransportErrorKind, TransportResult},
};
use backoff::backoff::Backoff;
use serde::{de::DeserializeOwned, Serialize};
use serde_json::Value;
use tokio::sync::{oneshot, oneshot::Receiver};

use crate::rpc::retry::{RetryPolicy, RetryableError};

/// Handle to retrieve the result of a registered RPC call.
pub struct RequestHandle<R> {
    receiver: Receiver<TransportResult<Value>>,
    _marker: PhantomData<R>,
}

impl<R: DeserializeOwned> RequestHandle<R> {
    /// Await the result and deserialize it into the expected type.
    pub async fn await_result(self) -> TransportResult<R> {
        let value = self
            .receiver
            .await
            .map_err(|_| RpcError::local_usage_str("RequestHandle channel closed"))??;

        serde_json::from_value(value)
            .map_err(|e| RpcError::local_usage_str(&format!("Failed to deserialize result: {e}")))
    }

    /// Await the raw Value result without deserializing.
    pub async fn await_raw(self) -> TransportResult<Value> {
        self.receiver
            .await
            .map_err(|_| RpcError::local_usage_str("RequestHandle channel closed"))?
    }
}

enum Call {
    Pending(PendingCall),
    Processed,
}

/// A pending RPC call waiting to be executed.
struct PendingCall {
    method: &'static str,
    params: Value,
    sender: oneshot::Sender<TransportResult<Value>>,
    /// Last retryable error encountered (used for error reporting on retry exhaustion)
    last_error: Option<RpcError<TransportErrorKind>>,
}

impl Call {
    /// Send the result through the channel, consuming this call.
    fn resolve(&mut self, result: TransportResult<Value>) {
        let this = std::mem::replace(self, Call::Processed);

        if let Call::Pending(pending) = this {
            let _ = pending.sender.send(result);
        }
    }

    fn set_last_error(&mut self, error: RpcError<TransportErrorKind>) {
        if let Call::Pending(pending) = self {
            pending.last_error = Some(error);
        }
    }
}

/// Outcome of executing a round of calls.
enum RoundOutcome {
    /// Round completed. Calls either succeeded, failed, or need retry.
    /// Contains backoff hint from retryable errors (rate limits, etc.)
    Continue,
    /// Execution aborted due to a non-retryable error.
    /// Contains the method that failed and the error for reporting.
    Aborted { error: RpcError<TransportErrorKind> },
}

/// Groups multiple RPC calls for efficient execution with automatic retry.
///
/// Supports:
/// - Chunked execution (respects `batch_size` for RPC batch limits)
/// - Automatic retry of retryable errors with backoff
/// - Two modes: collect all results, or abort on first non-retryable error
pub struct RpcRequestGroup<'a> {
    client: &'a ReqwestClient,
    retry_policy: RetryPolicy,
    batch_size: Option<usize>,
    calls: Vec<Call>,
}

impl<'a> RpcRequestGroup<'a> {
    pub fn new(
        client: &'a ReqwestClient,
        retry_policy: RetryPolicy,
        batch_size: Option<usize>,
    ) -> Self {
        Self { client, retry_policy, batch_size, calls: Vec::new() }
    }

    /// Register a call. Returns a handle to retrieve the result later.
    pub fn add_call<P: Serialize, R: DeserializeOwned>(
        &mut self,
        method: &'static str,
        params: &P,
    ) -> RequestHandle<R> {
        let (tx, rx) = oneshot::channel();
        self.calls
            .push(Call::Pending(PendingCall {
                method,
                sender: tx,
                params: serde_json::to_value(params).expect("params must serialize"),
                last_error: None,
            }));
        RequestHandle { receiver: rx, _marker: PhantomData }
    }

    // ==================== Execution ====================

    /// Execute all registered calls, retrying retryable errors.
    pub async fn execute(self) -> Result<(), RpcError<TransportErrorKind>> {
        self.run(false).await
    }

    /// Execute with fail-fast: abort on first non-retryable error.
    pub async fn execute_abort_early(self) -> Result<(), RpcError<TransportErrorKind>> {
        self.run(true).await
    }

    async fn run(self, abort_on_failure: bool) -> Result<(), RpcError<TransportErrorKind>> {
        let RpcRequestGroup { client, retry_policy, batch_size, mut calls } = self;
        let mut policy = retry_policy;

        loop {
            // Execute round: resolves completed calls, returns remaining (retryable or skipped)
            let outcome =
                Self::execute_round(client, &mut calls, batch_size, abort_on_failure).await;

            match outcome {
                RoundOutcome::Aborted { error } => {
                    // Notify remaining calls they were skipped
                    for mut call in calls {
                        call.resolve(Err(RpcError::local_usage_str(
                            "Request skipped due to earlier failure",
                        )));
                    }
                    return Err(error);
                }
                RoundOutcome::Continue => {
                    if calls
                        .iter()
                        .all(|call| matches!(call, Call::Processed))
                    {
                        // All calls completed
                        return Ok(());
                    }

                    let backoff_hint = calls
                        .iter()
                        .filter_map(|call| {
                            if let Call::Pending(p) = call {
                                p.last_error
                                    .as_ref()
                                    .and_then(|e| e.backoff_hint())
                            } else {
                                None
                            }
                        })
                        .max();

                    // Backoff before retry
                    match policy.next_backoff() {
                        Some(base) => {
                            let wait = backoff_hint.map_or(base, |h| std::cmp::min(base, h));
                            tokio::time::sleep(wait).await;
                        }
                        None => {
                            // Exhausted retries - fail remaining calls with their last error
                            for call in &mut calls {
                                if let Call::Pending(p) = call {
                                    let error = RpcError::local_usage_str(&format!(
                                            "Call to '{}' failed: exceeded retry attempts. Last error: {:?}",
                                            p.method,
                                            p.last_error
                                        ));
                                    call.resolve(Err(error));
                                }
                            }
                            return Err(RpcError::local_usage_str(
                                "Exceeded maximum retry attempts",
                            ));
                        }
                    }
                }
            }
        }
    }

    /// Execute one round of calls.
    ///
    /// - Takes ownership of calls
    /// - Resolves completed calls (success or hard failure) immediately
    /// - Returns remaining calls (retryable, or skipped if aborted)
    async fn execute_round(
        client: &ReqwestClient,
        calls: &mut [Call],
        batch_size: Option<usize>,
        abort_on_failure: bool,
    ) -> RoundOutcome {
        if calls.is_empty() {
            return RoundOutcome::Continue;
        }

        if let Some(batch_size) = batch_size {
            if batch_size > 1 && calls.len() > 1 {
                Self::execute_batched(client, calls, batch_size, abort_on_failure).await
            } else {
                Self::execute_sequential(client, calls, abort_on_failure).await
            }
        } else {
            Self::execute_sequential(client, calls, abort_on_failure).await
        }
    }

    // ==================== Sequential Execution ====================

    /// Execute calls one at a time (no batching).
    async fn execute_sequential(
        client: &ReqwestClient,
        calls: &mut [Call],
        abort_on_failure: bool,
    ) -> RoundOutcome {
        for call in calls.iter_mut() {
            let pending_call = match call {
                Call::Pending(p) => p,
                Call::Processed => continue,
            };

            let method = pending_call.method;
            let response = client
                .request::<_, Value>(method, &pending_call.params)
                .await;

            match response {
                Ok(value) => {
                    call.resolve(Ok(value));
                }
                Err(e) if e.is_retryable() => {
                    call.set_last_error(e);
                }
                Err(e) => {
                    let abort_error = RpcError::local_usage_str(&format!(
                        "Request for method {method} failed: {e}"
                    ));
                    call.resolve(Err(e));
                    if abort_on_failure {
                        return RoundOutcome::Aborted { error: abort_error };
                    }
                }
            }
        }

        RoundOutcome::Continue
    }

    // ==================== Batched Execution ====================

    /// Execute calls in batches (chunks).
    async fn execute_batched(
        client: &ReqwestClient,
        calls: &mut [Call],
        batch_size: usize,
        abort_on_failure: bool,
    ) -> RoundOutcome {
        let mut pending_calls_iter = calls
            .into_iter()
            .filter(|call| !matches!(call, Call::Processed))
            .peekable();

        while pending_calls_iter.peek().is_some() {
            // Collect next batch
            let mut batch = pending_calls_iter
                .by_ref()
                .take(batch_size);

            let batch_outcome = Self::execute_batch(client, &mut batch, abort_on_failure).await;

            if matches!(batch_outcome, RoundOutcome::Aborted { .. }) {
                return batch_outcome;
            }
        }

        RoundOutcome::Continue
    }

    /// Execute a single batch of calls.
    async fn execute_batch(
        client: &ReqwestClient,
        calls: impl Iterator<Item = &mut Call>,
        abort_on_failure: bool,
    ) -> RoundOutcome {
        let mut batch = client.new_batch();

        // Calls that were successfully added to batch, paired with their waiters
        let mut waiters_with_calls = Vec::new();

        // Step 1: Add calls to batch
        for call in calls {
            // We should never see processed calls here due to filtering upstream
            let pending_call = match call {
                Call::Pending(p) => p,
                Call::Processed => continue,
            };

            match batch.add_call::<_, Value>(pending_call.method, &pending_call.params) {
                Ok(waiter) => {
                    let method = pending_call.method;
                    waiters_with_calls.push((waiter, call, method));
                }
                Err(e) => {
                    // Failed to add to batch (serialization error, etc.)
                    if e.is_retryable() {
                        pending_call.last_error = Some(e);
                    } else {
                        let abort_error = RpcError::local_usage_str(&format!(
                            "Failed to add call to batch for method {}: {}",
                            pending_call.method, e
                        ));
                        call.resolve(Err(e));
                        if abort_on_failure {
                            return RoundOutcome::Aborted { error: abort_error };
                        }
                    }
                }
            }
        }

        if waiters_with_calls.is_empty() {
            return RoundOutcome::Continue
        }

        // Step 2: Send batch
        if let Err(e) = batch.send().await {
            let error = format!("Batch send failed: {e}");

            if e.is_retryable() {
                for (_, call, _) in waiters_with_calls {
                    call.set_last_error(RpcError::local_usage_str(&error));
                }
            } else {
                // Non-retryable batch failure - resolve all as failed
                for (_, call, _) in waiters_with_calls {
                    call.resolve(Err(RpcError::local_usage_str(&error)));
                }
                if abort_on_failure {
                    return RoundOutcome::Aborted { error: e };
                }
            }

            return RoundOutcome::Continue
        }

        // Step 3: Collect results
        for (waiter, call, method) in waiters_with_calls {
            let response = waiter.await;

            match response {
                Ok(value) => {
                    call.resolve(Ok(value));
                }
                Err(e) if e.is_retryable() => {
                    call.set_last_error(e);
                }
                Err(e) => {
                    let abort_error = RpcError::local_usage_str(&format!(
                        "Request for method {method} failed: {e}"
                    ));
                    call.resolve(Err(e));
                    if abort_on_failure {
                        return RoundOutcome::Aborted { error: abort_error };
                    }
                }
            }
        }

        RoundOutcome::Continue
    }
}

#[cfg(test)]
mod tests {
    use alloy::rpc::client::ClientBuilder;
    use mockito::{Matcher, Mock, Server};
    use rstest::rstest;

    use super::*;

    // ==================== Test Helpers ====================

    /// Helper to create a mock that expects to be called exactly `n` times
    async fn mock_response(server: &mut Server, body: &str, expect_calls: usize) -> Mock {
        server
            .mock("POST", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(body)
            .expect(expect_calls)
            .create_async()
            .await
    }

    fn json_rpc_response(id: u64, result: Value) -> String {
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": result
        })
        .to_string()
    }

    fn json_rpc_error(id: u64, code: i64, message: &str) -> String {
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {
                "code": code,
                "message": message
            }
        })
        .to_string()
    }

    /// Rate limit error (code -32005) - should be retryable
    fn rate_limit_error(id: u64) -> String {
        json_rpc_error(id, -32005, "rate limited")
    }

    /// Execution reverted error (code 3) - should NOT be retryable
    fn execution_reverted_error(id: u64) -> String {
        json_rpc_error(id, 3, "execution reverted")
    }

    async fn create_client(server: &Server) -> ReqwestClient {
        let url = server.url().parse().unwrap();
        ClientBuilder::default().http(url)
    }

    // ==================== Core Functionality Tests ====================

    #[rstest]
    #[case(None)]
    #[case(Some(1))]
    #[case(Some(10))]
    #[tokio::test]
    async fn test_single_call_success(#[case] batch_size: Option<usize>) {
        let mut server = Server::new_async().await;

        let mock = server
            .mock("POST", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(json_rpc_response(0, serde_json::json!("0x123")))
            .create_async()
            .await;

        let client = create_client(&server).await;
        let mut group = RpcRequestGroup::new(&client, RetryPolicy::no_retry(), batch_size);

        let handle: RequestHandle<String> = group.add_call("eth_call", &serde_json::json!([]));

        let result = group.execute().await;
        assert!(result.is_ok());

        let value = handle.await_result().await;
        assert!(value.is_ok());
        assert_eq!(value.unwrap(), "0x123");

        mock.assert_async().await;
    }

    #[rstest]
    #[case(None)]
    #[case(Some(1))]
    #[case(Some(10))]
    #[tokio::test]
    async fn test_multiple_calls_all_success(#[case] batch_size: Option<usize>) {
        let mut server = Server::new_async().await;

        // For batch mode, expect a single batched request; for sequential, expect multiple
        if batch_size.is_some() && batch_size.unwrap() > 1 {
            // Batch response
            let batch_response = serde_json::json!([
                {"jsonrpc": "2.0", "id": 0, "result": "0x1"},
                {"jsonrpc": "2.0", "id": 1, "result": "0x2"},
                {"jsonrpc": "2.0", "id": 2, "result": "0x3"}
            ]);
            server
                .mock("POST", "/")
                .with_status(200)
                .with_header("content-type", "application/json")
                .with_body(batch_response.to_string())
                .create_async()
                .await;
        } else {
            // Sequential: 3 separate responses
            for i in 0..3 {
                server
                    .mock("POST", "/")
                    .with_status(200)
                    .with_header("content-type", "application/json")
                    .with_body(json_rpc_response(i, serde_json::json!(format!("0x{}", i + 1))))
                    .create_async()
                    .await;
            }
        }

        let client = create_client(&server).await;
        let mut group = RpcRequestGroup::new(&client, RetryPolicy::no_retry(), batch_size);

        let h1: RequestHandle<String> = group.add_call("eth_call", &serde_json::json!([]));
        let h2: RequestHandle<String> = group.add_call("eth_call", &serde_json::json!([]));
        let h3: RequestHandle<String> = group.add_call("eth_call", &serde_json::json!([]));

        let result = group.execute().await;
        assert!(result.is_ok());

        assert!(h1.await_result().await.is_ok());
        assert!(h2.await_result().await.is_ok());
        assert!(h3.await_result().await.is_ok());
    }

    // ==================== Retry Behavior Tests ====================

    #[tokio::test]
    async fn test_retryable_error_is_retried() {
        let mut server = Server::new_async().await;

        // First call: rate limit error, second call: success
        server
            .mock("POST", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(rate_limit_error(0))
            .expect(1)
            .create_async()
            .await;

        server
            .mock("POST", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(json_rpc_response(0, serde_json::json!("0x123")))
            .expect(1)
            .create_async()
            .await;

        let client = create_client(&server).await;
        let policy = RetryPolicy::n_times(2);
        let mut group = RpcRequestGroup::new(&client, policy, None);

        let handle: RequestHandle<String> = group.add_call("eth_call", &serde_json::json!([]));

        let result = group.execute().await;
        assert!(result.is_ok());

        let value = handle.await_result().await;
        assert!(value.is_ok());
    }

    #[tokio::test]
    async fn test_retry_exhaustion_fails() {
        let mut server = Server::new_async().await;

        // All calls return rate limit error
        server
            .mock("POST", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(rate_limit_error(0))
            .expect(3) // Initial + 2 retries
            .create_async()
            .await;

        let client = create_client(&server).await;
        let policy = RetryPolicy::n_times(2);
        let mut group = RpcRequestGroup::new(&client, policy, None);

        let handle: RequestHandle<String> = group.add_call("eth_call", &serde_json::json!([]));

        let result = group.execute().await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("retry"));

        // Handle should receive an error
        let value = handle.await_result().await;
        assert!(value.is_err());
    }

    // ==================== Non-Retryable Error Tests ====================

    #[tokio::test]
    async fn test_non_retryable_error_fails_immediately() {
        let mut server = Server::new_async().await;

        server
            .mock("POST", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(execution_reverted_error(0))
            .expect(1) // Should only be called once, no retry
            .create_async()
            .await;

        let client = create_client(&server).await;
        let policy = RetryPolicy::n_times(5); // Would retry 5 times if retryable
        let mut group = RpcRequestGroup::new(&client, policy, None);

        let handle: RequestHandle<String> = group.add_call("eth_call", &serde_json::json!([]));

        let result = group.execute().await;
        assert!(result.is_ok()); // execute() succeeds, but the handle has error

        let value = handle.await_result().await;
        assert!(value.is_err());
    }

    // ==================== Abort Early Tests ====================

    #[tokio::test]
    async fn test_abort_early_stops_on_non_retryable() {
        let mut server = Server::new_async().await;

        // First call succeeds, second fails with non-retryable
        server
            .mock("POST", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(json_rpc_response(0, serde_json::json!("0x1")))
            .expect(1)
            .create_async()
            .await;

        server
            .mock("POST", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(execution_reverted_error(0))
            .expect(1)
            .create_async()
            .await;

        // Third call should NOT be made due to abort
        let client = create_client(&server).await;
        let mut group = RpcRequestGroup::new(&client, RetryPolicy::no_retry(), None);

        let h1: RequestHandle<String> = group.add_call("eth_call", &serde_json::json!([]));
        let h2: RequestHandle<String> = group.add_call("eth_call", &serde_json::json!([]));
        let h3: RequestHandle<String> = group.add_call("eth_call", &serde_json::json!([]));

        let result = group.execute_abort_early().await;
        assert!(result.is_err());

        // First succeeded
        assert!(h1.await_result().await.is_ok());
        // Second failed
        assert!(h2.await_result().await.is_err());
        // Third was skipped
        let h3_result = h3.await_result().await;
        assert!(h3_result.is_err());
        assert!(h3_result
            .unwrap_err()
            .to_string()
            .contains("skipped"));
    }

    #[tokio::test]
    async fn test_no_abort_continues_after_failure() {
        let mut server = Server::new_async().await;

        // First succeeds, second fails, third succeeds
        server
            .mock("POST", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(json_rpc_response(0, serde_json::json!("0x1")))
            .expect(1)
            .create_async()
            .await;

        server
            .mock("POST", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(execution_reverted_error(0))
            .expect(1)
            .create_async()
            .await;

        server
            .mock("POST", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(json_rpc_response(0, serde_json::json!("0x3")))
            .expect(1)
            .create_async()
            .await;

        let client = create_client(&server).await;
        let mut group = RpcRequestGroup::new(&client, RetryPolicy::no_retry(), None);

        let h1: RequestHandle<String> = group.add_call("eth_call", &serde_json::json!([]));
        let h2: RequestHandle<String> = group.add_call("eth_call", &serde_json::json!([]));
        let h3: RequestHandle<String> = group.add_call("eth_call", &serde_json::json!([]));

        // Use execute() not execute_abort_early()
        let result = group.execute().await;
        assert!(result.is_ok());

        assert!(h1.await_result().await.is_ok());
        assert!(h2.await_result().await.is_err()); // Failed but continued
        assert!(h3.await_result().await.is_ok()); // Was still executed
    }

    // ==================== Edge Cases ====================

    #[tokio::test]
    async fn test_empty_group_succeeds() {
        let server = Server::new_async().await;
        let client = create_client(&server).await;
        let group = RpcRequestGroup::new(&client, RetryPolicy::no_retry(), None);

        let result = group.execute().await;
        assert!(result.is_ok());
    }

    // ==================== Batch Mode Tests ====================

    /// Tests that batched requests are properly chunked when batch_size < calls.len().
    /// With 5 calls and batch_size=2, we expect 3 HTTP requests (2+2+1).
    #[tokio::test]
    async fn test_batch_chunking() {
        let mut server = Server::new_async().await;

        // First batch: 2 calls
        server
            .mock("POST", "/")
            .match_body(Matcher::Regex(r"^\[".to_string()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                serde_json::json!([
                    {"jsonrpc": "2.0", "id": 0, "result": "0x1"},
                    {"jsonrpc": "2.0", "id": 1, "result": "0x2"}
                ])
                .to_string(),
            )
            .expect(1)
            .create_async()
            .await;

        // Second batch: 2 calls
        server
            .mock("POST", "/")
            .match_body(Matcher::Regex(r"^\[".to_string()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                serde_json::json!([
                    {"jsonrpc": "2.0", "id": 2, "result": "0x3"},
                    {"jsonrpc": "2.0", "id": 3, "result": "0x4"}
                ])
                .to_string(),
            )
            .expect(1)
            .create_async()
            .await;

        // Third batch: 1 call (remainder)
        server
            .mock("POST", "/")
            .match_body(Matcher::Regex(r"^\[".to_string()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                serde_json::json!([
                    {"jsonrpc": "2.0", "id": 4, "result": "0x5"}
                ])
                .to_string(),
            )
            .expect(1)
            .create_async()
            .await;

        let client = create_client(&server).await;
        let mut group = RpcRequestGroup::new(&client, RetryPolicy::no_retry(), Some(2));

        let handles: Vec<RequestHandle<String>> = (0..5)
            .map(|_| group.add_call("eth_call", &serde_json::json!([])))
            .collect();

        let result = group.execute().await;
        assert!(result.is_ok());

        for (i, handle) in handles.into_iter().enumerate() {
            let value = handle.await_result().await.unwrap();
            assert_eq!(value, format!("0x{}", i + 1));
        }
    }

    /// Diagnostic test to understand batch waiter error types
    #[tokio::test]
    async fn test_batch_error_diagnostic() {
        use alloy::rpc::client::ClientBuilder;

        let mut server = Server::new_async().await;

        // Batch response where call 1 has a rate limit error
        server
            .mock("POST", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                serde_json::json!([
                    {"jsonrpc": "2.0", "id": 0, "result": "0xAAA"},
                    {"jsonrpc": "2.0", "id": 1, "error": {"code": -32005, "message": "rate limited"}}
                ])
                .to_string(),
            )
            .create_async()
            .await;

        let url = server.url().parse().unwrap();
        let client: ReqwestClient = ClientBuilder::default().http(url);

        let mut batch = client.new_batch();

        let waiter0 = batch
            .add_call::<_, Value>("eth_call", &serde_json::json!([]))
            .unwrap();
        let waiter1 = batch
            .add_call::<_, Value>("eth_call", &serde_json::json!([]))
            .unwrap();

        batch
            .send()
            .await
            .expect("batch send should succeed");

        let result0 = waiter0.await;
        let result1 = waiter1.await;

        println!("Result 0: {:?}", result0);
        println!("Result 1: {:?}", result1);

        // Check result 0 is Ok
        assert!(result0.is_ok(), "Result 0 should be Ok");

        // Check result 1 is an error
        let err = result1.expect_err("Result 1 should be an error");
        println!("Error type: {:?}", err);
        println!("Error is_retryable: {}", err.is_retryable());

        // Check the error variant
        match &err {
            RpcError::ErrorResp(payload) => {
                println!("ErrorResp payload: {:?}", payload);
                println!("ErrorResp code: {}", payload.code);
                println!("ErrorResp is_retry_err: {}", payload.is_retry_err());
            }
            other => {
                println!("Unexpected error variant: {:?}", other);
            }
        }

        // The error should be retryable
        assert!(err.is_retryable(), "Error with code -32005 should be retryable, got: {:?}", err);
    }

    /// Tests partial retry in batch mode: when some calls succeed and others need retry,
    /// only the failed calls should be retried on the next round.
    #[tokio::test]
    async fn test_partial_retry_in_batch_mode() {
        let mut server = Server::new_async().await;

        // First batch attempt: call 0 succeeds, call 1 gets retryable error
        let mock1 = server
            .mock("POST", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                serde_json::json!([
                    {"jsonrpc": "2.0", "id": 0, "result": "0xAAA"},
                    {"jsonrpc": "2.0", "id": 1, "error": {"code": -32005, "message": "rate limited"}}
                ])
                .to_string(),
            )
            .expect(1)
            .create_async()
            .await;

        // Retry: only call 1 is retried, but still uses batch format because
        // calls.len() still includes the Processed call (so len > 1).
        let mock2 = server
            .mock("POST", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                serde_json::json!([
                    {"jsonrpc": "2.0", "id": 2, "result": "0xBBB"}
                ])
                .to_string(),
            )
            .expect(1)
            .create_async()
            .await;

        let client = create_client(&server).await;
        let mut group = RpcRequestGroup::new(&client, RetryPolicy::n_times(2), Some(10));

        let h1: RequestHandle<String> = group.add_call("eth_call", &serde_json::json!([]));
        let h2: RequestHandle<String> = group.add_call("eth_call", &serde_json::json!([]));

        let result = group.execute().await;
        assert!(result.is_ok(), "execute() failed: {:?}", result.unwrap_err());

        // Verify both mocks were called
        mock1.assert_async().await;
        mock2.assert_async().await;

        // Both should succeed
        assert_eq!(h1.await_result().await.unwrap(), "0xAAA");
        assert_eq!(h2.await_result().await.unwrap(), "0xBBB");
    }

    /// Tests mixed batch results: success, retryable error, and non-retryable error
    /// in a single batch response.
    #[tokio::test]
    async fn test_mixed_batch_results() {
        let mut server = Server::new_async().await;

        // Batch response with mixed results
        server
            .mock("POST", "/")
            .match_body(Matcher::Regex(r"^\[".to_string()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                serde_json::json!([
                    {"jsonrpc": "2.0", "id": 0, "result": "0xSUCCESS"},
                    {"jsonrpc": "2.0", "id": 1, "error": {"code": -32005, "message": "rate limited"}},
                    {"jsonrpc": "2.0", "id": 2, "error": {"code": 3, "message": "execution reverted"}}
                ])
                .to_string(),
            )
            .expect(1)
            .create_async()
            .await;

        // Retry round: only call 1 (retryable) is retried, still uses batch format
        server
            .mock("POST", "/")
            .match_body(Matcher::Regex(r"^\[".to_string()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                serde_json::json!([
                    {"jsonrpc": "2.0", "id": 3, "result": "0xRETRIED"}
                ])
                .to_string(),
            )
            .expect(1)
            .create_async()
            .await;

        let client = create_client(&server).await;
        let mut group = RpcRequestGroup::new(&client, RetryPolicy::n_times(2), Some(10));

        let h1: RequestHandle<String> = group.add_call("eth_call", &serde_json::json!([]));
        let h2: RequestHandle<String> = group.add_call("eth_call", &serde_json::json!([]));
        let h3: RequestHandle<String> = group.add_call("eth_call", &serde_json::json!([]));

        let result = group.execute().await;
        assert!(result.is_ok());

        // Call 0: succeeded immediately
        assert_eq!(h1.await_result().await.unwrap(), "0xSUCCESS");
        // Call 1: retried and succeeded
        assert_eq!(h2.await_result().await.unwrap(), "0xRETRIED");
        // Call 2: non-retryable error (execution reverted)
        let h3_err = h3.await_result().await.unwrap_err();
        assert!(h3_err.to_string().contains("reverted"));
    }

    /// Tests abort_early behavior in batch mode.
    /// When a non-retryable error occurs in a batch, remaining calls in the batch
    /// are still processed, but subsequent batches are not executed.
    #[tokio::test]
    async fn test_abort_early_in_batch_mode() {
        let mut server = Server::new_async().await;

        // First batch: second call fails with non-retryable error
        server
            .mock("POST", "/")
            .match_body(Matcher::Regex(r"^\[".to_string()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                serde_json::json!([
                    {"jsonrpc": "2.0", "id": 0, "result": "0x1"},
                    {"jsonrpc": "2.0", "id": 1, "error": {"code": 3, "message": "execution reverted"}}
                ])
                .to_string(),
            )
            .expect(1)
            .create_async()
            .await;

        // Second batch should NOT be called due to abort

        let client = create_client(&server).await;
        let mut group = RpcRequestGroup::new(&client, RetryPolicy::no_retry(), Some(2));

        let h1: RequestHandle<String> = group.add_call("eth_call", &serde_json::json!([]));
        let h2: RequestHandle<String> = group.add_call("eth_call", &serde_json::json!([]));
        let h3: RequestHandle<String> = group.add_call("eth_call", &serde_json::json!([]));
        let h4: RequestHandle<String> = group.add_call("eth_call", &serde_json::json!([]));

        let result = group.execute_abort_early().await;
        assert!(result.is_err());

        // First batch processed: h1 succeeded, h2 failed
        assert!(h1.await_result().await.is_ok());
        assert!(h2.await_result().await.is_err());

        // Second batch skipped: h3 and h4 marked as skipped
        let h3_err = h3.await_result().await.unwrap_err();
        let h4_err = h4.await_result().await.unwrap_err();
        assert!(h3_err.to_string().contains("skipped"));
        assert!(h4_err.to_string().contains("skipped"));
    }

    /// Tests HTTP 503 server error (Service Unavailable).
    /// HTTP 503 is retryable by alloy's transport layer.
    #[tokio::test]
    async fn test_batch_send_failure_server_error() {
        let mut server = Server::new_async().await;

        // First attempt: HTTP 503 (Service Unavailable) - this IS retryable
        server
            .mock("POST", "/")
            .with_status(503)
            .with_header("content-type", "application/json")
            .with_body(r#"{"jsonrpc":"2.0","id":0,"error":{"code":-32603,"message":"Service Unavailable"}}"#)
            .expect(1)
            .create_async()
            .await;

        // Retry: success
        mock_response(&mut server, &json_rpc_response(0, serde_json::json!("0xOK")), 1).await;

        let client = create_client(&server).await;
        let mut group = RpcRequestGroup::new(&client, RetryPolicy::n_times(2), None);

        let handle: RequestHandle<String> = group.add_call("eth_call", &serde_json::json!([]));

        let result = group.execute().await;
        assert!(result.is_ok());

        assert_eq!(handle.await_result().await.unwrap(), "0xOK");
    }

    /// Tests that batch_size=0 falls back to sequential execution.
    #[tokio::test]
    async fn test_batch_size_zero_uses_sequential() {
        let mut server = Server::new_async().await;

        // Expect 2 sequential requests (not batched), matching single request format
        server
            .mock("POST", "/")
            .match_body(Matcher::Regex(r"^\{".to_string()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(json_rpc_response(0, serde_json::json!("0x1")))
            .expect(1)
            .create_async()
            .await;

        server
            .mock("POST", "/")
            .match_body(Matcher::Regex(r"^\{".to_string()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(json_rpc_response(0, serde_json::json!("0x2")))
            .expect(1)
            .create_async()
            .await;

        let client = create_client(&server).await;
        let mut group = RpcRequestGroup::new(&client, RetryPolicy::no_retry(), Some(0));

        let h1: RequestHandle<String> = group.add_call("eth_call", &serde_json::json!([]));
        let h2: RequestHandle<String> = group.add_call("eth_call", &serde_json::json!([]));

        let result = group.execute().await;
        assert!(result.is_ok());

        assert_eq!(h1.await_result().await.unwrap(), "0x1");
        assert_eq!(h2.await_result().await.unwrap(), "0x2");
    }
}
