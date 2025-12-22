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
