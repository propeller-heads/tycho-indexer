use std::{
    collections::{BTreeMap, HashMap},
    ops::Add,
    sync::Arc,
    time::Duration,
};

use tokio::sync::RwLock;

#[derive(Debug, Clone)]
struct ValidationData {
    token: Address,
    storage_addr: Address,
    slot: Bytes,
    original_balance: U256,
    test_value: U256,
}

use alloy::{
    primitives::{Address as AlloyAddress, U256},
    rpc::types::trace::geth::{GethTrace, PreStateFrame, PreStateMode},
    transports::http::reqwest,
};
use async_trait::async_trait;
use futures::future::join_all;
use serde_json::{json, Value};
use thiserror::Error;
use tracing::{debug, error, info, instrument, trace, warn};
use tycho_common::{
    models::{
        blockchain::{AccountOverrides, EntryPoint, RPCTracerParams, TracingParams},
        Address, BlockHash,
    },
    traits::BalanceSlotDetector,
    Bytes,
};

use crate::{entrypoint_tracer::tracer::EVMEntrypointService, RPCError};

/// Type alias for slot detection results: (storage_address, slot_bytes) with balance
type SlotDetectionResult = ((Address, Bytes), U256);

/// Type alias for token slot detection results
type TokenSlotResults = HashMap<Address, Result<SlotDetectionResult, BalanceSlotError>>;

/// Type alias for slot values from trace: (address, slot_bytes) with value
type SlotValues = Vec<((Address, Bytes), U256)>;

#[derive(Clone, Debug, Error)]
pub enum BalanceSlotError {
    #[error("Setup error: {0}")]
    SetupError(String),
    #[error("RPC request failed: {0}")]
    RequestError(String),
    #[error("Invalid response: {0}")]
    InvalidResponse(String),
    #[error("Token not found in trace")]
    TokenNotInTrace,
    #[error("Failed to parse trace: {0}")]
    ParseError(String),
    #[error("Failed to extract balance: {0}")]
    BalanceExtractionError(String),
    #[error("Unknown error: {0}")]
    UnknownError(String),
    #[error("Wrong slot detected :{0}")]
    WrongSlotError(String),
}

/// Configuration for balance slot detection.
/// Use max_batch_size to configure the behavior according to your node capacity.
/// Please ensure your node supports batching RPC requests and debug_traceCall
/// Read more: https://www.quicknode.com/guides/quicknode-products/apis/guide-to-efficient-rpc-requests
#[derive(Clone, Debug)]
pub struct BalanceSlotDetectorConfig {
    /// Maximum batch size to send in a single node request
    pub max_batch_size: usize,
    /// RPC endpoint URL (RPC needs to support debug_traceCall method)
    pub rpc_url: String,
    /// Maximum number of retry attempts for failed requests (default: 3)
    pub max_retries: usize,
    /// Initial backoff delay in milliseconds (default: 100ms)
    pub initial_backoff_ms: u64,
    /// Maximum backoff delay in milliseconds (default: 5000ms)
    pub max_backoff_ms: u64,
}

impl Default for BalanceSlotDetectorConfig {
    fn default() -> Self {
        Self {
            max_batch_size: 10,
            rpc_url: String::new(),
            max_retries: 3,
            initial_backoff_ms: 100,
            max_backoff_ms: 5000,
        }
    }
}

/// Cache type for balance slot detection results
type BalanceSlotCache = Arc<RwLock<HashMap<(Address, Address), (Address, Bytes)>>>;

/// EVM-specific implementation of BalanceSlotDetector using debug_traceCall
pub struct EVMBalanceSlotDetector {
    rpc_url: url::Url,
    max_batch_size: usize,
    cache: BalanceSlotCache,
    http_client: reqwest::Client,
    max_retries: usize,
    initial_backoff_ms: u64,
    max_backoff_ms: u64,
}

impl EVMBalanceSlotDetector {
    pub fn new(config: BalanceSlotDetectorConfig) -> Result<Self, BalanceSlotError> {
        let rpc_url = url::Url::parse(&config.rpc_url)
            .map_err(|_| BalanceSlotError::SetupError("Invalid URL".to_string()))?;

        // perf: Allow a client to be passed on the constructor, to use a shared client between
        // other parts of the code that perform node RPC requests

        // Create HTTP client with connection pooling and reasonable timeouts
        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(10))
            .pool_idle_timeout(Duration::from_secs(90))
            .pool_max_idle_per_host(10)
            // https://brooker.co.za/blog/2024/05/09/nagle.html
            .tcp_nodelay(true)
            .build()
            .map_err(|e| {
                BalanceSlotError::SetupError(format!("Failed to create HTTP client: {e}"))
            })?;

        Ok(Self {
            max_batch_size: config.max_batch_size,
            rpc_url,
            // perf: Add cache persistence to DB.
            cache: Arc::new(RwLock::new(HashMap::new())),
            http_client,
            max_retries: config.max_retries,
            initial_backoff_ms: config.initial_backoff_ms,
            max_backoff_ms: config.max_backoff_ms,
        })
    }

    /// Detect slots for a single component using batched requests (debug_traceCall + eth_call per
    /// token)
    #[instrument(fields(
        token_count = tokens.len()
    ), skip(self, tokens))]
    async fn detect_token_slots(
        &self,
        tokens: &[Address],
        owner: &Address,
        block_hash: &BlockHash,
    ) -> HashMap<Address, Result<(Address, Bytes), BalanceSlotError>> {
        if tokens.is_empty() {
            return HashMap::new();
        }

        let mut request_tokens = Vec::with_capacity(tokens.len());
        let mut cached_tokens = HashMap::new();

        // Check cache for tokens
        {
            let cache = self.cache.read().await;
            for token in tokens {
                if let Some(slot) = cache.get(&(token.clone(), owner.clone())) {
                    cached_tokens.insert(token.clone(), Ok(slot.clone()));
                } else {
                    request_tokens.push(token.clone());
                }
            }
        }

        if request_tokens.is_empty() {
            return cached_tokens;
        }

        // Create batched request: 2 requests per token (debug_traceCall + eth_call)
        let requests = self.create_balance_requests(&request_tokens, owner, block_hash);

        // Send the batched request
        let responses = match self
            .send_batched_request(requests)
            .await
        {
            Ok(responses) => responses,
            Err(e) => {
                for token in &request_tokens {
                    // Failed to send the batched request - return with only the cached values.
                    cached_tokens
                        .insert(token.clone(), Err(BalanceSlotError::RequestError(e.to_string())));
                }
                return cached_tokens;
            }
        };

        // Process the batched response to extract slots
        let token_slots = self.process_batched_response(&request_tokens, responses);

        // Validates that the selected slot actually matches the expectation.
        let validation_results = self
            .validate_best_slots(token_slots, owner, block_hash)
            .await;

        // Update cache and prepare final results
        let mut final_results = cached_tokens;
        {
            let mut cache = self.cache.write().await;
            for (token, result) in validation_results {
                match result {
                    Ok(((storage_addr, slot_bytes), _balance)) => {
                        // Update cache with successful detections
                        cache.insert(
                            (token.clone(), owner.clone()),
                            (storage_addr.clone(), slot_bytes.clone()),
                        );
                        final_results.insert(token, Ok((storage_addr, slot_bytes)));
                    }
                    Err(e) => {
                        final_results.insert(token, Err(e));
                    }
                }
            }
        }

        final_results
    }

    /// Create a batched JSON-RPC request for all tokens (2 requests per token).
    /// We need to send an eth_call after the tracing to get the return value of the balanceOf
    /// function. Currently, debug_traceCall does not support preStateTracer + returning the
    /// value in the same request.
    fn create_balance_requests(
        &self,
        tokens: &[Address],
        owner: &Address,
        block_hash: &BlockHash,
    ) -> Value {
        let mut batch = Vec::new();
        let mut id = 1u64;

        for token in tokens {
            let calldata = encode_balance_of_calldata(owner);

            let tracer_params = RPCTracerParams::new(None, calldata.clone());
            let trace_params =
                EVMEntrypointService::create_trace_call_params(token, &tracer_params, block_hash);

            let debug_request = json!({
                "jsonrpc": "2.0",
                "method": "debug_traceCall",
                "params": trace_params,
                "id": id
            });

            batch.push(debug_request);
            id += 1;

            // Create eth_call request for getting actual balance
            let eth_call_request = json!({
                "jsonrpc": "2.0",
                "method": "eth_call",
                "params": [
                    {
                        "to": format!("0x{}", alloy::hex::encode(token.as_ref())),
                        "data": format!("0x{}", alloy::hex::encode(calldata.as_ref()))
                    },
                    format!("0x{}", alloy::hex::encode(block_hash.as_ref()))
                ],
                "id": id
            });

            batch.push(eth_call_request);
            id += 1;
        }

        Value::Array(batch)
    }

    /// Send a batched JSON-RPC request with retry logic
    async fn send_batched_request(
        &self,
        batch_request: Value,
    ) -> Result<Vec<Value>, BalanceSlotError> {
        let mut attempt = 0;
        let mut last_error = None;

        while attempt < self.max_retries {
            // Calculate backoff with jitter
            if attempt > 0 {
                let backoff_ms = self.calculate_backoff(attempt);
                debug!(
                    attempt = attempt,
                    backoff_ms = backoff_ms,
                    "Retrying RPC request after backoff"
                );
                tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
            }

            match self
                .send_single_request(&batch_request)
                .await
            {
                Ok(response_json) => {
                    // Check if we got a valid JSON-RPC batch response
                    match response_json {
                        Value::Array(responses) => {
                            // Success - we got a properly formatted response
                            // Even if individual calls have errors, we don't retry
                            // because the node is working correctly
                            trace!("RPC request returned a response on attempt {}", attempt + 1);

                            let all_failed = responses
                                .iter()
                                .all(|r| r.get("error").is_some());

                            let has_retryable = responses.iter().any(|r| {
                                r.get("error")
                                    .is_some_and(Self::is_retryable_rpc_error)
                            });

                            // Retry if ALL responses failed (safety measure) OR if there are
                            // retryable errors
                            if all_failed || has_retryable {
                                // Log the RPC errors for debugging
                                let error_details: Vec<_> = responses
                                    .iter()
                                    .filter_map(|r| r.get("error"))
                                    .collect();
                                warn!(
                                    attempt = attempt + 1,
                                    errors = ?error_details,
                                    "Retrying batch request - all failed (safety) or has retryable errors"
                                );
                                attempt += 1;
                                continue;
                            }

                            return Ok(responses);
                        }
                        _ => {
                            // Malformed response - this is retryable
                            let error = BalanceSlotError::InvalidResponse(
                                "Expected array response for batched request".into(),
                            );
                            warn!(
                                attempt = attempt + 1,
                                error = %error,
                                actual_response = %serde_json::to_string(&response_json).unwrap_or_else(|_| "Unable to serialize response".to_string()),
                                "Received malformed response, will retry"
                            );
                            last_error = Some(error);
                        }
                    }
                }
                Err(e) => {
                    // Network/HTTP error - this is retryable
                    warn!(
                        attempt = attempt + 1,
                        error = %e,
                        "RPC request failed, will retry"
                    );
                    last_error = Some(e);
                }
            }

            attempt += 1;
        }

        // All retries exhausted
        error!("All {} retry attempts failed for RPC request", self.max_retries);
        Err(last_error
            .unwrap_or_else(|| BalanceSlotError::RequestError("All retry attempts failed".into())))
    }

    /// Send a single request without retry
    async fn send_single_request(&self, batch_request: &Value) -> Result<Value, BalanceSlotError> {
        let response = self
            .http_client
            .post(self.rpc_url.as_str())
            .header("Content-Type", "application/json")
            .body(serde_json::to_string(batch_request).unwrap())
            .send()
            .await
            .map_err(|e| BalanceSlotError::RequestError(format!("HTTP request failed: {e}")))?;

        let response_json = response
            .json()
            .await
            .map_err(|e| BalanceSlotError::InvalidResponse(format!("Failed to parse JSON: {e}")))?;

        Ok(response_json)
    }

    /// Check if an RPC error should be retried based on its error code
    /// Retryable errors are typically transient issues that may resolve on retry
    fn is_retryable_rpc_error(error: &Value) -> bool {
        if let Some(code) = error
            .get("code")
            .and_then(|c| c.as_i64())
        {
            match code {
                // Retryable errors (transient issues)
                -32000 => true, // "header not found" - block may not be available yet
                -32005 => true, // "limit exceeded" - rate limiting, backoff and retry
                -32603 => true, // "internal error" - temporary server issue

                // Non-retryable errors (permanent issues)
                -32600 => false, // "invalid request" - malformed request
                -32601 => false, // "method not found" - method doesn't exist
                -32602 => false, // "invalid params" - wrong parameters
                -32604 => false, // "method not supported" - not supported by this node

                // Default: retry unknown error codes (conservative approach)
                _ => true,
            }
        } else {
            // No error code found - retry to be safe
            true
        }
    }

    /// Calculate exponential backoff with jitter.
    /// Jitter prevents all clients from retrying simultaneously and crashing the recovering service
    fn calculate_backoff(&self, attempt: usize) -> u64 {
        use rand::Rng;

        // Calculate base exponential backoff: initial * 2^(attempt-1)
        let base_backoff = self
            .initial_backoff_ms
            .saturating_mul(1 << (attempt - 1));

        // Cap at max_backoff_ms
        let capped_backoff = base_backoff.min(self.max_backoff_ms);

        // Add jitter (0-25% of the backoff time)
        let jitter = rand::thread_rng().gen_range(0..=capped_backoff / 4);

        capped_backoff + jitter
    }

    /// Process batched responses and extract storage slots for each token
    fn process_batched_response(
        &self,
        tokens: &[Address],
        responses: Vec<Value>,
    ) -> TokenSlotResults {
        // Create a map of response ID to response for out-of-order handling
        // (can't trust RPC return ordering)
        let mut id_to_response = HashMap::new();
        for response in responses {
            if let Some(id) = response
                .get("id")
                .and_then(|v| v.as_u64())
            {
                id_to_response.insert(id, response);
            }
        }

        let mut token_slots = HashMap::new();

        for (token_idx, token) in tokens.iter().enumerate() {
            // Calculate expected response IDs for this token
            let debug_id = (token_idx * 2 + 1) as u64;
            let eth_call_id = (token_idx * 2 + 2) as u64;

            match self.extract_slot_from_paired_responses(
                token,
                id_to_response.get(&debug_id),
                id_to_response.get(&eth_call_id),
            ) {
                Ok(slot) => {
                    debug!(
                        token = %token,
                        slot = ?slot,
                        "Found storage slot for token"
                    );
                    token_slots.insert(token.clone(), Ok(slot));
                }
                Err(e) => {
                    error!(token = %token, error = %e, "Failed to extract slot for token");
                    token_slots.insert(token.clone(), Err(e));
                }
            }
        }

        token_slots
    }

    /// Extract storage slot from paired debug_traceCall and eth_call responses
    /// Returns A Tuple of Storage slot (Address and Slot) and the target Balance.
    fn extract_slot_from_paired_responses(
        &self,
        token: &Address,
        debug_response: Option<&Value>,
        eth_call_response: Option<&Value>,
    ) -> Result<SlotDetectionResult, BalanceSlotError> {
        let debug_resp = debug_response.ok_or_else(|| {
            BalanceSlotError::InvalidResponse("Missing debug_traceCall response".into())
        })?;

        let eth_call_resp = eth_call_response
            .ok_or_else(|| BalanceSlotError::InvalidResponse("Missing eth_call response".into()))?;

        // Check for errors in responses
        if let Some(error) = debug_resp.get("error") {
            warn!("Debug trace failed for token {}: {}", token, error);
            return Err(BalanceSlotError::RequestError(error.to_string()));
        }

        if let Some(error) = eth_call_resp.get("error") {
            warn!("Eth call failed for token {}: {}", token, error);
            return Err(BalanceSlotError::RequestError(error.to_string()));
        }

        // Extract balance from eth_call response
        let balance = self.extract_balance_from_call_response(eth_call_resp)?;

        // Extract slot values from debug_traceCall response for better slot selection
        let slot_values = self.extract_slot_values_from_trace_response(debug_resp)?;

        // Find the best slot by comparing values to the expected balance
        self.find_best_slot_by_value_comparison(slot_values, balance)
    }

    /// Extract balance from eth_call response
    fn extract_balance_from_call_response(
        &self,
        response: &Value,
    ) -> Result<U256, BalanceSlotError> {
        let result = response
            .get("result")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                BalanceSlotError::InvalidResponse("Missing result in eth_call".into())
            })?;

        let hex_str = result
            .strip_prefix("0x")
            .unwrap_or(result);
        if hex_str.len() != 64 {
            return Err(BalanceSlotError::BalanceExtractionError(format!(
                "Invalid result length: {} (expected 64)",
                hex_str.len()
            )));
        }

        U256::from_str_radix(hex_str, 16)
            .map_err(|e| BalanceSlotError::BalanceExtractionError(e.to_string()))
    }

    /// Extract accessed slots with their values from debug_traceCall response for better slot
    /// selection
    fn extract_slot_values_from_trace_response(
        &self,
        response: &Value,
    ) -> Result<SlotValues, BalanceSlotError> {
        let result = response.get("result").ok_or_else(|| {
            BalanceSlotError::InvalidResponse("Missing result in debug_traceCall".into())
        })?;

        // The debug_traceCall with prestateTracer returns the result directly as a hashmap
        let frame_map: std::collections::BTreeMap<Address, serde_json::Value> =
            match serde_json::from_value(result.clone()) {
                Ok(map) => map,
                Err(e) => {
                    error!("Failed to parse trace result as hashmap: {}", e);
                    return Err(BalanceSlotError::ParseError(format!(
                        "Failed to parse trace result: {e}"
                    )));
                }
            };

        let mut slot_values = Vec::new();

        for (address, account_data) in frame_map {
            // Extract storage from the account data
            if let Some(storage_obj) = account_data.get("storage") {
                if let Some(storage_map) = storage_obj.as_object() {
                    for (slot_key, slot_value) in storage_map {
                        // Decode slot key
                        let slot_hex = slot_key
                            .strip_prefix("0x")
                            .unwrap_or(slot_key);
                        let slot_bytes = match alloy::hex::decode(slot_hex) {
                            Ok(bytes) => Bytes::from(bytes),
                            Err(_) => {
                                warn!("Failed to decode slot key: {}", slot_key);
                                continue;
                            }
                        };

                        // Decode slot value
                        if let Some(value_str) = slot_value.as_str() {
                            let value_hex = value_str
                                .strip_prefix("0x")
                                .unwrap_or(value_str);
                            match U256::from_str_radix(value_hex, 16) {
                                Ok(value) => {
                                    slot_values.push(((address.clone(), slot_bytes), value));
                                }
                                Err(_) => {
                                    warn!("Failed to decode slot value: {}", value_str);
                                }
                            }
                        }
                    }
                    break;
                }
            } else {
                debug!("No storage field found for address {}", address);
            }
        }

        Ok(slot_values)
    }

    /// Find the best slot by comparing storage values to the expected balance. Select the value
    /// that is closest to the expected balance.
    fn find_best_slot_by_value_comparison(
        &self,
        slot_values: SlotValues,
        expected_balance: U256,
    ) -> Result<SlotDetectionResult, BalanceSlotError> {
        let slot_count = slot_values.len();

        match slot_count {
            0 => {
                debug!("No storage slots found in trace");
                Err(BalanceSlotError::TokenNotInTrace)
            }
            1 => {
                let slot = slot_values
                    .into_iter()
                    .next()
                    .unwrap()
                    .0;
                debug!("Single slot found, returning: {:?}", slot);
                Ok((slot, expected_balance))
            }
            _ => {
                // Find the slot with minimum difference to the expected balance
                let (best_slot, best_value, best_diff) = slot_values
                    .into_iter()
                    .map(|(slot, value)| {
                        let diff = value.abs_diff(expected_balance);
                        (slot, value, diff)
                    })
                    .min_by_key(|(_, _, diff)| *diff)
                    .expect("slot_values is not empty (checked above)");

                debug!(
                    "Found {} slots, selected best slot: Address=0x{} Slot=0x{} (value: {}, diff: {})",
                    slot_count,
                    alloy::hex::encode(best_slot.0.as_ref()),
                    alloy::hex::encode(best_slot.1.as_ref()),
                    best_value,
                    best_diff
                );

                Ok((best_slot, expected_balance))
            }
        }
    }

    /// Validates if the detected storage slots are correct.
    /// Sends batched eth_call requests with storage slot overrides to verify the slots work.
    /// If the value changes with the override, the slot is correct.
    /// If not, returns a WrongSlotError for that token.
    async fn validate_best_slots(
        &self,
        token_slots: TokenSlotResults,
        owner: &Address,
        block_hash: &BlockHash,
    ) -> TokenSlotResults {
        // Separate successful detections from errors
        let mut validated_results = HashMap::new();
        let mut validation_data = Vec::new();

        for (token, result) in token_slots {
            match result {
                Ok(((storage_addr, slot), original_balance)) => {
                    validation_data.push(ValidationData {
                        token,
                        storage_addr,
                        slot,
                        original_balance,
                        test_value: Self::generate_test_value(original_balance),
                    });
                }
                Err(e) => {
                    validated_results.insert(token, Err(e));
                }
            }
        }

        if validation_data.is_empty() {
            return validated_results;
        }

        // Create validation requests with storage overrides
        let requests = match self.create_validation_requests(&validation_data, owner, block_hash) {
            Ok(requests) => requests,
            Err(e) => {
                // If we can't create requests, mark all as failed
                for data in validation_data {
                    validated_results.insert(
                        data.token,
                        Err(BalanceSlotError::RequestError(format!(
                            "Failed to create validation request: {e}"
                        ))),
                    );
                }
                return validated_results;
            }
        };

        // Send batched request
        let responses = match self
            .send_batched_request(requests)
            .await
        {
            Ok(responses) => responses,
            Err(e) => {
                // If request fails, mark all as failed, since it has already exhausted retries.
                for data in validation_data {
                    validated_results.insert(
                        data.token,
                        Err(BalanceSlotError::RequestError(format!(
                            "Validation request failed: {e}"
                        ))),
                    );
                }
                return validated_results;
            }
        };

        // Process validation responses
        self.process_validation_responses(responses, validation_data, &mut validated_results);

        validated_results
    }

    /// Generate a test value for validation that's different from the original
    fn generate_test_value(original_balance: U256) -> U256 {
        if !original_balance.is_zero() && original_balance != U256::MAX {
            // Set to a different value (double the original) - this function caps to U256::MAX so
            // no overflow can happen.
            original_balance.saturating_mul(U256::from(2))
        } else {
            // If original is 0, set to a non-zero value (1 ETH in wei)
            U256::from(1_000_000_000_000_000_000u64)
        }
    }

    /// Create eth_call requests with storage overrides for validation
    fn create_validation_requests(
        &self,
        validation_data: &[ValidationData],
        owner: &Address,
        block_hash: &BlockHash,
    ) -> Result<Value, BalanceSlotError> {
        let mut batch = Vec::new();

        for (id, data) in validation_data.iter().enumerate() {
            let calldata = encode_balance_of_calldata(owner);

            // Format the override value as a 32-byte hex string
            let test_value_hex = format!("0x{:064x}", data.test_value);
            let slot_hex = format!("0x{}", alloy::hex::encode(data.slot.as_ref()));

            // Create eth_call with state override
            let request = json!({
                "jsonrpc": "2.0",
                "method": "eth_call",
                "params": [
                    {
                        "to": format!("0x{}", alloy::hex::encode(data.token.as_ref())),
                        "data": format!("0x{}", alloy::hex::encode(calldata.as_ref()))
                    },
                    format!("0x{}", alloy::hex::encode(block_hash.as_ref())),
                    {
                        format!("0x{}", alloy::hex::encode(data.storage_addr.as_ref())): {
                            "stateDiff": {
                                slot_hex: test_value_hex
                            }
                        }
                    }
                ],
                "id": (id + 1) as u64
            });

            batch.push(request);
        }

        Ok(Value::Array(batch))
    }

    /// Process validation responses and update results
    fn process_validation_responses(
        &self,
        responses: Vec<Value>,
        validation_data: Vec<ValidationData>,
        results: &mut TokenSlotResults,
    ) {
        // Create ID to response mapping
        let mut id_to_response = HashMap::new();
        for response in responses {
            if let Some(id) = response
                .get("id")
                .and_then(|v| v.as_u64())
            {
                id_to_response.insert(id, response);
            }
        }

        // Process each validation
        for (idx, data) in validation_data.into_iter().enumerate() {
            let response_id = (idx + 1) as u64;

            match id_to_response.get(&response_id) {
                Some(response) => {
                    // Check for errors
                    if let Some(error) = response.get("error") {
                        results.insert(
                            data.token,
                            Err(BalanceSlotError::RequestError(format!(
                                "Validation call failed: {error}",
                            ))),
                        );
                        continue;
                    }

                    // Extract the balance from the response
                    match self.extract_balance_from_call_response(response) {
                        Ok(returned_balance) => {
                            // Check if the override worked (balance should be different from
                            // original_balance). We can't guarantee that it will match the override
                            // value, as some tokens use shares systems, making it hard to control
                            // the balance with a single override.
                            if returned_balance != data.original_balance {
                                // Validation successful - the slot works
                                debug!(
                                    token = %data.token,
                                    storage = %data.storage_addr,
                                    slot = %alloy::hex::encode(data.slot.as_ref()),
                                    returned_balance = %returned_balance,
                                    original_balance = %data.original_balance,
                                    "Storage slot validated successfully"
                                );
                                results.insert(
                                    data.token,
                                    Ok(((data.storage_addr, data.slot), data.original_balance)),
                                );
                            } else {
                                // The override didn't work - wrong slot detected
                                warn!(
                                    token = %data.token,
                                    storage = %data.storage_addr,
                                    slot = %alloy::hex::encode(data.slot.as_ref()),
                                    expected = %data.test_value,
                                    got = %returned_balance,
                                    "Storage slot validation failed - value didn't change as expected"
                                );
                                results.insert(
                                    data.token,
                                    Err(BalanceSlotError::WrongSlotError(
                                        "Slot override didn't change balance.".to_string(),
                                    )),
                                );
                            }
                        }
                        Err(e) => {
                            results.insert(
                                data.token,
                                Err(BalanceSlotError::InvalidResponse(format!(
                                    "Failed to extract balance from validation response: {e}"
                                ))),
                            );
                        }
                    }
                }
                None => {
                    results.insert(
                        data.token,
                        Err(BalanceSlotError::InvalidResponse(
                            "Missing validation response".into(),
                        )),
                    );
                }
            }
        }
    }
}

/// Implement the BalanceSlotDetector trait
#[async_trait]
impl BalanceSlotDetector for EVMBalanceSlotDetector {
    type Error = BalanceSlotError;

    /// Detect balance storage slots for multiple tokens using a combination of batched and async
    /// concurrent requests.
    async fn detect_balance_slots(
        &self,
        tokens: &[Address],
        holder: Address,
        block_hash: BlockHash,
    ) -> HashMap<Address, Result<(Address, Bytes), Self::Error>> {
        info!("Starting balance slot detection for {} tokens", tokens.len());

        let mut all_results = HashMap::new();

        // Batch tokens into chunks to optimize, while avoiding being rate limited. Each token
        // spawns up to 2 requests in a single batch.
        for (chunk_idx, chunk) in tokens
            .chunks(self.max_batch_size)
            .enumerate()
        {
            debug!("Processing chunk {} with {} tokens", chunk_idx, chunk.len());

            let chunk_results = self
                .detect_token_slots(chunk, &holder, &block_hash)
                .await;

            // Merge chunk results into all_results
            all_results.extend(chunk_results);
        }

        info!("Balance slot detection completed. Found results for {} tokens", all_results.len());
        all_results
    }
}

/// Encode balanceOf(address) calldata
pub fn encode_balance_of_calldata(address: &Address) -> Bytes {
    // balanceOf selector: 0x70a08231
    let mut calldata = vec![0x70, 0xa0, 0x82, 0x31];

    // Pad address to 32 bytes (12 bytes of zeros + 20 bytes address)
    calldata.extend_from_slice(&[0u8; 12]);
    calldata.extend_from_slice(address.as_ref());

    Bytes::from(calldata)
}

#[cfg(test)]
mod tests {
    use mockito::Server;

    use super::*;

    #[test]
    fn test_encode_balance_of_calldata() {
        let address = Address::from([0x12u8; 20]);
        let calldata = encode_balance_of_calldata(&address);

        // Verify selector
        assert_eq!(&calldata[0..4], &[0x70, 0xa0, 0x82, 0x31]);

        // Verify total length (4 bytes selector + 32 bytes padded address)
        assert_eq!(calldata.len(), 36);

        // Verify padding
        assert_eq!(&calldata[4..16], &[0u8; 12]);

        // Verify address
        assert_eq!(&calldata[16..36], address.as_ref());
    }

    // Test helper to create mock trace response with storage slots
    fn create_mock_trace_response(storage_slots: Vec<(&str, &str, &str)>) -> Value {
        let mut storage_map = serde_json::Map::new();

        for (address, slot, value) in storage_slots {
            let address_key = format!(
                "0x{}",
                address
                    .strip_prefix("0x")
                    .unwrap_or(address)
            );
            let slot_key = format!("0x{}", slot.strip_prefix("0x").unwrap_or(slot));

            if !storage_map.contains_key(&address_key) {
                storage_map.insert(
                    address_key.clone(),
                    json!({
                        "storage": {
                            slot_key: value
                        }
                    }),
                );
            } else if let Some(account) = storage_map.get_mut(&address_key) {
                if let Some(storage) = account.get_mut("storage") {
                    if let Some(storage_obj) = storage.as_object_mut() {
                        storage_obj.insert(slot_key, json!(value));
                    }
                }
            }
        }

        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": storage_map
        })
    }

    // Test helper to create mock eth_call response
    fn create_mock_call_response(balance: &str) -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "result": balance
        })
    }

    // Test helper to create error response
    fn create_error_response(id: u64, error_msg: &str) -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {
                "code": -32000,
                "message": error_msg
            }
        })
    }

    #[test]
    fn test_calculate_backoff() {
        let config = BalanceSlotDetectorConfig {
            max_batch_size: 10,
            rpc_url: "http://localhost:8545".to_string(),
            max_retries: 3,
            initial_backoff_ms: 100,
            max_backoff_ms: 5000,
        };

        let detector = EVMBalanceSlotDetector::new(config).unwrap();

        // Test exponential backoff
        let backoff1 = detector.calculate_backoff(1);
        assert!((100..=125).contains(&backoff1)); // 100ms + up to 25% jitter

        let backoff2 = detector.calculate_backoff(2);
        assert!((200..=250).contains(&backoff2)); // 200ms + up to 25% jitter

        let backoff3 = detector.calculate_backoff(3);
        assert!((400..=500).contains(&backoff3)); // 400ms + up to 25% jitter

        // Test max cap
        let backoff_large = detector.calculate_backoff(10);
        assert!(backoff_large <= 5000 + 1250); // Max 5000ms + 25% jitter
    }

    #[test]
    fn test_generate_test_value() {
        // Test non-zero, non-max value
        let original = U256::from(1000u64);
        let test_value = EVMBalanceSlotDetector::generate_test_value(original);
        assert_eq!(test_value, U256::from(2000u64));

        // Test zero value
        let zero = U256::ZERO;
        let test_value = EVMBalanceSlotDetector::generate_test_value(zero);
        assert_eq!(test_value, U256::from(1_000_000_000_000_000_000u64));

        // Test max value - falls into else branch since original_balance == U256::MAX
        let max = U256::MAX;
        let test_value = EVMBalanceSlotDetector::generate_test_value(max);
        assert_eq!(test_value, U256::from(1_000_000_000_000_000_000u64)); // Returns 1 ETH for MAX
    }

    #[test]
    fn test_extract_balance_from_call_response() {
        let config = BalanceSlotDetectorConfig {
            max_batch_size: 10,
            rpc_url: "http://localhost:8545".to_string(),
            max_retries: 3,
            initial_backoff_ms: 100,
            max_backoff_ms: 5000,
        };
        let detector = EVMBalanceSlotDetector::new(config).unwrap();

        // Test valid response
        let response = json!({
            "result": "0x0000000000000000000000000000000000000000000000000de0b6b3a7640000"
        });
        let balance = detector
            .extract_balance_from_call_response(&response)
            .unwrap();
        assert_eq!(balance, U256::from(1_000_000_000_000_000_000u64)); // 1 ETH

        // Test missing result
        let response = json!({});
        let result = detector.extract_balance_from_call_response(&response);
        assert!(matches!(result, Err(BalanceSlotError::InvalidResponse(_))));

        // Test invalid hex length
        let response = json!({
            "result": "0x1234"
        });
        let result = detector.extract_balance_from_call_response(&response);
        assert!(matches!(result, Err(BalanceSlotError::BalanceExtractionError(_))));

        // Test invalid hex characters
        let response = json!({
            "result": "0xGGGG000000000000000000000000000000000000000000000000000000000000"
        });
        let result = detector.extract_balance_from_call_response(&response);
        assert!(matches!(result, Err(BalanceSlotError::BalanceExtractionError(_))));
    }

    #[test]
    fn test_extract_slot_values_from_trace_response() {
        let config = BalanceSlotDetectorConfig {
            max_batch_size: 10,
            rpc_url: "http://localhost:8545".to_string(),
            max_retries: 3,
            initial_backoff_ms: 100,
            max_backoff_ms: 5000,
        };
        let detector = EVMBalanceSlotDetector::new(config).unwrap();

        // Test valid trace with storage
        let response = json!({
            "result": {
                "0x1234567890123456789012345678901234567890": {
                    "storage": {
                        "0x0000000000000000000000000000000000000000000000000000000000000001": "0x0000000000000000000000000000000000000000000000000de0b6b3a7640000",
                        "0x0000000000000000000000000000000000000000000000000000000000000002": "0x0000000000000000000000000000000000000000000000001bc16d674ec80000"
                    }
                }
            }
        });

        let slot_values = detector
            .extract_slot_values_from_trace_response(&response)
            .unwrap();
        assert_eq!(slot_values.len(), 2);

        // Verify first slot
        let first_slot = &slot_values[0];
        assert_eq!(first_slot.1, U256::from(1_000_000_000_000_000_000u64));

        // Verify second slot
        let second_slot = &slot_values[1];
        assert_eq!(second_slot.1, U256::from(2_000_000_000_000_000_000u64));

        // Test missing result
        let response = json!({});
        let result = detector.extract_slot_values_from_trace_response(&response);
        assert!(matches!(result, Err(BalanceSlotError::InvalidResponse(_))));

        // Test malformed result
        let response = json!({
            "result": "not_an_object"
        });
        let result = detector.extract_slot_values_from_trace_response(&response);
        assert!(matches!(result, Err(BalanceSlotError::ParseError(_))));
    }

    #[test]
    fn test_find_best_slot_by_value_comparison() {
        let config = BalanceSlotDetectorConfig {
            max_batch_size: 10,
            rpc_url: "http://localhost:8545".to_string(),
            max_retries: 3,
            initial_backoff_ms: 100,
            max_backoff_ms: 5000,
        };
        let detector = EVMBalanceSlotDetector::new(config).unwrap();

        let addr = Address::from([0x11u8; 20]);
        let slot1 = Bytes::from(vec![0x01u8; 32]);
        let slot2 = Bytes::from(vec![0x02u8; 32]);
        let slot3 = Bytes::from(vec![0x03u8; 32]);

        // Test single slot - should return it regardless of value
        let single_slot = vec![((addr.clone(), slot1.clone()), U256::from(500u64))];
        let result = detector
            .find_best_slot_by_value_comparison(single_slot, U256::from(1000u64))
            .unwrap();
        assert_eq!(result.0, (addr.clone(), slot1.clone()));
        assert_eq!(result.1, U256::from(1000u64));

        // Test multiple slots - should return closest to expected
        let multiple_slots = vec![
            ((addr.clone(), slot1.clone()), U256::from(500u64)),
            ((addr.clone(), slot2.clone()), U256::from(900u64)),
            ((addr.clone(), slot3.clone()), U256::from(1500u64)),
        ];
        let result = detector
            .find_best_slot_by_value_comparison(multiple_slots, U256::from(1000u64))
            .unwrap();
        assert_eq!(result.0, (addr.clone(), slot2)); // slot2 has value 900, closest to 1000

        // Test empty slots
        let empty_slots = vec![];
        let result = detector.find_best_slot_by_value_comparison(empty_slots, U256::from(1000u64));
        assert!(matches!(result, Err(BalanceSlotError::TokenNotInTrace)));
    }

    #[test]
    fn test_process_batched_response() {
        let config = BalanceSlotDetectorConfig {
            max_batch_size: 10,
            rpc_url: "http://localhost:8545".to_string(),
            max_retries: 3,
            initial_backoff_ms: 100,
            max_backoff_ms: 5000,
        };
        let detector = EVMBalanceSlotDetector::new(config).unwrap();

        let token1 = Address::from([0x11u8; 20]);
        let token2 = Address::from([0x22u8; 20]);

        // Create responses with proper IDs (out of order to test ID mapping)
        let responses = vec![
            json!({
                "id": 2,
                "result": "0x0000000000000000000000000000000000000000000000000de0b6b3a7640000"
            }),
            json!({
                "id": 1,
                "result": {
                    "0x1111111111111111111111111111111111111111": {
                        "storage": {
                            "0x0000000000000000000000000000000000000000000000000000000000000001": "0x0000000000000000000000000000000000000000000000000de0b6b3a7640000"
                        }
                    }
                }
            }),
            json!({
                "id": 4,
                "result": "0x0000000000000000000000000000000000000000000000001bc16d674ec80000"
            }),
            json!({
                "id": 3,
                "result": {
                    "0x2222222222222222222222222222222222222222": {
                        "storage": {
                            "0x0000000000000000000000000000000000000000000000000000000000000002": "0x0000000000000000000000000000000000000000000000001bc16d674ec80000"
                        }
                    }
                }
            }),
        ];

        let tokens = vec![token1.clone(), token2.clone()];
        let result = detector.process_batched_response(&tokens, responses);

        assert_eq!(result.len(), 2);
        assert!(result.contains_key(&token1));
        assert!(result.contains_key(&token2));

        // Verify token1 result
        let token1_result = result.get(&token1).unwrap();
        assert!(token1_result.is_ok());

        // Verify token2 result
        let token2_result = result.get(&token2).unwrap();
        assert!(token2_result.is_ok());
    }

    #[test]
    fn test_create_balance_requests() {
        let config = BalanceSlotDetectorConfig {
            max_batch_size: 10,
            rpc_url: "http://localhost:8545".to_string(),
            max_retries: 3,
            initial_backoff_ms: 100,
            max_backoff_ms: 5000,
        };
        let detector = EVMBalanceSlotDetector::new(config).unwrap();

        let token1 = Address::from([0x11u8; 20]);
        let token2 = Address::from([0x22u8; 20]);
        let owner = Address::from([0x33u8; 20]);
        let block_hash = BlockHash::from([0x44u8; 32]);

        let tokens = vec![token1, token2];
        let requests = detector.create_balance_requests(&tokens, &owner, &block_hash);

        // Should create 2 requests per token (debug_traceCall + eth_call)
        assert!(requests.is_array());
        let array = requests.as_array().unwrap();
        assert_eq!(array.len(), 4);

        // Verify first request (debug_traceCall for token1)
        assert_eq!(array[0]["method"], "debug_traceCall");
        assert_eq!(array[0]["id"], 1);

        // Verify second request (eth_call for token1)
        assert_eq!(array[1]["method"], "eth_call");
        assert_eq!(array[1]["id"], 2);

        // Verify third request (debug_traceCall for token2)
        assert_eq!(array[2]["method"], "debug_traceCall");
        assert_eq!(array[2]["id"], 3);

        // Verify fourth request (eth_call for token2)
        assert_eq!(array[3]["method"], "eth_call");
        assert_eq!(array[3]["id"], 4);
    }

    #[test]
    fn test_create_validation_requests() {
        let config = BalanceSlotDetectorConfig {
            max_batch_size: 10,
            rpc_url: "http://localhost:8545".to_string(),
            max_retries: 3,
            initial_backoff_ms: 100,
            max_backoff_ms: 5000,
        };
        let detector = EVMBalanceSlotDetector::new(config).unwrap();

        let validation_data = vec![
            ValidationData {
                token: Address::from([0x11u8; 20]),
                storage_addr: Address::from([0x11u8; 20]),
                slot: Bytes::from(vec![0x01u8; 32]),
                original_balance: U256::from(1000u64),
                test_value: U256::from(2000u64),
            },
            ValidationData {
                token: Address::from([0x22u8; 20]),
                storage_addr: Address::from([0x22u8; 20]),
                slot: Bytes::from(vec![0x02u8; 32]),
                original_balance: U256::from(3000u64),
                test_value: U256::from(6000u64),
            },
        ];

        let owner = Address::from([0x33u8; 20]);
        let block_hash = BlockHash::from([0x44u8; 32]);

        let requests = detector
            .create_validation_requests(&validation_data, &owner, &block_hash)
            .unwrap();

        assert!(requests.is_array());
        let array = requests.as_array().unwrap();
        assert_eq!(array.len(), 2);

        // Verify first validation request
        assert_eq!(array[0]["method"], "eth_call");
        assert_eq!(array[0]["id"], 1);

        // Check state override is present
        let params = array[0]["params"].as_array().unwrap();
        assert_eq!(params.len(), 3);
        assert!(params[2].is_object()); // State override object

        // Verify second validation request
        assert_eq!(array[1]["method"], "eth_call");
        assert_eq!(array[1]["id"], 2);
    }

    #[test]
    fn test_process_validation_responses() {
        let config = BalanceSlotDetectorConfig {
            max_batch_size: 10,
            rpc_url: "http://localhost:8545".to_string(),
            max_retries: 3,
            initial_backoff_ms: 100,
            max_backoff_ms: 5000,
        };
        let detector = EVMBalanceSlotDetector::new(config).unwrap();

        let validation_data = vec![
            ValidationData {
                token: Address::from([0x11u8; 20]),
                storage_addr: Address::from([0x11u8; 20]),
                slot: Bytes::from(vec![0x01u8; 32]),
                original_balance: U256::from(1000u64),
                test_value: U256::from(2000u64),
            },
            ValidationData {
                token: Address::from([0x22u8; 20]),
                storage_addr: Address::from([0x22u8; 20]),
                slot: Bytes::from(vec![0x02u8; 32]),
                original_balance: U256::from(3000u64),
                test_value: U256::from(6000u64),
            },
        ];

        // Create responses - first one changes (valid), second doesn't (invalid)
        let responses = vec![
            json!({
                "id": 1,
                "result": "0x00000000000000000000000000000000000000000000000000000000000007d0" // 2000 (changed)
            }),
            json!({
                "id": 2,
                "result": "0x0000000000000000000000000000000000000000000000000000000000000bb8" // 3000 (unchanged)
            }),
        ];

        let mut results = HashMap::new();
        detector.process_validation_responses(responses, validation_data, &mut results);

        assert_eq!(results.len(), 2);

        // First token should be valid (balance changed)
        let token1 = Address::from([0x11u8; 20]);
        assert!(results.get(&token1).unwrap().is_ok());

        // Second token should be invalid (balance didn't change)
        let token2 = Address::from([0x22u8; 20]);
        assert!(matches!(results.get(&token2).unwrap(), Err(BalanceSlotError::WrongSlotError(_))));
    }

    #[tokio::test]
    async fn test_detect_token_slots_with_cache() {
        let config = BalanceSlotDetectorConfig {
            max_batch_size: 10,
            rpc_url: "http://localhost:8545".to_string(),
            max_retries: 1,
            initial_backoff_ms: 10,
            max_backoff_ms: 100,
        };

        let detector = EVMBalanceSlotDetector::new(config).unwrap();

        let token1 = Address::from([0x11u8; 20]);
        let token2 = Address::from([0x22u8; 20]);
        let owner = Address::from([0x33u8; 20]);
        let block_hash = BlockHash::from([0x44u8; 32]);

        // Pre-populate cache for token1
        {
            let mut cache = detector.cache.write().await;
            cache.insert(
                (token1.clone(), owner.clone()),
                (Address::from([0x11u8; 20]), Bytes::from(vec![0x01u8; 32])),
            );
        }

        // Mock server would be needed for token2, but since we can't make real requests,
        // we'll test that token1 returns from cache
        let tokens = vec![token1.clone()];
        let results = detector
            .detect_token_slots(&tokens, &owner, &block_hash)
            .await;

        // Token1 should return cached value
        assert!(results.contains_key(&token1));
        let token1_result = results.get(&token1).unwrap();
        assert!(token1_result.is_ok());

        let (storage_addr, slot) = token1_result.as_ref().unwrap();
        assert_eq!(*storage_addr, Address::from([0x11u8; 20]));
        assert_eq!(*slot, Bytes::from(vec![0x01u8; 32]));
    }

    #[tokio::test]
    async fn test_send_batched_request_retry_logic() {
        let mut server = Server::new_async().await;
        let config = BalanceSlotDetectorConfig {
            max_batch_size: 10,
            rpc_url: server.url(),
            max_retries: 3,
            initial_backoff_ms: 10,
            max_backoff_ms: 100,
        };

        let detector = EVMBalanceSlotDetector::new(config).unwrap();

        // Create a simple batch request
        let batch_request = json!([
            {
                "jsonrpc": "2.0",
                "method": "eth_call",
                "params": [],
                "id": 1
            }
        ]);

        // First two attempts fail, third succeeds
        let _m1 = server
            .mock("POST", "/")
            .with_status(500)
            .expect(1)
            .create_async()
            .await;

        let _m2 = server
            .mock("POST", "/")
            .with_status(500)
            .expect(1)
            .create_async()
            .await;

        let _m3 = server
            .mock("POST", "/")
            .with_status(200)
            .with_body(r#"[{"jsonrpc":"2.0","id":1,"result":"0x1234"}]"#)
            .expect(1)
            .create_async()
            .await;

        let result = detector
            .send_batched_request(batch_request)
            .await;
        assert!(result.is_ok());

        let responses = result.unwrap();
        assert_eq!(responses.len(), 1);
        assert_eq!(responses[0]["result"], "0x1234");
    }

    #[tokio::test]
    async fn test_send_batched_request_max_retries_exceeded() {
        let mut server = Server::new_async().await;
        let config = BalanceSlotDetectorConfig {
            max_batch_size: 10,
            rpc_url: server.url(),
            max_retries: 2,
            initial_backoff_ms: 10,
            max_backoff_ms: 100,
        };

        let detector = EVMBalanceSlotDetector::new(config).unwrap();

        let batch_request = json!([
            {
                "jsonrpc": "2.0",
                "method": "eth_call",
                "params": [],
                "id": 1
            }
        ]);

        // All attempts fail
        let _m = server
            .mock("POST", "/")
            .with_status(500)
            .expect(2)
            .create_async()
            .await;

        let result = detector
            .send_batched_request(batch_request)
            .await;
        assert!(result.is_err());
        // The error can be either RequestError (if the request itself fails) or
        // InvalidResponse (if the response body can't be parsed as JSON)
        assert!(matches!(
            result,
            Err(BalanceSlotError::RequestError(_)) | Err(BalanceSlotError::InvalidResponse(_))
        ));
    }

    #[tokio::test]
    #[ignore = "require RPC connection"]
    async fn test_detect_slots_integration() {
        let rpc_url = std::env::var("RPC_URL").expect("RPC_URL must be set");
        println!("Using RPC URL: {}", rpc_url);
        let config = BalanceSlotDetectorConfig {
            max_batch_size: 5,
            rpc_url,
            max_retries: 3,
            initial_backoff_ms: 100,
            max_backoff_ms: 5000,
        };

        // Use real token addresses and block for testing (WETH, USDC)
        let weth_bytes = alloy::hex::decode("C02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2").unwrap();
        let usdc_bytes = alloy::hex::decode("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48").unwrap();
        let usdt_bytes = alloy::hex::decode("0xdAC17F958D2ee523a2206206994597C13D831ec7").unwrap();

        let pool_manager_bytes =
            alloy::hex::decode("000000000004444c5dc75cB358380D2e3dE08A90").unwrap();

        let weth = Address::from(weth_bytes);
        let usdc = Address::from(usdc_bytes);
        let usdt = Address::from(usdt_bytes);

        let pool_manager = Address::from(pool_manager_bytes);

        println!("WETH address: 0x{}", alloy::hex::encode(weth.as_ref()));
        println!("USDC address: 0x{}", alloy::hex::encode(usdc.as_ref()));
        println!("USDT address: 0x{}", alloy::hex::encode(usdt.as_ref()));

        println!("Pool manager address: 0x{}", alloy::hex::encode(pool_manager.as_ref()));

        let tokens = vec![weth.clone(), usdc.clone(), usdt.clone()];

        // Use a recent block
        let block_hash_bytes =
            alloy::hex::decode("658814e4cb074359f10dd71237cc57b1ae6791fc9de59fde570e724bd884cbb0")
                .unwrap();
        let block_hash = BlockHash::from(block_hash_bytes);
        println!("Block hash: 0x{}", alloy::hex::encode(block_hash.as_ref()));

        let mut detector = EVMBalanceSlotDetector::new(config).unwrap();
        let results = detector
            .detect_balance_slots(&tokens, pool_manager, block_hash)
            .await;

        println!("Results: {:?}", results);
        println!("Number of tokens with results: {}", results.len());

        // We should get results for the tokens
        assert!(!results.is_empty(), "Expected results for at least one token, but got none");

        // Check individual tokens
        if let Some(weth_result) = results.get(&weth) {
            match weth_result {
                Ok((storage_addr, slot)) => {
                    println!(
                        "WETH slot detected - Storage: 0x{}, Slot: 0x{}",
                        alloy::hex::encode(storage_addr.as_ref()),
                        alloy::hex::encode(slot.as_ref())
                    );
                }
                Err(e) => panic!("Failed to detect WETH slot: {}", e),
            }
        } else {
            panic!("No result for WETH token");
        }

        if let Some(usdc_result) = results.get(&usdc) {
            match usdc_result {
                Ok((storage_addr, slot)) => {
                    println!(
                        "USDC slot detected - Storage: 0x{}, Slot: 0x{}",
                        alloy::hex::encode(storage_addr.as_ref()),
                        alloy::hex::encode(slot.as_ref())
                    );
                }
                Err(e) => panic!("Failed to detect USDC slot: {}", e),
            }
        } else {
            panic!("No result for USDC token");
        }

        if let Some(usdt_result) = results.get(&usdt) {
            match usdt_result {
                Ok((storage_addr, slot)) => {
                    println!(
                        "USDT slot detected - Storage: 0x{}, Slot: 0x{}",
                        alloy::hex::encode(storage_addr.as_ref()),
                        alloy::hex::encode(slot.as_ref())
                    );
                }
                Err(e) => panic!("Failed to detect USDT slot: {}", e),
            }
        } else {
            panic!("No result for USDT token");
        }
    }

    #[tokio::test]
    #[ignore] // Requires real RPC connection
    async fn test_detect_slots_rebasing_token() {
        let rpc_url = std::env::var("RPC_URL").expect("RPC_URL must be set");
        let config = BalanceSlotDetectorConfig {
            max_batch_size: 5,
            rpc_url,
            max_retries: 3,
            initial_backoff_ms: 100,
            max_backoff_ms: 5000,
        };

        // stETH contract address (Lido Staked Ether)
        let steth_bytes = alloy::hex::decode("ae7ab96520DE3A18E5e111B5EaAb095312D7fE84").unwrap();
        let steth = Address::from(steth_bytes);

        // Address extracted from stETH events. Verified that it has funds
        let owner_address = alloy::hex::decode("ef417FCE1883c6653E7dC6AF7c6F85CCDE84Aa09").unwrap();
        let balance_owner = Address::from(owner_address);

        let tokens = vec![steth.clone()];

        // Use a recent block where stETH has activity
        let block_hash_bytes =
            alloy::hex::decode("658814e4cb074359f10dd71237cc57b1ae6791fc9de59fde570e724bd884cbb0")
                .unwrap();
        let block_hash = BlockHash::from(block_hash_bytes);

        let mut detector = EVMBalanceSlotDetector::new(config).unwrap();
        let results = detector
            .detect_balance_slots(&tokens, balance_owner.clone(), block_hash.clone())
            .await;

        dbg!(&results);

        // For rebasing tokens like stETH, we expect multiple slots to be accessed
        // because balanceOf() needs to:
        // 1. Read the shares mapping for the holder
        // 2. Read total shares value (stored at TOTAL_SHARES_POSITION)
        // 3. Read total pooled ether to calculate the rate
        if let Some(result) = results.get(&steth) {
            if let Ok((storage_addr, detected_slot)) = result {
                println!(
                    "Detected stETH storage slot - Storage: 0x{}, Slot: 0x{}",
                    alloy::hex::encode(storage_addr.as_ref()),
                    alloy::hex::encode(detected_slot.as_ref())
                );

                // Convert to hex string for verification
                let slot_hex = alloy::hex::encode(detected_slot.as_ref());
                println!("stETH slot hex: 0x{}", slot_hex);

                // Now verify the detected slot by setting it to a specific value and checking
                // balanceOf
                let target_balance = U256::from(5000000000000000000u64); // 5 ETH in wei. Without overrides
                let verified_balance = verify_storage_slot_manipulation(
                    &detector,
                    &steth,
                    &balance_owner,
                    detected_slot,
                    target_balance,
                    &block_hash,
                )
                .await
                .expect("Storage slot verification should succeed");

                // Convert U256 to f64 for display
                let target_eth = target_balance.to::<u128>() as f64 / 1e18;
                let verified_eth = verified_balance.to::<u128>() as f64 / 1e18;
                println!("Target balance: {:.6} ETH", target_eth);
                println!("Verified balance: {:.6} ETH", verified_eth);

                // For stETH, due to the shares system, we expect the actual balance to be
                // equal to or higher than our target (shares are converted to ETH)
                // Expected 6.064202 ETH
                let expected_eth = U256::from(6064202338070893051u128);

                assert_eq!(
                    verified_balance, expected_eth,
                    "Verified balance ({}) should be == expected balance ({})",
                    verified_balance, expected_eth
                );

                println!("✓ Storage slot manipulation verified successfully!");

                // Check if this matches known stETH storage positions:
                let expected_slot =
                    "28b290becf7be0019520d491d9cd869337f3d683be3e569e54f9044b94df94c0";

                assert_eq!(slot_hex, expected_slot);
            } else if let Err(e) = result {
                // If no slot detected, print debug info
                println!("Failed to detect slots for stETH: {} - this might indicate the balance owner has no stETH balance", e);
            }
        } else {
            panic!("No result for stETH token");
        }
    }

    /// Verify that a detected storage slot can be manipulated to achieve a target balance
    async fn verify_storage_slot_manipulation(
        detector: &EVMBalanceSlotDetector,
        token: &Address,
        balance_owner: &Address,
        detected_slot: &Bytes,
        target_balance: U256,
        block_hash: &BlockHash,
    ) -> Result<U256, BalanceSlotError> {
        let slot_hex = alloy::hex::encode(detected_slot.as_ref());
        let target_hex = format!("0x{:064x}", target_balance);

        println!("Setting storage slot 0x{} to value {}", slot_hex, target_hex);

        let calldata = encode_balance_of_calldata(balance_owner);

        // This would need to be enhanced to return the actual call result
        // For now, fall back to direct RPC call
        let request = json!({
            "jsonrpc": "2.0",
            "method": "eth_call",
            "params": [
                {
                    "to": format!("0x{}", alloy::hex::encode(token.as_ref())),
                    "data": format!("0x{}", alloy::hex::encode(calldata.as_ref()))
                },
                format!("0x{}", alloy::hex::encode(block_hash.as_ref())),
                {
                    format!("0x{}", alloy::hex::encode(token.as_ref())): {
                        "stateDiff": {
                            format!("0x{}", slot_hex): target_hex
                        }
                    }
                }
            ],
            "id": 1
        });

        let client = reqwest::Client::new();
        let response = client
            .post(detector.rpc_url.as_str())
            .header("Content-Type", "application/json")
            .body(serde_json::to_string(&request).unwrap())
            .send()
            .await
            .map_err(|e| BalanceSlotError::RequestError(e.to_string()))?;

        let response_json: serde_json::Value = response
            .json()
            .await
            .map_err(|e| BalanceSlotError::InvalidResponse(e.to_string()))?;

        if let Some(error) = response_json.get("error") {
            return Err(BalanceSlotError::RequestError(format!("RPC error: {}", error)));
        }

        let result = response_json
            .get("result")
            .and_then(|v| v.as_str())
            .ok_or_else(|| BalanceSlotError::InvalidResponse("Missing result".into()))?;

        let hex_str = result
            .strip_prefix("0x")
            .unwrap_or(result);
        if hex_str.len() != 64 {
            return Err(BalanceSlotError::BalanceExtractionError(format!(
                "Invalid result length: {} (expected 64)",
                hex_str.len()
            )));
        }

        U256::from_str_radix(hex_str, 16)
            .map_err(|e| BalanceSlotError::BalanceExtractionError(e.to_string()))
    }

    #[test]
    fn test_is_retryable_rpc_error() {
        // Test retryable error codes
        assert!(EVMBalanceSlotDetector::is_retryable_rpc_error(&json!({
            "code": -32000,
            "message": "header not found"
        })));

        assert!(EVMBalanceSlotDetector::is_retryable_rpc_error(&json!({
            "code": -32005,
            "message": "limit exceeded"
        })));

        assert!(EVMBalanceSlotDetector::is_retryable_rpc_error(&json!({
            "code": -32603,
            "message": "internal error"
        })));

        // Test non-retryable error codes
        assert!(!EVMBalanceSlotDetector::is_retryable_rpc_error(&json!({
            "code": -32600,
            "message": "invalid request"
        })));

        assert!(!EVMBalanceSlotDetector::is_retryable_rpc_error(&json!({
            "code": -32601,
            "message": "method not found"
        })));

        assert!(!EVMBalanceSlotDetector::is_retryable_rpc_error(&json!({
            "code": -32602,
            "message": "invalid params"
        })));

        assert!(!EVMBalanceSlotDetector::is_retryable_rpc_error(&json!({
            "code": -32604,
            "message": "method not supported"
        })));

        // Test unknown error code (should be retryable)
        assert!(EVMBalanceSlotDetector::is_retryable_rpc_error(&json!({
            "code": -99999,
            "message": "unknown error"
        })));

        // Test missing error code (should be retryable)
        assert!(EVMBalanceSlotDetector::is_retryable_rpc_error(&json!({
            "message": "error without code"
        })));

        // Test invalid error format (should be retryable)
        assert!(EVMBalanceSlotDetector::is_retryable_rpc_error(&json!({
            "code": "not_a_number",
            "message": "invalid code format"
        })));
    }

    #[tokio::test]
    async fn test_retry_on_all_failed_responses() {
        let mut server = Server::new_async().await;
        let config = BalanceSlotDetectorConfig {
            max_batch_size: 10,
            rpc_url: server.url(),
            max_retries: 2,
            initial_backoff_ms: 10,
            max_backoff_ms: 100,
        };

        let detector = EVMBalanceSlotDetector::new(config).unwrap();

        let batch_request = json!([
            {
                "jsonrpc": "2.0",
                "method": "eth_call",
                "params": [],
                "id": 1
            },
            {
                "jsonrpc": "2.0",
                "method": "debug_traceCall",
                "params": [],
                "id": 2
            }
        ]);

        // First attempt: all errors
        let _m1 = server
            .mock("POST", "/")
            .with_status(200)
            .with_body(
                r#"[
                {"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"header not found"}},
                {"jsonrpc":"2.0","id":2,"error":{"code":-32000,"message":"header not found"}}
            ]"#,
            )
            .expect(1)
            .create_async()
            .await;

        // Second attempt: success
        let _m2 = server
            .mock("POST", "/")
            .with_status(200)
            .with_body(
                r#"[
                {"jsonrpc":"2.0","id":1,"result":"0x1234"},
                {"jsonrpc":"2.0","id":2,"result":"0x5678"}
            ]"#,
            )
            .expect(1)
            .create_async()
            .await;

        let result = detector
            .send_batched_request(batch_request)
            .await;

        assert!(result.is_ok());
        let responses = result.unwrap();
        assert_eq!(responses.len(), 2);
        assert_eq!(responses[0]["result"], "0x1234");
        assert_eq!(responses[1]["result"], "0x5678");
    }

    #[tokio::test]
    async fn test_retry_on_retryable_errors_mixed_with_success() {
        let mut server = Server::new_async().await;
        let config = BalanceSlotDetectorConfig {
            max_batch_size: 10,
            rpc_url: server.url(),
            max_retries: 2,
            initial_backoff_ms: 10,
            max_backoff_ms: 100,
        };

        let detector = EVMBalanceSlotDetector::new(config).unwrap();

        let batch_request = json!([
            {
                "jsonrpc": "2.0",
                "method": "eth_call",
                "params": [],
                "id": 1
            },
            {
                "jsonrpc": "2.0",
                "method": "debug_traceCall",
                "params": [],
                "id": 2
            }
        ]);

        // First attempt: one success, one retryable error
        let _m1 = server
            .mock("POST", "/")
            .with_status(200)
            .with_body(
                r#"[
                {"jsonrpc":"2.0","id":1,"result":"0x1234"},
                {"jsonrpc":"2.0","id":2,"error":{"code":-32000,"message":"header not found"}}
            ]"#,
            )
            .expect(1)
            .create_async()
            .await;

        // Second attempt: all success
        let _m2 = server
            .mock("POST", "/")
            .with_status(200)
            .with_body(
                r#"[
                {"jsonrpc":"2.0","id":1,"result":"0x1234"},
                {"jsonrpc":"2.0","id":2,"result":"0x5678"}
            ]"#,
            )
            .expect(1)
            .create_async()
            .await;

        let result = detector
            .send_batched_request(batch_request)
            .await;

        assert!(result.is_ok());
        let responses = result.unwrap();
        assert_eq!(responses.len(), 2);
        assert_eq!(responses[0]["result"], "0x1234");
        assert_eq!(responses[1]["result"], "0x5678");
    }

    #[tokio::test]
    async fn test_retry_on_all_failed_non_retryable_errors_for_safety() {
        let mut server = Server::new_async().await;
        let config = BalanceSlotDetectorConfig {
            max_batch_size: 10,
            rpc_url: server.url(),
            max_retries: 2,
            initial_backoff_ms: 10,
            max_backoff_ms: 100,
        };

        let detector = EVMBalanceSlotDetector::new(config).unwrap();

        let batch_request = json!([
            {
                "jsonrpc": "2.0",
                "method": "eth_call",
                "params": [],
                "id": 1
            }
        ]);

        // First attempt: non-retryable error (but all failed, so should retry for safety)
        let _m1 = server
            .mock("POST", "/")
            .with_status(200)
            .with_body(
                r#"[
                {"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"invalid params"}}
            ]"#,
            )
            .expect(1)
            .create_async()
            .await;

        // Second attempt: success (after retry for safety)
        let _m2 = server
            .mock("POST", "/")
            .with_status(200)
            .with_body(
                r#"[
                {"jsonrpc":"2.0","id":1,"result":"0x1234"}
            ]"#,
            )
            .expect(1)
            .create_async()
            .await;

        let result = detector
            .send_batched_request(batch_request)
            .await;

        // Should succeed after retry (safety measure)
        assert!(result.is_ok());
        let responses = result.unwrap();
        assert_eq!(responses.len(), 1);
        assert_eq!(responses[0]["result"], "0x1234");
    }

    #[tokio::test]
    async fn test_retry_exhaustion_with_retryable_errors() {
        let mut server = Server::new_async().await;
        let config = BalanceSlotDetectorConfig {
            max_batch_size: 10,
            rpc_url: server.url(),
            max_retries: 2,
            initial_backoff_ms: 10,
            max_backoff_ms: 100,
        };

        let detector = EVMBalanceSlotDetector::new(config).unwrap();

        let batch_request = json!([
            {
                "jsonrpc": "2.0",
                "method": "eth_call",
                "params": [],
                "id": 1
            }
        ]);

        // All attempts return retryable errors
        let _m = server
            .mock("POST", "/")
            .with_status(200)
            .with_body(
                r#"[
                {"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"header not found"}}
            ]"#,
            )
            .expect(2) // max_retries attempts
            .create_async()
            .await;

        let result = detector
            .send_batched_request(batch_request)
            .await;

        // Should return an error after exhausting all retries
        assert!(result.is_err());
        match result {
            Err(BalanceSlotError::RequestError(msg)) => {
                assert_eq!(msg, "All retry attempts failed");
            }
            other => panic!("Expected RequestError('All retry attempts failed'), got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_mixed_retryable_and_non_retryable_errors() {
        let mut server = Server::new_async().await;
        let config = BalanceSlotDetectorConfig {
            max_batch_size: 10,
            rpc_url: server.url(),
            max_retries: 2,
            initial_backoff_ms: 10,
            max_backoff_ms: 100,
        };

        let detector = EVMBalanceSlotDetector::new(config).unwrap();

        let batch_request = json!([
            {
                "jsonrpc": "2.0",
                "method": "eth_call",
                "params": [],
                "id": 1
            },
            {
                "jsonrpc": "2.0",
                "method": "debug_traceCall",
                "params": [],
                "id": 2
            }
        ]);

        // First attempt: one retryable error, one non-retryable error
        let _m1 = server
            .mock("POST", "/")
            .with_status(200)
            .with_body(
                r#"[
                {"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"header not found"}},
                {"jsonrpc":"2.0","id":2,"error":{"code":-32602,"message":"invalid params"}}
            ]"#,
            )
            .expect(1)
            .create_async()
            .await;

        // Second attempt: success for both
        let _m2 = server
            .mock("POST", "/")
            .with_status(200)
            .with_body(
                r#"[
                {"jsonrpc":"2.0","id":1,"result":"0x1234"},
                {"jsonrpc":"2.0","id":2,"result":"0x5678"}
            ]"#,
            )
            .expect(1)
            .create_async()
            .await;

        let result = detector
            .send_batched_request(batch_request)
            .await;

        // Should retry because there's at least one retryable error
        assert!(result.is_ok());
        let responses = result.unwrap();
        assert_eq!(responses.len(), 2);
        assert_eq!(responses[0]["result"], "0x1234");
        assert_eq!(responses[1]["result"], "0x5678");
    }

    #[tokio::test]
    async fn test_no_retry_on_mixed_success_and_non_retryable_errors() {
        let mut server = Server::new_async().await;
        let config = BalanceSlotDetectorConfig {
            max_batch_size: 10,
            rpc_url: server.url(),
            max_retries: 2,
            initial_backoff_ms: 10,
            max_backoff_ms: 100,
        };

        let detector = EVMBalanceSlotDetector::new(config).unwrap();

        let batch_request = json!([
            {
                "jsonrpc": "2.0",
                "method": "eth_call",
                "params": [],
                "id": 1
            },
            {
                "jsonrpc": "2.0",
                "method": "debug_traceCall",
                "params": [],
                "id": 2
            }
        ]);

        // Only one request should be made (no retry - mixed success/non-retryable error)
        let _m = server
            .mock("POST", "/")
            .with_status(200)
            .with_body(
                r#"[
                {"jsonrpc":"2.0","id":1,"result":"0x1234"},
                {"jsonrpc":"2.0","id":2,"error":{"code":-32602,"message":"invalid params"}}
            ]"#,
            )
            .expect(1)
            .create_async()
            .await;

        let result = detector
            .send_batched_request(batch_request)
            .await;

        // Should return mixed results without retrying (not all failed)
        assert!(result.is_ok());
        let responses = result.unwrap();
        assert_eq!(responses.len(), 2);
        assert_eq!(responses[0]["result"], "0x1234");
        assert!(responses[1]["error"].is_object());
    }
}
