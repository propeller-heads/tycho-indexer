use std::{
    collections::{BTreeMap, HashMap},
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use alloy::{
    primitives::U256,
    transports::{RpcError, TransportResult},
};
use futures::future::join_all;
use serde_json::{json, Value};
use thiserror::Error;
use tracing::{debug, error, trace, warn};
use tycho_common::{
    models::{blockchain::RPCTracerParams, Address, BlockHash},
    Bytes,
};

use crate::{rpc::EthereumRpcClient, services::entrypoint_tracer::tracer::EVMEntrypointService};

/// Type alias for intermediate slot detection results: maps token address to (all_slots,
/// expected_value)
type DetectedSlotsResults = HashMap<Address, Result<(SlotValues, U256), SlotDetectorError>>;

/// Type alias for final slot detection results: maps token address to (storage_addr, slot_bytes)
type TokenSlotResults = HashMap<Address, Result<(Address, Bytes), SlotDetectorError>>;

/// Type alias for slot values from trace: (address, slot_bytes) with value
type SlotValues = Vec<((Address, Bytes), U256)>;

/// Type alias for the cache
type ThreadSafeCache<K, V> = Arc<std::sync::RwLock<HashMap<K, V>>>;

#[derive(Debug, Clone)]
struct SlotMetadata {
    token: Address,
    original_value: U256,
    test_value: U256,
    all_slots: SlotValues,
}

/// Configuration for slot detection.
/// Use max_batch_size to configure the behavior according to your node capacity.
/// Please ensure your node supports batching RPC requests and debug_traceCall
/// Read more: https://www.quicknode.com/guides/quicknode-products/apis/guide-to-efficient-rpc-requests
#[derive(Clone, Debug)]
pub struct SlotDetectorConfig {
    /// Maximum batch size to send in a single node request
    pub max_batch_size: usize,
    /// Maximum number of retry attempts for failed requests (default: 3)
    pub max_retries: usize,
    /// Initial backoff delay in milliseconds (default: 100ms)
    pub initial_backoff_ms: u64,
    /// Maximum backoff delay in milliseconds (default: 5000ms)
    pub max_backoff_ms: u64,
}

impl Default for SlotDetectorConfig {
    fn default() -> Self {
        Self { max_batch_size: 10, max_retries: 3, initial_backoff_ms: 100, max_backoff_ms: 5000 }
    }
}

/// Shared error type for slot detection RPC operations
#[derive(Clone, Debug, Error)]
pub enum SlotDetectorError {
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
    #[error("Failed to extract traget: {0}")]
    ValueExtractionError(String),
    #[error("Unknown error: {0}")]
    UnknownError(String),
    #[error("Wrong slot detected :{0}")]
    WrongSlotError(String),
}

/// Represents a single RPC request in a batch (cloneable for retries)
#[derive(Debug, Clone)]
pub(crate) struct BatchRequestData {
    pub(crate) method: String,
    pub(crate) params: Value,
}

/// Strategy trait for different slot detection types (balance, allowance, etc.)
/// This allows the SlotDetector to work with different parameter types and cache keys
pub trait SlotDetectionStrategy: Send + Sync {
    /// The cache key type for this strategy
    type CacheKey: std::hash::Hash + Eq + Clone;
    /// The parameters needed for this strategy (e.g., owner for balance, (owner, spender) for
    /// allowance)
    type Params: Clone;

    /// Generate a cache key from token and parameters
    fn cache_key(token: &Address, params: &Self::Params) -> Self::CacheKey;

    /// Encode the calldata for this slot type
    fn encode_calldata(params: &Self::Params) -> Bytes;
}

/// Generic slot detector that handles RPC communication and slot detection with a configurable
/// strategy. This struct eliminates code duplication between balance and allowance detectors.
pub struct SlotDetector<S: SlotDetectionStrategy> {
    max_batch_size: usize,
    rpc: EthereumRpcClient,
    max_retries: usize,
    initial_backoff_ms: u64,
    max_backoff_ms: u64,
    cache: ThreadSafeCache<S::CacheKey, (Address, Bytes)>,
}

impl<S: SlotDetectionStrategy> SlotDetector<S> {
    /// Create a new SlotDetector with the given configuration and strategy
    pub fn new(config: SlotDetectorConfig, rpc: &EthereumRpcClient) -> Self {
        // Create HTTP client with connection pooling and reasonable timeouts
        Self {
            max_batch_size: config.max_batch_size,
            rpc: rpc.clone(),
            max_retries: config.max_retries,
            initial_backoff_ms: config.initial_backoff_ms,
            max_backoff_ms: config.max_backoff_ms,
            cache: Arc::new(std::sync::RwLock::new(HashMap::new())),
        }
    }

    /// Detect slots for tokens using batched requests (debug_traceCall + eth_call per token)
    async fn detect_token_slots(
        &self,
        tokens: &[Address],
        params: &S::Params,
        block_hash: &BlockHash,
    ) -> HashMap<Address, Result<(Address, Bytes), SlotDetectorError>> {
        if tokens.is_empty() {
            return HashMap::new();
        }

        let mut request_tokens = Vec::with_capacity(tokens.len());
        let mut cached_tokens = HashMap::new();

        // Check cache for tokens
        {
            let cache = self.cache.read().unwrap();
            for token in tokens {
                let cache_key = S::cache_key(token, params);
                if let Some(slot) = cache.get(&cache_key) {
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
        let calldata = S::encode_calldata(params);
        let requests = self.create_value_requests(&request_tokens, &calldata, block_hash);

        // Send the batched request
        let responses = match self
            .send_batched_request(&requests)
            .await
        {
            Ok(responses) => responses,
            Err(e) => {
                for token in &request_tokens {
                    cached_tokens
                        .insert(token.clone(), Err(SlotDetectorError::RequestError(e.to_string())));
                }
                return cached_tokens;
            }
        };

        // Process the batched response to extract slots
        let token_slots = self.process_batched_response(&request_tokens, responses);

        // Detect the correct slot by testing candidates with storage overrides
        let detected_results = self
            .detect_correct_slots(token_slots, &calldata, block_hash)
            .await;

        // Update cache and prepare final results
        let mut final_results = cached_tokens;
        {
            let mut cache = self.cache.write().unwrap();
            for (token, result) in detected_results {
                match result {
                    Ok((storage_addr, slot_bytes)) => {
                        // Update cache with successful detections
                        let cache_key = S::cache_key(&token, params);
                        cache.insert(cache_key, (storage_addr.clone(), slot_bytes.clone()));
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

    /// Detect slots for multiple tokens in chunks
    pub async fn detect_slots_chunked(
        &self,
        tokens: &[Address],
        params: &S::Params,
        block_hash: &BlockHash,
    ) -> HashMap<Address, Result<(Address, Bytes), SlotDetectorError>> {
        let mut all_results = HashMap::new();

        for (chunk_idx, chunk) in tokens
            .chunks(self.max_batch_size)
            .enumerate()
        {
            debug!("Processing chunk {} with {} tokens", chunk_idx, chunk.len());

            let chunk_results = self
                .detect_token_slots(chunk, params, block_hash)
                .await;
            all_results.extend(chunk_results);
        }

        all_results
    }

    /// Create batch request data for all tokens (2 requests per token).
    /// We need to send an eth_call after the tracing to get the return value of the balanceOf
    /// function. Currently, debug_traceCall does not support preStateTracer + returning the
    /// value in the same request.
    pub(crate) fn create_value_requests(
        &self,
        tokens: &[Address],
        calldata: &Bytes,
        block_hash: &BlockHash,
    ) -> Vec<BatchRequestData> {
        let mut batch_data = Vec::new();
        let tracer_params = RPCTracerParams::new(None, calldata.clone());

        for token in tokens {
            let trace_params =
                EVMEntrypointService::create_trace_call_params(token, &tracer_params, block_hash);

            // debug_traceCall request
            batch_data.push(BatchRequestData {
                method: "debug_traceCall".to_string(),
                params: trace_params,
            });

            // eth_call request
            batch_data.push(BatchRequestData {
                method: "eth_call".to_string(),
                params: json!([
                    {
                        "to": token.to_string(),
                        "data": calldata.to_string()
                    },
                    block_hash.to_string()
                ]),
            });
        }

        batch_data
    }

    /// Send a batched JSON-RPC request with retry logic
    /// Takes batch request data and rebuilds the batch on each retry attempt
    async fn send_batched_request(
        &self,
        batch_data: &[BatchRequestData],
    ) -> Result<Vec<TransportResult<Value>>, SlotDetectorError> {
        let mut attempt = 0;
        let mut last_error = None;

        while attempt < self.max_retries {
            if attempt > 0 {
                let backoff_ms = self.calculate_backoff(attempt);
                debug!(attempt, backoff_ms, "Retrying RPC request after backoff");
                tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
            }

            // Build fresh batch from data for this attempt (no cloning needed!)
            match self
                .send_single_request(batch_data)
                .await
            {
                Ok(responses) => {
                    trace!("RPC request returned a response on attempt {}", attempt + 1);

                    let all_failed = responses.iter().all(|r| r.is_err());
                    let has_retryable = responses.iter().any(|r| {
                        if let Err(RpcError::ErrorResp(e)) = r {
                            Self::is_retryable_rpc_error(e.code)
                        } else {
                            false
                        }
                    });

                    if all_failed || has_retryable {
                        let error_details: Vec<_> = responses
                            .iter()
                            .filter_map(
                                |r| if let Err(e) = r { Some(format!("{}", e)) } else { None },
                            )
                            .collect();
                        warn!(
                            attempt = attempt + 1,
                            errors = ?error_details,
                            "Retrying batch request - all failed or has retryable errors"
                        );
                        attempt += 1;
                        continue;
                    }

                    return Ok(responses);
                }
                Err(e) => {
                    warn!(attempt = attempt + 1, error = %e, "RPC request failed, will retry");
                    last_error = Some(e);
                }
            }

            attempt += 1;
        }

        error!("All {} retry attempts failed for RPC request", self.max_retries);
        Err(last_error
            .unwrap_or_else(|| SlotDetectorError::RequestError("All retry attempts failed".into())))
    }

    /// Process batched responses and extract storage slots for each token
    fn process_batched_response(
        &self,
        tokens: &[Address],
        responses: Vec<TransportResult<Value>>,
    ) -> DetectedSlotsResults {
        let mut token_slots = HashMap::new();

        for (token_idx, token) in tokens.iter().enumerate() {
            // Calculate expected response IDs for this token
            let debug_id = token_idx * 2;
            let eth_call_id = token_idx * 2 + 1;

            match self.extract_slot_from_paired_responses(
                token,
                responses.get(debug_id),
                responses.get(eth_call_id),
            ) {
                Ok((all_slots, expected_balance)) => {
                    debug!(
                        token = %token,
                        num_slots = all_slots.len(),
                        "Found {} storage slots for token, will test to find correct one",
                        all_slots.len()
                    );
                    token_slots.insert(token.clone(), Ok((all_slots, expected_balance)));
                }
                Err(e) => {
                    error!(token = %token, error = %e, "Failed to extract slots for token");
                    token_slots.insert(token.clone(), Err(e));
                }
            }
        }

        token_slots
    }

    async fn test_slots_with_fallback(
        &self,
        slots_to_test: Vec<SlotMetadata>,
        calldata: &Bytes,
        block_hash: &BlockHash,
    ) -> TokenSlotResults {
        let mut detected_results = HashMap::new();
        let mut current_attempts = slots_to_test;

        // Retry loop: Test slots with storage overrides, and if a slot fails validation,
        // remove it from the candidate list and retry with remaining slots.
        // This continues until either:
        // 1. All tokens find a valid slot (added to detected_results)
        // 2. A token exhausts all slot candidates (error added to detected_results)
        // 3. An RPC error occurs (error added to detected_results)
        loop {
            if current_attempts.is_empty() {
                break;
            }

            let requests =
                match self.create_slot_test_requests(&current_attempts, calldata, block_hash) {
                    Ok(requests) => requests,
                    Err(e) => {
                        for metadata in current_attempts {
                            detected_results.insert(
                                metadata.token,
                                Err(SlotDetectorError::RequestError(format!(
                                    "Failed to create slot test request: {e}"
                                ))),
                            );
                        }
                        break;
                    }
                };

            let responses = match self
                .send_batched_request(&requests)
                .await
            {
                Ok(responses) => responses,
                Err(e) => {
                    for metadata in current_attempts {
                        detected_results.insert(
                            metadata.token,
                            Err(SlotDetectorError::RequestError(format!(
                                "Slot test request failed: {e}"
                            ))),
                        );
                    }
                    break;
                }
            };

            current_attempts = self.process_slot_test_responses(
                responses,
                current_attempts,
                &mut detected_results,
            );
        }

        detected_results
    }

    /// Sort slots by priority for testing.
    ///
    /// Primary sort: Distance to expected balance (closest first)
    /// Secondary sort: Reverse index (last accessed first, used as tiebreaker)
    ///
    /// This sorting is done once when we first get the slot candidates.
    fn sort_slots_by_priority(slots: &mut SlotValues, original_value: U256) {
        slots.sort_by_key(|(_, new_value)| {
            // Primary: distance to original balance (closer is better)
            // Note: We can't use reverse index here as a secondary key in a simple way,
            // but the initial order from the trace is already in access order,
            // so slots with the same distance will maintain their relative order (stable sort)
            new_value.abs_diff(original_value)
        });
    }

    /// Send a single request without retry
    /// Rebuilds the batch from scratch each time it's called
    async fn send_single_request(
        &self,
        batch_data: &[BatchRequestData],
    ) -> Result<Vec<TransportResult<Value>>, SlotDetectorError> {
        // Clone the data once at the start so it has a long enough lifetime for the batch API
        let owned_data = batch_data.to_vec();
        let mut batch = self.rpc.inner.new_batch();

        // Add all calls to the batch and collect their future handles
        let mut futures = Vec::with_capacity(owned_data.len());
        for req_data in &owned_data {
            let fut = batch
                .add_call(req_data.method.clone(), &req_data.params)
                .map_err(|e| {
                    SlotDetectorError::RequestError(format!(
                        "Failed to add call '{}': {}",
                        req_data.method, e
                    ))
                })?;
            futures.push(fut);
        }

        // Send the batch
        batch
            .send()
            .await
            .map_err(|e| SlotDetectorError::RequestError(format!("Batch send failed: {}", e)))?;

        // Await all responses by joining their futures
        Ok(join_all(futures).await)
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

    /// Check if an RPC error should be retried based on its error code
    /// Retryable errors are typically transient issues that may resolve on retry
    fn is_retryable_rpc_error(error_code: i64) -> bool {
        match error_code {
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
    }

    /// Extract storage slot from paired debug_traceCall and eth_call responses
    /// Returns all slots and the expected values for testing
    fn extract_slot_from_paired_responses(
        &self,
        token: &Address,
        debug_response: Option<&TransportResult<Value>>,
        eth_call_response: Option<&TransportResult<Value>>,
    ) -> Result<(SlotValues, U256), SlotDetectorError> {
        let debug_resp = debug_response.ok_or_else(|| {
            SlotDetectorError::InvalidResponse("Missing debug_traceCall response".into())
        })?;

        let eth_call_resp = eth_call_response.ok_or_else(|| {
            SlotDetectorError::InvalidResponse("Missing eth_call response".into())
        })?;

        // Extract slot values from debug_traceCall response
        let slot_values = match debug_resp {
            Err(error) => {
                warn!("Debug trace failed for token {}: {}", token, error);
                return Err(SlotDetectorError::RequestError(error.to_string()));
            }
            Ok(debug_trace_call) => {
                self.extract_slot_values_from_trace_response(debug_trace_call)?
            }
        };

        // Extract value from eth_call response
        let value = match eth_call_resp {
            Err(error) => {
                warn!("Eth call failed for token {}: {}", token, error);
                return Err(SlotDetectorError::RequestError(error.to_string()));
            }
            Ok(eth_call) => self.extract_u256_from_call_response(eth_call)?,
        };

        if slot_values.is_empty() {
            return Err(SlotDetectorError::TokenNotInTrace);
        }

        debug!(
            "Found {} slots for token {}, will test starting from closest value to original allowance",
            slot_values.len(),
            token
        );

        Ok((slot_values, value))
    }

    pub fn extract_u256_from_call_response(
        &self,
        response: &Value,
    ) -> Result<U256, SlotDetectorError> {
        let result = response.as_str().ok_or_else(|| {
            SlotDetectorError::InvalidResponse("Missing result in eth_call".into())
        })?;

        let hex_str = result
            .strip_prefix("0x")
            .unwrap_or(result);
        if hex_str.len() != 64 {
            return Err(SlotDetectorError::ValueExtractionError(format!(
                "Invalid result length: {} (expected 64)",
                hex_str.len()
            )));
        }

        U256::from_str_radix(hex_str, 16)
            .map_err(|e| SlotDetectorError::ValueExtractionError(e.to_string()))
    }

    /// Extract accessed slots with their values from debug_traceCall response for better slot
    /// selection
    fn extract_slot_values_from_trace_response(
        &self,
        response: &Value,
    ) -> Result<SlotValues, SlotDetectorError> {
        // The debug_traceCall with prestateTracer returns the result directly as a hashmap
        let frame_map: BTreeMap<Address, Value> = match serde_json::from_value(response.clone()) {
            Ok(map) => map,
            Err(e) => {
                error!("Failed to parse trace result as hashmap: {}", e);
                return Err(SlotDetectorError::ParseError(format!(
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
                        let slot_bytes = if let Ok(bytes) = Bytes::from_str(slot_key) {
                            bytes
                        } else {
                            warn!("Failed to decode slot key: {slot_key}");
                            continue;
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
                                    warn!("Failed to decode slot value: {value_str}");
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

    /// Detects the correct storage slot by testing candidates with storage overrides.
    ///
    /// Testing order:
    /// 1. Start with the slot whose value is closest to the original allowance
    /// 2. Fall back to the last accessed slot
    /// 3. Try remaining slots in reverse order (most recently accessed first)
    async fn detect_correct_slots(
        &self,
        token_slots: DetectedSlotsResults,
        calldata: &Bytes,
        block_hash: &BlockHash,
    ) -> TokenSlotResults {
        let mut detected_results = HashMap::new();
        let mut slots_to_test = Vec::new();

        for (token, result) in token_slots {
            match result {
                Ok((mut all_slots, original_value)) => {
                    if all_slots.is_empty() {
                        detected_results.insert(token, Err(SlotDetectorError::TokenNotInTrace));
                    } else {
                        Self::sort_slots_by_priority(&mut all_slots, original_value);

                        slots_to_test.push(SlotMetadata {
                            token,
                            original_value,
                            test_value: Self::generate_test_value(original_value),
                            all_slots,
                        });
                    }
                }
                Err(e) => {
                    detected_results.insert(token, Err(e));
                }
            }
        }

        if slots_to_test.is_empty() {
            return detected_results;
        }

        // Test all slot candidates, trying alternate slots if needed
        let test_results = self
            .test_slots_with_fallback(slots_to_test, calldata, block_hash)
            .await;
        detected_results.extend(test_results);

        detected_results
    }

    /// Generate a test value for validation that's different from the original
    fn generate_test_value(original_value: U256) -> U256 {
        if !original_value.is_zero() && original_value != U256::MAX {
            // Set to a different value (double the original) - this function caps to U256::MAX so
            // no overflow can happen.
            original_value.saturating_mul(U256::from(2))
        } else {
            // If original is 0, set to a non-zero value (1 ETH in wei)
            U256::from(1_000_000_000_000_000_000u64)
        }
    }

    fn create_slot_test_requests(
        &self,
        slots_to_test: &[SlotMetadata],
        calldata: &Bytes,
        block_hash: &BlockHash,
    ) -> Result<Vec<BatchRequestData>, SlotDetectorError> {
        let mut batch_data = Vec::new();

        for metadata in slots_to_test {
            let (storage_addr, slot) = &metadata
                .all_slots
                .first()
                .ok_or(SlotDetectorError::TokenNotInTrace)?
                .0;

            // Format the override value as a 32-byte hex string
            let test_value_hex = format!("0x{:064x}", metadata.test_value);

            // Create eth_call with state override
            batch_data.push(BatchRequestData {
                method: "eth_call".to_string(),
                params: json!([
                    {
                        "to": metadata.token.to_string(),
                        "data": calldata.to_string()
                    },
                    block_hash.to_string(),
                    {
                        storage_addr.to_string(): {
                            "stateDiff": {
                                slot.to_string(): test_value_hex
                            }
                        }
                    }
                ]),
            });
        }

        Ok(batch_data)
    }

    fn process_slot_test_responses(
        &self,
        responses: Vec<TransportResult<Value>>,
        slots_to_test: Vec<SlotMetadata>,
        results: &mut TokenSlotResults,
    ) -> Vec<SlotMetadata> {
        let mut retry_data = Vec::new();
        for (idx, mut metadata) in slots_to_test.into_iter().enumerate() {
            let response_id = idx;

            match responses.get(response_id) {
                Some(response) => {
                    // Check for errors
                    let response_value = match response {
                        Err(error) => {
                            results.insert(
                                metadata.token,
                                Err(SlotDetectorError::RequestError(format!(
                                    "Slot test call failed: {error}",
                                ))),
                            );
                            continue;
                        }
                        Ok(response_value) => response_value,
                    };

                    let (storage_addr, slot) = &metadata
                        .all_slots
                        .first()
                        .expect("all_slots should not be empty")
                        .0
                        .clone();

                    match self.extract_u256_from_call_response(response_value) {
                        Ok(returned_value) => {
                            // Check if the override worked (balance should be different from
                            // original_value). We can't guarantee that it will match the override
                            // value, as some tokens use shares systems, making it hard to control
                            // the balance with a single override.
                            if returned_value != metadata.original_value {
                                // Validation successful - the slot works
                                debug!(
                                    token = %metadata.token,
                                    storage = %storage_addr,
                                    slot = %slot,
                                    returned_balance = %returned_value,
                                    original_value = %metadata.original_value,
                                    "Storage slot detected successfully"
                                );
                                results.insert(
                                    metadata.token,
                                    Ok((storage_addr.clone(), slot.clone())),
                                );
                            } else {
                                // Override didn't change the value - this slot is incorrect.
                                // Remove it from candidates and try the next slot in priority
                                // order.
                                metadata
                                    .all_slots
                                    .retain(|s| s.0 != (storage_addr.clone(), slot.clone()));
                                if !metadata.all_slots.is_empty() {
                                    warn!("Storage slot test failed - trying next slot");
                                    retry_data.push(metadata.clone());
                                } else {
                                    warn!(
                                        token = %metadata.token,
                                        slot = %slot,
                                        "Storage slot test failed - no more slots to try"
                                    );
                                    results.insert(
                                        metadata.token,
                                        Err(SlotDetectorError::WrongSlotError(
                                            "Slot override didn't change value for any detected slot.".to_string(),
                                        )),
                                    );
                                }
                            }
                        }
                        Err(e) => {
                            results.insert(
                                metadata.token,
                                Err(SlotDetectorError::InvalidResponse(format!(
                                    "Failed to extract value from slot test response: {e}"
                                ))),
                            );
                        }
                    }
                }
                None => {
                    results.insert(
                        metadata.token,
                        Err(SlotDetectorError::InvalidResponse(
                            "Missing validation response".into(),
                        )),
                    );
                }
            }
        }

        retry_data
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use alloy::{primitives::U256, transports::RpcError};
    use mockito::Server;
    use serde_json::json;
    use tycho_common::{
        models::{Address, BlockHash},
        Bytes,
    };

    use crate::{
        rpc::EthereumRpcClient,
        services::entrypoint_tracer::{
            balance_slot_detector::BalanceStrategy,
            slot_detector::{
                BatchRequestData, SlotDetectionStrategy, SlotDetector, SlotDetectorConfig,
                SlotDetectorError, SlotMetadata,
            },
        },
        test_fixtures::TestFixture,
    };

    struct TestFixtureStrategy {}

    impl SlotDetectionStrategy for TestFixtureStrategy {
        type CacheKey = ();
        type Params = ();

        fn cache_key(_token: &Address, _params: &Self::Params) -> Self::CacheKey {
            unreachable!()
        }

        fn encode_calldata(_params: &Self::Params) -> Bytes {
            unreachable!()
        }
    }

    const LONG_BACKOFF_CONFIG: SlotDetectorConfig = SlotDetectorConfig {
        max_batch_size: 10,
        max_retries: 3,
        initial_backoff_ms: 100,
        max_backoff_ms: 5000,
    };

    const SHORT_BACKOFF_CONFIG: SlotDetectorConfig = SlotDetectorConfig {
        max_batch_size: 10,
        max_retries: 3,
        initial_backoff_ms: 10,
        max_backoff_ms: 100,
    };

    fn create_slot_candidates() -> Vec<SlotMetadata> {
        vec![
            SlotMetadata {
                token: Address::from([0x11u8; 20]),
                original_value: U256::from(1000u64),
                test_value: U256::from(2000u64),
                all_slots: vec![(
                    (Address::from([0x11u8; 20]), Bytes::from(vec![0x01u8; 32])),
                    U256::from(1000u64),
                )],
            },
            SlotMetadata {
                token: Address::from([0x22u8; 20]),
                original_value: U256::from(3000u64),
                test_value: U256::from(6000u64),
                all_slots: vec![(
                    (Address::from([0x22u8; 20]), Bytes::from(vec![0x02u8; 32])),
                    U256::from(3000u64),
                )],
            },
        ]
    }

    impl TestFixture {
        fn create_slot_detector_without_rpc(
            config: SlotDetectorConfig,
        ) -> SlotDetector<TestFixtureStrategy> {
            TestFixture::create_slot_detector(config, "http://localhost:8545")
        }

        fn create_slot_detector(
            config: SlotDetectorConfig,
            rpc_url: &str,
        ) -> SlotDetector<TestFixtureStrategy> {
            let rpc = EthereumRpcClient::new(rpc_url).expect("Failed to create RPC client");

            SlotDetector::<TestFixtureStrategy>::new(config, &rpc)
        }
    }

    #[test]
    fn test_calculate_backoff() {
        let detector = TestFixture::create_slot_detector_without_rpc(LONG_BACKOFF_CONFIG);
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
        let test_value = SlotDetector::<TestFixtureStrategy>::generate_test_value(original);
        assert_eq!(test_value, U256::from(2000u64));

        // Test zero value
        let zero = U256::ZERO;
        let test_value = SlotDetector::<TestFixtureStrategy>::generate_test_value(zero);
        assert_eq!(test_value, U256::from(1_000_000_000_000_000_000u64));

        // Test max value - falls into else branch since original_value == U256::MAX
        let max = U256::MAX;
        let test_value = SlotDetector::<TestFixtureStrategy>::generate_test_value(max);
        assert_eq!(test_value, U256::from(1_000_000_000_000_000_000u64)); // Returns 1 ETH for MAX
    }

    #[test]
    fn test_extract_balance_from_call_response() {
        let detector = TestFixture::create_slot_detector_without_rpc(LONG_BACKOFF_CONFIG);
        // Test valid response
        let response = json!("0x0000000000000000000000000000000000000000000000000de0b6b3a7640000");
        let balance = detector
            .extract_u256_from_call_response(&response)
            .unwrap();
        assert_eq!(balance, U256::from(1_000_000_000_000_000_000u64)); // 1 ETH

        // Test missing result
        let response = json!({});
        let result = detector.extract_u256_from_call_response(&response);
        assert!(matches!(result, Err(SlotDetectorError::InvalidResponse(_))));

        // Test invalid hex length
        let response = json!("0x1234");
        let result = detector.extract_u256_from_call_response(&response);
        assert!(matches!(result, Err(SlotDetectorError::ValueExtractionError(_))));

        // Test invalid hex characters
        let response = json!("0xGGGG000000000000000000000000000000000000000000000000000000000000");
        let result = detector.extract_u256_from_call_response(&response);
        assert!(matches!(result, Err(SlotDetectorError::ValueExtractionError(_))));
    }

    #[test]
    fn test_extract_slot_values_from_trace_response() {
        let detector = TestFixture::create_slot_detector_without_rpc(LONG_BACKOFF_CONFIG);
        // Test valid trace with storage
        let response = json!({
                "0x1234567890123456789012345678901234567890": {
                    "storage": {
                        "0x0000000000000000000000000000000000000000000000000000000000000001": "0x0000000000000000000000000000000000000000000000000de0b6b3a7640000",
                        "0x0000000000000000000000000000000000000000000000000000000000000002": "0x0000000000000000000000000000000000000000000000001bc16d674ec80000"
                    }
                }
            }
        );

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
        assert!(result.ok().unwrap().is_empty());

        // Test malformed result
        let response = json!("not_an_object");
        let result = detector.extract_slot_values_from_trace_response(&response);
        assert!(matches!(result, Err(SlotDetectorError::ParseError(_))));
    }

    #[test]
    fn test_process_batched_response() {
        let detector = TestFixture::create_slot_detector_without_rpc(LONG_BACKOFF_CONFIG);
        let token1 = Address::from([0x11u8; 20]);
        let token2 = Address::from([0x22u8; 20]);

        // Create responses with proper IDs (out of order to test ID mapping)
        let responses = vec![
            json!({
                "0x1111111111111111111111111111111111111111": {
                    "storage": {
                        "0x0000000000000000000000000000000000000000000000000000000000000001": "0x0000000000000000000000000000000000000000000000000de0b6b3a7640000"
                    }
                }
            }),
            json!("0x0000000000000000000000000000000000000000000000000de0b6b3a7640000"),
            json!({
                    "0x2222222222222222222222222222222222222222": {
                        "storage": {
                            "0x0000000000000000000000000000000000000000000000000000000000000002": "0x0000000000000000000000000000000000000000000000001bc16d674ec80000"
                        }
                    }

            }),
            json!("0x0000000000000000000000000000000000000000000000001bc16d674ec80000"),
        ];

        let responses = responses.into_iter().map(Ok).collect();

        let tokens = vec![token1.clone(), token2.clone()];
        let result = detector.process_batched_response(&tokens, responses);

        assert_eq!(result.len(), 2);
        assert!(result.contains_key(&token1));
        assert!(result.contains_key(&token2));

        // Verify token1 result
        let token1_result = result.get(&token1).unwrap();
        println!("{:?}", token1_result);
        assert!(token1_result.is_ok());

        // Verify token2 result
        let token2_result = result.get(&token2).unwrap();
        assert!(token2_result.is_ok());
    }

    #[test]
    fn test_create_balance_requests() {
        let detector = TestFixture::create_slot_detector_without_rpc(LONG_BACKOFF_CONFIG);
        let token1 = Address::from([0x11u8; 20]);
        let token2 = Address::from([0x22u8; 20]);
        let owner = Address::from([0x33u8; 20]);
        let block_hash = BlockHash::from([0x44u8; 32]);

        let tokens = vec![token1, token2];
        let calldata = BalanceStrategy::encode_calldata(&owner);
        let requests = detector.create_value_requests(&tokens, &calldata, &block_hash);

        // Should create 2 requests per token (debug_traceCall + eth_call)
        let array = requests;
        assert_eq!(array.len(), 4);

        // Verify first request (debug_traceCall for token1)
        assert_eq!(array[0].method, "debug_traceCall");

        // Verify second request (eth_call for token1)
        assert_eq!(array[1].method, "eth_call");

        // Verify third request (debug_traceCall for token2)
        assert_eq!(array[2].method, "debug_traceCall");

        // Verify fourth request (eth_call for token2)
        assert_eq!(array[3].method, "eth_call");
    }

    #[test]
    fn test_create_validation_requests() {
        let detector = TestFixture::create_slot_detector_without_rpc(LONG_BACKOFF_CONFIG);
        let slot_candidates = create_slot_candidates();

        // Create responses - first one changes (valid), second doesn't (invalid)
        let responses = vec![
            Ok(json!(
                "0x00000000000000000000000000000000000000000000000000000000000007d0" /* 2000 (changed) */
            )),
            Ok(json!(
                "0x0000000000000000000000000000000000000000000000000000000000000bb8" /* 3000 (unchanged) */
            )),
        ];

        let mut results = HashMap::new();
        let retry_data =
            detector.process_slot_test_responses(responses, slot_candidates, &mut results);

        assert_eq!(results.len(), 2);

        // First token should be valid (balance changed)
        let token1 = Address::from([0x11u8; 20]);
        assert!(results.get(&token1).unwrap().is_ok());

        // Second token should be invalid (balance didn't change) - no retry because SlotValues is
        // empty after pop
        let token2 = Address::from([0x22u8; 20]);
        assert!(matches!(results.get(&token2).unwrap(), Err(SlotDetectorError::WrongSlotError(_))));

        // No retries should be scheduled since SlotValues only had one slot each
        assert!(retry_data.is_empty());
    }

    #[tokio::test]
    async fn test_send_batched_request_retry_logic() {
        let mut server = Server::new_async().await;
        let detector = TestFixture::create_slot_detector(SHORT_BACKOFF_CONFIG, &server.url());

        // Create a simple batch request
        let batch_request =
            vec![BatchRequestData { method: "eth_call".to_string(), params: json!([]) }];

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

        // At this point the id counter should be 2 as it increments per request starting from 0
        let _m3 = server
            .mock("POST", "/")
            .with_status(200)
            .with_body(r#"[{"jsonrpc":"2.0","id":2,"result":"0x1234"}]"#)
            .expect(1)
            .create_async()
            .await;

        let result = detector
            .send_batched_request(&batch_request)
            .await;
        assert!(result.is_ok());

        let responses = result.unwrap();
        assert_eq!(responses.len(), 1);

        match &responses[0] {
            Ok(val) => assert_eq!(*val, json!("0x1234")),
            Err(err) => panic!("Expected Ok response, got Err: {}", err),
        }
    }

    #[tokio::test]
    async fn test_send_batched_request_max_retries_exceeded() {
        let mut server = Server::new_async().await;
        let detector = TestFixture::create_slot_detector(SHORT_BACKOFF_CONFIG, &server.url());

        let batch_request =
            vec![BatchRequestData { method: "eth_call".to_string(), params: json!([]) }];

        // All attempts fail
        let _m = server
            .mock("POST", "/")
            .with_status(500)
            .expect(2)
            .create_async()
            .await;

        let result = detector
            .send_batched_request(&batch_request)
            .await;
        assert!(result.is_err());
        // The error can be either RequestError (if the request itself fails) or
        // InvalidResponse (if the response body can't be parsed as JSON)
        assert!(matches!(
            result,
            Err(SlotDetectorError::RequestError(_)) | Err(SlotDetectorError::InvalidResponse(_))
        ));
    }

    #[test]
    fn test_is_retryable_rpc_error() {
        // Test retryable error codes
        assert!(SlotDetector::<TestFixtureStrategy>::is_retryable_rpc_error(32000));

        assert!(SlotDetector::<TestFixtureStrategy>::is_retryable_rpc_error(-32005,));

        assert!(SlotDetector::<TestFixtureStrategy>::is_retryable_rpc_error(-32603));

        // Test non-retryable error codes
        assert!(!SlotDetector::<TestFixtureStrategy>::is_retryable_rpc_error(-32600));

        assert!(!SlotDetector::<TestFixtureStrategy>::is_retryable_rpc_error(-32601));

        assert!(!SlotDetector::<TestFixtureStrategy>::is_retryable_rpc_error(-32602));

        assert!(!SlotDetector::<TestFixtureStrategy>::is_retryable_rpc_error(-32604));

        // Test unknown error code (should be retryable)
        assert!(SlotDetector::<TestFixtureStrategy>::is_retryable_rpc_error(-99999));
    }

    #[tokio::test]
    async fn test_retry_on_all_failed_responses() {
        let mut server = Server::new_async().await;
        let detector = TestFixture::create_slot_detector(SHORT_BACKOFF_CONFIG, &server.url());

        let batch_request = vec![
            BatchRequestData { method: "eth_call".to_string(), params: json!([]) },
            BatchRequestData { method: "debug_traceCall".to_string(), params: json!([]) },
        ];

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
                {"jsonrpc":"2.0","id":2,"result":"0x1234"},
                {"jsonrpc":"2.0","id":3,"result":"0x5678"}
            ]"#,
            )
            .expect(1)
            .create_async()
            .await;

        let result = detector
            .send_batched_request(&batch_request)
            .await;

        assert!(result.is_ok());
        let responses = result.unwrap();
        assert_eq!(responses.len(), 2);
        match &responses[0] {
            Ok(val) => assert_eq!(*val, json!("0x1234")),
            Err(err) => panic!("Expected Ok response, got Err: {}", err),
        }
        match &responses[1] {
            Ok(val) => assert_eq!(*val, json!("0x5678")),
            Err(err) => panic!("Expected Ok response, got Err: {}", err),
        }
    }

    #[tokio::test]
    async fn test_retry_on_retryable_errors_mixed_with_success() {
        let mut server = Server::new_async().await;
        let detector = TestFixture::create_slot_detector(SHORT_BACKOFF_CONFIG, &server.url());

        let batch_request = vec![
            BatchRequestData { method: "eth_call".to_string(), params: json!([]) },
            BatchRequestData { method: "debug_traceCall".to_string(), params: json!([]) },
        ];

        // First attempt: one success, one retryable error
        let _m1 = server
            .mock("POST", "/")
            .with_status(200)
            .with_body(
                r#"[
                {"jsonrpc":"2.0","id":0,"result":"0x1234"},
                {"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"header not found"}}
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
                {"jsonrpc":"2.0","id":2,"result":"0x1234"},
                {"jsonrpc":"2.0","id":3,"result":"0x5678"}
            ]"#,
            )
            .expect(1)
            .create_async()
            .await;

        let result = detector
            .send_batched_request(&batch_request)
            .await;

        assert!(result.is_ok());
        let responses = result.unwrap();
        assert_eq!(responses.len(), 2);
        match &responses[0] {
            Ok(val) => assert_eq!(*val, json!("0x1234")),
            Err(err) => panic!("Expected Ok response, got Err: {}", err),
        }
        match &responses[1] {
            Ok(val) => assert_eq!(*val, json!("0x5678")),
            Err(err) => panic!("Expected Ok response, got Err: {}", err),
        }
    }

    #[tokio::test]
    async fn test_retry_on_all_failed_non_retryable_errors_for_safety() {
        let mut server = Server::new_async().await;
        let detector = TestFixture::create_slot_detector(SHORT_BACKOFF_CONFIG, &server.url());

        let batch_request =
            vec![BatchRequestData { method: "eth_call".to_string(), params: json!([]) }];

        // First attempt: non-retryable error (but all failed, so should retry for safety)
        let _m1 = server
            .mock("POST", "/")
            .with_status(200)
            .with_body(
                r#"[
                {"jsonrpc":"2.0","id":0,"error":{"code":-32602,"message":"invalid params"}}
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
            .send_batched_request(&batch_request)
            .await;

        // Should succeed after retry (safety measure)
        assert!(result.is_ok());
        let responses = result.unwrap();
        assert_eq!(responses.len(), 1);
        match &responses[0] {
            Ok(val) => assert_eq!(*val, json!("0x1234")),
            Err(err) => panic!("Expected Ok response, got Err: {}", err),
        }
    }

    #[tokio::test]
    async fn test_retry_exhaustion_with_retryable_errors() {
        let mut server = Server::new_async().await;
        let detector = TestFixture::create_slot_detector(SHORT_BACKOFF_CONFIG, &server.url());

        let batch_request =
            vec![BatchRequestData { method: "eth_call".to_string(), params: json!([]) }];

        // All attempts return retryable errors
        let _m1 = server
            .mock("POST", "/")
            .with_status(200)
            .with_body(
                r#"[
                {"jsonrpc":"2.0","id":0,"error":{"code":-32000,"message":"header not found"}}
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
                {"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"header not found"}}
            ]"#,
            )
            .expect(1)
            .create_async()
            .await;

        // Second attempt: all success
        let _m3 = server
            .mock("POST", "/")
            .with_status(200)
            .with_body(
                r#"[
                {"jsonrpc":"2.0","id":2,"error":{"code":-32000,"message":"header not found"}}
            ]"#,
            )
            .expect(1)
            .create_async()
            .await;

        let result = detector
            .send_batched_request(&batch_request)
            .await;

        // Should return an error after exhausting all retries
        assert!(result.is_err());
        match result {
            Err(SlotDetectorError::RequestError(msg)) => {
                assert_eq!(msg, "All retry attempts failed");
            }
            other => panic!("Expected RequestError('All retry attempts failed'), got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_mixed_retryable_and_non_retryable_errors() {
        let mut server = Server::new_async().await;
        let detector = TestFixture::create_slot_detector(SHORT_BACKOFF_CONFIG, &server.url());

        let batch_request = vec![
            BatchRequestData { method: "eth_call".to_string(), params: json!([]) },
            BatchRequestData { method: "debug_traceCall".to_string(), params: json!([]) },
        ];

        // First attempt: one retryable error, one non-retryable error
        let _m1 = server
            .mock("POST", "/")
            .with_status(200)
            .with_body(
                r#"[
                {"jsonrpc":"2.0","id":0,"error":{"code":-32000,"message":"header not found"}},
                {"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"invalid params"}}
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
                {"jsonrpc":"2.0","id":2,"result":"0x1234"},
                {"jsonrpc":"2.0","id":3,"result":"0x5678"}
            ]"#,
            )
            .expect(1)
            .create_async()
            .await;

        let result = detector
            .send_batched_request(&batch_request)
            .await;

        // Should retry because there's at least one retryable error
        assert!(result.is_ok());
        let responses = result.unwrap();
        assert_eq!(responses.len(), 2);
        match &responses[0] {
            Ok(val) => assert_eq!(*val, json!("0x1234")),
            Err(err) => panic!("Expected Ok response, got Err: {}", err),
        }
        match &responses[1] {
            Ok(val) => assert_eq!(*val, json!("0x5678")),
            Err(err) => panic!("Expected Ok response, got Err: {}", err),
        }
    }

    #[tokio::test]
    async fn test_no_retry_on_mixed_success_and_non_retryable_errors() {
        let mut server = Server::new_async().await;
        let detector = TestFixture::create_slot_detector(SHORT_BACKOFF_CONFIG, &server.url());

        let batch_request = vec![
            BatchRequestData { method: "eth_call".to_string(), params: json!([]) },
            BatchRequestData { method: "debug_traceCall".to_string(), params: json!([]) },
        ];

        // Only one request should be made (no retry - mixed success/non-retryable error)
        let _m = server
            .mock("POST", "/")
            .with_status(200)
            .with_body(
                r#"[
                {"jsonrpc":"2.0","id":0,"result":"0x1234"},
                {"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"invalid params"}}
            ]"#,
            )
            .expect(1)
            .create_async()
            .await;

        let result = detector
            .send_batched_request(&batch_request)
            .await;

        println!("{:?}", result);
        // Should return mixed results without retrying (not all failed)
        assert!(result.is_ok());
        let responses = result.unwrap();
        assert_eq!(responses.len(), 2);
        match &responses[0] {
            Ok(val) => assert_eq!(*val, json!("0x1234")),
            Err(err) => panic!("Expected Ok response, got Err: {}", err),
        }
        match &responses[1] {
            Ok(val) => panic!("Expected Err response, got Ok: {}", val),
            Err(RpcError::ErrorResp(err)) => assert_eq!(err.code, -32602),
            _ => panic!("Expected RpcError::ErrorResp, got different error"),
        }
    }
}
