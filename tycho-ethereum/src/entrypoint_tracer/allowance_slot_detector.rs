use std::{
    collections::{BTreeMap, HashMap},
    ops::Add,
    sync::Arc,
    time::Duration,
};

use alloy::primitives::{Address as AlloyAddress, U256};
use alloy_rpc_types_trace::geth::{GethTrace, PreStateFrame, PreStateMode};
use async_trait::async_trait;
use ethers::types::spoof::balance;
use futures::future::join_all;
use serde_json::{json, Value};
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{debug, error, info, instrument, trace, warn};
use tycho_common::{
    models::{
        blockchain::{AccountOverrides, EntryPoint, RPCTracerParams, TracingParams},
        Address, BlockHash,
    },
    traits::AllowanceSlotDetector,
    Bytes,
};

use crate::{entrypoint_tracer::tracer::EVMEntrypointService, RPCError};

struct ValidationData {
    token: Address,
    storage_addr: Address,
    slot: Bytes,
    original_allowance: U256,
    test_value: U256,
}

/// Type alias for slot detection results: (storage_address, slot_bytes) with allowance
type SlotDetectionResult = ((Address, Bytes), U256);

/// Type alias for token slot detection results
type TokenSlotResults = HashMap<Address, Result<SlotDetectionResult, AllowanceSlotError>>;

/// Type alias for slot values from trace: (address, slot_bytes) with value
type SlotValues = Vec<((Address, Bytes), U256)>;

#[derive(Clone, Debug, Error)]
pub enum AllowanceSlotError {
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
    #[error("Failed to extract allowance: {0}")]
    AllowanceExtractionError(String),
    #[error("Unknown error: {0}")]
    UnknownError(String),
    #[error("Wrong slot detected :{0}")]
    WrongSlotError(String),
}

/// Configuration for allowance slot detection.
#[derive(Clone, Debug)]
pub struct AllowanceSlotDetectorConfig {
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

impl Default for AllowanceSlotDetectorConfig {
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

/// Cache type for allowance slot detection results
type AllowanceSlotCache = Arc<RwLock<HashMap<(Address, Address, Address), (Address, Bytes)>>>;

/// EVM-specific implementation of AllowanceSlotDetector using debug_traceCall
pub struct EVMAllowanceSlotDetector {
    rpc_url: url::Url,
    max_batch_size: usize,
    cache: AllowanceSlotCache,
    http_client: reqwest::Client,
    max_retries: usize,
    initial_backoff_ms: u64,
    max_backoff_ms: u64,
}

impl EVMAllowanceSlotDetector {
    pub fn new(config: AllowanceSlotDetectorConfig) -> Result<Self, AllowanceSlotError> {
        let rpc_url = url::Url::parse(&config.rpc_url)
            .map_err(|_| AllowanceSlotError::SetupError("Invalid URL".to_string()))?;

        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(10))
            .pool_idle_timeout(Duration::from_secs(90))
            .pool_max_idle_per_host(10)
            .tcp_nodelay(true)
            .build()
            .map_err(|e| {
                AllowanceSlotError::SetupError(format!("Failed to create HTTP client: {e}"))
            })?;

        Ok(Self {
            max_batch_size: config.max_batch_size,
            rpc_url,
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
        spender: &Address,
        block_hash: &BlockHash,
    ) -> HashMap<Address, Result<(Address, Bytes), AllowanceSlotError>> {
        if tokens.is_empty() {
            return HashMap::new();
        }

        let mut request_tokens = Vec::with_capacity(tokens.len());
        let mut cached_tokens = HashMap::new();

        // Check cache for tokens
        {
            let cache = self.cache.read().await;
            for token in tokens {
                if let Some(slot) = cache.get(&(token.clone(), owner.clone(), spender.clone())) {
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
        let requests = self.create_allowance_requests(&request_tokens, owner, spender, block_hash);

        // Send the batched request
        let responses = match self
            .send_batched_request(requests)
            .await
        {
            Ok(responses) => responses,
            Err(e) => {
                for token in &request_tokens {
                    cached_tokens.insert(
                        token.clone(),
                        Err(AllowanceSlotError::RequestError(e.to_string())),
                    );
                }
                return cached_tokens;
            }
        };

        // Process the batched response to extract slots
        let token_slots = self.process_batched_response(&request_tokens, responses);

        // Validates that the selected slot actually matches the expectation.
        let validation_results = self
            .validate_best_slots(token_slots, owner, spender, block_hash)
            .await;

        // Update cache and prepare final results
        let mut final_results = cached_tokens;
        {
            let mut cache = self.cache.write().await;
            for (token, result) in validation_results {
                match result {
                    Ok(((storage_addr, slot_bytes), _allowance)) => {
                        // Update cache with successful detections
                        cache.insert(
                            (token.clone(), owner.clone(), spender.clone()),
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
    fn create_allowance_requests(
        &self,
        tokens: &[Address],
        owner: &Address,
        spender: &Address,
        block_hash: &BlockHash,
    ) -> Value {
        let mut batch = Vec::new();
        let mut id = 1u64;

        for token in tokens {
            let calldata = encode_allowance_calldata(owner, spender);

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

            // Create eth_call request for getting actual allowance
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
    ) -> Result<Vec<Value>, AllowanceSlotError> {
        let mut attempt = 0;
        let mut last_error = None;

        while attempt < self.max_retries {
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
                Ok(response_json) => match response_json {
                    Value::Array(responses) => {
                        trace!("RPC request successful on attempt {}", attempt + 1);
                        return Ok(responses);
                    }
                    _ => {
                        let error = AllowanceSlotError::InvalidResponse(
                            "Expected array response for batched request".into(),
                        );
                        warn!(
                            attempt = attempt + 1,
                            error = %error,
                            "Received malformed response, will retry"
                        );
                        last_error = Some(error);
                    }
                },
                Err(e) => {
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

        error!("All {} retry attempts failed for RPC request", self.max_retries);
        Err(last_error.unwrap_or_else(|| {
            AllowanceSlotError::RequestError("All retry attempts failed".into())
        }))
    }

    /// Send a single request without retry
    async fn send_single_request(
        &self,
        batch_request: &Value,
    ) -> Result<Value, AllowanceSlotError> {
        let response = self
            .http_client
            .post(self.rpc_url.as_str())
            .header("Content-Type", "application/json")
            .body(serde_json::to_string(batch_request).unwrap())
            .send()
            .await
            .map_err(|e| AllowanceSlotError::RequestError(format!("HTTP request failed: {e}")))?;

        let response_json = response.json().await.map_err(|e| {
            AllowanceSlotError::InvalidResponse(format!("Failed to parse JSON: {e}"))
        })?;

        Ok(response_json)
    }

    /// Calculate exponential backoff with jitter.
    fn calculate_backoff(&self, attempt: usize) -> u64 {
        use rand::Rng;

        let base_backoff = self
            .initial_backoff_ms
            .saturating_mul(1 << (attempt - 1));

        let capped_backoff = base_backoff.min(self.max_backoff_ms);

        let jitter = rand::thread_rng().gen_range(0..=capped_backoff / 4);

        capped_backoff + jitter
    }

    /// Process batched responses and extract storage slots for each token
    fn process_batched_response(
        &self,
        tokens: &[Address],
        responses: Vec<Value>,
    ) -> TokenSlotResults {
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
    fn extract_slot_from_paired_responses(
        &self,
        token: &Address,
        debug_response: Option<&Value>,
        eth_call_response: Option<&Value>,
    ) -> Result<SlotDetectionResult, AllowanceSlotError> {
        let debug_resp = debug_response.ok_or_else(|| {
            AllowanceSlotError::InvalidResponse("Missing debug_traceCall response".into())
        })?;

        let eth_call_resp = eth_call_response.ok_or_else(|| {
            AllowanceSlotError::InvalidResponse("Missing eth_call response".into())
        })?;

        if let Some(error) = debug_resp.get("error") {
            warn!("Debug trace failed for token {}: {}", token, error);
            return Err(AllowanceSlotError::RequestError(error.to_string()));
        }

        if let Some(error) = eth_call_resp.get("error") {
            warn!("Eth call failed for token {}: {}", token, error);
            return Err(AllowanceSlotError::RequestError(error.to_string()));
        }

        // Extract allowance from eth_call response
        let allowance = self.extract_allowance_from_call_response(eth_call_resp)?;

        // Extract slot values from debug_traceCall response
        let slot_values = self.extract_slot_values_from_trace_response(debug_resp)?;

        // Find the best slot by comparing values to the expected allowance
        self.find_best_slot_by_value_comparison(slot_values, allowance)
    }

    /// Extract allowance from eth_call response
    fn extract_allowance_from_call_response(
        &self,
        response: &Value,
    ) -> Result<U256, AllowanceSlotError> {
        let result = response
            .get("result")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                AllowanceSlotError::InvalidResponse("Missing result in eth_call".into())
            })?;

        let hex_str = result
            .strip_prefix("0x")
            .unwrap_or(result);
        if hex_str.len() != 64 {
            return Err(AllowanceSlotError::AllowanceExtractionError(format!(
                "Invalid result length: {} (expected 64)",
                hex_str.len()
            )));
        }

        U256::from_str_radix(hex_str, 16)
            .map_err(|e| AllowanceSlotError::AllowanceExtractionError(e.to_string()))
    }

    /// Extract accessed slots with their values from debug_traceCall response
    fn extract_slot_values_from_trace_response(
        &self,
        response: &Value,
    ) -> Result<SlotValues, AllowanceSlotError> {
        let result = response.get("result").ok_or_else(|| {
            AllowanceSlotError::InvalidResponse("Missing result in debug_traceCall".into())
        })?;

        let frame_map: std::collections::BTreeMap<Address, serde_json::Value> =
            match serde_json::from_value(result.clone()) {
                Ok(map) => map,
                Err(e) => {
                    error!("Failed to parse trace result as hashmap: {}", e);
                    return Err(AllowanceSlotError::ParseError(format!(
                        "Failed to parse trace result: {e}"
                    )));
                }
            };

        let mut slot_values = Vec::new();

        for (address, account_data) in frame_map {
            if let Some(storage_obj) = account_data.get("storage") {
                if let Some(storage_map) = storage_obj.as_object() {
                    for (slot_key, slot_value) in storage_map {
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
            }
        }

        Ok(slot_values)
    }

    /// Find the best slot by comparing storage values to the expected allowance
    fn find_best_slot_by_value_comparison(
        &self,
        slot_values: SlotValues,
        expected_allowance: U256,
    ) -> Result<SlotDetectionResult, AllowanceSlotError> {
        let slot_count = slot_values.len();

        match slot_count {
            0 => {
                debug!("No storage slots found in trace");
                Err(AllowanceSlotError::TokenNotInTrace)
            }
            1 => {
                let slot = slot_values
                    .into_iter()
                    .next()
                    .unwrap()
                    .0;
                debug!("Single slot found, returning: {:?}", slot);
                Ok((slot, expected_allowance))
            }
            _ => {
                let (best_slot, best_value, best_diff) = slot_values
                    .into_iter()
                    .map(|(slot, value)| {
                        let diff = value.abs_diff(expected_allowance);
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

                Ok((best_slot, expected_allowance))
            }
        }
    }

    /// Validates if the detected storage slots are correct.
    async fn validate_best_slots(
        &self,
        token_slots: TokenSlotResults,
        owner: &Address,
        spender: &Address,
        block_hash: &BlockHash,
    ) -> TokenSlotResults {
        let mut validated_results = HashMap::new();
        let mut validation_data = Vec::new();

        for (token, result) in token_slots {
            match result {
                Ok(((storage_addr, slot), original_allowance)) => {
                    validation_data.push(ValidationData {
                        token,
                        storage_addr,
                        slot,
                        original_allowance,
                        test_value: Self::generate_test_value(original_allowance),
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

        let requests =
            match self.create_validation_requests(&validation_data, owner, spender, block_hash) {
                Ok(requests) => requests,
                Err(e) => {
                    for data in validation_data {
                        validated_results.insert(
                            data.token,
                            Err(AllowanceSlotError::RequestError(format!(
                                "Failed to create validation request: {e}"
                            ))),
                        );
                    }
                    return validated_results;
                }
            };

        let responses = match self
            .send_batched_request(requests)
            .await
        {
            Ok(responses) => responses,
            Err(e) => {
                for data in validation_data {
                    validated_results.insert(
                        data.token,
                        Err(AllowanceSlotError::RequestError(format!(
                            "Validation request failed: {e}"
                        ))),
                    );
                }
                return validated_results;
            }
        };

        self.process_validation_responses(responses, validation_data, &mut validated_results);

        validated_results
    }

    /// Generate a test value for validation that's different from the original
    fn generate_test_value(original_allowance: U256) -> U256 {
        if !original_allowance.is_zero() && original_allowance != U256::MAX {
            original_allowance.saturating_mul(U256::from(2))
        } else {
            U256::from(1_000_000_000_000_000_000u64)
        }
    }

    /// Create eth_call requests with storage overrides for validation
    fn create_validation_requests(
        &self,
        validation_data: &[ValidationData],
        owner: &Address,
        spender: &Address,
        block_hash: &BlockHash,
    ) -> Result<Value, AllowanceSlotError> {
        let mut batch = Vec::new();

        for (id, data) in validation_data.iter().enumerate() {
            let calldata = encode_allowance_calldata(owner, spender);

            let test_value_hex = format!("0x{:064x}", data.test_value);
            let slot_hex = format!("0x{}", alloy::hex::encode(data.slot.as_ref()));

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
        let mut id_to_response = HashMap::new();
        for response in responses {
            if let Some(id) = response
                .get("id")
                .and_then(|v| v.as_u64())
            {
                id_to_response.insert(id, response);
            }
        }

        for (idx, data) in validation_data.into_iter().enumerate() {
            let response_id = (idx + 1) as u64;

            match id_to_response.get(&response_id) {
                Some(response) => {
                    if let Some(error) = response.get("error") {
                        results.insert(
                            data.token,
                            Err(AllowanceSlotError::RequestError(format!(
                                "Validation call failed: {error}",
                            ))),
                        );
                        continue;
                    }

                    match self.extract_allowance_from_call_response(response) {
                        Ok(returned_allowance) => {
                            if returned_allowance != data.original_allowance {
                                debug!(
                                    token = %data.token,
                                    storage = %data.storage_addr,
                                    slot = %alloy::hex::encode(data.slot.as_ref()),
                                    returned_allowance = %returned_allowance,
                                    original_allowance = %data.original_allowance,
                                    "Storage slot validated successfully"
                                );
                                results.insert(
                                    data.token,
                                    Ok(((data.storage_addr, data.slot), data.original_allowance)),
                                );
                            } else {
                                warn!(
                                    token = %data.token,
                                    storage = %data.storage_addr,
                                    slot = %alloy::hex::encode(data.slot.as_ref()),
                                    expected = %data.test_value,
                                    got = %returned_allowance,
                                    "Storage slot validation failed - value didn't change as expected"
                                );
                                results.insert(
                                    data.token,
                                    Err(AllowanceSlotError::WrongSlotError(
                                        "Slot override didn't change allowance.".to_string(),
                                    )),
                                );
                            }
                        }
                        Err(e) => {
                            results.insert(
                                data.token,
                                Err(AllowanceSlotError::InvalidResponse(format!(
                                    "Failed to extract allowance from validation response: {e}"
                                ))),
                            );
                        }
                    }
                }
                None => {
                    results.insert(
                        data.token,
                        Err(AllowanceSlotError::InvalidResponse(
                            "Missing validation response".into(),
                        )),
                    );
                }
            }
        }
    }
}

/// Implement the AllowanceSlotDetector trait
#[async_trait]
impl AllowanceSlotDetector for EVMAllowanceSlotDetector {
    type Error = AllowanceSlotError;

    /// Detect allowance storage slots for multiple tokens using batched and async concurrent
    /// requests.
    async fn detect_allowance_slots(
        &self,
        tokens: &[Address],
        owner: Address,
        spender: Address,
        block_hash: BlockHash,
    ) -> HashMap<Address, Result<(Address, Bytes), Self::Error>> {
        info!("Starting allowance slot detection for {} tokens", tokens.len());

        let mut all_results = HashMap::new();

        for (chunk_idx, chunk) in tokens
            .chunks(self.max_batch_size)
            .enumerate()
        {
            debug!("Processing chunk {} with {} tokens", chunk_idx, chunk.len());

            let chunk_results = self
                .detect_token_slots(chunk, &owner, &spender, &block_hash)
                .await;

            all_results.extend(chunk_results);
        }

        info!("Allowance slot detection completed. Found results for {} tokens", all_results.len());
        all_results
    }
}

/// Encode allowance(owner, spender) calldata
pub fn encode_allowance_calldata(owner: &Address, spender: &Address) -> Bytes {
    // allowance selector: 0xdd62ed3e
    let mut calldata = vec![0xdd, 0x62, 0xed, 0x3e];

    // Pad owner address to 32 bytes
    calldata.extend_from_slice(&[0u8; 12]);
    calldata.extend_from_slice(owner.as_ref());

    // Pad spender address to 32 bytes
    calldata.extend_from_slice(&[0u8; 12]);
    calldata.extend_from_slice(spender.as_ref());

    Bytes::from(calldata)
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    #[test]
    fn test_encode_allowance_calldata() {
        let owner = Address::from([0x11u8; 20]);
        let spender = Address::from([0x22u8; 20]);
        let calldata = encode_allowance_calldata(&owner, &spender);

        // Verify selector
        assert_eq!(&calldata[0..4], &[0xdd, 0x62, 0xed, 0x3e]);

        // Verify total length (4 bytes selector + 32 bytes padded owner + 32 bytes padded spender)
        assert_eq!(calldata.len(), 68);

        // Verify owner padding and address
        assert_eq!(&calldata[4..16], &[0u8; 12]);
        assert_eq!(&calldata[16..36], owner.as_ref());

        // Verify spender padding and address
        assert_eq!(&calldata[36..48], &[0u8; 12]);
        assert_eq!(&calldata[48..68], spender.as_ref());
    }

    #[tokio::test]
    #[ignore = "require RPC connection"]
    async fn test_detect_truf_allowance_slot() {
        let rpc_url = std::env::var("RPC_URL").expect("RPC_URL must be set");

        let detector = EVMAllowanceSlotDetector::new(AllowanceSlotDetectorConfig {
            rpc_url: rpc_url.clone(),
            ..Default::default()
        })
        .expect("failed to construct detector");

        // TRUF
        let token = Address::from_str("0x38c2a4a7330b22788374b8ff70bba513c8d848ca").unwrap();

        let owner = Address::from_str("0xcd09f75e2bf2a4d11f3ab23f1389fcc1621c0cc2").unwrap();
        let spender = Address::from_str("0xfd0b31d2e955fa55e3fa641fe90e08b677188d35").unwrap();

        let block_hash = BlockHash::from_str(
            "0x23efd28b949cff1bea0cce77277d4e113793ff029c0c9815a36b6528eaa187ca",
        )
        .unwrap();

        let results = detector
            .detect_allowance_slots(std::slice::from_ref(&token), owner, spender, block_hash)
            .await;

        let res = results.get(&token);

        match results.get(&token) {
            Some(Ok((storage_addr, slot))) => {
                assert_eq!(storage_addr, &token);
                let expected_slot = Bytes::from_str(
                    "0x4e4b5f80f87725e40fd825bd7b26188e05acd6dbf57e82d1bd0f2bd067293504",
                )
                .unwrap();
                assert_eq!(slot, &expected_slot);
            }
            Some(Err(e)) => panic!("Failed to detect slot: {e:?}"),
            None => panic!("No result returned for TRUF"),
        }
    }
}
