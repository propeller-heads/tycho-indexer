use std::collections::{BTreeMap, HashMap};

use alloy::primitives::{Address as AlloyAddress, U256};
use alloy_rpc_types_trace::geth::{GethTrace, PreStateFrame, PreStateMode};
use async_trait::async_trait;
use futures::future::join_all;
use serde_json::{json, Value};
use thiserror::Error;
use tracing::{debug, error, info, instrument, trace, warn};
use tycho_common::{
    models::{
        blockchain::{AccountOverrides, EntryPoint, RPCTracerParams, TracingParams},
        Address, BlockHash, ComponentId,
    },
    traits::{BalanceSlotDetector, EntryPointTracer},
    Bytes,
};

use crate::{entrypoint_tracer::tracer::EVMEntrypointService, RPCError};

#[derive(Debug, Error)]
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
}

/// Configuration for balance slot detection
#[derive(Clone, Debug)]
pub struct BalanceSlotDetectorConfig {
    /// Maximum number of components to process concurrently
    pub max_concurrent_components: usize,
    /// RPC endpoint URL (RPC needs to support debug_traceCall method)
    pub rpc_url: String,
}

/// EVM-specific implementation of BalanceSlotDetector using debug_traceCall
#[derive(Debug)]
pub struct EVMBalanceSlotDetector {
    tracer: EVMEntrypointService,
    max_concurrent_components: usize,
}

impl EVMBalanceSlotDetector {
    pub fn new(config: BalanceSlotDetectorConfig) -> Result<Self, BalanceSlotError> {
        let tracer = EVMEntrypointService::try_from_url(&config.rpc_url).map_err(|e| match e {
            RPCError::SetupError(msg) => BalanceSlotError::SetupError(msg),
            _ => BalanceSlotError::UnknownError(e.to_string()),
        })?;

        Ok(Self { tracer, max_concurrent_components: config.max_concurrent_components })
    }

    /// Detect slots for a single component using batched requests (debug_traceCall + eth_call per
    /// token)
    #[instrument(fields(
        component_id = %component_id,
        token_count = tokens.len()
    ))]
    async fn detect_component_slots(
        &self,
        component_id: ComponentId,
        tokens: Vec<Address>,
        owner: &Address,
        block_hash: &BlockHash,
    ) -> Result<(ComponentId, HashMap<Address, Bytes>), BalanceSlotError> {
        if tokens.is_empty() {
            return Ok((component_id, HashMap::new()));
        }

        // Create batched request: 2 requests per token (debug_traceCall + eth_call)
        let batch_request = self.create_batched_request(&tokens, owner, block_hash)?;

        // Send the batched request
        let responses = self
            .send_batched_request(batch_request)
            .await?;

        // Process the batched response to extract slots
        let token_slots = self.process_batched_response(tokens, responses)?;

        Ok((component_id, token_slots))
    }

    /// Create a batched JSON-RPC request for all tokens (2 requests per token).
    /// We need to send a eth_call after the tracing to get the return value of the balanceOf
    /// function. Currently, debug_traceCall does not support preStateTracer + returning the
    /// value in the same request.
    fn create_batched_request(
        &self,
        tokens: &[Address],
        owner: &Address,
        block_hash: &BlockHash,
    ) -> Result<Value, BalanceSlotError> {
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

        Ok(Value::Array(batch))
    }

    /// Send a batched JSON-RPC request and return the responses
    async fn send_batched_request(
        &self,
        batch_request: Value,
    ) -> Result<Vec<Value>, BalanceSlotError> {
        let client = reqwest::Client::new();
        let response = client
            .post(self.tracer.rpc_url().as_str())
            .header("Content-Type", "application/json")
            .body(serde_json::to_string(&batch_request).unwrap())
            .send()
            .await
            .map_err(|e| BalanceSlotError::RequestError(e.to_string()))?;

        let response_json: serde_json::Value = response
            .json()
            .await
            .map_err(|e| BalanceSlotError::InvalidResponse(e.to_string()))?;

        // Handle batched response array
        match response_json {
            Value::Array(responses) => Ok(responses),
            _ => Err(BalanceSlotError::InvalidResponse(
                "Expected array response for batched request".into(),
            )),
        }
    }

    /// Process batched responses and extract storage slots for each token
    fn process_batched_response(
        &self,
        tokens: Vec<Address>,
        responses: Vec<Value>,
    ) -> Result<HashMap<Address, Bytes>, BalanceSlotError> {
        // We expect 2 responses per token (debug_traceCall + eth_call)
        if responses.len() != tokens.len() * 2 {
            return Err(BalanceSlotError::InvalidResponse(format!(
                "Expected {} responses for {} tokens, got {}",
                tokens.len() * 2,
                tokens.len(),
                responses.len()
            )));
        }

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
                Ok(Some(slot)) => {
                    debug!(
                        token = %token,
                        slot = ?slot,
                        "Found storage slot for token"
                    );
                    token_slots.insert(token.clone(), slot);
                }
                Ok(None) => {
                    debug!(token = %token, "No suitable slot found for token");
                }
                Err(e) => {
                    error!(token = %token, error = %e, "Failed to extract slot for token");
                    return Err(e);
                }
            }
        }

        Ok(token_slots)
    }

    /// Extract storage slot from paired debug_traceCall and eth_call responses
    fn extract_slot_from_paired_responses(
        &self,
        token: &Address,
        debug_response: Option<&Value>,
        eth_call_response: Option<&Value>,
    ) -> Result<Option<Bytes>, BalanceSlotError> {
        let debug_resp = debug_response.ok_or_else(|| {
            BalanceSlotError::InvalidResponse("Missing debug_traceCall response".into())
        })?;

        let eth_call_resp = eth_call_response
            .ok_or_else(|| BalanceSlotError::InvalidResponse("Missing eth_call response".into()))?;

        // Check for errors in responses
        if let Some(error) = debug_resp.get("error") {
            warn!("Debug trace failed for token {}: {}", token, error);
            return Ok(None);
        }

        if let Some(error) = eth_call_resp.get("error") {
            warn!("Eth call failed for token {}: {}", token, error);
            return Ok(None);
        }

        // Extract balance from eth_call response
        let balance = self.extract_balance_from_call_response(eth_call_resp)?;

        // Extract slot values from debug_traceCall response for better slot selection
        let slot_values = self.extract_slot_values_from_trace_response(debug_resp, token)?;

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
                "Invalid result length: {}",
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
        token: &Address,
    ) -> Result<Vec<(Bytes, U256)>, BalanceSlotError> {
        let result = response.get("result").ok_or_else(|| {
            BalanceSlotError::InvalidResponse("Missing result in debug_traceCall".into())
        })?;

        // The debug_traceCall with prestateTracer returns the result directly as a hashmap
        let frame_map: std::collections::BTreeMap<String, serde_json::Value> =
            match serde_json::from_value(result.clone()) {
                Ok(map) => map,
                Err(e) => {
                    error!("Failed to parse trace result as hashmap: {}", e);
                    return Err(BalanceSlotError::ParseError(format!(
                        "Failed to parse trace result: {}",
                        e
                    )));
                }
            };

        let mut slot_values = Vec::new();
        let token_hex = format!("0x{}", alloy::hex::encode(token.as_ref()));

        for (address_str, account_data) in frame_map {
            if address_str.to_lowercase() == token_hex.to_lowercase() {
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
                                        slot_values.push((slot_bytes, value));
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
                    debug!("No storage field found for address {}", address_str);
                }
            }
        }

        Ok(slot_values)
    }

    /// Find the best slot by comparing storage values to the expected balance
    fn find_best_slot_by_value_comparison(
        &self,
        slot_values: Vec<(Bytes, U256)>,
        expected_balance: U256,
    ) -> Result<Option<Bytes>, BalanceSlotError> {
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
                Ok(Some(slot))
            }
            _ => {
                // Find the slot with minimum difference without allocating a new vector
                let (best_slot, best_value, best_diff) = slot_values
                    .into_iter()
                    .map(|(slot, value)| {
                        let diff = value.abs_diff(expected_balance);
                        (slot, value, diff)
                    })
                    .min_by_key(|(_, _, diff)| *diff)
                    .unwrap(); // Safe because we know len > 0

                debug!(
                    "Found {} slots, selected best slot: 0x{} (value: {}, diff: {})",
                    slot_count,
                    alloy::hex::encode(best_slot.as_ref()),
                    best_value,
                    best_diff
                );

                Ok(Some(best_slot))
            }
        }
    }
}

/// Implement the BalanceSlotDetector trait
#[async_trait]
impl BalanceSlotDetector for EVMBalanceSlotDetector {
    type Error = BalanceSlotError;

    /// Detect balance storage slots for multiple components in parallel
    async fn detect_slots_for_components(
        &self,
        components: Vec<(ComponentId, Vec<Address>)>,
        holder: Address,
        block_hash: BlockHash,
    ) -> HashMap<ComponentId, Result<HashMap<Address, Bytes>, Self::Error>> {
        info!("Starting balance slot detection for {} components", components.len());
        let mut all_results = HashMap::new();

        // Process components in chunks to optimize, while avoiding being rate limited
        for (chunk_idx, chunk) in components
            .chunks(self.max_concurrent_components)
            .enumerate()
        {
            debug!("Processing chunk {} with {} components", chunk_idx, chunk.len());

            let futures = chunk.iter().map(|(comp_id, tokens)| {
                self.detect_component_slots(comp_id.clone(), tokens.clone(), &holder, &block_hash)
            });

            // join_all guarantees that the results of the completed futures will be collected into
            // a Vec<T> in the same order as the input futures were provided.
            let chunk_results = join_all(futures).await;

            for (idx, result) in chunk_results.into_iter().enumerate() {
                let component_id = chunk[idx].0.clone();
                match result {
                    Ok((comp_id, slots)) => {
                        if !slots.is_empty() {
                            debug!(
                                component_id = %comp_id,
                                slot_count = slots.len(),
                                "Successfully detected slots for component"
                            );
                        } else {
                            // Shouldn't happen - only if we ever got a component without tokens
                            warn!(
                                component_id = %comp_id,
                                "No slots detected for component"
                            );
                        }
                        all_results.insert(comp_id, Ok(slots));
                    }
                    Err(e) => {
                        error!("Failed to detect slots for component: {}", e);
                        all_results.insert(component_id, Err(e));
                    }
                }
            }
        }

        info!(
            "Balance slot detection completed. Found results for {} components",
            all_results.len()
        );
        all_results
    }

    /// Set the maximum number of components to process concurrently
    fn set_max_concurrent(&mut self, max: usize) {
        self.max_concurrent_components = max;
    }

    /// Get the current max concurrent setting
    fn max_concurrent(&self) -> usize {
        self.max_concurrent_components
    }
}

impl EVMBalanceSlotDetector {
    /// Direct access to the underlying tracer for advanced use cases
    pub fn tracer(&self) -> &EVMEntrypointService {
        &self.tracer
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

    #[tokio::test]
    #[ignore = "require RPC connection"]
    async fn test_detect_slots_integration() {
        let rpc_url = std::env::var("RPC_URL").expect("RPC_URL must be set");
        println!("Using RPC URL: {}", rpc_url);
        let config = BalanceSlotDetectorConfig { max_concurrent_components: 5, rpc_url };

        let detector = EVMBalanceSlotDetector::new(config).unwrap();

        // Use real token addresses and block for testing (WETH, USDC)
        let weth_bytes = alloy::hex::decode("C02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2").unwrap();
        let usdc_bytes = alloy::hex::decode("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48").unwrap();
        let pool_manager_bytes =
            alloy::hex::decode("000000000004444c5dc75cB358380D2e3dE08A90").unwrap();

        let weth = Address::from(weth_bytes);
        let usdc = Address::from(usdc_bytes);
        let pool_manager = Address::from(pool_manager_bytes);

        println!("WETH address: 0x{}", alloy::hex::encode(weth.as_ref()));
        println!("USDC address: 0x{}", alloy::hex::encode(usdc.as_ref()));
        println!("Pool manager address: 0x{}", alloy::hex::encode(pool_manager.as_ref()));

        let components = vec![("test_comp".to_string(), vec![weth.clone(), usdc.clone()])];

        // Use a recent block
        let block_hash_bytes =
            alloy::hex::decode("658814e4cb074359f10dd71237cc57b1ae6791fc9de59fde570e724bd884cbb0")
                .unwrap();
        let block_hash = BlockHash::from(block_hash_bytes);
        println!("Block hash: 0x{}", alloy::hex::encode(block_hash.as_ref()));

        let results = detector
            .detect_slots_for_components(components, pool_manager, block_hash)
            .await;

        println!("Results: {:?}", results);
        println!("Number of components with results: {}", results.len());

        // Check if we got any results at all
        if results.is_empty() {
            println!("WARNING: No results returned from detect_slots_for_components");
        }

        // We should get results for the component
        assert!(!results.is_empty(), "Expected results for at least one component, but got none");

        if let Some(result) = results.get("test_comp") {
            let slots = result
                .as_ref()
                .expect("Expected successful result for test_comp");
            println!("Detected slots for test_comp: {:?}", slots);
            println!("Number of tokens with detected slots: {}", slots.len());

            // Check individual tokens
            if let Some(weth_slot) = slots.get(&weth) {
                println!("WETH slot: 0x{}", alloy::hex::encode(weth_slot.as_ref()));
            } else {
                panic!("No slot detected for WETH");
            }

            if let Some(usdc_slot) = slots.get(&usdc) {
                println!("USDC slot: 0x{}", alloy::hex::encode(usdc_slot.as_ref()));
            } else {
                panic!("No slot detected for USDC");
            }
        } else {
            panic!("Expected results for 'test_comp', but it was not in the results map");
        }
    }

    #[tokio::test]
    #[ignore] // Requires real RPC connection
    async fn test_detect_slots_rebasing_token() {
        let rpc_url = std::env::var("RPC_URL").expect("RPC_URL must be set");
        let config = BalanceSlotDetectorConfig { max_concurrent_components: 5, rpc_url };

        let detector = EVMBalanceSlotDetector::new(config).unwrap();

        // stETH contract address (Lido Staked Ether)
        let steth_bytes = alloy::hex::decode("ae7ab96520DE3A18E5e111B5EaAb095312D7fE84").unwrap();
        let steth = Address::from(steth_bytes);

        // Address extracted from stETH events. Verified that it has funds
        let owner_address = alloy::hex::decode("ef417FCE1883c6653E7dC6AF7c6F85CCDE84Aa09").unwrap();
        let balance_owner = Address::from(owner_address);

        let components = vec![("steth_comp".to_string(), vec![steth.clone()])];

        // Use a recent block where stETH has activity
        let block_hash_bytes =
            alloy::hex::decode("658814e4cb074359f10dd71237cc57b1ae6791fc9de59fde570e724bd884cbb0")
                .unwrap();
        let block_hash = BlockHash::from(block_hash_bytes);

        let results = detector
            .detect_slots_for_components(components, balance_owner.clone(), block_hash.clone())
            .await;

        dbg!(&results);

        // For rebasing tokens like stETH, we expect multiple slots to be accessed
        // because balanceOf() needs to:
        // 1. Read the shares mapping for the holder
        // 2. Read total shares value (stored at TOTAL_SHARES_POSITION)
        // 3. Read total pooled ether to calculate the rate
        if let Some(result) = results.get("steth_comp") {
            let slots = result
                .as_ref()
                .expect("Expected successful result for steth_comp");
            if let Some(detected_slot) = slots.get(&steth) {
                println!("Detected stETH storage slot: {:?}", detected_slot);

                // For rebasing tokens, we should detect a storage slot
                assert!(!detected_slot.is_empty());

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

                assert!(
                    verified_balance == expected_eth,
                    "Verified balance ({}) should be == target balance ({})",
                    verified_balance,
                    expected_eth
                );

                println!("✓ Storage slot manipulation verified successfully!");

                // Check if this matches known stETH storage positions:
                let expected_slot =
                    "28b290becf7be0019520d491d9cd869337f3d683be3e569e54f9044b94df94c0";

                assert_eq!(slot_hex, expected_slot);
            } else {
                // If no slot detected, print debug info
                println!("No slots detected for stETH - this might indicate the balance owner has no stETH balance");
            }
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
        // Create storage overrides using the existing tracer infrastructure
        let slot_hex = alloy::hex::encode(detected_slot.as_ref());
        let target_hex = format!("0x{:064x}", target_balance);

        println!("Setting storage slot 0x{} to value {}", slot_hex, target_hex);

        let calldata = encode_balance_of_calldata(balance_owner);

        // Create storage overrides
        let mut slot_overrides = BTreeMap::new();
        slot_overrides.insert(
            detected_slot.clone(),
            Bytes::from(
                target_balance
                    .to_be_bytes::<32>()
                    .to_vec(),
            ),
        );

        let account_overrides = AccountOverrides {
            slots: Some(tycho_common::models::blockchain::StorageOverride::Diff(slot_overrides)),
            native_balance: None,
            code: None,
        };

        let mut state_overrides = BTreeMap::new();
        state_overrides.insert(token.clone(), account_overrides);

        // Use the existing tracer with state overrides
        let entry_point = EntryPoint::new(
            format!("{}:balanceOf(address)", token),
            token.clone(),
            "balanceOf(address)".to_string(),
        );

        let tracer_params =
            RPCTracerParams::new(None, calldata.clone()).with_state_overrides(state_overrides);

        let entry_point_with_params =
            tycho_common::models::blockchain::EntryPointWithTracingParams::new(
                entry_point,
                TracingParams::RPCTracer(tracer_params),
            );

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
            .post(detector.tracer.rpc_url().as_str())
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
                "Invalid result length: {}",
                hex_str.len()
            )));
        }

        U256::from_str_radix(hex_str, 16)
            .map_err(|e| BalanceSlotError::BalanceExtractionError(e.to_string()))
    }
}
