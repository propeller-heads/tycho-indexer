use std::{collections::HashMap, sync::Arc, time::Duration};

use alloy::{
    primitives::U256,
    rpc::types::trace::geth::{GethTrace, PreStateFrame, PreStateMode},
};
use async_trait::async_trait;
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

use crate::{
    entrypoint_tracer::{
        slot_detector::{
            SlotDetector, SlotDetectorConfig, SlotDetectorError, TokenSlotResults, ValidationData,
        },
        tracer::EVMEntrypointService,
    },
    RPCError,
};

/// Cache type for allowance slot detection results
type AllowanceSlotCache = Arc<RwLock<HashMap<(Address, Address, Address), (Address, Bytes)>>>;

/// EVM-specific implementation of AllowanceSlotDetector using debug_traceCall
pub struct EVMAllowanceSlotDetector {
    cache: AllowanceSlotCache,
    inner: SlotDetector,
}

impl EVMAllowanceSlotDetector {
    pub fn new(config: SlotDetectorConfig) -> Result<Self, SlotDetectorError> {
        let slot_detector =
            SlotDetector::new(config).map_err(|e| SlotDetectorError::SetupError(e.to_string()))?;

        // perf: Allow a client to be passed on the constructor, to use a shared client between
        // other parts of the code that perform node RPC requests

        Ok(Self { cache: Arc::new(RwLock::new(HashMap::new())), inner: slot_detector })
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
    ) -> HashMap<Address, Result<(Address, Bytes), SlotDetectorError>> {
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
        let calldata = Self::encode_allowance_calldata(owner, spender);
        let requests =
            self.inner
                .create_value_requests(&request_tokens, calldata.clone(), block_hash);

        // Send the batched request
        let responses = match self
            .inner
            .send_batched_request(requests)
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
        let token_slots = self
            .inner
            .process_batched_response(&request_tokens, responses);

        // Validates that the selected slot actually matches the expectation.
        let validation_results = self
            .inner
            .validate_best_slots(token_slots, calldata, block_hash)
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

    /// Encode allowance(owner, spender) calldata
    fn encode_allowance_calldata(owner: &Address, spender: &Address) -> Bytes {
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
}

/// Implement the AllowanceSlotDetector trait
#[async_trait]
impl AllowanceSlotDetector for EVMAllowanceSlotDetector {
    type Error = SlotDetectorError;

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
            .chunks(self.inner.max_batch_size)
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

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    #[test]
    fn test_encode_allowance_calldata() {
        let owner = Address::from([0x11u8; 20]);
        let spender = Address::from([0x22u8; 20]);
        let calldata = EVMAllowanceSlotDetector::encode_allowance_calldata(&owner, &spender);

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

        let detector = EVMAllowanceSlotDetector::new(SlotDetectorConfig {
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
