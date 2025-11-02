use std::collections::HashMap;

use async_trait::async_trait;
use tracing::info;
use tycho_common::{
    models::{Address, BlockHash},
    traits::BalanceSlotDetector,
    Bytes,
};

use crate::entrypoint_tracer::slot_detector::{
    SlotDetectionStrategy, SlotDetector, SlotDetectorConfig, SlotDetectorError,
};

/// Strategy for balance slot detection
#[derive(Clone)]
pub struct BalanceStrategy;

impl SlotDetectionStrategy for BalanceStrategy {
    type CacheKey = (Address, Address);
    type Params = Address;

    fn cache_key(token: &Address, params: &Self::Params) -> Self::CacheKey {
        (token.clone(), params.clone())
    }

    fn encode_calldata(params: &Self::Params) -> Bytes {
        // balanceOf selector: 0x70a08231
        let mut calldata = vec![0x70, 0xa0, 0x82, 0x31];

        // Pad address to 32 bytes (12 bytes of zeros + 20 bytes address)
        calldata.extend_from_slice(&[0u8; 12]);
        calldata.extend_from_slice(params.as_ref());

        Bytes::from(calldata)
    }
}

/// EVM-specific implementation of BalanceSlotDetector using debug_traceCall
pub type EVMBalanceSlotDetector = SlotDetector<BalanceStrategy>;

/// Implement the BalanceSlotDetector trait
#[async_trait]
impl BalanceSlotDetector for EVMBalanceSlotDetector {
    type Error = SlotDetectorError;

    /// Detect balance storage slots for multiple tokens using a combination of batched and async
    /// concurrent requests.
    async fn detect_balance_slots(
        &self,
        tokens: &[Address],
        holder: Address,
        block_hash: BlockHash,
    ) -> HashMap<Address, Result<(Address, Bytes), Self::Error>> {
        info!("Starting balance slot detection for {} tokens", tokens.len());

        let results = self
            .detect_slots_chunked(tokens, &holder, &block_hash)
            .await;

        info!("Balance slot detection completed. Found results for {} tokens", results.len());
        results
    }
}

#[cfg(test)]
mod tests {
    use alloy::{primitives::U256, transports::http::reqwest};
    use serde_json::json;

    use super::{BalanceStrategy, SlotDetectionStrategy, *};

    #[test]
    fn test_encode_balance_of_calldata() {
        let address = Address::from([0x12u8; 20]);
        let calldata = BalanceStrategy::encode_calldata(&address);

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
        let config = SlotDetectorConfig {
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
        let config = SlotDetectorConfig {
            max_batch_size: 5,
            rpc_url: rpc_url.clone(),
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
                    &rpc_url,
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
        rpc_url: &str,
        detector: &EVMBalanceSlotDetector,
        token: &Address,
        balance_owner: &Address,
        detected_slot: &Bytes,
        target_balance: U256,
        block_hash: &BlockHash,
    ) -> Result<U256, SlotDetectorError> {
        let slot_hex = alloy::hex::encode(detected_slot.as_ref());
        let target_hex = format!("0x{:064x}", target_balance);

        println!("Setting storage slot 0x{} to value {}", slot_hex, target_hex);

        let calldata = BalanceStrategy::encode_calldata(balance_owner);

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
            .post(rpc_url)
            .header("Content-Type", "application/json")
            .body(serde_json::to_string(&request).unwrap())
            .send()
            .await
            .map_err(|e| SlotDetectorError::RequestError(e.to_string()))?;

        let response_json: serde_json::Value = response
            .json()
            .await
            .map_err(|e| SlotDetectorError::InvalidResponse(e.to_string()))?;

        if let Some(error) = response_json.get("error") {
            return Err(SlotDetectorError::RequestError(format!("RPC error: {}", error)));
        }

        let result = response_json
            .get("result")
            .and_then(|v| v.as_str())
            .ok_or_else(|| SlotDetectorError::InvalidResponse("Missing result".into()))?;

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
}
