use std::collections::HashMap;

use async_trait::async_trait;
use tracing::info;
use tycho_common::{
    models::{Address, BlockHash},
    traits::AllowanceSlotDetector,
    Bytes,
};

use crate::entrypoint_tracer::slot_detector::{
    SlotDetectionStrategy, SlotDetector, SlotDetectorConfig, SlotDetectorError,
};

/// Strategy for allowance slot detection
#[derive(Clone)]
pub struct AllowanceStrategy;

impl SlotDetectionStrategy for AllowanceStrategy {
    type CacheKey = (Address, Address, Address);
    type Params = (Address, Address);

    fn cache_key(token: &Address, params: &Self::Params) -> Self::CacheKey {
        let (owner, spender) = params;
        (token.clone(), owner.clone(), spender.clone())
    }

    fn encode_calldata(params: &Self::Params) -> Bytes {
        let (owner, spender) = params;
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

/// EVM-specific implementation of AllowanceSlotDetector using debug_traceCall
pub type EVMAllowanceSlotDetector = SlotDetector<AllowanceStrategy>;

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

        let params = (owner, spender);
        let results = self
            .detect_slots_chunked(tokens, &params, &block_hash)
            .await;

        info!("Allowance slot detection completed. Found results for {} tokens", results.len());
        results
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use crate::rpc::EthereumRpcClient;

    #[test]
    fn test_encode_allowance_calldata() {
        let owner = Address::from([0x11u8; 20]);
        let spender = Address::from([0x22u8; 20]);
        let calldata = AllowanceStrategy::encode_calldata(&(owner.clone(), spender.clone()));

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

        let rpc = EthereumRpcClient::new(&rpc_url).expect("failed to create RPC client");
        let detector = EVMAllowanceSlotDetector::new(SlotDetectorConfig::default(), &rpc);

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
