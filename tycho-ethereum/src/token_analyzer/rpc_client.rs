use std::{collections::HashMap, default::Default};

use alloy::{
    primitives::{Address, B256, U256},
    rpc::{
        client::{ClientBuilder, ReqwestClient},
        types::{debug::StorageRangeResult, Block, BlockId, BlockNumberOrTag},
    },
};
use async_trait::async_trait;
use tracing::{debug, info, trace};
use tycho_common::Bytes;

use crate::{errors::extract_error_chain, RPCError, RequestError};

// TODO - move this trait to tycho_common to implement for other chains
#[async_trait]
pub trait RpcClient: Sized {
    fn new(rpc_url: &str) -> Result<Self, RPCError>;

    async fn get_block_number(&self) -> Result<u64, RPCError>;
}

pub trait EthereumRpcConfig: Clone + Default + Send + Sync {}

// TODO: Optimize these configurable for preventing rate limiting.
// TODO: Handle rate limiting / individual connection failures & retries
#[derive(Clone)]
pub struct WithBatching {
    max_batch_size: usize,
    max_storage_slot_batch_size: usize,
}

impl Default for WithBatching {
    fn default() -> Self {
        Self { max_batch_size: 50, max_storage_slot_batch_size: 10000 }
    }
}

pub type Plain = ();

impl EthereumRpcConfig for WithBatching {}
impl EthereumRpcConfig for Plain {}

#[derive(Clone)]
pub struct EthereumRpcClient<C: EthereumRpcConfig> {
    inner: ReqwestClient,
    config: C,
}

impl<C: EthereumRpcConfig> EthereumRpcClient<C> {
    pub(crate) fn from_inner(inner: ReqwestClient) -> Self {
        Self { inner, config: C::default() }
    }

    pub(crate) async fn eth_get_block_by_number(
        &self,
        block_id: BlockId,
    ) -> Result<Block, RPCError> {
        let full_tx_objects = false;

        let result: Option<Block> = self
            .inner
            .request("eth_getBlockByNumber", (block_id, full_tx_objects))
            .await
            .map_err(|e| {
                RPCError::RequestError(RequestError::Other(format!("Failed to get block: {e}")))
            })?;

        result.ok_or(RPCError::RequestError(RequestError::Other("Block not found".to_string())))
    }

    pub(crate) async fn eth_get_balance(
        &self,
        block_id: BlockNumberOrTag,
        address: Address,
    ) -> Result<U256, RPCError> {
        self.inner
            .request("eth_getBalance", (address, block_id))
            .await
            .map_err(|e| {
                let error_chain = extract_error_chain(&e);
                RPCError::RequestError(RequestError::Other(format!(
                    "Failed to get balance: {error_chain}"
                )))
            })
    }

    pub(crate) async fn eth_get_code(
        &self,
        block_id: BlockNumberOrTag,
        address: Address,
    ) -> Result<Bytes, RPCError> {
        self.inner
            .request("eth_getCode", (address, block_id))
            .await
            .map_err(|e| {
                let error_chain = extract_error_chain(&e);
                RPCError::RequestError(RequestError::Other(format!(
                    "Failed to get code: {error_chain}"
                )))
            })
    }

    pub(crate) async fn debug_storage_range_at(
        &self,
        block_hash: B256,
        address: Address,
        start_key: B256,
    ) -> Result<StorageRangeResult, RPCError> {
        let params = (
            block_hash, 0, // transaction index, 0 for the state at the end of the block
            address, start_key, // The offset (hash of storage key)
            100000,    // The number of storage entries to return
        );

        self.inner
            .request("debug_storageRangeAt", params)
            .await
            .map_err(|e| {
                let error_chain = extract_error_chain(&e);
                RPCError::RequestError(RequestError::Other(format!(
                    "Failed to get storage: {error_chain}, address: {address}, block: {block_hash}",
                )))
            })
    }

    pub(crate) async fn get_storage_range(
        &self,
        address: Address,
        block_hash: B256,
    ) -> Result<HashMap<B256, B256>, RPCError> {
        let mut all_slots = HashMap::new();
        let mut start_key = B256::ZERO;
        loop {
            trace!("Requesting storage range for {:?}, block: {:?}", address, block_hash);
            let result = self
                .debug_storage_range_at(block_hash, address, start_key)
                .await?;

            for (_, entry) in result.storage.0 {
                all_slots.insert(entry.key, entry.value);
            }

            if let Some(next_key) = result.next_key {
                start_key = next_key;
            } else {
                break;
            }
        }

        Ok(all_slots)
    }
}

impl EthereumRpcClient<WithBatching> {
    pub fn with_batching_params(
        self,
        max_batch_size: usize,
        max_storage_slot_batch_size: usize,
    ) -> Self {
        Self {
            inner: self.inner,
            config: WithBatching { max_batch_size, max_storage_slot_batch_size },
        }
    }

    pub(crate) async fn batch_fetch_account_code_and_balance(
        &self,
        block_id: BlockNumberOrTag,
        addresses: &[Address],
    ) -> Result<HashMap<Address, (Bytes, U256)>, RPCError> {
        debug!(
            chunk_size = self.config.max_batch_size,
            total_chunks = addresses.len() / self.config.max_batch_size + 1,
            block_id = block_id.to_string(),
            "Preparing batch request for account code and balance"
        );

        let mut codes_and_balances = HashMap::with_capacity(addresses.len());

        for chunk_addresses in addresses.chunks(self.config.max_batch_size) {
            let mut batch = self.inner.new_batch();
            let mut code_requests = Vec::with_capacity(self.config.max_batch_size);
            let mut balance_requests = Vec::with_capacity(self.config.max_batch_size);

            for address in chunk_addresses {
                code_requests.push(Box::pin(
                    batch
                        .add_call::<_, Bytes>("eth_getCode", &(address, block_id))
                        .map_err(|e| {
                            RPCError::RequestError(RequestError::Other(format!(
                                "Failed to get code: {e}"
                            )))
                        })?,
                ));

                balance_requests.push(Box::pin(
                    batch
                        .add_call::<_, U256>("eth_getBalance", &(address, block_id))
                        .map_err(|e| {
                            RPCError::RequestError(RequestError::Other(format!(
                                "Failed to get balance: {e}"
                            )))
                        })?,
                ));
            }

            debug!(
                total_requests = chunk_addresses.len() * 2, // code + balance for each address
                block_id = block_id.to_string(),
                "Sending batch request to RPC provider"
            );

            // Add debugging to understand when the URL issue occurs
            debug!(
                "About to send batch with {} code requests and {} balance requests",
                code_requests.len(),
                balance_requests.len()
            );

            batch.send().await.map_err(|e| {
                let error_chain = extract_error_chain(&e);
                let printable_addresses = chunk_addresses
                    .iter()
                    .map(|addr| format!("{:?}", addr))
                    .collect::<Vec<String>>()
                    .join(", ");
                RPCError::RequestError(RequestError::Other(format!(
                    "Failed to send batch request for code & balance: {error_chain}. Block: {block_id}, Addresses count: {}, Addresses: [{}]",
                    chunk_addresses.len(),
                    printable_addresses
                )))
            })?;

            info!(
                chunk_size = chunk_addresses.len(),
                block_id = block_id.to_string(),
                "Successfully sent batch request for account code and balance"
            );

            for (idx, address) in chunk_addresses.iter().enumerate() {
                let code_result = code_requests[idx]
                    .as_mut()
                    .await
                    .map_err(|e| {
                        RPCError::RequestError(RequestError::Other(format!(
                            "Failed to collect code request data: {e}"
                        )))
                    })?;

                let balance_result = balance_requests[idx]
                    .as_mut()
                    .await
                    .map_err(|e| {
                        RPCError::RequestError(RequestError::Other(format!(
                            "Failed to collect balance request data: {e}"
                        )))
                    })?;

                codes_and_balances.insert(*address, (code_result, balance_result));
            }
        }

        Ok(codes_and_balances)
    }

    pub(crate) async fn batch_get_selected_storage(
        &self,
        block_id: BlockNumberOrTag,
        address: Address,
        slots: &[B256],
    ) -> Result<HashMap<B256, Option<B256>>, RPCError> {
        let mut storage_requests = Vec::with_capacity(self.config.max_storage_slot_batch_size);

        let mut result = HashMap::new();

        for slot_batch in slots.chunks(self.config.max_storage_slot_batch_size) {
            let mut storage_batch = self.inner.new_batch();

            for slot in slot_batch {
                storage_requests.push(Box::pin(
                    storage_batch
                        .add_call::<_, B256>("eth_getStorageAt", &(&address, slot, block_id))
                        .map_err(|e| {
                            RPCError::RequestError(RequestError::Other(format!(
                                "Failed to get storage: {e}, address: {address}, block: {block_id}, slot: {slot}",
                            )))
                        })?,
                ));
            }

            let request_size = slot_batch.len();
            storage_batch
                        .send()
                        .await
                        .map_err(|e| {
                            let error_chain = extract_error_chain(&e);
                            RPCError::RequestError(RequestError::Other(format!(
                                "Failed to send storage batch request. Requested for {request_size} : {error_chain}"
                            )))
                        })?;

            for (idx, slot) in slot_batch.iter().enumerate() {
                let storage_result = storage_requests[idx]
                    .as_mut()
                    .await
                    .map_err(|e| {
                        RPCError::RequestError(RequestError::Other(format!(
                            "Failed to collect storage request data: {e}"
                        )))
                    })?;

                let value = if storage_result == [0; 32] { None } else { Some(storage_result) };

                result.insert(*slot, value);
            }
        }

        Ok(result)
    }
}

#[async_trait]
impl<C: EthereumRpcConfig> RpcClient for EthereumRpcClient<C> {
    fn new(rpc_url: &str) -> Result<Self, RPCError> {
        let url = rpc_url
            .parse()
            .map_err(|e| RPCError::SetupError(format!("Invalid RPC URL: {}", e)))?;

        let rpc = ClientBuilder::default().http(url);

        Ok(Self::from_inner(rpc))
    }

    async fn get_block_number(&self) -> Result<u64, RPCError> {
        let block_number: BlockNumberOrTag = self
            .inner
            .request_noparams("eth_blockNumber")
            .await
            .map_err(|e| {
                RPCError::RequestError(RequestError::Other(format!(
                    "Failed to get block number: {}",
                    e
                )))
            })?;

        if let BlockNumberOrTag::Number(num) = block_number {
            Ok(num)
        } else {
            Err(RPCError::RequestError(RequestError::Other("Unexpected block ID type".to_string())))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use alloy::hex;
    use rstest::rstest;
    use tracing::warn;
    use tracing_test::traced_test;

    use super::*;
    use crate::{
        test_fixtures::{
            TestFixture, BALANCER_VAULT_EXPECTED_SLOTS, BALANCER_VAULT_STR, STETH_EXPECTED_SLOTS,
            STETH_STR, TEST_BLOCK_HASH, TEST_BLOCK_NUMBER, TEST_SLOTS,
        },
        BytesCodec,
    };

    // Local extension methods specific to account extractor tests
    impl TestFixture {
        fn create_batching_rpc_client(&self) -> EthereumRpcClient<WithBatching> {
            EthereumRpcClient::<WithBatching>::from_inner(self.inner_rpc.clone())
        }
    }

    fn parse_address(address_str: &str) -> Address {
        Address::from_str(address_str).expect("failed to parse address")
    }

    #[tokio::test]
    #[ignore = "require RPC connection"]
    async fn test_ethereum_rpc_client_creation() -> Result<(), RPCError> {
        let url = std::env::var("RPC_URL").expect("RPC_URL must be set for testing");

        // Test with valid URL
        let result = EthereumRpcClient::<WithBatching>::new(&url);
        assert!(result.is_ok());

        // Test with invalid URL
        let result = EthereumRpcClient::<WithBatching>::new("invalid_url");
        assert!(result.is_err());

        Ok(())
    }

    #[tokio::test]
    #[ignore = "require RPC connection"]
    async fn test_get_block_number() -> Result<(), RPCError> {
        let fixture = TestFixture::new();
        let client = fixture.create_batching_rpc_client();

        let block_number = client.get_block_number().await?;

        // For Ethereum mainnet, we know block numbers are in the millions
        // This is a sanity check to ensure we're not getting garbage data
        assert!(
            block_number > TEST_BLOCK_NUMBER,
            "Block number seems too low for Ethereum mainnet: {}",
            block_number
        );

        Ok(())
    }

    #[rstest]
    #[case(BALANCER_VAULT_STR, U256::ZERO)]
    #[case(STETH_STR, U256::from_str("8158647137036262954484").unwrap())]
    #[tokio::test]
    #[ignore = "require RPC connection"]
    async fn test_get_balance(
        #[case] address_str: &str,
        #[case] expected_balance: U256,
    ) -> Result<(), RPCError> {
        let fixture = TestFixture::new();
        let client = fixture.create_batching_rpc_client();

        let address = Address::from_str(address_str).expect("failed to parse address");
        let block_id = BlockNumberOrTag::Number(TEST_BLOCK_NUMBER);

        let balance = client
            .eth_get_balance(block_id, address)
            .await
            .expect("Failed to get balance");

        assert_eq!(
            balance, expected_balance,
            "Balance mismatch for address {}. Expected: {}, Got: {}",
            address_str, expected_balance, balance
        );

        Ok(())
    }

    #[rstest]
    #[case(BALANCER_VAULT_STR, 24512, "0x60806040526004361061")]
    #[case(STETH_STR, 1035, "0x60806040526004361061")]
    #[case("0x0000000000000000000000000000000000000000", 0, "0x")]
    #[tokio::test]
    #[ignore = "require RPC connection"]
    async fn test_get_code(
        #[case] address_str: &str,
        #[case] expected_length: usize,
        #[case] expected_prefix: &str,
    ) -> Result<(), RPCError> {
        let fixture = TestFixture::new();
        let client = fixture.create_batching_rpc_client();

        let address = parse_address(address_str);
        let block_id = BlockNumberOrTag::Number(TEST_BLOCK_NUMBER);

        let code = client
            .eth_get_code(block_id, address)
            .await?;

        assert_eq!(
            code.len(),
            expected_length,
            "{} code length mismatch. Expected: {}, Got: {}",
            address_str,
            expected_length,
            code.len()
        );

        let actual_prefix = if code.len() >= 10 {
            format!("0x{}", hex::encode(&code[..10]))
        } else {
            format!("0x{}", hex::encode(&code))
        };

        assert_eq!(
            actual_prefix, expected_prefix,
            "{} code prefix mismatch. Expected: {}, Got: {}",
            address_str, expected_prefix, actual_prefix
        );

        Ok(())
    }

    #[rstest]
    #[case(BALANCER_VAULT_STR, BALANCER_VAULT_EXPECTED_SLOTS)]
    #[case(STETH_STR, STETH_EXPECTED_SLOTS)]
    #[traced_test]
    #[tokio::test]
    #[ignore = "require RPC connection"]
    async fn test_get_storage_range(
        #[case] address_str: &str,
        #[case] expected_slot_count: usize,
    ) -> Result<(), RPCError> {
        let fixture = TestFixture::new();
        let client = fixture.create_batching_rpc_client();

        // Warn about large contracts (STETH has 789k+ slots, takes ~2 mins, ~50MB data)
        if expected_slot_count > 100_000 {
            warn!(
                "Testing large contract {} with {} storage slots - this will take ~2 minutes and retrieve ~50MB of data",
                address_str, expected_slot_count
            );
        }

        let address = parse_address(address_str);
        let block_id = B256::from_str(TEST_BLOCK_HASH).expect("failed to parse block hash");

        let storage = client
            .get_storage_range(address, block_id)
            .await?;

        assert_eq!(
            storage.len(),
            expected_slot_count,
            "{} storage slot count mismatch. Expected: {}, Got: {}",
            address_str,
            expected_slot_count,
            storage.len()
        );

        Ok(())
    }

    #[traced_test]
    #[tokio::test]
    #[ignore = "require RPC connection"]
    async fn test_batch_fetch_account_code_and_balance() -> Result<(), RPCError> {
        let fixture = TestFixture::new();
        let client = fixture.create_batching_rpc_client();

        // Test with multiple addresses
        let requests = vec![parse_address(BALANCER_VAULT_STR), parse_address(STETH_STR)];

        let codes_and_balances = client
            .batch_fetch_account_code_and_balance(
                BlockNumberOrTag::Number(fixture.block.number),
                &requests,
            )
            .await?;

        // Check that we got code and balance for both addresses
        assert_eq!(codes_and_balances.len(), 2);

        // Check that the first address has code and balance
        let first_address = parse_address(BALANCER_VAULT_STR);
        assert!(codes_and_balances.contains_key(&first_address));

        // Check that the second address has code and balance
        let second_address = parse_address(STETH_STR);
        assert!(codes_and_balances.contains_key(&second_address));

        // Verify code is non-empty for contract addresses
        assert!(!codes_and_balances
            .get(&first_address)
            .unwrap()
            .0
            .is_empty());
        assert!(!codes_and_balances
            .get(&second_address)
            .unwrap()
            .0
            .is_empty());

        Ok(())
    }

    #[traced_test]
    #[tokio::test]
    #[ignore = "require RPC connection"]
    async fn test_fetch_account_storage_without_specific_slots() -> Result<(), RPCError> {
        let fixture = TestFixture::new();
        let client = fixture.create_batching_rpc_client();

        let storage = client
            .get_storage_range(
                parse_address(BALANCER_VAULT_STR),
                B256::from_bytes(&fixture.block.hash),
            )
            .await?;

        // Verify that we got the storage for all requested slots
        assert_eq!(storage.len(), BALANCER_VAULT_EXPECTED_SLOTS);

        // Check that each slot has a value
        for (key, value) in TEST_SLOTS.iter() {
            println!("slot: {key:?}");
            assert!(storage.contains_key(key));
            assert_eq!(storage.get(key), Some(value)); // Storage value exists and matches
        }

        Ok(())
    }

    #[traced_test]
    #[tokio::test]
    #[ignore = "require RPC connection"]
    async fn test_fetch_account_storage_with_specific_slots() -> Result<(), RPCError> {
        let fixture = TestFixture::new();
        let client = fixture.create_batching_rpc_client();

        // Create request with specific slots
        let slots_request: Vec<B256> = TEST_SLOTS.keys().cloned().collect();

        let storage = client
            .batch_get_selected_storage(
                BlockNumberOrTag::Number(fixture.block.number),
                parse_address(BALANCER_VAULT_STR),
                &slots_request,
            )
            .await?;

        // Verify that we got the storage for all requested slots
        assert_eq!(storage.len(), 3);

        // Check that each slot has a value
        for (key, value) in TEST_SLOTS.iter() {
            println!("slot: {key:?}");
            assert!(storage.contains_key(key));
            assert_eq!(
                storage
                    .get(key)
                    .and_then(|v| v.as_ref()),
                Some(value)
            ); // Storage value exists and matches
        }

        Ok(())
    }
}
