use std::{
    collections::{HashMap, HashSet},
    error::Error,
};

use alloy::{
    primitives::{Address as AlloyAddress, Uint, B256, U256},
    rpc::{
        client::{ClientBuilder, ReqwestClient},
        types::{Block as AlloyBlock, BlockId, BlockNumberOrTag},
    },
};
use async_trait::async_trait;
use chrono::DateTime;
use futures::future::try_join_all;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, trace, warn};
use tycho_common::{
    models::{blockchain::Block, contract::AccountDelta, Address, Chain, ChangeType},
    traits::{AccountExtractor, StorageSnapshotRequest},
    Bytes,
};
use url::Url;

use crate::{BytesCodec, RPCError, RequestError};

/// Helper function to extract the full error chain including source errors
fn extract_error_chain(error: &dyn Error) -> String {
    let mut chain = vec![error.to_string()];
    let mut source = error.source();

    while let Some(err) = source {
        chain.push(err.to_string());
        source = err.source();
    }

    if chain.len() == 1 {
        chain[0].clone()
    } else {
        format!("{} (caused by: {})", chain[0], chain[1..].join(" -> "))
    }
}

/// `EVMAccountExtractor` is a struct that implements the `AccountExtractor` trait for Ethereum
/// accounts. It is recommended for nodes that do not support batch requests.
pub struct EVMAccountExtractor {
    rpc: ReqwestClient,
    chain: Chain,
}

/// `EVMBatchAccountExtractor` is a struct that implements the `AccountStorageSource` trait for
/// Ethereum accounts. It can only be used with nodes that support batch requests. If you are using
/// a node that does not support batch requests, use `EVMAccountExtractor` instead.
pub struct EVMBatchAccountExtractor {
    rpc: ReqwestClient,
    chain: Chain,
}

#[async_trait]
impl AccountExtractor for EVMAccountExtractor {
    type Error = RPCError;

    async fn get_accounts_at_block(
        &self,
        block: &Block,
        requests: &[StorageSnapshotRequest],
    ) -> Result<HashMap<Bytes, AccountDelta>, Self::Error> {
        let mut updates = HashMap::new();
        let block_id = BlockId::number(block.number);

        // Convert addresses to AlloyAddress for easier handling
        let alloy_addresses: Vec<AlloyAddress> = requests
            .iter()
            .map(|request| AlloyAddress::from_bytes(&request.address))
            .collect();

        // Create futures for balance and code retrieval
        let balance_futures = alloy_addresses
            .iter()
            .map(|&address| async move {
                self.eth_get_balance(block_id, address)
                    .await
            });

        let code_futures = alloy_addresses
            .iter()
            .map(|&address| async move {
                self.eth_get_code(block_id, address)
                    .await
            });

        // Execute all balance and code requests concurrently
        let (result_balances, result_codes) =
            tokio::join!(try_join_all(balance_futures), try_join_all(code_futures));

        let balances = result_balances?;
        let codes = result_codes?;

        // Process each address with its corresponding balance and code
        for (i, &address) in alloy_addresses.iter().enumerate() {
            trace!(contract=?address, block_number=?block.number, block_hash=?block.hash, "Extracting contract code and storage" );

            let balance = Some(balances[i]);
            let code = Some(Bytes::from(codes[i].to_vec()));

            let slots_request = requests
                .get(i)
                .expect("Request should exist");
            if slots_request.slots.is_some() {
                // TODO: Implement this
                warn!("Specific storage slot requests are not supported in EVMAccountExtractor");
            }

            let slots = self
                .get_storage_range(address, B256::from_slice(&block.hash))
                .await?
                .into_iter()
                .map(|(k, v)| (k.to_bytes(), Some(v.to_bytes())))
                .collect();

            updates.insert(
                address.to_bytes(),
                AccountDelta::new(
                    self.chain,
                    address.to_bytes(),
                    slots,
                    balance.map(BytesCodec::to_bytes),
                    code,
                    ChangeType::Creation,
                ),
            );
        }

        Ok(updates)
    }
}

impl EVMAccountExtractor {
    pub async fn new_from_url(rpc_url: &str, chain: Chain) -> Result<Self, RPCError> {
        let url = rpc_url
            .parse()
            .map_err(|e: url::ParseError| {
                RPCError::RequestError(RequestError::Other(e.to_string()))
            })?;
        let client = ClientBuilder::default().http(url);
        Self::new(client, chain).await
    }

    pub async fn new(client: ReqwestClient, chain: Chain) -> Result<Self, RPCError> {
        Ok(Self { rpc: client, chain })
    }

    pub(super) async fn get_storage_range(
        &self,
        address: AlloyAddress,
        block_hash: B256,
    ) -> Result<HashMap<U256, U256>, RPCError> {
        let mut all_slots = HashMap::new();
        let mut start_key = B256::ZERO;
        loop {
            let params = (
                block_hash, 0, // transaction index, 0 for the state at the end of the block
                address, start_key, 100000, // limit
            );

            trace!("Requesting storage range for {:?}, block: {:?}", address, block_hash);
            let result: StorageRange = self
                .rpc
                .request("debug_storageRangeAt", params)
                .await
                .map_err(|e| {
                    let error_chain = extract_error_chain(&e);
                    RPCError::RequestError(RequestError::Other(format!(
                        "Failed to get storage: {error_chain}"
                    )))
                })?;

            for (_, entry) in result.storage {
                all_slots.insert(
                    U256::from_be_bytes(entry.key.into()),
                    U256::from_be_bytes(entry.value.into()),
                );
            }

            if let Some(next_key) = result.next_key {
                start_key = next_key;
            } else {
                break;
            }
        }

        Ok(all_slots)
    }

    // TODO - change this to use block_id as BlockId
    pub async fn get_block_data(&self, block_id: i64) -> Result<Block, RPCError> {
        let block_id = BlockId::from(u64::try_from(block_id).expect("Invalid block number"));
        let full_tx_objects = false; // same as get_block_by_number(..., false)

        let result: Option<AlloyBlock> = self
            .rpc
            .request("eth_getBlockByNumber", (block_id, full_tx_objects))
            .await
            .map_err(|e| {
                RPCError::RequestError(RequestError::Other(format!("Failed to get block: {e}")))
            })?;

        let block = result
            .ok_or_else(|| RPCError::RequestError(RequestError::Other("Block not found".into())))?;

        Ok(Block {
            number: block.header.number,
            hash: block.header.hash.to_bytes(),
            parent_hash: block.header.parent_hash.to_bytes(),
            chain: Chain::Ethereum,
            ts: DateTime::from_timestamp(block.header.timestamp as i64, 0)
                .expect("Failed to convert timestamp")
                .naive_utc(),
        })
    }

    async fn eth_get_balance(
        &self,
        block_id: BlockId,
        address: AlloyAddress,
    ) -> Result<U256, RPCError> {
        self.rpc
            .request("eth_getBalance", (address, block_id))
            .await
            .map_err(|e| {
                let error_chain = extract_error_chain(&e);
                RPCError::RequestError(RequestError::Other(format!(
                    "Failed to get balance: {error_chain}"
                )))
            })
    }

    async fn eth_get_code(
        &self,
        block_id: BlockId,
        address: AlloyAddress,
    ) -> Result<Bytes, RPCError> {
        self.rpc
            .request("eth_getCode", (address, block_id))
            .await
            .map_err(|e| {
                let error_chain = extract_error_chain(&e);
                RPCError::RequestError(RequestError::Other(format!(
                    "Failed to get code: {error_chain}"
                )))
            })
    }
}

impl EVMBatchAccountExtractor {
    pub async fn new_from_url(rpc_url: &str, chain: Chain) -> Result<Self, RPCError> {
        let url: Url = rpc_url
            .parse()
            .map_err(|e: url::ParseError| {
                RPCError::SetupError(format!(
                "Invalid URL '{}': {}. Make sure the URL includes the scheme (http:// or https://)",
                rpc_url, e
            ))
            })?;
        debug!(scheme = url.scheme(), host = url.host_str(), "Parsed URL successfully");

        let rpc = ClientBuilder::default().http(url.clone());
        info!(scheme = url.scheme(), "Successfully created RPC client");

        Self::new(rpc, chain).await
    }

    pub async fn new(rpc: ReqwestClient, chain: Chain) -> Result<Self, RPCError> {
        Ok(Self { rpc, chain })
    }

    async fn batch_fetch_account_code_and_balance(
        &self,
        block: &Block,
        max_batch_size: usize,
        chunk: &[StorageSnapshotRequest],
    ) -> Result<(HashMap<Bytes, Bytes>, HashMap<Bytes, Bytes>), RPCError> {
        debug!(
            chunk_size = chunk.len(),
            max_batch_size,
            block_number = block.number,
            "Preparing batch request for account code and balance"
        );

        let mut batch = self.rpc.new_batch();
        let mut code_requests = Vec::with_capacity(max_batch_size);
        let mut balance_requests = Vec::with_capacity(max_batch_size);

        for request in chunk {
            code_requests.push(Box::pin(
                batch
                    .add_call(
                        "eth_getCode",
                        &(&request.address, BlockNumberOrTag::from(block.number)),
                    )
                    .map_err(|e| {
                        RPCError::RequestError(RequestError::Other(format!(
                            "Failed to get code: {e}"
                        )))
                    })?
                    .map_resp(|resp: Bytes| resp.to_vec()),
            ));

            balance_requests.push(Box::pin(
                batch
                    .add_call::<_, Uint<256, 4>>(
                        "eth_getBalance",
                        &(&request.address, BlockNumberOrTag::from(block.number)),
                    )
                    .map_err(|e| {
                        RPCError::RequestError(RequestError::Other(format!(
                            "Failed to get balance: {e}"
                        )))
                    })?,
            ));
        }

        debug!(
            total_requests = chunk.len() * 2, // code + balance for each address
            block_number = block.number,
            "Sending batch request to RPC provider"
        );

        // Add debugging to understand when the URL issue occurs
        debug!(
            "About to send batch with {} code requests and {} balance requests",
            code_requests.len(),
            balance_requests.len()
        );

        batch.send().await.map_err(|e| {
            let addresses: Vec<String> = chunk.iter().map(|r| r.address.to_string()).collect();
            let error_chain = extract_error_chain(&e);
            RPCError::RequestError(RequestError::Other(format!(
                "Failed to send batch request for code & balance: {}. Block: {}, Addresses count: {}, Addresses: [{}]",
                error_chain,
                block.number,
                chunk.len(),
                addresses.join(", ")
            )))
        })?;

        info!(
            chunk_size = chunk.len(),
            block_number = block.number,
            "Successfully sent batch request for account code and balance"
        );

        let mut codes: HashMap<Bytes, Bytes> = HashMap::with_capacity(max_batch_size);
        let mut balances: HashMap<Bytes, Bytes> = HashMap::with_capacity(max_batch_size);

        for (idx, request) in chunk.iter().enumerate() {
            let address = &request.address;

            let code_result = code_requests[idx]
                .as_mut()
                .await
                .map_err(|e| {
                    RPCError::RequestError(RequestError::Other(format!(
                        "Failed to collect code request data: {e}"
                    )))
                })?;

            codes.insert(address.clone(), code_result.into());

            let balance_result = balance_requests[idx]
                .as_mut()
                .await
                .map_err(|e| {
                    RPCError::RequestError(RequestError::Other(format!(
                        "Failed to collect balance request data: {e}"
                    )))
                })?;

            balances.insert(address.clone(), Bytes::from(balance_result.to_be_bytes::<32>()));
        }
        Ok((codes, balances))
    }

    async fn fetch_account_storage(
        &self,
        block: &Block,
        max_batch_size: usize,
        request: &StorageSnapshotRequest,
    ) -> Result<HashMap<Bytes, Option<Bytes>>, RPCError> {
        let mut storage_requests = Vec::with_capacity(max_batch_size);

        let mut result = HashMap::new();

        match request.slots.clone() {
            Some(slots) => {
                for slot_batch in slots.chunks(max_batch_size) {
                    let mut storage_batch = self.rpc.new_batch();

                    for slot in slot_batch {
                        storage_requests.push(Box::pin(
                            storage_batch
                                .add_call(
                                    "eth_getStorageAt",
                                    &(&request.address, slot, BlockNumberOrTag::from(block.number)),
                                )
                                .map_err(|e| {
                                    RPCError::RequestError(RequestError::Other(format!(
                                        "Failed to get storage: {e}, address: {}, block: {}, slot: {}",
                                        request.address, block.number, slot,
                                    )))
                                })?
                                .map_resp(|res: Bytes| res.to_vec()),
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

                        let value = if storage_result == [0; 32] {
                            None
                        } else {
                            Some(Bytes::from(storage_result))
                        };

                        result.insert(slot.clone(), value);
                    }
                }
            }
            None => {
                let storage = self
                    .get_storage_range(&request.address, block)
                    .await?;
                for (key, value) in storage {
                    result.insert(key, Some(value));
                }
                return Ok(result);
            }
        }

        Ok(result)
    }

    async fn get_storage_range(
        &self,
        address: &Address,
        block: &Block,
    ) -> Result<HashMap<Bytes, Bytes>, RPCError> {
        warn!("Requesting all storage slots for address: {:?}. This request can consume a lot of data, and the method might not be available on the requested chain / node.", address);

        let mut all_slots = HashMap::new();
        let mut start_key = B256::ZERO;
        loop {
            trace!("Requesting storage range for {:?}, block: {:?}", address.clone(), block);

            // We request as a generic Value to see the raw response
            // This allows us to see the raw response and debug deserialization errors
            let raw_result: serde_json::Value = self
                .rpc
                .request(
                    "debug_storageRangeAt",
                    &(
                        block.hash.to_string(),
                        0, // transaction index, 0 for the state at the end of the block
                        address,
                        start_key,
                        100000, // limit
                    ),
                )
                .await
                .map_err(|e| {
                    let error_chain = extract_error_chain(&e);
                    RPCError::RequestError(RequestError::Other(format!(
                        "Failed to get storage: {error_chain}, address: {address}, block: {}",
                        block.number,
                    )))
                })?;

            // This is settable because cloning the value is expensive
            let should_debug = std::env::var("TYCHO_DEBUG_ACCOUNT_EXTRACTOR_RESPONSE").is_ok();
            let result = if should_debug {
                let value_string = raw_result.to_string();
                let result: StorageRange =
                    serde_json::from_value(raw_result.clone()).map_err(|e| {
                        RPCError::RequestError(RequestError::Other(format!("Failed to deserialize storage response: {e}, address: {address}, block: {}, raw_json: {}", block.number, value_string)))
                    })?;
                result
            } else {
                let result: StorageRange =
                    serde_json::from_value(raw_result.clone()).map_err(|e| {
                        RPCError::RequestError(RequestError::Other(format!("Failed to deserialize storage response: {e}, address: {address}, block: {block:?}")))
                    })?;
                result
            };

            for (_, entry) in result.storage {
                all_slots
                    .insert(Bytes::from(entry.key.0.to_vec()), Bytes::from(entry.value.0.to_vec()));
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

#[async_trait]
impl AccountExtractor for EVMBatchAccountExtractor {
    type Error = RPCError;

    async fn get_accounts_at_block(
        &self,
        block: &Block,
        requests: &[StorageSnapshotRequest],
    ) -> Result<HashMap<Address, AccountDelta>, Self::Error> {
        let mut updates = HashMap::new();

        // Remove duplicates to avoid making more requests than necessary.
        let unique_requests: Vec<StorageSnapshotRequest> = requests
            .iter()
            .cloned()
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();

        // TODO: Make these configurable and optimize for preventing rate limiting.
        // TODO: Handle rate limiting / individual connection failures & retries

        let max_batch_size = 50;
        let storage_max_batch_size = 10000;
        info!(
            total_requests = unique_requests.len(),
            max_batch_size,
            block_number = block.number,
            "Starting batch account extraction"
        );

        for chunk in unique_requests.chunks(max_batch_size) {
            debug!(
                chunk_size = chunk.len(),
                block_number = block.number,
                "Processing batch chunk for code and balance"
            );

            // Batch request code and balances of all accounts on the chunk.
            // Worst case scenario = 2 * chunk_size requests
            let metadata_fut =
                self.batch_fetch_account_code_and_balance(block, max_batch_size, chunk);

            let mut storage_futures = Vec::new();
            // Batch requests storage_max_batch_size until
            // Worst case scenario = chunk_size * (MAX_EVM_STORAGE_LIMIT / storage_max_batch_size)
            // requests
            for request in chunk.iter() {
                storage_futures.push(self.fetch_account_storage(
                    block,
                    storage_max_batch_size,
                    request,
                ));
            }

            let (codes, balances) = metadata_fut.await?;
            debug!(
                chunk_size = chunk.len(),
                codes_count = codes.len(),
                balances_count = balances.len(),
                block_number = block.number,
                "Successfully retrieved account code and balance data"
            );

            let storage_results = try_join_all(storage_futures).await?;

            for (idx, request) in chunk.iter().enumerate() {
                let address = &request.address;
                let code = codes.get(address).cloned();
                let balance = balances.get(address).cloned();
                let storage = storage_results
                    .get(idx)
                    .cloned()
                    .ok_or_else(|| {
                        RPCError::UnknownError(format!(
                            "Unable to find storage result. Request: {request:?} at block: {block:?}"
                        ))
                    })?;

                let account_delta = AccountDelta::new(
                    self.chain,
                    address.clone(),
                    storage,
                    balance,
                    code,
                    ChangeType::Creation,
                );

                updates.insert(address.clone(), account_delta);
            }
        }

        info!(
            total_accounts_processed = updates.len(),
            block_number = block.number,
            "Completed batch account extraction successfully"
        );

        Ok(updates)
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct StorageEntry {
    key: B256,
    value: B256,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct StorageRange {
    storage: HashMap<B256, StorageEntry>,
    next_key: Option<B256>,
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use alloy::hex;
    use rstest::rstest;
    use tracing_test::traced_test;

    use super::*;

    // Common test constants
    const BALANCER_VAULT_STR: &str = "0xba12222222228d8ba445958a75a0704d566bf2c8";
    const STETH_STR: &str = "0xae7ab96520de3a18e5e111b5eaab095312d7fe84";
    const TEST_BLOCK_HASH: &str =
        "0x7f70ac678819e24c4947a3a95fdab886083892a18ba1a962ebaac31455584042";
    const TEST_BLOCK_NUMBER: u64 = 20378314;

    // Common token addresses for tests
    const TOKEN_ADDRESSES: [&str; 5] = [
        BALANCER_VAULT_STR,
        STETH_STR,
        "0x6b175474e89094c44da98b954eedeac495271d0f", // DAI
        "0x2260fac5e5542a773aa44fbcfedf7c193bc2c599", // WBTC
        "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", // USDC
    ];

    // Common storage slots for testing
    fn get_test_slots() -> HashMap<Bytes, Bytes> {
        HashMap::from([
            (
                Bytes::from_str("0000000000000000000000000000000000000000000000000000000000000000")
                    .unwrap(),
                Bytes::from_str("0000000000000000000000000000000000000000000000000000000000000001")
                    .unwrap(),
            ),
            (
                Bytes::from_str("0000000000000000000000000000000000000000000000000000000000000003")
                    .unwrap(),
                Bytes::from_str("00000000000000000000006048a8c631fb7e77eca533cf9c29784e482391e700")
                    .unwrap(),
            ),
            (
                Bytes::from_str("00015ea75c6f99b2e8663793de8ab1ce7c52e3295bf307bbf9990d4af56f7035")
                    .unwrap(),
                Bytes::from_str("0000000000000000000000000000000000000000000000000000000000000001")
                    .unwrap(),
            ),
        ])
    }

    // Test fixture setup
    struct TestFixture {
        block: Block,
        node_url: String,
    }

    impl TestFixture {
        async fn new() -> Self {
            let node_url = std::env::var("RPC_URL").expect("RPC_URL must be set for testing");

            let block_hash = B256::from_bytes(
                &hex::decode(
                    TEST_BLOCK_HASH
                        .strip_prefix("0x")
                        .unwrap_or(TEST_BLOCK_HASH),
                )
                .expect("valid hex")
                .into(),
            );

            let block = Block::new(
                TEST_BLOCK_NUMBER,
                Chain::Ethereum,
                block_hash.to_bytes(),
                Default::default(),
                Default::default(),
            );

            Self { block, node_url }
        }

        async fn create_evm_extractor(&self) -> Result<EVMAccountExtractor, RPCError> {
            EVMAccountExtractor::new_from_url(&self.node_url, Chain::Ethereum).await
        }

        async fn create_batch_extractor(&self) -> Result<EVMBatchAccountExtractor, RPCError> {
            EVMBatchAccountExtractor::new_from_url(&self.node_url, Chain::Ethereum).await
        }

        fn create_address(address_str: &str) -> Address {
            Address::from_str(address_str).expect("valid address")
        }

        fn create_storage_request(
            address_str: &str,
            slots: Option<Vec<Bytes>>,
        ) -> StorageSnapshotRequest {
            StorageSnapshotRequest { address: Self::create_address(address_str), slots }
        }
    }

    #[rstest]
    #[case(BALANCER_VAULT_STR, U256::ZERO)]
    #[case(STETH_STR, U256::from_str("4550827602262703358208").unwrap())]
    #[tokio::test]
    #[ignore = "require RPC connection"]
    async fn test_get_balance(
        #[case] address_str: &str,
        #[case] expected_balance: U256,
    ) -> Result<(), RPCError> {
        let fixture = TestFixture::new().await;
        let extractor = fixture.create_evm_extractor().await?;

        let address = AlloyAddress::from_str(address_str).expect("failed to parse address");
        let block_id = BlockId::number(TEST_BLOCK_NUMBER);

        let balance = extractor
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
        let fixture = TestFixture::new().await;
        let extractor = fixture.create_evm_extractor().await?;

        let address = AlloyAddress::from_str(address_str).expect("failed to parse address");
        let block_id = BlockId::number(TEST_BLOCK_NUMBER);

        let code = extractor
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
    #[case(BALANCER_VAULT_STR, 47690)]
    #[case(STETH_STR, 789526)]
    #[tokio::test]
    #[ignore = "require RPC connection"]
    async fn test_get_storage_range(
        #[case] address_str: &str,
        #[case] expected_slot_count: usize,
    ) -> Result<(), RPCError> {
        let fixture = TestFixture::new().await;
        let extractor = fixture.create_evm_extractor().await?;

        let address = AlloyAddress::from_str(address_str).expect("failed to parse address");
        let block_id = B256::from_str(TEST_BLOCK_HASH).expect("failed to parse block hash");

        let storage = extractor
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

    #[tokio::test]
    #[ignore = "require RPC connection"]
    async fn test_account_extractor() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = TestFixture::new().await;
        let extractor = fixture.create_evm_extractor().await?;

        let requests = vec![TestFixture::create_storage_request(BALANCER_VAULT_STR, None)];

        let updates = extractor
            .get_accounts_at_block(&fixture.block, &requests)
            .await?;

        assert_eq!(updates.len(), 1);
        let update = updates
            .get(&Bytes::from_str(BALANCER_VAULT_STR).expect("valid address"))
            .expect("update exists");

        assert_eq!(update.slots.len(), 47690);

        Ok(())
    }

    #[traced_test]
    #[tokio::test]
    #[ignore = "require RPC connection"]
    /// Test the contract extractor with a large number of storage slots (stETH is the 9th largest
    /// token by number of holders).
    /// This test takes around 2 mins to run and retreives around 50mb of data
    async fn test_contract_extractor_steth() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = TestFixture::new().await;
        let extractor = fixture.create_evm_extractor().await?;

        let requests = vec![TestFixture::create_storage_request(STETH_STR, None)];

        println!("Getting accounts for block: {TEST_BLOCK_NUMBER:?}");
        let start_time = std::time::Instant::now();
        let updates = extractor
            .get_accounts_at_block(&fixture.block, &requests)
            .await?;
        let duration = start_time.elapsed();
        println!("Time taken to get accounts: {duration:?}");

        assert_eq!(updates.len(), 1);
        let update = updates
            .get(&Bytes::from_str(STETH_STR).expect("valid address"))
            .expect("update exists");

        assert_eq!(update.slots.len(), 789526);

        Ok(())
    }

    #[traced_test]
    #[tokio::test]
    #[ignore = "require RPC connection"]
    async fn test_get_storage_snapshots() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = TestFixture::new().await;
        println!("Using node: {}", fixture.node_url);

        let extractor = fixture.create_batch_extractor().await?;

        let requests = vec![
            TestFixture::create_storage_request(BALANCER_VAULT_STR, Some(vec![])),
            TestFixture::create_storage_request(STETH_STR, Some(vec![])),
        ];

        let start_time = std::time::Instant::now();
        let result = extractor
            .get_accounts_at_block(&fixture.block, &requests)
            .await?;
        let duration = start_time.elapsed();
        println!("Time taken to get storage snapshots: {duration:?}");

        assert_eq!(result.len(), 2);

        // First account check
        let first_address = TestFixture::create_address(BALANCER_VAULT_STR);
        let first_delta = result
            .get(&first_address)
            .expect("first address should exist");
        assert_eq!(first_delta.address, first_address);
        assert_eq!(first_delta.chain, Chain::Ethereum);
        assert!(first_delta.code().is_some());
        assert!(first_delta.balance.is_some());
        println!("Balance: {:?}", first_delta.balance);

        // Second account check
        let second_address = TestFixture::create_address(STETH_STR);
        let second_delta: &AccountDelta = result
            .get(&second_address)
            .expect("second address should exist");
        assert_eq!(second_delta.address, second_address);
        assert_eq!(second_delta.chain, Chain::Ethereum);
        assert!(second_delta.code().is_some());
        assert!(second_delta.balance.is_some());
        println!("Balance: {:?}", second_delta.balance);

        Ok(())
    }

    #[traced_test]
    #[tokio::test]
    #[ignore = "require RPC connection"]
    async fn test_evm_batch_extractor_new() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = TestFixture::new().await;

        // Test with valid URL
        let extractor =
            EVMBatchAccountExtractor::new_from_url(&fixture.node_url, Chain::Ethereum).await?;
        assert_eq!(extractor.chain, Chain::Ethereum);

        // Test with invalid URL
        let result = EVMBatchAccountExtractor::new_from_url("invalid-url", Chain::Ethereum).await;
        assert!(result.is_err());

        Ok(())
    }

    #[traced_test]
    #[tokio::test]
    #[ignore = "require RPC connection"]
    async fn test_batch_fetch_account_code_and_balance() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = TestFixture::new().await;
        let extractor = fixture.create_batch_extractor().await?;

        // Test with multiple addresses
        let requests = vec![
            TestFixture::create_storage_request(BALANCER_VAULT_STR, Some(Vec::new())),
            TestFixture::create_storage_request(STETH_STR, Some(Vec::new())),
        ];

        let (codes, balances) = extractor
            .batch_fetch_account_code_and_balance(&fixture.block, 10, &requests)
            .await?;

        // Check that we got code and balance for both addresses
        assert_eq!(codes.len(), 2);
        assert_eq!(balances.len(), 2);

        // Check that the first address has code and balance
        let first_address = TestFixture::create_address(BALANCER_VAULT_STR);
        assert!(codes.contains_key(&first_address));
        assert!(balances.contains_key(&first_address));

        // Check that the second address has code and balance
        let second_address = TestFixture::create_address(STETH_STR);
        assert!(codes.contains_key(&second_address));
        assert!(balances.contains_key(&second_address));

        // Verify code is non-empty for contract addresses
        assert!(!codes
            .get(&first_address)
            .unwrap()
            .is_empty());
        assert!(!codes
            .get(&second_address)
            .unwrap()
            .is_empty());

        Ok(())
    }

    #[traced_test]
    #[tokio::test]
    #[ignore = "require RPC connection"]
    async fn test_fetch_account_storage_without_specific_slots(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let fixture = TestFixture::new().await;
        let extractor = fixture.create_batch_extractor().await?;

        // Create request with specific slots
        let slots = get_test_slots();
        let request = TestFixture::create_storage_request(BALANCER_VAULT_STR, None);

        let storage = extractor
            .fetch_account_storage(&fixture.block, 10, &request)
            .await?;

        // Verify that we got the storage for all requested slots
        assert_eq!(storage.len(), 47690);

        // Check that each slot has a value
        for (key, value) in slots.iter().take(3) {
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

    #[traced_test]
    #[tokio::test]
    #[ignore = "require RPC connection"]
    async fn test_fetch_account_storage_with_specific_slots(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let fixture = TestFixture::new().await;
        let extractor = fixture.create_batch_extractor().await?;

        // Create request with specific slots
        let slots = get_test_slots();
        let slots_request: Vec<Bytes> = slots.keys().cloned().collect();
        let request = TestFixture::create_storage_request(BALANCER_VAULT_STR, Some(slots_request));

        let storage = extractor
            .fetch_account_storage(&fixture.block, 10, &request)
            .await?;

        // Verify that we got the storage for all requested slots
        assert_eq!(storage.len(), 3);

        // Check that each slot has a value
        for (key, value) in slots.iter() {
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

    #[traced_test]
    #[tokio::test]
    #[ignore = "require RPC connection"]
    async fn test_get_storage_snapshots_with_specific_slots(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let fixture = TestFixture::new().await;
        let extractor = fixture.create_batch_extractor().await?;

        // Create request with specific slots
        let slots = get_test_slots();
        let slots_request: Vec<Bytes> = slots.keys().cloned().collect();

        let requests =
            vec![TestFixture::create_storage_request(BALANCER_VAULT_STR, Some(slots_request))];

        let result = extractor
            .get_accounts_at_block(&fixture.block, &requests)
            .await?;

        assert_eq!(result.len(), 1);

        // Check the account delta
        let address = TestFixture::create_address(BALANCER_VAULT_STR);
        let delta = result
            .get(&address)
            .expect("address should exist");

        assert_eq!(delta.address, address);
        assert_eq!(delta.chain, Chain::Ethereum);
        assert!(delta.code().is_some());
        assert!(delta.balance.is_some());

        // Check that storage slots match what we requested
        assert_eq!(delta.slots.len(), 3);
        for (key, value) in slots.iter() {
            assert!(delta.slots.contains_key(key));
            assert_eq!(
                delta
                    .slots
                    .get(key)
                    .and_then(|v| v.as_ref()),
                Some(value)
            );
        }

        Ok(())
    }

    #[traced_test]
    #[tokio::test]
    #[ignore = "require RPC connection"]
    async fn test_get_storage_snapshots_with_empty_slot() -> Result<(), Box<dyn std::error::Error>>
    {
        let fixture = TestFixture::new().await;
        let extractor = fixture.create_batch_extractor().await?;

        // Try to get a slot that was not initialized / is empty
        let slots_request: Vec<Bytes> = vec![Bytes::from_str(
            "0000000000000000000000000000000000000000000000000000000000000002",
        )
        .unwrap()];

        let requests = vec![TestFixture::create_storage_request(
            BALANCER_VAULT_STR,
            Some(slots_request.clone()),
        )];

        let result = extractor
            .get_accounts_at_block(&fixture.block, &requests)
            .await?;

        assert_eq!(result.len(), 1);

        // Check the account delta
        let address = TestFixture::create_address(BALANCER_VAULT_STR);
        let delta = result
            .get(&address)
            .expect("address should exist");

        assert_eq!(delta.address, address);
        assert_eq!(delta.chain, Chain::Ethereum);
        assert!(delta.code().is_some());
        assert!(delta.balance.is_some());

        // Check that storage slots match what we requested
        assert_eq!(delta.slots.len(), 1);
        assert_eq!(
            delta
                .slots
                .get(&slots_request[0])
                .unwrap(),
            &None
        );

        Ok(())
    }

    #[traced_test]
    #[tokio::test]
    #[ignore = "require RPC connection"]
    async fn test_get_storage_snapshots_multiple_accounts() -> Result<(), Box<dyn std::error::Error>>
    {
        let fixture = TestFixture::new().await;
        let extractor = fixture.create_batch_extractor().await?;

        // Create multiple requests with different token addresses
        let requests: Vec<_> = TOKEN_ADDRESSES
            .iter()
            .map(|&addr| {
                TestFixture::create_storage_request(
                    addr,
                    Some(vec![Bytes::from_str(
                        "0000000000000000000000000000000000000000000000000000000000000000",
                    )
                    .unwrap()]),
                )
            })
            .collect();

        let start_time = std::time::Instant::now();
        let result = extractor
            .get_accounts_at_block(&fixture.block, &requests)
            .await?;
        let duration = start_time.elapsed();
        println!(
            "Time taken to get storage snapshots for {} accounts: {:?}",
            requests.len(),
            duration
        );

        assert_eq!(result.len(), TOKEN_ADDRESSES.len());

        // Check each account has the required data
        for addr_str in TOKEN_ADDRESSES.iter() {
            let address = TestFixture::create_address(addr_str);
            let delta = result
                .get(&address)
                .expect("address should exist");

            assert_eq!(delta.address, address);
            assert_eq!(delta.chain, Chain::Ethereum);
            assert!(delta.code().is_some());
            assert!(delta.balance.is_some());
            assert_eq!(delta.slots.len(), 1);

            println!(
                "Address: {}, Code size: {}, Has balance: {}",
                addr_str,
                delta.code().as_ref().unwrap().len(),
                delta.balance.is_some()
            );
        }

        Ok(())
    }
}
