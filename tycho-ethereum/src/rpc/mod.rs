use std::{
    collections::{BTreeMap, HashMap}, default::Default, iter::IntoIterator, time::Duration,
};

use alloy::{
    primitives::{private::serde, Address, B256, U256},
    rpc::{
        client::{ClientBuilder, ReqwestClient},
        types::{
            debug::{StorageMap, StorageRangeResult, StorageResult},
            trace::{
                geth::GethTrace,
                parity::{TraceResults, TraceType},
            },
            AccessListResult, Block, BlockId, BlockNumberOrTag, TransactionRequest,
        },
    },
    transports::{http::reqwest, RpcError, TransportErrorKind, TransportResult},
};
use futures::future::join_all;
use serde_json::{json, Value};
use serde::Deserialize;
use tracing::{debug, info, trace};
use tycho_common::Bytes;

use crate::{RPCError, RequestError};

pub mod errors;
pub(crate) mod retry;

use retry::RetryPolicy;

use crate::services::entrypoint_tracer::slot_detector::{
    SlotDetectorSlotTestRequest, SlotDetectorValueRequest,
};

// TODO: Optimize these configurable for preventing rate limiting.
// TODO: Handle rate limiting / individual connection failures & retries
#[derive(Clone, Debug)]
pub struct BatchingConfig {
    /// Maximum number of general (e.g., code) requests per batch.
    pub(crate) max_batch_size: usize,
    pub(crate) max_storage_slot_batch_size: usize,
}

impl Default for BatchingConfig {
    fn default() -> Self {
        let max_storage_slot_batch_size =
            std::env::var("TYCHO_BATCH_ACCOUNT_EXTRACTOR_STORAGE_MAX_BATCH_SIZE")
                .unwrap_or_else(|_| "1000".to_string())
                .parse::<usize>()
                .unwrap_or(1000);

        Self { max_batch_size: 50, max_storage_slot_batch_size }
    }
}

// TODO: Consider adding rate limiting and retry logic for all RPC requests.
// TODO: Consider adding fallback for batching requests to non-batched version on failure.
/// This struct wraps the ReqwestClient and provides Ethereum-specific RPC methods
/// with optional batching support and automatic retry logic.
/// It is cheap to clone, as the `inner` internally uses an Arc for the ReqwestClient.
#[derive(Clone, Debug)]
pub struct EthereumRpcClient {
    pub(crate) inner: ReqwestClient,
    pub(crate) batching: Option<BatchingConfig>,
    retry_policy: RetryPolicy,
    url: String,
}

impl EthereumRpcClient {
    pub fn new(rpc_url: &str) -> Result<Self, RPCError> {
        let url = rpc_url
            .parse()
            .map_err(|e| RPCError::SetupError(format!("Invalid RPC URL: {}", e)))?;

        let http_client = reqwest::ClientBuilder::new()
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(10))
            .pool_idle_timeout(Duration::from_secs(90))
            .pool_max_idle_per_host(10)
            .tcp_nodelay(true)
            .build()
            .map_err(|e| RPCError::SetupError(format!("Failed to create HTTP client: {e}")))?;

        let rpc = ClientBuilder::default().http_with_client(http_client, url);
        let batching = Some(BatchingConfig::default());
        let retry_policy = RetryPolicy::default();

        Ok(Self { inner: rpc, batching, retry_policy, url: rpc_url.to_string() })
    }

    pub fn get_url(&self) -> &str {
        &self.url
    }

    pub fn with_batching(self, batching: Option<BatchingConfig>) -> Self {
        Self { inner: self.inner, batching, retry_policy: self.retry_policy, url: self.url }
    }

    pub fn with_retry_policy(self, retry_policy: RetryPolicy) -> Self {
        Self { inner: self.inner, batching: self.batching, retry_policy, url: self.url }
    }

    pub async fn get_block_number(&self) -> Result<u64, RPCError> {
        let block_number = self
            .retry_policy
            .retry_request(|| async {
                self.inner
                    .request_noparams("eth_blockNumber")
                    .await
            })
            .await
            .map_err(|e| RPCError::from_alloy("Failed to get block number", e))?;

        if let BlockNumberOrTag::Number(num) = block_number {
            Ok(num)
        } else {
            Err(RPCError::RequestError(RequestError::Other(
                "Failed to get block number: Unexpected block tag returned".to_string(),
            )))
        }
    }

    pub(crate) async fn eth_get_block_by_number(
        &self,
        block_id: BlockId,
    ) -> Result<Block, RPCError> {
        let full_tx_objects = false;

        let result: Option<Block> = self
            .retry_policy
            .retry_request(|| async {
                self.inner
                    .request("eth_getBlockByNumber", (block_id, full_tx_objects))
                    .await
            })
            .await
            .map_err(|e| {
                RPCError::from_alloy(format!("Failed to get block for block id {block_id}"), e)
            })?;

        result.ok_or(RPCError::RequestError(RequestError::Other(format!(
            "Failed to get block for block id {block_id}: Block not found"
        ))))
    }

    pub(crate) async fn eth_get_balance(
        &self,
        block_id: BlockNumberOrTag,
        address: Address,
    ) -> Result<U256, RPCError> {
        self.retry_policy
            .retry_request(|| async {
                self.inner
                    .request("eth_getBalance", (address, block_id))
                    .await
            })
            .await
            .map_err(|e| {
                RPCError::from_alloy(
                    format!("Failed to get balance for address {address}, block {block_id}"),
                    e,
                )
            })
    }

    pub(crate) async fn eth_get_code(
        &self,
        block_id: BlockNumberOrTag,
        address: Address,
    ) -> Result<Bytes, RPCError> {
        self.retry_policy
            .retry_request(|| async {
                self.inner
                    .request("eth_getCode", (address, block_id))
                    .await
            })
            .await
            .map_err(|e| {
                RPCError::from_alloy(
                    format!("Failed to get code for address {address}, block {block_id}"),
                    e,
                )
            })
    }

    pub(crate) async fn debug_storage_range_at(
        &self,
        block_hash: B256,
        address: Address,
        start_key: B256,
    ) -> Result<StorageRangeResult, RPCError> {
        // TEMPORARY WORKAROUND: A custom wrapper for StorageRangeResult that handles null storage.
        // Some nodes (specifically observed on Unichain) return `"storage": null` instead of
        // `"storage": {}` for empty storage. This wrapper deserializes null as an empty BTreeMap
        // and converts it to the standard alloy StorageRangeResult type.
        // TODO: Remove this workaround once the Unichain node behaviour is fixed or we switch node
        // providers.
        #[derive(Debug, Deserialize)]
        struct StorageRangeResultWrapper {
            storage: Option<BTreeMap<B256, StorageResult>>,
            #[serde(rename = "nextKey")]
            next_key: Option<B256>,
        }

        impl From<StorageRangeResultWrapper> for StorageRangeResult {
            fn from(wrapper: StorageRangeResultWrapper) -> Self {
                StorageRangeResult {
                    storage: StorageMap(wrapper.storage.unwrap_or_default()),
                    next_key: wrapper.next_key,
                }
            }
        }

        let params = (
            block_hash, 0, // transaction index, 0 for the state at the end of the block
            address, start_key, // The offset (hash of storage key)
            100000,    // The number of storage entries to return
        );

        // Use the wrapper type to handle nodes that return null instead of {} for empty storage
        let wrapper: StorageRangeResultWrapper = self.retry_policy
            .retry_request(|| async {
                self.inner
                    .request("debug_storageRangeAt", params)
                    .await
            })
            .await
            .map_err(|e| {
                RPCError::from_alloy(
                    format!("Failed to get storage for address {address}, block {block_hash}"),
                    e,
                )
            })?;

        Ok(wrapper.into())
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

    pub(crate) async fn non_batch_fetch_accounts_code_and_balance(
        &self,
        block_id: BlockNumberOrTag,
        addresses: &[Address],
    ) -> Result<HashMap<Address, (Bytes, U256)>, RPCError> {
        Ok(futures::future::try_join_all(
            addresses
                .iter()
                .map(|&address| async move {
                    let (code, balance) = tokio::try_join!(
                        self.eth_get_code(block_id, address),
                        self.eth_get_balance(block_id, address)
                    )?;
                    Ok::<_, RPCError>((address, (code, balance)))
                }),
        )
        .await?
        .into_iter()
        .collect())
    }

    pub(crate) async fn batch_fetch_accounts_code_and_balance(
        &self,
        block_id: BlockNumberOrTag,
        addresses: &[Address],
    ) -> Result<HashMap<Address, (Bytes, U256)>, RPCError> {
        let batching = self
            .batching
            .as_ref()
            .ok_or(RPCError::SetupError(
                "BatchingConfig is required for batch operations".to_string(),
            ))?;

        debug!(
            chunk_size = batching.max_batch_size,
            total_chunks = addresses.len() / batching.max_batch_size + 1,
            block_id = block_id.to_string(),
            "Preparing batch request for account code and balance"
        );

        let mut result = HashMap::with_capacity(addresses.len());

        let chunk_size = batching.max_batch_size / 2; // we make 2 requests in a batch call: code + balance
        if chunk_size == 0 {
            return Err(RPCError::SetupError(
                "BatchingConfig max_batch_size must be at least 2".to_string(),
            ));
        }

        // perf: consider running multiple batches in parallel using map of futures
        for chunk_addresses in addresses.chunks(chunk_size) {
            let batch_call = || async {
                let mut batch = self.inner.new_batch();

                let code_balance_requests = chunk_addresses
                    .iter()
                    .map(|&address| {
                        Ok((
                            batch.add_call::<_, Bytes>("eth_getCode", &(address, block_id))?,
                            batch.add_call::<_, U256>("eth_getBalance", &(address, block_id))?,
                        ))
                    })
                    .collect::<Result<Vec<_>, RpcError<TransportErrorKind>>>()?;

                debug!(
                    total_requests = chunk_size * 2, // code + balance for each batch call
                    block_id = block_id.to_string(),
                    "Sending batch request to RPC provider"
                );

                batch.send().await?;

                info!(
                    chunk_size = chunk_addresses.len(),
                    block_id = block_id.to_string(),
                    "Successfully sent batch request for account code and balance"
                );

                let mut code_balance_res = Vec::with_capacity(chunk_addresses.len());
                for (code_fut, balance_fut) in code_balance_requests {
                    let code = code_fut.await?;
                    let balance = balance_fut.await?;
                    code_balance_res.push((code, balance));
                }

                Ok(code_balance_res)
            };

            let chunk_results = self.retry_policy.retry_request(batch_call).await
            .map_err(|e| {
                    let printable_addresses = chunk_addresses
                        .iter()
                        .map(|addr| format!("{:?}", addr))
                        .collect::<Vec<String>>()
                        .join(", ");
                    RPCError::from_alloy(format!(
                        "Failed to send batch request for code & balance for block {block_id}, address count {}, addresses [{printable_addresses}]",
                        chunk_addresses.len(),
                    ), e)
                })?;

            for (value, &address) in chunk_results
                .into_iter()
                .zip(chunk_addresses.iter())
            {
                result.insert(address, value);
            }
        }

        Ok(result)
    }

    pub(crate) async fn non_batch_get_selected_storage(
        &self,
        block_id: BlockNumberOrTag,
        address: Address,
        slots: &[B256],
    ) -> Result<HashMap<B256, Option<B256>>, RPCError> {
        let mut result = HashMap::with_capacity(slots.len());

        for slot in slots {
            let storage_value = self.retry_policy
            .retry_request(|| async {
                self
                    .inner
                    .request("eth_getStorageAt", (&address, slot, block_id))
                    .await
                                })
            .await
            .map_err(|e| {
                RPCError::from_alloy(
                    format!("Failed to get storage for address {address}, block {block_id}, slot {slot}"),
                    e,
                )
            })?;

            let value = if storage_value == [0; 32] { None } else { Some(storage_value) };

            result.insert(*slot, value);
        }

        Ok(result)
    }

    pub(crate) async fn batch_get_selected_storage(
        &self,
        block_id: BlockNumberOrTag,
        address: Address,
        slots: &[B256],
    ) -> Result<HashMap<B256, Option<B256>>, RPCError> {
        let batching = self
            .batching
            .as_ref()
            .ok_or(RPCError::SetupError(
                "BatchingConfig is required for batch operations".to_string(),
            ))?;

        let mut result = HashMap::with_capacity(slots.len());

        let chunk_size = batching.max_storage_slot_batch_size; // we make 1 request in a batch call

        // perf: consider running multiple batches in parallel using map of futures
        for slot_batch in slots.chunks(chunk_size) {
            let batch_call = || async {
                let mut batch = self.inner.new_batch();

                let mut storage_requests = slot_batch
                    .iter()
                    .map(|slot| {
                        batch.add_call::<_, B256>("eth_getStorageAt", &(&address, slot, block_id))
                    })
                    .collect::<Result<Vec<_>, RpcError<TransportErrorKind>>>()?;

                batch.send().await?;

                let mut storage_res = Vec::with_capacity(slot_batch.len());
                for storage_fut in storage_requests.iter_mut() {
                    let storage_value = storage_fut.await?;
                    storage_res.push(storage_value);
                }

                Ok(storage_res)
            };

            let chunk_res = self.retry_policy.retry_request(batch_call).await
            .map_err(|e| {
                let printable_slots = slot_batch
                    .iter()
                    .map(|slot| format!("{:?}", slot))
                    .collect::<Vec<String>>()
                    .join(", ");
                RPCError::from_alloy(
                    format!(
                                    "Failed to get storage for address {address}, block {block_id}, slots {printable_slots}",
                                ),
                    e,
                )
            })?;

            for (storage_result, &address) in chunk_res
                .into_iter()
                .zip(slot_batch.iter())
            {
                let value = if storage_result == [0; 32] { None } else { Some(storage_result) };
                result.insert(address, value);
            }
        }

        Ok(result)
    }

    /// Use the trace_callMany API to simulate multiple call requests applied together one after
    /// another. See https://openethereum.github.io/JSONRPC-trace-module#trace_callmany
    ///
    /// Returns error if communication with the node failed.
    pub(crate) async fn trace_call_many(
        &self,
        requests: Vec<TransactionRequest>,
        block: BlockNumberOrTag,
    ) -> Result<Vec<TraceResults>, RPCError> {
        let trace_requests: Vec<(TransactionRequest, Vec<TraceType>)> = requests
            .into_iter()
            .map(|request| (request, vec![TraceType::Trace]))
            .collect();

        self.retry_policy
            .retry_request(|| async {
                self.inner
                    .request("trace_callMany", (&trace_requests, block))
                    .await
            })
            .await
            .map_err(|e| {
                RPCError::from_alloy(format!("Failed to get trace call many for block {block}"), e)
            })
    }

    /// Executes a new message call immediately without creating a transaction on the blockchain.
    /// See https://ethereum.org/en/developers/docs/apis/json-rpc/#eth_call
    ///
    /// Returns the output data from the call or an error if the call failed.
    pub(crate) async fn eth_call(
        &self,
        request: TransactionRequest,
        block: BlockNumberOrTag,
    ) -> Result<Bytes, RPCError> {
        self.retry_policy
            .retry_request(|| async {
                self.inner
                    .request("eth_call", (&request, block))
                    .await
            })
            .await
            .map_err(|e| {
                RPCError::from_alloy(
                    format!("Failed to send an eth_call request for block {block}"),
                    e,
                )
            })
    }

    pub(crate) async fn batch_trace_and_access_list(
        &self,
        target: &Address,
        block_hash: &B256,
        access_list_params: &Value,
        trace_call_params: &Value,
    ) -> Result<(AccessListResult, GethTrace), RPCError> {
        let batching = self
            .batching
            .as_ref()
            .ok_or(RPCError::SetupError(
                "BatchingConfig is required for batch operations".to_string(),
            ))?;

        if batching.max_batch_size < 2 {
            return Err(RPCError::SetupError(
                "BatchingConfig max_batch_size must be at least 2".to_string(),
            ));
        }

        let batch_call = || async {
            let mut batch = self.inner.new_batch();

            // Add eth_createAccessList call
            let access_list_future = batch
                .add_call::<_, AccessListResult>("eth_createAccessList", &access_list_params)?;

            // Add debug_traceCall call
            let trace_future =
                batch.add_call::<_, GethTrace>("debug_traceCall", &trace_call_params)?;

            // Send batch
            batch.send().await?;

            // Await access list result
            let access_list_data = access_list_future.await?;

            // Await trace result
            let pre_state_trace = trace_future.await?;

            Ok((access_list_data, pre_state_trace))
        };

        self.retry_policy.retry_request(|| async {
            batch_call().await
        }).await
        .map_err(|e| {
            RPCError::from_alloy(
                format!(
                    "Failed to send batch request for trace and access list for target {target}, block {block_hash}"
                ),
                e,
            )
        })
    }

    pub(crate) async fn batch_slot_detector_trace(
        &self,
        requests: Vec<SlotDetectorValueRequest>,
        calldata: &Bytes,
        block_hash: &B256,
    ) -> Result<Vec<(GethTrace, U256)>, RPCError> {
        let batching = self
            .batching
            .as_ref()
            .ok_or(RPCError::SetupError(
                "BatchingConfig is required for batch operations".to_string(),
            ))?;

        let chunk_size = batching.max_batch_size / 2; // we make 2 requests in a batch call: trace + eth_call
        if chunk_size == 0 {
            return Err(RPCError::SetupError(
                "BatchingConfig max_batch_size must be at least 2".to_string(),
            ));
        }

        let mut result = Vec::with_capacity(requests.len());

        for chunk_requests in requests.chunks(chunk_size) {
            let batch_call = || async {
                let mut batch = self.inner.new_batch();

                // perf: consider limiting batch size based on config
                let batch_calls = chunk_requests
                    .iter()
                    .map(|SlotDetectorValueRequest { token, tracer_params }| {
                        let trace_call =
                            batch.add_call::<_, GethTrace>("debug_traceCall", tracer_params)?;

                        let eth_call_param = json!([
                            {
                                "to": token.to_string(),
                                "data": calldata.to_string()
                            },
                            block_hash.to_string()
                        ]);
                        let eth_call = batch.add_call::<_, U256>("eth_call", &eth_call_param)?;

                        Ok((trace_call, eth_call))
                    })
                    .collect::<Result<Vec<_>, RpcError<TransportErrorKind>>>()?;

                batch.send().await?;

                let mut results = Vec::with_capacity(requests.len());
                for (trace_call_fut, eth_call_fut) in batch_calls {
                    let trace = trace_call_fut.await?;
                    let value = eth_call_fut.await?;
                    results.push((trace, value));
                }

                Ok(results)
            };

            let chunk_results = self
                .retry_policy
                .retry_request(|| async { batch_call().await })
                .await
                .map_err(|e| {
                    RPCError::from_alloy(
                        format!(
                    "Failed to send batch request for slot detector traces for block {block_hash}"
                ),
                        e,
                    )
                })?;

            result.extend(chunk_results);
        }

        Ok(result)
    }

    pub(crate) async fn batch_slot_detector_tests(
        &self,
        requests: &[SlotDetectorSlotTestRequest],
        calldata: &Bytes,
        block_hash: &B256,
    ) -> Result<Vec<TransportResult<Value>>, RPCError> {
        let batching = self
            .batching
            .as_ref()
            .ok_or(RPCError::SetupError(
                "BatchingConfig is required for batch operations".to_string(),
            ))?;

        let chunk_size = batching.max_batch_size; // we make 1 request per test
        let mut result = Vec::with_capacity(requests.len());

        for chunk_requests in requests.chunks(chunk_size) {
            let batch_call = || async {
                let mut batch = self.inner.new_batch();

                let batch_calls = chunk_requests
                    .iter()
                    .map(
                        |SlotDetectorSlotTestRequest {
                             storage_address,
                             slot,
                             token,
                             test_value,
                         }| {
                            // Format slot and value as 32-byte hex strings
                            let test_value_hex = format!("0x{:064x}", test_value);
                            let slot_hex = format!("0x{:064x}", slot);

                            let tracer_params = json!([
                                {
                                    "to": token.to_string(),
                                    "data": calldata.to_string()
                                },
                                block_hash.to_string(),
                                {
                                    storage_address.to_string(): {
                                        "stateDiff": {
                                            slot_hex: test_value_hex
                                        }
                                    }
                                }
                            ]);
                            batch.add_call::<_, Value>("eth_call", &tracer_params)
                        },
                    )
                    .collect::<Result<Vec<_>, RpcError<TransportErrorKind>>>()?;

                batch.send().await?;

                Ok(join_all(batch_calls).await)
            };

            let chunk_results = self
                .retry_policy
                .retry_request(|| async { batch_call().await })
                .await
                .map_err(|e| {
                    RPCError::from_alloy(
                        format!(
                            "Failed to send batch request for slot detector tests for block {block_hash}"
                        ),
                        e,
                    )
                })?;

            result.extend(chunk_results);
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use alloy::{rpc::types::TransactionInput, sol_types::SolCall};
    use rstest::rstest;
    use tracing::warn;
    use tracing_test::traced_test;

    use super::*;
    use crate::{
        erc20::balanceOfCall,
        test_fixtures::{
            TestFixture, BALANCER_VAULT_EXPECTED_SLOTS, BALANCER_VAULT_STR, STETH_EXPECTED_SLOTS,
            STETH_STR, TEST_BLOCK_HASH, TEST_BLOCK_NUMBER, TEST_SLOTS, USDC_HOLDER_ADDR,
            USDC_HOLDER_BALANCE, USDC_STR,
        },
        BytesCodec,
    };

    // Local extension methods specific to account extractor tests
    impl TestFixture {
        pub(crate) fn create_rpc_client(&self, batching: bool) -> EthereumRpcClient {
            let batching = if batching { Some(BatchingConfig::default()) } else { None };
            // Extremely short intervals for very fast testing
            let retry_policy = RetryPolicy::for_testing();

            EthereumRpcClient { inner: self.inner_rpc.clone(), batching, retry_policy, url: self.url.clone() }
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
        let result = EthereumRpcClient::new(&url);
        assert!(result.is_ok());

        // Test with invalid URL
        let result = EthereumRpcClient::new("invalid_url");
        assert!(result.is_err());

        Ok(())
    }

    #[tokio::test]
    #[ignore = "require RPC connection"]
    async fn test_get_block_number() -> Result<(), RPCError> {
        let fixture = TestFixture::new();
        let client = fixture.create_rpc_client(false);

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
        let client = fixture.create_rpc_client(false);

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
        let client = fixture.create_rpc_client(false);

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

        // Adjust the code prefix check to match the expected prefix length
        // As we are not checking the full code, just the beginning
        let mut code_string = code.to_string();
        code_string.truncate(22);

        assert_eq!(
            code_string, expected_prefix,
            "{} code prefix mismatch. Expected: {}, Got: {}",
            address_str, expected_prefix, code_string
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
        let client = fixture.create_rpc_client(false);

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

    #[rstest]
    #[traced_test]
    #[tokio::test]
    #[ignore = "require RPC connection"]
    async fn test_fetch_account_code_and_balance(
        #[values(false, true)] batching: bool,
    ) -> Result<(), RPCError> {
        let fixture = TestFixture::new();
        let client = fixture.create_rpc_client(batching);

        // Test with multiple addresses
        let requests = vec![parse_address(BALANCER_VAULT_STR), parse_address(STETH_STR)];

        let codes_and_balances = if batching {
            client
                .batch_fetch_accounts_code_and_balance(
                    BlockNumberOrTag::Number(fixture.block.number),
                    &requests,
                )
                .await
        } else {
            client
                .non_batch_fetch_accounts_code_and_balance(
                    BlockNumberOrTag::Number(fixture.block.number),
                    &requests,
                )
                .await
        }?;

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
        let client = fixture.create_rpc_client(false);

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

    #[rstest]
    #[traced_test]
    #[tokio::test]
    #[ignore = "require RPC connection"]
    async fn test_fetch_account_storage_with_specific_slots(
        #[values(false, true)] batching: bool,
    ) -> Result<(), RPCError> {
        let fixture = TestFixture::new();
        let client = fixture.create_rpc_client(batching);

        // Create request with specific slots
        let slots_request: Vec<B256> = TEST_SLOTS.keys().cloned().collect();

        let storage = if batching {
            client
                .batch_get_selected_storage(
                    BlockNumberOrTag::Number(fixture.block.number),
                    parse_address(BALANCER_VAULT_STR),
                    &slots_request,
                )
                .await
        } else {
            client
                .non_batch_get_selected_storage(
                    BlockNumberOrTag::Number(fixture.block.number),
                    parse_address(BALANCER_VAULT_STR),
                    &slots_request,
                )
                .await
        }?;

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

    #[tokio::test]
    #[ignore = "require RPC connection"]
    async fn test_trace_call_many() -> Result<(), RPCError> {
        let fixture = TestFixture::new();
        let client = fixture.create_rpc_client(false);

        // Create a simple trace_callMany request: check USDC balance
        let usdc = parse_address(USDC_STR);
        let balance_holder = parse_address(USDC_HOLDER_ADDR);

        // Request balance of a known holder at TEST_BLOCK_NUMBER
        let calldata = balanceOfCall { _owner: balance_holder }.abi_encode();
        let request = TransactionRequest::default()
            .to(usdc)
            .input(TransactionInput::both(calldata.into()));

        let traces = client
            .trace_call_many(vec![request], BlockNumberOrTag::Number(TEST_BLOCK_NUMBER))
            .await?;

        // Verify we got a response
        assert_eq!(traces.len(), 1);
        assert!(!traces[0].trace.is_empty());

        // Verify the trace doesn't have an error
        let first_trace = &traces[0].trace[0];
        assert!(first_trace.error.is_none(), "trace should not have an error");

        // Decode and verify the output
        let output_bytes = &traces[0].output;
        assert_eq!(output_bytes.len(), 32, "balance should be 32 bytes");

        let balance = U256::from_be_bytes::<32>(
            output_bytes
                .as_ref()
                .try_into()
                .unwrap(),
        );

        // Expected balance: 74743132960379 (74,743,132.960379 USDC with 6 decimals)
        let expected_balance = U256::from(USDC_HOLDER_BALANCE);
        assert_eq!(
            balance, expected_balance,
            "USDC balance from trace mismatch. Expected: {}, Got: {}",
            expected_balance, balance
        );

        Ok(())
    }

    #[tokio::test]
    #[ignore = "require RPC connection"]
    async fn test_eth_call() -> Result<(), RPCError> {
        use alloy::{
            primitives::U256,
            rpc::types::{TransactionInput, TransactionRequest},
            sol_types::SolCall,
        };

        use crate::erc20::balanceOfCall;

        let fixture = TestFixture::new();
        let client = fixture.create_rpc_client(false);

        // Create an eth_call request: check USDC balance
        let usdc = parse_address(USDC_STR);
        let balance_holder = parse_address(USDC_HOLDER_ADDR);

        // Request balance of a known holder
        let calldata = balanceOfCall { _owner: balance_holder }.abi_encode();
        let request = TransactionRequest::default()
            .to(usdc)
            .input(TransactionInput::both(calldata.into()));

        let result = client
            .eth_call(request, BlockNumberOrTag::Number(TEST_BLOCK_NUMBER))
            .await?;

        // Verify we got a response
        assert!(!result.is_empty(), "eth_call should return non-empty data");
        assert_eq!(result.len(), 32, "balance should be 32 bytes");

        // Verify we can decode the balance as U256
        let balance = U256::from_be_bytes::<32>(result.as_ref().try_into().unwrap());

        // Expected balance: 74743132960379 (74,743,132.960379 USDC with 6 decimals)
        let expected_balance = U256::from(USDC_HOLDER_BALANCE);
        assert_eq!(
            balance, expected_balance,
            "USDC balance mismatch. Expected: {}, Got: {}",
            expected_balance, balance
        );

        Ok(())
    }

    /// Note: We support `"storage": null` as a temporary workaround for Unichain nodes that
    /// return null instead of {} for empty storage. See StorageRangeResultWrapper for details.
    #[rstest]
    #[case::null_storage(r#"{"id":1,"jsonrpc":"2.0","result":{"storage":null,"nextKey":null}}"#)]
    #[case::empty_storage(r#"{"id":1,"jsonrpc":"2.0","result":{"storage":{},"nextKey":null}}"#)]
    #[tokio::test]
    async fn test_debug_storage_range_at_handles_empty_storage(#[case] json_response: &str) {
        let mut server = mockito::Server::new_async().await;
        let mock_url = server.url();

        // Mock the debug_storageRangeAt response
        let _mock = server
            .mock("POST", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(json_response)
            .create_async()
            .await;

        let client = EthereumRpcClient::new(&mock_url).expect("Failed to create client");

        let address = Address::from_str("0xa6c8d7514785c4314ee05ed566cb41151d43c0c0")
            .expect("Failed to parse address");
        let block_hash =
            B256::from_str("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
                .expect("Failed to parse block hash");

        let result = client
            .debug_storage_range_at(block_hash, address, B256::ZERO)
            .await;

        // Verify that alloy handles both null and empty storage correctly
        println!("{:?}", result);
        assert!(result.is_ok(), "Should handle empty storage gracefully");
        let storage_result = result.unwrap();

        // Both null and empty storage should result in empty HashMap
        assert!(
            storage_result.storage.0.is_empty(),
            "Empty storage (null or {{}}) should result in empty storage map"
        );
        assert!(storage_result.next_key.is_none(), "nextKey should be None");
    }
}
