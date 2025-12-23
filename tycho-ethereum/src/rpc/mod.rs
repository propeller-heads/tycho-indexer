use std::{
    collections::{BTreeMap, HashMap},
    default::Default,
    iter::IntoIterator,
    time::Duration,
};

use alloy::{
    primitives::{map::AddressHashMap, private::serde, Address, B256, U256},
    rpc::{
        client::{ClientBuilder, ReqwestClient},
        types::{
            debug::{StorageMap, StorageRangeResult, StorageResult},
            state::AccountOverride,
            trace::{
                geth::{
                    GethDebugBuiltInTracerType, GethDebugTracerType, GethDebugTracingCallOptions,
                    GethDebugTracingOptions, GethTrace,
                },
                parity::{TraceResults, TraceType},
            },
            AccessListResult, Block, BlockId, BlockNumberOrTag, TransactionRequest,
        },
    },
    transports::{http::reqwest, TransportResult},
};
use serde::Deserialize;
use serde_json::{json, Value};
use tracing::{debug, info, instrument, trace, Span};
use tycho_common::Bytes;

use crate::{RPCError, RequestError};

pub mod config;
pub mod errors;
mod executor;
mod retry;

use errors::RpcResultExt;

pub use executor::{RequestHandle, RpcRequestGroup};

use crate::{
    rpc::{
        config::{RPCBatchingConfig, RPCRetryConfig},
        retry::RetryPolicy,
    },
    services::entrypoint_tracer::slot_detector::{
        SlotDetectorSlotTestRequest, SlotDetectorValueRequest,
    },
};

/// This struct wraps the ReqwestClient and provides Ethereum-specific RPC methods
/// with default batching support and retry logic.
/// It is cheap to clone, as the `inner` internally uses an Arc for the ReqwestClient.
#[derive(Clone, Debug)]
pub struct EthereumRpcClient {
    inner: ReqwestClient,
    batching: RPCBatchingConfig,
    retry_policy: RetryPolicy,
    url: String,
}

impl EthereumRpcClient {
    /// Creates a new EthereumRpcClient with the given RPC URL.
    /// Uses default batching and retry configurations.
    ///
    /// Batching: enabled with defaults (max batch size 50, max storage slot batch size 1000).
    /// Retry: enabled with defaults (max retries 3, initial backoff 100ms, max backoff 5000ms).
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

        // Enable batching with default settings as most RPC providers support it
        let batching = RPCBatchingConfig::enabled_with_defaults();

        // Enable retry with default settings
        // Note that we do not use the `layer` method to set the retry layer, as we want to support
        // retrying batch requests if any individual request in the batch fails.
        let retry_policy = RPCRetryConfig::default().into();

        Ok(Self { inner: rpc, batching, retry_policy, url: rpc_url.to_string() })
    }

    pub fn get_url(&self) -> &str {
        &self.url
    }

    pub fn get_retry_config(&self) -> RPCRetryConfig {
        (&self.retry_policy).into()
    }

    pub fn with_batching(mut self, batching_config: RPCBatchingConfig) -> Self {
        self.batching = batching_config;
        self
    }

    pub fn with_retry(mut self, retry_config: RPCRetryConfig) -> Self {
        self.retry_policy = retry_config.into();
        self
    }

    /// Creates a new request group for batching multiple RPC calls.
    /// Uses the default `max_batch_size` from batching config.
    fn new_request_group(&self) -> RpcRequestGroup<'_> {
        RpcRequestGroup::new(&self.inner, self.retry_policy.clone(), self.batching.max_batch_size())
    }

    /// Creates a new request group optimized for storage slot queries.
    /// Uses `storage_slot_max_batch_size` which is typically larger than the default.
    fn new_storage_request_group(&self) -> RpcRequestGroup<'_> {
        RpcRequestGroup::new(
            &self.inner,
            self.retry_policy.clone(),
            self.batching
                .storage_slot_max_batch_size(),
        )
    }

    #[instrument(level = "debug", skip(self))]
    pub async fn get_block_number(&self) -> Result<u64, RPCError> {
        let block_number = self
            .retry_policy
            .call_with_retry(|| async {
                self.inner
                    .request_noparams("eth_blockNumber")
                    .await
            })
            .await
            .rpc_context("Failed to get block number")?;

        if let BlockNumberOrTag::Number(num) = block_number {
            Ok(num)
        } else {
            Err(RPCError::RequestError(RequestError::Other(
                "Failed to get block number: Unexpected block tag returned".to_string(),
            )))
        }
    }

    #[instrument(level = "debug", skip(self))]
    pub(crate) async fn eth_get_block_by_number(
        &self,
        block_id: BlockId,
    ) -> Result<Block, RPCError> {
        let full_tx_objects = false;

        let result: Option<Block> = self
            .retry_policy
            .call_with_retry(|| async {
                self.inner
                    .request("eth_getBlockByNumber", (block_id, full_tx_objects))
                    .await
            })
            .await
            .with_rpc_context(|| format!("Failed to get block for block id {block_id}"))?;

        result.ok_or(RPCError::RequestError(RequestError::Other(format!(
            "Failed to get block for block id {block_id}: Block not found"
        ))))
    }

    #[instrument(level = "debug", skip(self))]
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
        let wrapper: StorageRangeResultWrapper = self
            .retry_policy
            .call_with_retry(|| async {
                self.inner
                    .request("debug_storageRangeAt", params)
                    .await
            })
            .await
            .with_rpc_context(|| {
                format!("Failed to get storage for address {address}, block {block_hash}")
            })?;

        Ok(wrapper.into())
    }

    #[instrument(level = "debug", skip(self), fields(slot_count = tracing::field::Empty))]
    pub(crate) async fn get_storage_range(
        &self,
        address: Address,
        block_hash: B256,
    ) -> Result<HashMap<B256, B256>, RPCError> {
        let span = Span::current();
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

        let slot_count = all_slots.len();
        span.record("slot_count", slot_count as u64);
        Ok(all_slots)
    }

    #[instrument(level = "debug", skip(self))]
    pub(crate) async fn fetch_accounts_code_and_balance(
        &self,
        block_id: BlockNumberOrTag,
        addresses: &[Address],
    ) -> Result<HashMap<Address, (Bytes, U256)>, RPCError> {
        debug!(
            address_count = addresses.len(),
            block_id = block_id.to_string(),
            "Fetching account code and balance"
        );

        let mut group = self.new_request_group();

        // Register all calls (2 per address: code + balance)
        let handles: Vec<(Address, RequestHandle<Bytes>, RequestHandle<U256>)> = addresses
            .iter()
            .map(|&address| {
                let code_handle = group.add_call("eth_getCode", &(address, block_id))?;
                let balance_handle = group.add_call("eth_getBalance", &(address, block_id))?;
                Ok((address, code_handle, balance_handle))
            })
            .collect::<Result<_, _>>().with_rpc_context(|| {
                format!(
                    "Failed to register code & balance calls for {} addresses at block {block_id}",
                    addresses.len()
                )
            })?;

        // Execute all calls with retry
        group.execute().await.with_rpc_context(|| {
            format!(
                "Failed to fetch code & balance for {} addresses at block {block_id}",
                addresses.len()
            )
        })?;

        // Collect results
        let mut result = HashMap::with_capacity(addresses.len());
        for (address, code_handle, balance_handle) in handles {
            let code = code_handle
                .await_result()
                .await
                .with_rpc_context(|| format!("eth_getCode failed for {address:?}"))?;
            let balance = balance_handle
                .await_result()
                .await
                .with_rpc_context(|| format!("eth_getBalance failed for {address:?}"))?;
            result.insert(address, (code, balance));
        }

        info!(
            address_count = addresses.len(),
            block_id = block_id.to_string(),
            "Successfully fetched account code and balance"
        );

        Ok(result)
    }

    #[instrument(level = "debug", skip(self, slots))]
    pub(crate) async fn get_selected_storage(
        &self,
        block_id: BlockNumberOrTag,
        address: Address,
        slots: &[B256],
    ) -> Result<HashMap<B256, Option<B256>>, RPCError> {
        let mut group = self.new_storage_request_group();

        // Register all storage slot queries
        let handles: Vec<(B256, RequestHandle<B256>)> = slots
            .iter()
            .map(|&slot| {
                let handle = group.add_call("eth_getStorageAt", &(&address, slot, block_id))?;
                Ok((slot, handle))
            })
            .collect::<Result<_, _>>().with_rpc_context(|| {
                format!(
                    "Failed to register storage calls for address {address}, block {block_id}, {} slots",
                    slots.len()
                )
            })?;

        // Execute all calls with retry
        group.execute().await.with_rpc_context(|| {
            format!(
                "Failed to get storage for address {address}, block {block_id}, {} slots",
                slots.len()
            )
        })?;

        // Collect results
        let mut result = HashMap::with_capacity(slots.len());
        for (slot, handle) in handles {
            let storage_value: B256 = handle.await_result().await.with_rpc_context(|| {
                format!(
                    "eth_getStorageAt failed for address {address}, block {block_id}, slot {slot}"
                )
            })?;

            let value = if storage_value == B256::ZERO { None } else { Some(storage_value) };
            result.insert(slot, value);
        }

        Ok(result)
    }

    /// Use the trace_callMany API to simulate multiple call requests applied together one after
    /// another. See https://openethereum.github.io/JSONRPC-trace-module#trace_callmany
    ///
    /// Returns error if communication with the node failed.
    #[instrument(level = "debug", skip(self, requests))]
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
            .call_with_retry(|| async {
                self.inner
                    .request("trace_callMany", (&trace_requests, block))
                    .await
            })
            .await
            .with_rpc_context(|| format!("Failed to get trace call many for block {block}"))
    }

    /// Executes a new message call immediately without creating a transaction on the blockchain.
    /// See https://ethereum.org/en/developers/docs/apis/json-rpc/#eth_call
    ///
    /// Returns the output data from the call or an error if the call failed.
    #[instrument(level = "debug", skip(self, request))]
    pub(crate) async fn eth_call(
        &self,
        request: TransactionRequest,
        block: BlockNumberOrTag,
    ) -> Result<Bytes, RPCError> {
        self.retry_policy
            .call_with_retry(|| async {
                self.inner
                    .request("eth_call", (&request, block))
                    .await
            })
            .await
            .with_rpc_context(|| format!("Failed to send an eth_call request for block {block}"))
    }

    #[instrument(level = "debug", skip(self, access_list_params, trace_call_params))]
    pub(crate) async fn trace_and_access_list(
        &self,
        target: &Address,
        block_hash: &B256,
        access_list_params: &Value,
        trace_call_params: &Value,
    ) -> Result<(AccessListResult, GethTrace), RPCError> {
        let mut group = self.new_request_group();

        let access_list_handle: RequestHandle<AccessListResult> = group
            .add_call("eth_createAccessList", access_list_params)
            .with_rpc_context(|| {
                format!("Failed to register eth_createAccessList for target {target}, block {block_hash}")
            })?;
        let trace_handle: RequestHandle<GethTrace> = group
            .add_call("debug_traceCall", trace_call_params)
            .with_rpc_context(|| {
                format!("Failed to register debug_traceCall for target {target}, block {block_hash}")
            })?;

        group
            .execute_abort_early()
            .await
            .with_rpc_context(|| {
                format!("Failed to execute trace and access list for target {target}, block {block_hash}")
            })?;

        let access_list_data = access_list_handle
            .await_result()
            .await
            .with_rpc_context(|| {
                format!("eth_createAccessList failed for target {target}, block {block_hash}")
            })?;

        let pre_state_trace = trace_handle
            .await_result()
            .await
            .with_rpc_context(|| {
                format!("debug_traceCall failed for target {target}, block {block_hash}")
            })?;

        Ok((access_list_data, pre_state_trace))
    }

    #[instrument(level = "debug", skip(self, requests, calldata))]
    pub(crate) async fn slot_detector_trace(
        &self,
        requests: Vec<SlotDetectorValueRequest>,
        calldata: &Bytes,
        block_hash: &B256,
    ) -> Result<Vec<(GethTrace, U256)>, RPCError> {
        let mut group = self.new_request_group();

        // Register all calls (2 per request: debug_traceCall + eth_call)
        let handles: Vec<(RequestHandle<GethTrace>, RequestHandle<U256>)> = requests
            .iter()
            .map(|SlotDetectorValueRequest { token, tracer_params }| {
                let trace_handle = group.add_call("debug_traceCall", tracer_params)?;

                let eth_call_param = json!([
                    {
                        "to": token.to_string(),
                        "data": calldata.to_string()
                    },
                    block_hash.to_string()
                ]);
                let eth_call_handle = group.add_call("eth_call", &eth_call_param)?;

                Ok((trace_handle, eth_call_handle))
            })
            .collect::<Result<_, _>>()
            .with_rpc_context(|| {
                format!("Failed to register slot detector calls for block {block_hash}")
            })?;

        // Execute all calls with retry
        group
            .execute()
            .await
            .with_rpc_context(|| {
                format!("Failed to execute slot detector traces for block {block_hash}")
            })?;

        // Collect results
        let mut result = Vec::with_capacity(requests.len());
        for (trace_handle, eth_call_handle) in handles {
            let trace = trace_handle
                .await_result()
                .await
                .with_rpc_context(|| {
                    format!("debug_traceCall failed for slot detector at block {block_hash}")
                })?;
            let value = eth_call_handle
                .await_result()
                .await
                .with_rpc_context(|| {
                    format!("eth_call failed for slot detector at block {block_hash}")
                })?;
            result.push((trace, value));
        }

        Ok(result)
    }

    /// Performs slot detector tests using eth_call with state diffs.
    /// This method returns a vector of Results for each individual test request.
    #[instrument(level = "debug", skip(self, requests, calldata))]
    pub(crate) async fn slot_detector_tests(
        &self,
        requests: &[SlotDetectorSlotTestRequest],
        calldata: &Bytes,
        block_hash: &B256,
    ) -> Result<Vec<TransportResult<Value>>, RPCError> {
        let mut group = self.new_request_group();

        // Register all test calls
        let handles: Vec<RequestHandle<Value>> = requests
            .iter()
            .map(|SlotDetectorSlotTestRequest { storage_address, slot, token, test_value }| {
                // Format slot and value as 32-byte hex strings
                let test_value_hex = format!("0x{:064x}", test_value);
                let slot_hex = format!("0x{:064x}", slot);

                let tracer_params = json!([
                    {
                        "to": token,
                        "data": calldata
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
                group.add_call("eth_call", &tracer_params)
            })
            .collect::<Result<_, _>>()
            .with_rpc_context(|| {
                format!("Failed to register slot detector tests for block {block_hash}")
            })?;

        // Execute all calls with retry (use execute, not execute_abort_early,
        // as we want to preserve individual errors in the result)
        group
            .execute()
            .await
            .with_rpc_context(|| {
                format!("Failed to execute slot detector tests for block {block_hash}")
            })?;

        // Collect individual results (preserving errors per call)
        let mut results = Vec::with_capacity(handles.len());
        for handle in handles {
            results.push(handle.await_raw().await);
        }

        Ok(results)
    }

    #[instrument(level = "debug", skip(self, tx_with_overrides), fields(tx_count = tx_with_overrides.len()))]
    pub async fn simulate_txs_with_trace(
        &self,
        block: BlockNumberOrTag,
        tx_with_overrides: Vec<(TransactionRequest, Option<AddressHashMap<AccountOverride>>)>,
    ) -> Result<Vec<TransportResult<Value>>, RPCError> {
        // use callTracer for better formatted results
        let tracing_options = GethDebugTracingOptions {
            tracer: Some(GethDebugTracerType::BuiltInTracer(
                GethDebugBuiltInTracerType::CallTracer,
            )),
            config: Default::default(),
            tracer_config: Default::default(),
            timeout: None,
        };

        let mut group = self.new_request_group();

        // Register all calls
        let handles: Vec<RequestHandle<Value>> = tx_with_overrides
            .iter()
            .map(|(tx, overrides)| {
                let trace_options = GethDebugTracingCallOptions {
                    tracing_options: tracing_options.clone(),
                    state_overrides: overrides.clone(),
                    block_overrides: None,
                    tx_index: None,
                };
                group.add_call("debug_traceCall", &(tx.clone(), block, trace_options))
            })
            .collect::<Result<_, _>>()
            .with_rpc_context(|| {
                format!("Failed to register simulate tx with trace for block {block}")
            })?;

        // Execute all calls with retry (use execute, not execute_abort_early,
        // as we want to preserve individual errors in the result)
        group
            .execute()
            .await
            .with_rpc_context(|| format!("Failed to execute simulate tx with trace for block {block}"))?;

        // Collect individual results (preserving errors per call)
        let mut results = Vec::with_capacity(handles.len());
        for handle in handles {
            results.push(handle.await_raw().await);
        }

        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use alloy::{
        hex, primitives::map::B256HashMap, rpc::types::TransactionInput, sol_types::SolCall,
        transports::RpcError,
    };
    use mockito::{Mock, Server, ServerGuard};
    use rstest::rstest;
    use tracing::warn;
    use tracing_test::traced_test;

    use super::*;
    use crate::{
        erc20::balanceOfCall,
        rpc::retry::tests::MOCK_RETRY_POLICY_MAX_ATTEMPTS,
        services::entrypoint_tracer::slot_detector::{
            SlotDetectorSlotTestRequest, SlotDetectorValueRequest,
        },
        test_fixtures::{
            TestFixture, BALANCER_VAULT_EXPECTED_SLOTS, BALANCER_VAULT_STR, STETH_EXPECTED_SLOTS,
            STETH_STR, TEST_BLOCK_HASH, TEST_BLOCK_NUMBER, TEST_SLOTS, USDC_HOLDER_ADDR,
            USDC_HOLDER_BALANCE, USDC_STR, USDT_STR, WETH_STR,
        },
        BytesCodec,
    };

    // Local extension methods specific to account extractor tests
    impl TestFixture {
        pub(crate) fn create_rpc_client(&self, batching: bool) -> EthereumRpcClient {
            let batching = if batching {
                RPCBatchingConfig::enabled_with_defaults()
            } else {
                RPCBatchingConfig::Disabled
            };
            // We use 10 retries for tests to potential rate limiting issues.
            let retry_policy = RPCRetryConfig { max_retries: 10, ..Default::default() }.into();

            EthereumRpcClient {
                inner: self.inner_rpc.clone(),
                batching,
                retry_policy,
                url: self.url.clone(),
            }
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
    async fn test_get_retry_config() {
        // Test default config
        let client =
            EthereumRpcClient::new("https://example.com").expect("Failed to create client");
        let config = client.get_retry_config();

        assert_eq!(config.max_retries, 3, "Default max_retries should be 3");
        assert_eq!(config.initial_backoff_ms, 100, "Default initial_backoff_ms should be 100");
        assert_eq!(config.max_backoff_ms, 5000, "Default max_backoff_ms should be 5000");

        // Test custom config roundtrip
        let custom_config =
            RPCRetryConfig { max_retries: 7, initial_backoff_ms: 200, max_backoff_ms: 10000 };

        let client_with_custom = client.with_retry(custom_config.clone());
        let retrieved_config = client_with_custom.get_retry_config();

        assert_eq!(
            retrieved_config.max_retries, custom_config.max_retries,
            "Custom max_retries should be preserved"
        );
        assert_eq!(
            retrieved_config.initial_backoff_ms, custom_config.initial_backoff_ms,
            "Custom initial_backoff_ms should be preserved"
        );
        assert_eq!(
            retrieved_config.max_backoff_ms, custom_config.max_backoff_ms,
            "Custom max_backoff_ms should be preserved"
        );
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

        let codes_and_balances = client
            .fetch_accounts_code_and_balance(
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

        let storage = client
            .get_selected_storage(
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
        assert!(result.is_ok(), "Should handle empty storage gracefully");
        let storage_result = result.unwrap();

        // Both null and empty storage should result in empty HashMap
        assert!(
            storage_result.storage.0.is_empty(),
            "Empty storage (null or {{}}) should result in empty storage map"
        );
        assert!(storage_result.next_key.is_none(), "nextKey should be None");
    }

    #[tokio::test]
    #[ignore = "require RPC connection"]
    async fn test_batch_slot_detector_trace() {
        let fixture = TestFixture::new();
        let client = fixture
            .create_rpc_client(true)
            .with_batching(RPCBatchingConfig::enabled_with_defaults());

        let weth = parse_address(WETH_STR);
        let usdc = parse_address(USDC_STR);
        let usdt = parse_address(USDT_STR);

        // Holder address that has balances in all three tokens
        let holder = parse_address(USDC_HOLDER_ADDR);
        let calldata: Bytes = balanceOfCall { _owner: holder }
            .abi_encode()
            .into();

        // Verified block hash where all tokens have non-zero balances
        let block_hash_str = "0x658814e4cb074359f10dd71237cc57b1ae6791fc9de59fde570e724bd884cbb0";
        let block_hash = B256::from_str(block_hash_str).expect("Failed to parse block hash");

        // Create requests with different tokens to test order preservation
        // The eth_call uses the same calldata, but we call different token contracts
        let tokens = [weth, usdc, usdt];
        let requests: Vec<SlotDetectorValueRequest> = tokens
            .iter()
            .map(|&token| {
                let tracer_params = json!([
                    {
                        "to": token.to_string(),
                        "input": calldata.to_string()
                    },
                    {
                        "blockHash": block_hash_str
                    },
                    {
                        "tracer": "prestateTracer",
                        "enableReturnData": true
                    }
                ]);
                SlotDetectorValueRequest { token, tracer_params }
            })
            .collect();

        let results = client
            .slot_detector_trace(requests.clone(), &calldata, &block_hash)
            .await
            .expect("Batch slot detector trace failed");

        // Verify all results returned and order preserved
        assert_eq!(results.len(), tokens.len(), "Should receive result for each request");

        let expected_balances = [
            U256::from_str("911262488844363150815").unwrap(), // WETH balance
            U256::from(69346617579396u64),                    // USDC balance
            U256::from(52511836228219u64),                    // USDT balance
        ];

        // Each token should return a result in expected order with the correct balance
        for (idx, (trace, value)) in results.iter().enumerate() {
            assert!(
                matches!(trace, GethTrace::PreStateTracer(_)),
                "Request {} should return PreStateTracer",
                idx
            );
            assert_eq!(
                *value, expected_balances[idx],
                "Request {} balance mismatch. Expected: {}, Got: {}",
                idx, expected_balances[idx], *value
            );
        }
    }

    #[tokio::test]
    #[ignore = "require RPC connection"]
    async fn test_batch_slot_detector_tests() {
        let fixture = TestFixture::new();
        let client = fixture
            .create_rpc_client(true)
            .with_batching(RPCBatchingConfig::Enabled {
                max_batch_size: 2,
                storage_slot_max_batch_size_override: None,
            });

        // Using verified test case data with real balance slots for USDT, WETH, and USDC
        let usdt = parse_address(USDT_STR);
        let weth = parse_address(WETH_STR);
        let usdc = parse_address(USDC_STR);

        let balance_holder = parse_address(USDC_HOLDER_ADDR); // 0x000000000004444c5dc75cb358380d2e3de08a90

        // Create calldata for balanceOf call
        let calldata: Bytes = balanceOfCall { _owner: balance_holder }
            .abi_encode()
            .into();

        // Verified calldata:
        // 0x70a08231000000000000000000000000000000000004444c5dc75cb358380d2e3de08a90
        assert_eq!(
            calldata.to_string(),
            "0x70a08231000000000000000000000000000000000004444c5dc75cb358380d2e3de08a90",
            "Calldata should match verified test case"
        );

        // Verified block hash where all slots contain actual balances
        let block_hash_str = "0x658814e4cb074359f10dd71237cc57b1ae6791fc9de59fde570e724bd884cbb0";
        let block_hash = B256::from_str(block_hash_str).expect("Failed to parse block hash");

        // Create test requests with verified slot locations and test values
        // These are real balance storage slots for the holder at this block
        let requests = vec![
            // USDT: slot and test_value verified to work
            SlotDetectorSlotTestRequest {
                storage_address: usdt,
                slot: U256::from_str(
                    "58503166935794899529373963234700026353561458556759469400570547766664673378107",
                )
                .unwrap(),
                token: usdt,
                test_value: U256::from(105023672456438_u64),
            },
            // WETH: slot and test_value verified to work
            SlotDetectorSlotTestRequest {
                storage_address: weth,
                slot: U256::from_str(
                    "11839838417408005300668405460519842744078024714876931848523103724423050260794",
                )
                .unwrap(),
                token: weth,
                test_value: U256::from_str("1822524977688726301630").unwrap(),
            },
            // USDC: slot and test_value verified to work
            SlotDetectorSlotTestRequest {
                storage_address: usdc,
                slot: U256::from_str(
                    "27200642610643119904443225166668021742846989772583561028640892867511244344442",
                )
                .unwrap(),
                token: usdc,
                test_value: U256::from(138693235158792_u64),
            },
        ];

        let results = client
            .slot_detector_tests(&requests, &calldata, &block_hash)
            .await
            .expect("Batch slot detector tests failed");

        // Verify we got results for all requests
        assert_eq!(results.len(), requests.len(), "Should receive result for each request");

        let expected_values = [
            U256::from(105023672456438_u64),                   // USDT test value
            U256::from_str("1822524977688726301630").unwrap(), // WETH test value
            U256::from(138693235158792_u64),                   // USDC test value
        ];

        // Verify each result succeeded (TransportResult can be Ok or Err)
        for (idx, result) in results.iter().enumerate() {
            assert!(
                result.is_ok(),
                "Request {} should succeed, got error: {:?}",
                idx,
                result.as_ref().err()
            );

            let value = serde_json::from_value::<U256>(result.as_ref().unwrap().clone())
                .expect("Failed to parse U256 from result");

            assert_eq!(
                value, expected_values[idx],
                "Request {} test value mismatch. Expected: {}, Got: {}",
                idx, expected_values[idx], value
            );
        }
    }

    async fn mock_batch_slot_detector_tests_call(
        server: &mut ServerGuard,
    ) -> Result<Vec<TransportResult<Value>>, RPCError> {
        let policy = retry::tests::mock_retry_policy();

        let rpc_client = EthereumRpcClient::new(&server.url())
            .expect("Failed to create EthereumRpcClient")
            .with_batching(RPCBatchingConfig::enabled_with_defaults())
            .with_retry((&policy).into());

        let batch_request = vec![
            SlotDetectorSlotTestRequest {
                storage_address: Address::ZERO,
                slot: U256::ZERO,
                token: Address::ZERO,
                test_value: U256::ZERO,
            };
            2
        ];

        let calldata: Bytes = Bytes::new();

        let result = rpc_client
            .slot_detector_tests(&batch_request, &calldata, &B256::ZERO)
            .await;

        result
    }

    async fn mock_retryable_failure(server: &mut ServerGuard) -> Mock {
        server
            .mock("POST", "/")
            .with_status(429)
            .expect(1)
            .create_async()
            .await
    }

    async fn mock_success_at(server: &mut ServerGuard, retry_num: usize) -> Mock {
        // Note that for the batch requests, the ids increment per request retry, starting from 0.
        // So the correct ids for the response are `retry_num * calls_per_batch + request_index`.
        let first_id = retry_num * 2; // batch size is 2
        let second_id = first_id + 1;

        server
            .mock("POST", "/")
            .with_status(200)
            .with_body(format!(
                r#"[
                {{"jsonrpc":"2.0","id":{first_id},"result":"0x1234"}},
                {{"jsonrpc":"2.0","id":{second_id},"result":"0x5678"}}
            ]"#
            ))
            .expect(1)
            .create_async()
            .await
    }

    #[tokio::test]
    async fn test_batch_slot_detector_tests_retry_on_transient_failure() {
        let mut server = Server::new_async().await;

        // First two attempts fail, third succeeds
        for _ in 0..MOCK_RETRY_POLICY_MAX_ATTEMPTS {
            let _m = mock_retryable_failure(&mut server).await;
        }

        // At this point the id counter should be 2 as it increments per request starting from 0
        let m_success = mock_success_at(&mut server, MOCK_RETRY_POLICY_MAX_ATTEMPTS).await;

        let result = mock_batch_slot_detector_tests_call(&mut server).await;

        assert!(result.is_ok());

        let responses = result.unwrap();
        assert_eq!(responses.len(), 2);

        match &responses[0] {
            Ok(val) => assert_eq!(*val, json!("0x1234")),
            Err(err) => panic!("Expected Ok response, got Err: {}", err),
        }

        m_success.assert();
    }

    #[tokio::test]
    async fn test_batch_slot_detector_tests_retry_on_transient_failure_exceeding_retries() {
        let mut server = Server::new_async().await;

        // All attempts fail
        for _ in 0..MOCK_RETRY_POLICY_MAX_ATTEMPTS {
            let _m = mock_retryable_failure(&mut server).await;
        }
        let m_failure = mock_retryable_failure(&mut server).await;

        let result = mock_batch_slot_detector_tests_call(&mut server).await;

        assert!(result.is_err());
        // The error can be either RequestError (if the request itself fails) or
        // InvalidResponse (if the response body can't be parsed as JSON)
        assert!(matches!(result, Err(RPCError::RequestError(_))));

        m_failure.assert();
    }

    #[rstest]
    #[case::other_is_success("\"result\":\"0x1234\"")]
    #[case::other_is_retriable_error(
        "\"error\":{\"code\":-32000,\"message\":\"header not found\"}"
    )]
    #[case::other_is_permanent_error("\"error\":{\"code\":-32602,\"message\":\"invalid params\"}")]
    #[tokio::test]
    async fn test_batch_slot_detector_tests_partial_retryable_is_retried(
        #[case] other_response: &str,
    ) {
        let mut server = Server::new_async().await;

        // First attempt: all errors
        let _m1 = server
            .mock("POST", "/")
            .with_status(200)
            .with_body(format!(
                r#"[
                {{"jsonrpc":"2.0","id":0,"error":{{"code":-32000,"message":"header not found"}}}},
                {{"jsonrpc":"2.0","id":1,{other_response}}}
            ]"#
            ))
            .expect(1)
            .create_async()
            .await;

        // Second attempt: success
        let m2 = mock_success_at(&mut server, 1).await;

        let result = mock_batch_slot_detector_tests_call(&mut server).await;

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

        m2.assert();
    }

    #[tokio::test]
    async fn test_batch_slot_detector_tests_retry_on_all_failed_non_retryable_errors_for_safety() {
        let mut server = Server::new_async().await;

        // First attempt: non-retryable error (but all failed, so should retry for safety)
        let _m1 = server
            .mock("POST", "/")
            .with_status(200)
            .with_body(
                r#"[
                {"jsonrpc":"2.0","id":0,"error":{"code":-32602,"message":"invalid params"}},
                {"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"invalid params"}}
            ]"#,
            )
            .expect(1)
            .create_async()
            .await;

        // Second attempt: success (after retry for safety)
        let m2 = mock_success_at(&mut server, 1).await;

        let result = mock_batch_slot_detector_tests_call(&mut server).await;

        // Should succeed after retry (safety measure)
        assert!(result.is_ok());
        let responses = result.unwrap();
        assert_eq!(responses.len(), 2);
        match &responses[0] {
            Ok(val) => assert_eq!(*val, json!("0x1234")),
            Err(err) => panic!("Expected Ok response, got Err: {}", err),
        }

        m2.assert();
    }

    #[tokio::test]
    async fn test_batch_slot_detector_tests_no_retry_on_mixed_success_and_non_retryable_errors() {
        let mut server = Server::new_async().await;

        // Only one request should be made (no retry - mixed success/non-retryable error)
        let m = server
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

        let result = mock_batch_slot_detector_tests_call(&mut server).await;

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

        m.assert();
    }

    /// Parses the balance from a callTracer output field
    fn parse_balance_from_trace(trace_value: &Value) -> U256 {
        let output = trace_value
            .as_object()
            .and_then(|obj| obj.get("output"))
            .and_then(|v| v.as_str())
            .expect("trace should have output field");
        let balance_bytes = hex::decode(&output[2..]).expect("output should be valid hex");
        U256::from_be_slice(&balance_bytes)
    }

    #[tokio::test]
    #[ignore = "require RPC connection"]
    async fn test_simulate_txs_with_trace_state_override() -> Result<(), RPCError> {
        let fixture = TestFixture::new();
        let client = fixture.create_rpc_client(true);

        let usdc = parse_address(USDC_STR);
        let balance_holder = parse_address(USDC_HOLDER_ADDR);

        // USDC balance storage slot for USDC_HOLDER_ADDR (from test_batch_slot_detector_tests)
        let balance_slot = B256::from(
            U256::from_str(
                "27200642610643119904443225166668021742846989772583561028640892867511244344442",
            )
            .unwrap(),
        );

        // Our test override value - a distinctive balance we can verify
        let override_balance = B256::from(U256::from_str("123456789000000").unwrap()); // 123,456,789 USDC

        // Create calldata for balanceOf
        let calldata: alloy::primitives::Bytes = balanceOfCall { _owner: balance_holder }
            .abi_encode()
            .into();

        let base_tx = TransactionRequest::default()
            .to(usdc)
            .input(TransactionInput::both(calldata));

        // Create state override for the balance slot
        let mut state_diff = B256HashMap::default();
        state_diff.insert(balance_slot, override_balance);
        let mut overrides = AddressHashMap::default();
        overrides
            .insert(usdc, AccountOverride { state_diff: Some(state_diff), ..Default::default() });

        // Two requests: without override, with override
        let tx_requests = vec![(base_tx.clone(), None), (base_tx.clone(), Some(overrides))];

        let results = client
            .simulate_txs_with_trace(BlockNumberOrTag::Number(TEST_BLOCK_NUMBER), tx_requests)
            .await?;

        assert_eq!(results.len(), 2);

        // First call: should return real balance
        let real_balance = parse_balance_from_trace(results[0].as_ref().unwrap());
        assert_eq!(
            real_balance,
            U256::from(USDC_HOLDER_BALANCE),
            "Without override should return real balance"
        );

        // Second call: should return overridden balance
        let overridden_balance = parse_balance_from_trace(results[1].as_ref().unwrap());
        assert_eq!(
            B256::from(overridden_balance),
            override_balance,
            "With override should return overridden balance"
        );

        Ok(())
    }
}
