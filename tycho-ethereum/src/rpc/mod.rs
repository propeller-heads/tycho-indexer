use std::{
    collections::{BTreeMap, HashMap},
    default::Default,
    iter::IntoIterator,
    time::Duration,
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
use async_trait::async_trait;
use backoff::backoff::Backoff;
use futures::future::join_all;
use serde::Deserialize;
use serde_json::{json, Value};
use tracing::{debug, info, instrument, trace, Span};
use tycho_common::{traits::GasPriceGetter, Bytes};

use crate::{RPCError, RequestError};

pub mod config;
pub mod errors;
mod retry;

use crate::{
    rpc::{
        config::{RPCBatchingConfig, RPCRetryConfig},
        retry::{has_custom_retry_code, RetryPolicy, RetryableError},
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

    #[instrument(level = "debug", skip(self))]
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

    /// Gets the gas price from the node using eth_gasPrice RPC method.
    ///
    /// Returns the gas price in wei as a u128.
    #[instrument(level = "debug", skip(self))]
    pub async fn get_gas_price(&self) -> Result<u128, RPCError> {
        let gas_price: U256 = self
            .retry_policy
            .retry_request(|| async {
                self.inner
                    .request_noparams("eth_gasPrice")
                    .await
            })
            .await
            .map_err(|e| RPCError::from_alloy("Failed to get gas price", e))?;

        Ok(gas_price.to::<u128>())
    }

    #[instrument(level = "debug", skip(self))]
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

    #[instrument(level = "debug", skip(self))]
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

    #[instrument(level = "debug", skip(self))]
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

    async fn non_batch_fetch_accounts_code_and_balance(
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

    #[instrument(level = "debug", skip(self))]
    pub(crate) async fn fetch_accounts_code_and_balance(
        &self,
        block_id: BlockNumberOrTag,
        addresses: &[Address],
    ) -> Result<HashMap<Address, (Bytes, U256)>, RPCError> {
        if let Some(max_batch_size) = self.batching.max_batch_size() {
            self.batch_fetch_accounts_code_and_balance(block_id, addresses, max_batch_size)
                .await
        } else {
            self.non_batch_fetch_accounts_code_and_balance(block_id, addresses)
                .await
        }
    }

    async fn batch_fetch_accounts_code_and_balance(
        &self,
        block_id: BlockNumberOrTag,
        addresses: &[Address],
        batch_size: usize,
    ) -> Result<HashMap<Address, (Bytes, U256)>, RPCError> {
        let chunk_size = batch_size / 2; // we make 2 requests in a batch call: code + balance
        if chunk_size == 0 {
            return Err(RPCError::SetupError(
                "BatchingConfig max_batch_size must be at least 2".to_string(),
            ));
        }

        debug!(
            chunk_size = chunk_size,
            total_chunks = addresses.len() / chunk_size + 1,
            block_id = block_id.to_string(),
            "Preparing batch request for account code and balance"
        );

        let mut result = HashMap::with_capacity(addresses.len());

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

            // perf: current retry logic retries the entire batch on any retriable failure. Instead:
            // 1. Only retry failed requests, not successful ones
            // 2. Fail fast if any request has a non-retryable error (currently we only check the
            //    first error encountered, potentially missing fatal errors in other requests)
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

    #[instrument(level = "debug", skip(self, slots))]
    pub(crate) async fn get_selected_storage(
        &self,
        block_id: BlockNumberOrTag,
        address: Address,
        slots: &[B256],
    ) -> Result<HashMap<B256, Option<B256>>, RPCError> {
        if let Some(storage_slot_max_batch_size) = self
            .batching
            .storage_slot_max_batch_size()
        {
            self.batch_get_selected_storage(block_id, address, slots, storage_slot_max_batch_size)
                .await
        } else {
            self.non_batch_get_selected_storage(block_id, address, slots)
                .await
        }
    }

    async fn non_batch_get_selected_storage(
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

    async fn batch_get_selected_storage(
        &self,
        block_id: BlockNumberOrTag,
        address: Address,
        slots: &[B256],
        batch_size: usize,
    ) -> Result<HashMap<B256, Option<B256>>, RPCError> {
        let mut result = HashMap::with_capacity(slots.len());

        let chunk_size = batch_size; // we make 1 request in a batch call

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

            // perf: current retry logic retries the entire batch on any retriable failure. Instead:
            // 1. Only retry failed requests, not successful ones
            // 2. Fail fast if any request has a non-retryable error (currently we only check the
            //    first error encountered, potentially missing fatal errors in other requests)
            let chunk_res = self
                .retry_policy
                .retry_request(batch_call)
                .await
                .map_err(|e| {
                    let printable_slots = slot_batch
                        .iter()
                        .map(|slot| format!("{:?}", slot))
                        .collect::<Vec<String>>()
                        .join(", ");
                    RPCError::from_alloy(
                        format!(
                            "Failed to get storage for address {address}, block {block_id}, slots {printable_slots}"
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
    #[instrument(level = "debug", skip(self, request))]
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

    #[instrument(level = "debug", skip(self, access_list_params, trace_call_params))]
    pub(crate) async fn trace_and_access_list(
        &self,
        target: &Address,
        block_hash: &B256,
        access_list_params: &Value,
        trace_call_params: &Value,
    ) -> Result<(AccessListResult, GethTrace), RPCError> {
        if let Some(max_batch_size) = self.batching.max_batch_size() {
            self.batch_trace_and_access_list(
                target,
                block_hash,
                access_list_params,
                trace_call_params,
                max_batch_size,
            )
            .await
        } else {
            Err(RPCError::SetupError(
                "`trace_and_access_list` requires the `EthereumRpcClient` to have batching enabled. \
                Either use a suitable RPC provider and enable batching in the `EthereumRpcClient`, \
                or implement a non-batched version of this method.".to_string(),
            ))
        }
    }

    async fn batch_trace_and_access_list(
        &self,
        target: &Address,
        block_hash: &B256,
        access_list_params: &Value,
        trace_call_params: &Value,
        batch_size: usize,
    ) -> Result<(AccessListResult, GethTrace), RPCError> {
        if batch_size < 2 {
            return Err(RPCError::SetupError(
                "trace_and_access_list requires max_batch_size >= 2".to_string(),
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

    #[instrument(level = "debug", skip(self, requests, calldata))]
    pub(crate) async fn slot_detector_trace(
        &self,
        requests: Vec<SlotDetectorValueRequest>,
        calldata: &Bytes,
        block_hash: &B256,
    ) -> Result<Vec<(GethTrace, U256)>, RPCError> {
        if let Some(max_batch_size) = self.batching.max_batch_size() {
            self.batch_slot_detector_trace(requests, calldata, block_hash, max_batch_size)
                .await
        } else {
            Err(RPCError::SetupError(
                "`slot_detector_trace` requires the `EthereumRpcClient` to have batching enabled. \
                Either use a suitable RPC provider and enable batching in the `EthereumRpcClient`, \
                or implement a non-batched version of this method."
                    .to_string(),
            ))
        }
    }

    async fn batch_slot_detector_trace(
        &self,
        requests: Vec<SlotDetectorValueRequest>,
        calldata: &Bytes,
        block_hash: &B256,
        batch_size: usize,
    ) -> Result<Vec<(GethTrace, U256)>, RPCError> {
        let chunk_size = batch_size / 2; // we make 2 requests in a batch call: trace + eth_call
        if chunk_size == 0 {
            return Err(RPCError::SetupError(
                "slot_detector_trace requires max_batch_size >= 2".to_string(),
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

            // perf: current retry logic retries the entire batch on any retriable failure. Instead:
            // 1. Only retry failed requests, not successful ones
            // 2. Fail fast if any request has a non-retryable error (currently we only check the
            //    first error encountered, potentially missing fatal errors in other requests)
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

    /// Performs slot detector tests using eth_call with state diffs.
    /// This method returns a vector of Results for each individual test request.
    #[instrument(level = "debug", skip(self, requests, calldata))]
    pub(crate) async fn slot_detector_tests(
        &self,
        requests: &[SlotDetectorSlotTestRequest],
        calldata: &Bytes,
        block_hash: &B256,
    ) -> Result<Vec<TransportResult<Value>>, RPCError> {
        if let Some(max_batch_size) = self.batching.max_batch_size() {
            self.batch_slot_detector_tests(requests, calldata, block_hash, max_batch_size)
                .await
        } else {
            Err(RPCError::SetupError(
                "`slot_detector_tests` requires the `EthereumRpcClient` to have batching enabled. \
                Either use a suitable RPC provider and enable batching in the `EthereumRpcClient`, \
                or implement a non-batched version of this method."
                    .to_string(),
            ))
        }
    }

    async fn batch_slot_detector_tests(
        &self,
        requests: &[SlotDetectorSlotTestRequest],
        calldata: &Bytes,
        block_hash: &B256,
        batch_size: usize,
    ) -> Result<Vec<TransportResult<Value>>, RPCError> {
        let chunk_size = batch_size; // we make 1 request per test
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
                            batch.add_call::<_, Value>("eth_call", &tracer_params)
                        },
                    )
                    .collect::<Result<Vec<_>, RpcError<TransportErrorKind>>>()?;

                batch.send().await?;

                // We do not check individual results for errors here, instead we handle that
                // in the consumer.
                Ok(join_all(batch_calls).await)
            };

            // Send the initial batch call
            let mut last_batch_result: Result<_, RpcError<TransportErrorKind>> = batch_call().await;

            let mut policy = self.retry_policy.clone();

            // Retries the batch if:
            // - The RPC call itself fails with a retryable error
            // - Any batched request fails with a retryable error
            // - All batched requests fail (regardless of error type)
            //
            // This uses a more aggressive retry strategy than other batch methods as slot detector
            // tests expect some requests to fail, so we retry in the described manner
            // to maximize successful results. This is also why we need a custom retry closure here.
            let should_retry = |batch_result: &Result<
                Vec<TransportResult<Value>>,
                RpcError<TransportErrorKind>,
            >| {
                let batch_result = match batch_result {
                    Ok(res) => res,
                    Err(err) => {
                        return err.is_retryable();
                    }
                };

                // Check if all requests failed or some requests failed with retryable errors
                // If so, we retry the entire batch
                let all_failed = batch_result
                    .iter()
                    .all(|res| res.is_err());
                let some_retryable_failed = batch_result.iter().any(|res| {
                    if let Err(RpcError::ErrorResp(e)) = res {
                        e.is_retry_err() || has_custom_retry_code(e)
                    } else {
                        false
                    }
                });

                all_failed || some_retryable_failed
            };

            loop {
                if !should_retry(&last_batch_result) {
                    break;
                }

                if let Some(backoff_duration) = policy.next_backoff() {
                    tokio::time::sleep(backoff_duration).await;
                    last_batch_result = batch_call().await;
                } else {
                    // We have exhausted all retries
                    break;
                }
            }

            let chunk_results = last_batch_result.map_err(|e| {
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

// Implement the GasPriceGetter trait for EthereumRpcClient
#[async_trait]
impl GasPriceGetter for EthereumRpcClient {
    type Error = RPCError;

    async fn get_latest_gas_price(&self) -> Result<u128, Self::Error> {
        self.get_gas_price().await
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use alloy::{rpc::types::TransactionInput, sol_types::SolCall};
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

    #[tokio::test]
    async fn test_get_gas_price_mocked() {
        let mut server = Server::new_async().await;

        let m = server
            .mock("POST", "/")
            .with_status(200)
            .with_body("{\"jsonrpc\":\"2.0\",\"id\":0,\"result\":\"0x1234\"}")
            .expect(1)
            .create_async()
            .await;

        let client =
            EthereumRpcClient::new(&server.url()).expect("Failed to create EthereumRpcClient");

        let gas_price = client
            .get_gas_price()
            .await
            .expect("Failed to get gas price");
        assert_eq!(gas_price, 0x1234);

        m.assert();
    }

    #[tokio::test]
    #[ignore = "require RPC connection"]
    async fn test_get_gas_price() -> Result<(), RPCError> {
        use tycho_common::traits::GasPriceGetter;

        let fixture = TestFixture::new();
        let client = fixture.create_rpc_client(false);

        let gas_price = client.get_gas_price().await?;
        assert!(gas_price > 0, "Gas price should be positive");

        let gas_price_via_trait = client.get_latest_gas_price().await?;
        assert!(gas_price_via_trait > 0, "Gas price from trait should be positive");

        Ok(())
    }
}
