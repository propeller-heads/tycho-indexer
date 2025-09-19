use std::{collections::HashMap, env, path::Path, sync::Arc};

use anyhow::{format_err, Context, Result};
use async_trait::async_trait;
use aws_config::meta::region::RegionProviderChain;
use aws_sdk_s3::Client;
use metrics::gauge;
use prost::Message;
use serde::Deserialize;
use tokio::{
    runtime::Handle,
    sync::{
        mpsc::{self, error::SendError, Receiver, Sender},
        Mutex,
    },
    task::JoinHandle,
};
use tokio_stream::StreamExt;
use tracing::{debug, error, info, instrument, trace, warn, Instrument};
use tycho_common::{
    models::{Address, Chain, ExtractorIdentity, FinancialType, ImplementationType, ProtocolType},
    Bytes,
};
use tycho_ethereum::{
    account_extractor::contract::EVMBatchAccountExtractor,
    entrypoint_tracer::tracer::EVMEntrypointService,
    token_pre_processor::EthereumTokenPreProcessor,
};
use tycho_storage::postgres::cache::CachedGateway;

use crate::{
    extractor::{
        chain_state::ChainState,
        dynamic_contract_indexer::{
            dci::DynamicContractIndexer, hook_dci::UniswapV4HookDCI,
            hooks_dci_setup::create_testing_hooks_dci,
        },
        post_processors::POST_PROCESSOR_REGISTRY,
        protocol_cache::ProtocolMemoryCache,
        protocol_extractor::{ExtractorPgGateway, ProtocolExtractor},
        ExtractionError, Extractor, ExtractorExtension, ExtractorMsg,
    },
    pb::sf::substreams::v1::Package,
    substreams::{
        stream::{BlockResponse, SubstreamsStream},
        SubstreamsEndpoint,
    },
};

/// Enum to handle both standard DCI and UniswapV4 Hook DCI
#[allow(clippy::large_enum_variant)]
pub(crate) enum DCIPlugin {
    Standard(DynamicContractIndexer<EVMBatchAccountExtractor, EVMEntrypointService, CachedGateway>),
    UniswapV4Hooks(
        Box<UniswapV4HookDCI<EVMBatchAccountExtractor, EVMEntrypointService, CachedGateway>>,
    ),
}

#[async_trait]
impl ExtractorExtension for DCIPlugin {
    async fn process_block_update(
        &mut self,
        block_changes: &mut crate::extractor::models::BlockChanges,
    ) -> Result<(), ExtractionError> {
        match self {
            DCIPlugin::Standard(dci) => {
                dci.process_block_update(block_changes)
                    .await
            }
            DCIPlugin::UniswapV4Hooks(hooks_dci) => {
                hooks_dci
                    .process_block_update(block_changes)
                    .await
            }
        }
    }

    async fn process_revert(
        &mut self,
        target_block: &tycho_common::models::BlockHash,
    ) -> Result<(), ExtractionError> {
        match self {
            DCIPlugin::Standard(dci) => dci.process_revert(target_block).await,
            DCIPlugin::UniswapV4Hooks(hooks_dci) => {
                hooks_dci
                    .process_revert(target_block)
                    .await
            }
        }
    }
}
pub enum ControlMessage {
    Stop,
    Subscribe(Sender<ExtractorMsg>),
}

/// A trait for a message sender that can be used to subscribe to messages
///
/// Extracted out of the [ExtractorHandle] to allow for easier testing
#[async_trait]
pub trait MessageSender: Send + Sync {
    async fn subscribe(&self) -> Result<Receiver<ExtractorMsg>, SendError<ControlMessage>>;
}

#[derive(Clone)]
pub struct ExtractorHandle {
    id: ExtractorIdentity,
    control_tx: Sender<ControlMessage>,
}

impl ExtractorHandle {
    fn new(id: ExtractorIdentity, control_tx: Sender<ControlMessage>) -> Self {
        Self { id, control_tx }
    }

    pub fn get_id(&self) -> ExtractorIdentity {
        self.id.clone()
    }

    #[instrument(skip(self))]
    pub async fn stop(&self) -> Result<(), ExtractionError> {
        // TODO: send a oneshot along here and wait for it
        self.control_tx
            .send(ControlMessage::Stop)
            .await
            .map_err(|err| ExtractionError::Unknown(err.to_string()))
    }
}

#[async_trait]
impl MessageSender for ExtractorHandle {
    #[instrument(skip(self))]
    async fn subscribe(&self) -> Result<Receiver<ExtractorMsg>, SendError<ControlMessage>> {
        let (tx, rx) = mpsc::channel(16);
        // Define a timeout duration
        let timeout_duration = std::time::Duration::from_secs(5); // 5 seconds timeout

        // Wrap the send operation with a timeout
        let send_result = tokio::time::timeout(
            timeout_duration,
            self.control_tx
                .send(ControlMessage::Subscribe(tx)),
        )
        .await;

        match send_result {
            Ok(Ok(())) => Ok(rx),
            Ok(Err(e)) => Err(e),
            // TODO: use a better error type that let's us return this as an error.
            Err(_) => panic!("Subscription timed out!"),
        }
    }
}

// Define the SubscriptionsMap type alias
type SubscriptionsMap = HashMap<u64, Sender<ExtractorMsg>>;

pub struct ExtractorRunner {
    extractor: Arc<dyn Extractor>,
    substreams: SubstreamsStream,
    subscriptions: Arc<Mutex<SubscriptionsMap>>,
    next_subscriber_id: u64,
    control_rx: Receiver<ControlMessage>,
    /// Handle of the tokio runtime on which the extraction tasks will be run.
    /// If 'None' the default runtime will be used.
    runtime_handle: Option<Handle>,
}

impl ExtractorRunner {
    pub fn new(
        extractor: Arc<dyn Extractor>,
        substreams: SubstreamsStream,
        subscriptions: Arc<Mutex<SubscriptionsMap>>,
        control_rx: Receiver<ControlMessage>,
        runtime_handle: Option<Handle>,
    ) -> Self {
        ExtractorRunner {
            extractor,
            substreams,
            subscriptions,
            next_subscriber_id: 0,
            control_rx,
            runtime_handle,
        }
    }

    pub fn run(mut self) -> JoinHandle<Result<(), ExtractionError>> {
        info!("Extractor {} started!", self.extractor.get_id());

        let runtime = self
            .runtime_handle
            .clone()
            .unwrap_or_else(|| tokio::runtime::Handle::current());

        runtime.spawn(async move {
            let id = self.extractor.get_id();
            loop {
                // this is the main info span of an extractor
                let loop_span = tracing::info_span!(
                    parent: None,  // don't attach this to the parent (builder) span to keep spans short
                    "extractor",
                    extractor_id = %id,
                    sf_trace_id = tracing::field::Empty,
                    block_number = tracing::field::Empty,
                    otel.status_code = tracing::field::Empty,
                );

                let should_continue = async {
                    tokio::select! {
                        Some(ctrl) = self.control_rx.recv() => {
                            match ctrl {
                                ControlMessage::Stop => {
                                    warn!("Stop signal received; exiting!");
                                    return Ok(false);
                                },
                                ControlMessage::Subscribe(sender) => {
                                    self.subscribe(sender).await;
                                },
                            }
                        }
                        val = self.substreams.next() => {
                            match val {
                                None => {
                                    error!("stream ended");
                                    tracing::Span::current().record("otel.status_code", "error");
                                    return Err(ExtractionError::SubstreamsError(format!("{id}: stream ended")));
                                }
                                Some(Ok(BlockResponse::New(data))) => {
                                    let block_number = data.clock.as_ref().map(|v| v.number).unwrap_or(0);
                                    tracing::Span::current().record("block_number", block_number);
                                    gauge!(
                                        "extractor_current_block_number",
                                        "chain" => id.chain.to_string(),
                                        "extractor" => id.name.to_string()
                                    ).set(block_number as f64);

                                    // Start measuring block processing time
                                    let start_time = std::time::Instant::now();

                                    // TODO: change interface to take a reference to avoid this clone
                                    match self.extractor.handle_tick_scoped_data(data.clone()).await {
                                        Ok(Some(msg)) => {
                                            trace!("Propagating new block data message.");
                                            Self::propagate_msg(&self.subscriptions, msg).await
                                        }
                                        Ok(None) => {
                                            trace!("No message to propagate.");
                                        }
                                        Err(err) => {
                                            error!(error = %err, "Error while processing tick!");
                                            tracing::Span::current().record("otel.status_code", "error");
                                            return Err(err);
                                        }
                                    }

                                    let duration = start_time.elapsed();
                                    gauge!(
                                        "block_processing_time_ms",
                                        "chain" => id.chain.to_string(),
                                        "extractor" => id.name.to_string()
                                    ).set(duration.as_millis() as f64);
                                }
                                Some(Ok(BlockResponse::Undo(undo_signal))) => {
                                    info!(block=?&undo_signal.last_valid_block,  "Revert requested!");
                                    match self.extractor.handle_revert(undo_signal.clone()).await {
                                        Ok(Some(msg)) => {
                                            trace!("Propagating block undo message.");
                                            Self::propagate_msg(&self.subscriptions, msg).await
                                        }
                                        Ok(None) => {
                                            trace!("No message to propagate.");
                                        }
                                        Err(err) => {
                                            error!(error = %err, "Error while processing revert!");
                                            tracing::Span::current().record("otel.status_code", "error");
                                            return Err(err);
                                        }
                                    }
                                }
                                Some(Ok(BlockResponse::Ended)) => {
                                    tracing::Span::current().record("otel.status_code", "ok");
                                    return Ok(false);
                                }
                                Some(Err(err)) => {
                                    error!(error = %err, "Stream terminated with error.");
                                    tracing::Span::current().record("otel.status_code", "error");
                                    return Err(ExtractionError::SubstreamsError(err.to_string()));
                                }
                            };
                        }
                    }

                    tracing::Span::current().record("otel.status_code", "ok");
                    Ok(true) // Continue the loop
                }
                .instrument(loop_span)
                .await?;

                if !should_continue {
                    break Ok(());
                }
            }
        })
    }

    #[instrument(skip_all)]
    async fn subscribe(&mut self, sender: Sender<ExtractorMsg>) {
        let subscriber_id = self.next_subscriber_id;
        self.next_subscriber_id += 1;
        tracing::Span::current().record("subscriber_id", subscriber_id);
        info!(?subscriber_id, "New subscription");
        self.subscriptions
            .lock()
            .await
            .insert(subscriber_id, sender);
    }

    // TODO: add message tracing_id to the log
    #[instrument(skip_all)]
    async fn propagate_msg(subscribers: &Arc<Mutex<SubscriptionsMap>>, message: ExtractorMsg) {
        trace!(msg = %message, "Propagating message to subscribers.");
        // TODO: rename variable here instead
        let arced_message = message;

        let mut to_remove = Vec::new();

        // Lock the subscribers HashMap for exclusive access
        let mut subscribers = subscribers.lock().await;

        for (counter, sender) in subscribers.iter_mut() {
            match sender.send(arced_message.clone()).await {
                Ok(_) => {
                    // Message sent successfully
                    trace!(subscriber_id = %counter, "Message sent successfully.");
                }
                Err(err) => {
                    // Receiver has been dropped, mark for removal
                    to_remove.push(*counter);
                    error!(error = %err, counter, "Error while sending message to subscriber");
                }
            }
        }

        // Remove inactive subscribers
        for counter in to_remove {
            subscribers.remove(&counter);
            debug!("Subscriber {} has been dropped", counter);
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct ProtocolTypeConfig {
    name: String,
    financial_type: FinancialType,
}

impl ProtocolTypeConfig {
    pub fn new(name: String, financial_type: FinancialType) -> Self {
        Self { name, financial_type }
    }
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct ExtractorConfig {
    name: String,
    chain: Chain,
    implementation_type: ImplementationType,
    sync_batch_size: usize,
    start_block: i64,
    stop_block: Option<i64>,
    protocol_types: Vec<ProtocolTypeConfig>,
    spkg: String,
    module_name: String,
    #[serde(default)]
    pub initialized_accounts: Vec<Bytes>,
    #[serde(default)]
    pub initialized_accounts_block: i64,
    #[serde(default)]
    pub post_processor: Option<String>,
    #[serde(default)]
    pub dci_plugin: Option<DCIType>,
}

impl ExtractorConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name: String,
        chain: Chain,
        implementation_type: ImplementationType,
        sync_batch_size: usize,
        start_block: i64,
        stop_block: Option<i64>,
        protocol_types: Vec<ProtocolTypeConfig>,
        spkg: String,
        module_name: String,
        initialized_accounts: Vec<Bytes>,
        initialized_accounts_block: i64,
        post_processor: Option<String>,
        dci_plugin: Option<DCIType>,
    ) -> Self {
        Self {
            name,
            chain,
            implementation_type,
            sync_batch_size,
            start_block,
            stop_block,
            protocol_types,
            spkg,
            module_name,
            initialized_accounts,
            initialized_accounts_block,
            post_processor,
            dci_plugin,
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub enum DCIType {
    /// RPC DCI plugin - uses the RPC endpoint to fetch the account data
    RPC,
}

pub struct ExtractorBuilder {
    config: ExtractorConfig,
    endpoint_url: String,
    s3_bucket: Option<String>,
    token: String,
    extractor: Option<Arc<dyn Extractor>>,
    final_block_only: bool,
    /// Handle of the tokio runtime on which the extraction tasks will be run.
    /// If 'None' the default runtime will be used.
    runtime_handle: Option<Handle>,
    /// Global RPC URL to use for DCI plugins
    rpc_url: Option<String>,
}

impl ExtractorBuilder {
    pub fn new(config: &ExtractorConfig, endpoint_url: &str, s3_bucket: Option<&str>) -> Self {
        Self {
            config: config.clone(),
            endpoint_url: endpoint_url.to_owned(),
            s3_bucket: s3_bucket.map(ToString::to_string),
            token: env::var("SUBSTREAMS_API_TOKEN").unwrap_or("".to_string()),
            extractor: None,
            final_block_only: false,
            runtime_handle: None,
            rpc_url: None,
        }
    }

    /// Set the substreams endpoint url
    pub fn endpoint_url(mut self, val: &str) -> Self {
        val.clone_into(&mut self.endpoint_url);
        self
    }

    pub fn module_name(mut self, val: &str) -> Self {
        val.clone_into(&mut self.config.module_name);
        self
    }

    pub fn start_block(mut self, val: i64) -> Self {
        self.config.start_block = val;
        self
    }

    pub fn token(mut self, val: &str) -> Self {
        val.clone_into(&mut self.token);
        self
    }

    pub fn only_final_blocks(mut self) -> Self {
        self.final_block_only = true;
        self
    }

    pub fn set_runtime(mut self, runtime: Handle) -> Self {
        self.runtime_handle = Some(runtime);
        self
    }

    /// Set the global RPC URL to use for DCI plugins
    pub fn rpc_url(mut self, rpc_url: &str) -> Self {
        self.rpc_url = Some(rpc_url.to_string());
        self
    }

    #[cfg(test)]
    pub fn set_extractor(mut self, val: Arc<dyn Extractor>) -> Self {
        self.extractor = Some(val);
        self
    }

    async fn ensure_spkg(&self) -> Result<(), ExtractionError> {
        // Pull spkg from s3 and copy it at `spkg_path`
        if !Path::new(&self.config.spkg).exists() {
            download_file_from_s3(
                self.s3_bucket.as_ref().ok_or_else(|| {
                    ExtractionError::Setup(format!(
                        "Missing spkg and s3 bucket config for {}",
                        &self.config.spkg
                    ))
                })?,
                &self.config.spkg,
                Path::new(&self.config.spkg),
            )
            .await
            .map_err(|e| {
                ExtractionError::Setup(format!(
                    "Failed to download {} from s3. {}",
                    &self.config.spkg, e
                ))
            })?;
        }
        Ok(())
    }

    pub async fn build(
        mut self,
        chain_state: ChainState,
        cached_gw: &CachedGateway,
        token_pre_processor: &EthereumTokenPreProcessor,
        protocol_cache: &ProtocolMemoryCache,
    ) -> Result<Self, ExtractionError> {
        let protocol_types = self
            .config
            .protocol_types
            .iter()
            .map(|pt| {
                (
                    pt.name.clone(),
                    ProtocolType::new(
                        pt.name.clone(),
                        pt.financial_type.clone(),
                        None,
                        self.config.implementation_type.clone(),
                    ),
                )
            })
            .collect();

        let gw = ExtractorPgGateway::new(
            &self.config.name,
            self.config.chain,
            self.config.sync_batch_size,
            cached_gw.clone(),
        );

        let post_processor = self
            .config
            .post_processor
            .as_ref()
            .map(|name| {
                POST_PROCESSOR_REGISTRY
                    .get(name)
                    .cloned()
                    .ok_or_else(|| {
                        ExtractionError::Setup(format!(
                            "Post processor '{name}' not found in registry"
                        ))
                    })
            })
            .transpose()?;

        let dci_plugin = if let Some(ref dci_type) = self.config.dci_plugin {
            Some(match dci_type {
                DCIType::RPC => {
                    let rpc_url = self.rpc_url.as_ref().ok_or_else(|| {
                        ExtractionError::Setup(
                            "RPC URL is required for RPC DCI plugin but not provided".to_string(),
                        )
                    })?;

                    let account_extractor =
                        EVMBatchAccountExtractor::new(rpc_url, self.config.chain)
                            .await
                            .map_err(|err| {
                                ExtractionError::Setup(format!(
                                    "Failed to create account extractor for {rpc_url}: {err}"
                                ))
                            })?;
                    // Use TRACE_RPC_URL if available, otherwise fall back to RPC_URL
                    let trace_rpc_url =
                        std::env::var("TRACE_RPC_URL").unwrap_or_else(|_| rpc_url.to_string());

                    let max_retries = std::env::var("TRACE_MAX_RETRIES")
                        .ok()
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(3);

                    let retry_delay_ms = std::env::var("TRACE_RETRY_DELAY_MS")
                        .ok()
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(200);

                    let tracer = EVMEntrypointService::try_from_url_with_config(
                        &trace_rpc_url,
                        max_retries,
                        retry_delay_ms,
                    )
                    .map_err(|err| {
                        ExtractionError::Setup(format!(
                            "Failed to create entrypoint tracer for {trace_rpc_url}: {err}"
                        ))
                    })?;
                    let mut base_dci = DynamicContractIndexer::new(
                        self.config.chain,
                        self.config.name.clone(),
                        cached_gw.clone(),
                        account_extractor,
                        tracer,
                    );
                    base_dci.initialize().await?;

                    // Check if this is a UniswapV4 extractor
                    let is_uniswap_v4 = self
                        .config
                        .protocol_types
                        .iter()
                        .any(|pt| {
                            pt.name
                                .to_lowercase()
                                .contains("uniswap_v4")
                        });

                    if is_uniswap_v4 {
                        // Wrap the base DCI with UniswapV4HookDCI for UniswapV4 extractors
                        // Default UniswapV4 addresses - these should ideally be configurable
                        let router_address =
                            Address::from("0x2e234DAe75C793f67A35089C9d99245E1C58470b"); // V4Router
                        let pool_manager =
                            Address::from("0x000000000004444c5dc75cB358380D2e3dE08A90"); // PoolManager

                        let mut hooks_dci = create_testing_hooks_dci(
                            base_dci,
                            rpc_url.clone(),
                            router_address,
                            pool_manager,
                            cached_gw.clone(),
                            self.config.chain,
                            3, // pause_after_retries
                            5, // max_retries
                        );
                        hooks_dci.initialize().await?;
                        DCIPlugin::UniswapV4Hooks(Box::new(hooks_dci))
                    } else {
                        DCIPlugin::Standard(base_dci)
                    }
                }
            })
        } else {
            None
        };

        self.extractor = Some(Arc::new(
            ProtocolExtractor::<ExtractorPgGateway, EthereumTokenPreProcessor, DCIPlugin>::new(
                gw,
                &self.config.name,
                self.config.chain,
                chain_state,
                self.config.name.clone(),
                protocol_cache.clone(),
                protocol_types,
                token_pre_processor.clone(),
                post_processor,
                dci_plugin,
            )
            .await?,
        ));

        Ok(self)
    }

    /// Converts this builder into a ready-to-run ExtractorRunner and its associated handle.
    ///
    /// This method completes the extractor setup process by:
    /// - Ensuring the Substreams package (.spkg) file is available, downloading from S3 if
    ///   necessary
    /// - Creating a Substreams endpoint connection with authentication
    /// - Setting up the data stream with the configured module, block range, and cursor
    /// - Initializing control channels for managing the extractor lifecycle
    ///
    /// # Returns
    ///
    /// A tuple containing:
    /// - `ExtractorRunner`: The main component that processes blockchain data from the stream
    /// - `ExtractorHandle`: A control interface for stopping the extractor and subscribing to its
    ///   output
    ///
    /// # Errors
    ///
    /// Returns `ExtractionError` if:
    /// - The extractor was not properly configured
    /// - The Substreams package file cannot be accessed or downloaded
    /// - The Substreams endpoint connection cannot be established
    /// - Package decoding fails due to corrupted or invalid data
    #[instrument(name = "extractor_runner_build", skip(self), fields(extractor_id))]
    pub async fn into_runner(self) -> Result<(ExtractorRunner, ExtractorHandle), ExtractionError> {
        let extractor = self
            .extractor
            .clone()
            .expect("Extractor not set");
        let extractor_id = extractor.get_id();

        tracing::Span::current().record("id", format!("{extractor_id}"));

        self.ensure_spkg().await?;

        let content = std::fs::read(&self.config.spkg)
            .context(format_err!("read package from file '{}'", self.config.spkg))
            .map_err(|err| ExtractionError::SubstreamsError(err.to_string()))?;
        let spkg = Package::decode(content.as_ref())
            .context("decode command")
            .map_err(|err| ExtractionError::SubstreamsError(err.to_string()))?;
        let endpoint = Arc::new(
            SubstreamsEndpoint::new(&self.endpoint_url, Some(self.token))
                .await
                .map_err(|err| ExtractionError::SubstreamsError(err.to_string()))?,
        );

        let cursor = extractor.get_cursor().await;
        let stream = SubstreamsStream::new(
            endpoint,
            Some(cursor),
            spkg.modules.clone(),
            self.config.module_name,
            self.config.start_block,
            self.config.stop_block.unwrap_or(0) as u64,
            self.final_block_only,
            extractor_id.to_string(),
        );

        let (ctrl_tx, ctrl_rx) = mpsc::channel(128);
        let runner = ExtractorRunner::new(
            extractor,
            stream,
            Arc::new(Mutex::new(HashMap::new())),
            ctrl_rx,
            self.runtime_handle,
        );

        Ok((runner, ExtractorHandle::new(extractor_id, ctrl_tx)))
    }
}

async fn download_file_from_s3(
    bucket: &str,
    key: &str,
    download_path: &Path,
) -> anyhow::Result<()> {
    info!("Downloading file from s3: {}/{} to {:?}", bucket, key, download_path);

    let region_provider = RegionProviderChain::default_provider().or_else("eu-central-1");

    let config = aws_config::from_env()
        .region(region_provider)
        .load()
        .await;

    let client = Client::new(&config);

    let resp = client
        .get_object()
        .bucket(bucket)
        .key(key)
        .send()
        .await?;

    let data = resp.body.collect().await.unwrap();

    // Ensure the directory exists
    if let Some(parent) = download_path.parent() {
        std::fs::create_dir_all(parent)
            .context(format!("Failed to create directories for {parent:?}"))?;
    }

    std::fs::write(download_path, data.into_bytes()).unwrap();

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::extractor::MockExtractor;

    #[tokio::test]
    async fn test_extractor_runner_builder() {
        // Mock the Extractor
        let mut mock_extractor = MockExtractor::new();
        mock_extractor
            .expect_get_cursor()
            .returning(|| "cursor@0".to_string());
        mock_extractor
            .expect_get_id()
            .returning(ExtractorIdentity::default);

        // Build the ExtractorRunnerBuilder
        let extractor = Arc::new(mock_extractor);
        let builder = ExtractorBuilder::new(
            &ExtractorConfig {
                name: "test_module".to_owned(),
                implementation_type: ImplementationType::Vm,
                protocol_types: vec![ProtocolTypeConfig {
                    name: "test_module_pool".to_owned(),
                    financial_type: FinancialType::Swap,
                }],
                spkg: "./test/spkg/substreams-ethereum-quickstart-v1.0.0.spkg".to_owned(),
                module_name: "test_module".to_owned(),
                ..Default::default()
            },
            "https://mainnet.eth.streamingfast.io",
            None,
        )
        .token("test_token")
        .set_extractor(extractor);

        // Run the builder
        let (runner, _handle) = builder.into_runner().await.unwrap();

        // Wait for the handle to complete
        match runner.run().await {
            Ok(_) => {
                info!("ExtractorRunnerBuilder completed successfully");
            }
            Err(err) => {
                error!(error = %err, "ExtractorRunnerBuilder failed");
                panic!("ExtractorRunnerBuilder failed");
            }
        }
    }
}
