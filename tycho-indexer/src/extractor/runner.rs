use std::{collections::HashMap, env, ffi::OsStr, fs, path::Path, sync::Arc};

use anyhow::{format_err, Context, Result};
use async_trait::async_trait;
use aws_config::meta::region::RegionProviderChain;
use aws_sdk_s3::Client as AWSClient;
use metrics::gauge;
use prost::Message;
use regex::Regex;
use reqwest::Client;
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

use tycho_core::{
    models::{Chain, ExtractorIdentity, FinancialType, ImplementationType, ProtocolType},
    Bytes,
};
use tycho_ethereum::token_pre_processor::EthereumTokenPreProcessor;
use tycho_storage::postgres::cache::CachedGateway;

use crate::{
    extractor::{
        chain_state::ChainState,
        post_processors::POST_PROCESSOR_REGISTRY,
        protocol_cache::ProtocolMemoryCache,
        protocol_extractor::{ExtractorPgGateway, ProtocolExtractor},
        ExtractionError, Extractor, ExtractorMsg,
    },
    pb::sf::substreams::v1::Package,
    substreams::{
        stream::{BlockResponse, SubstreamsStream},
        SubstreamsEndpoint,
    },
};
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
                async {
                    tokio::select! {
                    Some(ctrl) = self.control_rx.recv() =>  {
                        match ctrl {
                            ControlMessage::Stop => {
                                warn!("Stop signal received; exiting!");
                                return Ok(())
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
                                return Err(ExtractionError::SubstreamsError(format!("{}: stream ended", id)));
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
                            Some(Err(err)) => {
                                error!(error = %err, "Stream terminated with error.");
                                tracing::Span::current().record("otel.status_code", "error");
                                return Err(ExtractionError::SubstreamsError(err.to_string()));
                            }
                        };
                    }
                };
                    tracing::Span::current().record("otel.status_code", "ok");
                    Ok(())
                }.instrument(loop_span).await?
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

#[derive(Debug, Deserialize, Clone)]
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
        }
    }
}

pub struct ExtractorBuilder {
    config: ExtractorConfig,
    endpoint_url: String,
    s3_bucket: Option<String>,
    spkg_registry_url: Option<String>,
    token: String,
    extractor: Option<Arc<dyn Extractor>>,
    final_block_only: bool,
    /// Handle of the tokio runtime on which the extraction tasks will be run.
    /// If 'None' the default runtime will be used.
    runtime_handle: Option<Handle>,
}

pub type HandleResult = (JoinHandle<Result<(), ExtractionError>>, ExtractorHandle);

impl ExtractorBuilder {
    pub fn new(
        config: &ExtractorConfig,
        endpoint_url: &str,
        s3_bucket: Option<&str>,
        spkg_registry_url: Option<&str>,
    ) -> Self {
        Self {
            config: config.clone(),
            endpoint_url: endpoint_url.to_owned(),
            s3_bucket: s3_bucket.map(ToString::to_string),
            spkg_registry_url: spkg_registry_url.map(ToString::to_string),
            token: env::var("SUBSTREAMS_API_TOKEN").unwrap_or("".to_string()),
            extractor: None,
            final_block_only: false,
            runtime_handle: None,
        }
    }

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

    #[cfg(test)]
    pub fn set_extractor(mut self, val: Arc<dyn Extractor>) -> Self {
        self.extractor = Some(val);
        self
    }

    async fn ensure_spkg(&self) -> Result<(), ExtractionError> {
        let spkg_path = Path::new(&self.config.spkg);

        if spkg_path.exists() {
            info!("Found SPKG: {:?}", spkg_path);
            return Ok(());
        }

        let registry_url = self
            .spkg_registry_url
            .as_ref()
            .ok_or_else(|| {
                ExtractionError::Setup(format!(
                    "Missing SPKG file and no registry URL configured for {}",
                    self.config.spkg
                ))
            })?;

        let file_name = spkg_path
            .file_name()
            .and_then(OsStr::to_str)
            .ok_or_else(|| {
                ExtractionError::Setup(format!("Invalid file name in path: {:?}", spkg_path))
            })?;

        let version_regex = Regex::new(r"(.+)-v([\d.]+)\.spkg$").unwrap();
        let (package_name, version) = version_regex
            .captures(file_name)
            .and_then(|caps| Some((caps.get(1)?.as_str(), caps.get(2)?.as_str())))
            .ok_or_else(|| {
                ExtractionError::Setup(format!(
                    "Couldn't find specified spkg version in the file name: {:?}",
                    spkg_path
                ))
            })?;

        let download_url =
            format!("{}/{}/v{}", registry_url.trim_end_matches('/'), package_name, version);

        if let Err(e) = download_spkg_from_registry(&download_url, spkg_path).await {
            warn!(
                "Failed to download from registry: {}. Error: {}. Trying S3 fallback...",
                download_url, e
            );

            let s3_bucket = self.s3_bucket.as_ref().ok_or_else(|| {
                ExtractionError::Setup(format!(
                    "Missing SPKG file and no S3 bucket configured for {}",
                    &self.config.spkg
                ))
            })?;

            download_file_from_s3(s3_bucket, &self.config.spkg, spkg_path)
                .await
                .map_err(|_| {
                    ExtractionError::Setup(format!(
                        "Failed to download {} from the registry and s3. {}",
                        &self.config.spkg, e
                    ))
                })?
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
                            "Post processor '{}' not found in registry",
                            name
                        ))
                    })
            })
            .transpose()?;

        self.extractor = Some(Arc::new(
            ProtocolExtractor::new(
                gw,
                &self.config.name,
                self.config.chain,
                chain_state,
                self.config.name.clone(),
                protocol_cache.clone(),
                protocol_types,
                token_pre_processor.clone(),
                post_processor,
            )
            .await?,
        ));

        Ok(self)
    }

    #[instrument(name = "extractor_start", skip(self), fields(id))]
    pub async fn run(self) -> Result<HandleResult, ExtractionError> {
        let extractor = self
            .extractor
            .clone()
            .expect("Extractor not set");

        tracing::Span::current().record("id", format!("{}", extractor.get_id()));

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
            extractor.get_id().to_string(),
        );

        let id = extractor.get_id();
        let (ctrl_tx, ctrl_rx) = mpsc::channel(128);
        let runner = ExtractorRunner::new(
            extractor,
            stream,
            Arc::new(Mutex::new(HashMap::new())),
            ctrl_rx,
            self.runtime_handle,
        );

        let handle = runner.run();
        Ok((handle, ExtractorHandle::new(id, ctrl_tx)))
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

    let client = AWSClient::new(&config);

    let resp = client
        .get_object()
        .bucket(bucket)
        .key(key)
        .send()
        .await?;

    let data = resp.body.collect().await.unwrap();

    // Ensure the directory exists
    if let Some(parent) = download_path.parent() {
        fs::create_dir_all(parent)
            .context(format!("Failed to create directories for {:?}", parent))?;
    }

    fs::write(download_path, data.into_bytes()).unwrap();

    Ok(())
}

pub async fn download_spkg_from_registry(package_url: &str, download_path: &Path) -> Result<()> {
    info!("Downloading file from package registry: {:?} to {:?}", package_url, download_path);

    let client = Client::new();

    let response = client.get(package_url).send().await?;

    if !response.status().is_success() {
        anyhow::bail!("Failed to download file: HTTP {}", response.status());
    }

    let data = response.bytes().await?;

    // Ensure the directory exists
    if let Some(parent) = download_path.parent() {
        fs::create_dir_all(parent)
            .context(format!("Failed to create directories for {:?}", parent))?;
    }
    fs::write(download_path, data).unwrap();

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;

    use serde::Serialize;

    use crate::extractor::MockExtractor;
    use tycho_core::models::NormalisedMessage;

    #[derive(Clone, Debug, PartialEq, Eq, Hash, Deserialize, Serialize)]
    struct DummyMessage {
        extractor_id: ExtractorIdentity,
    }

    impl std::fmt::Display for DummyMessage {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.extractor_id)
        }
    }

    #[typetag::serde]
    impl NormalisedMessage for DummyMessage {
        fn source(&self) -> ExtractorIdentity {
            self.extractor_id.clone()
        }

        fn drop_state(&self) -> Arc<dyn NormalisedMessage> {
            Arc::new(self.clone())
        }

        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

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
            &ExtractorConfig::new(
                "test_module".to_owned(),
                Chain::Ethereum,
                ImplementationType::Vm,
                0,
                0,
                None,
                vec![ProtocolTypeConfig {
                    name: "test_module_pool".to_owned(),
                    financial_type: FinancialType::Swap,
                }],
                "./test/spkg/substreams-ethereum-quickstart-v1.0.0.spkg".to_owned(),
                "test_module".to_owned(),
                vec![],
                0,
                None,
            ),
            "https://mainnet.eth.streamingfast.io",
            None,
            None,
        )
        .token("test_token")
        .set_extractor(extractor);

        // Run the builder
        let (task, _handle) = builder.run().await.unwrap();

        // Wait for the handle to complete
        match task.await {
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
