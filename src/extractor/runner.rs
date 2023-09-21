use anyhow::{format_err, Context, Result};
use async_trait::async_trait;
use prost::Message;
use std::{collections::HashMap, env, error::Error, sync::Arc};
use tokio::{
    sync::{
        mpsc::{self, error::SendError, Receiver, Sender},
        Mutex,
    },
    task::JoinHandle,
};
use tokio_stream::StreamExt;
use tracing::{debug, error, info, instrument, trace, warn, Instrument};

use super::Extractor;
use crate::{
    models::NormalisedMessage,
    pb::sf::substreams::v1::Package,
    substreams::{
        stream::{BlockResponse, SubstreamsStream},
        SubstreamsEndpoint,
    },
};

pub enum ControlMessage<M> {
    Stop,
    Subscribe(Sender<Arc<M>>),
}

/// A trait for a message sender that can be used to subscribe to messages
///
/// Extracted out of the [ExtractorHandle] to allow for easier testing
#[async_trait]
pub trait MessageSender<M: NormalisedMessage>: Send + Sync {
    async fn subscribe(&self) -> Result<Receiver<Arc<M>>, SendError<ControlMessage<M>>>;
}

pub struct ExtractorHandle<M> {
    handle: JoinHandle<()>,
    control_tx: Sender<ControlMessage<M>>,
}

impl<M> ExtractorHandle<M>
where
    M: NormalisedMessage,
{
    fn new(handle: JoinHandle<()>, control_tx: Sender<ControlMessage<M>>) -> Self {
        Self { handle, control_tx }
    }

    #[instrument(skip(self))]
    pub async fn stop(self) -> Result<(), Box<dyn Error>> {
        self.control_tx
            .send(ControlMessage::Stop)
            .await?;
        self.handle.await?;
        Ok(())
    }

    #[instrument(skip(self))]
    pub async fn wait(self) {
        self.handle.await.unwrap();
    }
}

#[async_trait]
impl<M> MessageSender<M> for ExtractorHandle<M>
where
    M: NormalisedMessage,
{
    #[instrument(skip(self))]
    async fn subscribe(&self) -> Result<Receiver<Arc<M>>, SendError<ControlMessage<M>>> {
        let (tx, rx) = mpsc::channel(1);
        self.control_tx
            .send(ControlMessage::Subscribe(tx))
            .await?;

        Ok(rx)
    }
}

// Define the SubscriptionsMap type alias
type SubscriptionsMap<M> = HashMap<u64, Sender<Arc<M>>>;

pub struct ExtractorRunner<G, M> {
    extractor: Arc<dyn Extractor<G, M>>,
    substreams: SubstreamsStream,
    subscriptions: Arc<Mutex<SubscriptionsMap<M>>>,
    control_rx: Receiver<ControlMessage<M>>,
}

impl<G, M> ExtractorRunner<G, M>
where
    M: NormalisedMessage,
    G: Sync + Send + 'static,
{
    pub fn run(mut self) -> JoinHandle<()> {
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    Some(ctrl) = self.control_rx.recv() =>  {
                        match ctrl {
                            ControlMessage::Stop => {
                                warn!("Stopping stream.");
                                break;
                            },
                            ControlMessage::Subscribe(sender) => {
                                self.subscribe(sender).await;
                            },
                        }
                    }
                    val = self.substreams.next() => {
                        match val {
                            None => {
                                warn!("Stream consumed.");
                                break;
                            }
                            Some(Ok(BlockResponse::New(data))) => {
                                debug!("New block data received.");
                                match self.extractor.handle_tick_scoped_data(data).await {
                                    Ok(Some(msg)) => {
                                        trace!(msg = %msg, "Propagating new block data message.");
                                        Self::propagate_msg(&self.subscriptions, msg).await
                                    }
                                    Ok(None) => {
                                        trace!("No message to propagate.");
                                    }
                                    Err(err) => {
                                        error!(error = %err, "Error while processing tick!");
                                        break;
                                    }
                                }
                            }
                            Some(Ok(BlockResponse::Undo(undo_signal))) => {
                                match self.extractor.handle_revert(undo_signal).await {
                                    Ok(Some(msg)) => {
                                        trace!(msg = %msg, "Propagating block undo message.");
                                        Self::propagate_msg(&self.subscriptions, msg).await
                                    }
                                    Ok(None) => {
                                        trace!("No message to propagate.");
                                    }
                                    Err(err) => {
                                        error!(error = %err, "Error while processing revert!");
                                        break;
                                    }
                                }
                            }
                            Some(Err(err)) => {
                                error!(error = %err, "Error while processing block!");
                                break;
                            }
                        };
                    }
                }
            }
        }
        .instrument(tracing::info_span!("extractor_runner::run"))
    )
    }

    #[instrument(skip_all)]
    async fn subscribe(&mut self, sender: Sender<Arc<M>>) {
        let subscriber_id = self.subscriptions.lock().await.len() as u64;
        info!(subscriber_id = %subscriber_id, "New subscription.");
        self.subscriptions
            .lock()
            .await
            .insert(subscriber_id, sender);
    }

    // TODO: add message tracing_id to the log
    #[instrument(skip_all)]
    async fn propagate_msg(subscribers: &Arc<Mutex<SubscriptionsMap<M>>>, message: M) {
        debug!(msg = %message, "Propagating message to subscribers.");
        let arced_message = Arc::new(message);

        let mut to_remove = Vec::new();

        // Lock the subscribers HashMap for exclusive access
        let mut subscribers = subscribers.lock().await;

        for (counter, sender) in subscribers.iter_mut() {
            match sender.send(arced_message.clone()).await {
                Ok(_) => {
                    // Message sent successfully
                    info!(subscriber_id = %counter, "Message sent successfully.");
                }
                Err(err) => {
                    // Receiver has been dropped, mark for removal
                    to_remove.push(*counter);
                    error!(error = %err, subscriber_id = %counter, "Subscriber {} has been dropped", counter);
                }
            }
        }

        // Remove inactive subscribers
        for counter in to_remove {
            subscribers.remove(&counter);
        }
    }
}

pub struct ExtractorRunnerBuilder<G, M> {
    spkg_file: String,
    endpoint_url: String,
    module_name: String,
    start_block: i64,
    end_block: i64,
    token: String,
    extractor: Arc<dyn Extractor<G, M>>,
}

impl<G, M> ExtractorRunnerBuilder<G, M>
where
    M: NormalisedMessage,
    G: Sync + Send + 'static,
{
    pub fn new(spkg: &str, extractor: Arc<dyn Extractor<G, M>>) -> Self {
        Self {
            spkg_file: spkg.to_owned(),
            endpoint_url: "https://mainnet.eth.streamingfast.io:443".to_owned(),
            module_name: "map_changes".to_owned(),
            start_block: 0,
            end_block: 0,
            token: env::var("SUBSTREAMS_API_TOKEN").unwrap_or("".to_string()),
            extractor,
        }
    }

    pub fn endpoint_url(mut self, val: &str) -> Self {
        self.endpoint_url = val.to_owned();
        self
    }

    pub fn module_name(mut self, val: &str) -> Self {
        self.module_name = val.to_owned();
        self
    }

    pub fn start_block(mut self, val: i64) -> Self {
        self.start_block = val;
        self
    }

    pub fn end_block(mut self, val: i64) -> Self {
        self.end_block = val;
        self
    }

    pub fn token(mut self, val: &str) -> Self {
        self.token = val.to_owned();
        self
    }

    pub async fn run(self) -> Result<ExtractorHandle<M>, anyhow::Error> {
        let content = std::fs::read(&self.spkg_file)
            .context(format_err!("read package from file '{}'", self.spkg_file))?;
        let spkg = Package::decode(content.as_ref()).context("decode command")?;
        let endpoint =
            Arc::new(SubstreamsEndpoint::new(&self.endpoint_url, Some(self.token)).await?);
        let cursor = self.extractor.get_cursor().await;
        let stream = SubstreamsStream::new(
            endpoint,
            Some(cursor),
            spkg.modules.clone(),
            self.module_name,
            self.start_block,
            self.end_block as u64,
        );

        let (ctrl_tx, ctrl_rx) = mpsc::channel(1);
        let runner = ExtractorRunner {
            extractor: self.extractor,
            substreams: stream,
            subscriptions: Arc::new(Mutex::new(HashMap::new())),
            control_rx: ctrl_rx,
        };

        Ok(ExtractorHandle::new(runner.run(), ctrl_tx))
    }
}
