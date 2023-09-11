use anyhow::{format_err, Context};
use prost::Message;
use std::{collections::HashMap, env, error::Error, sync::Arc};
use tokio::{
    sync::mpsc::{self, error::SendError, Receiver, Sender},
    task::JoinHandle,
};
use tokio_stream::StreamExt;
use tracing::{error, info};

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

pub struct ExtractorHandle<M> {
    handle: JoinHandle<()>,
    control_tx: Sender<ControlMessage<M>>,
}

impl<M> ExtractorHandle<M>
where
    M: NormalisedMessage + Sync + Send + 'static,
{
    pub async fn subscribe(&self) -> Result<Receiver<Arc<M>>, SendError<ControlMessage<M>>> {
        let (tx, rx) = mpsc::channel(1);
        self.control_tx
            .send(ControlMessage::Subscribe(tx))
            .await?;
        Ok(rx)
    }

    pub async fn stop(self) -> Result<(), Box<dyn Error>> {
        self.control_tx
            .send(ControlMessage::Stop)
            .await?;
        self.handle.await?;
        Ok(())
    }
}

pub struct ExtractorRunner<G, M> {
    extractor: Arc<dyn Extractor<G, M>>,
    substreams: SubstreamsStream,
    subscriptions: HashMap<u64, Sender<Arc<M>>>,
    control_rx: Receiver<ControlMessage<M>>,
}

impl<G, M> ExtractorRunner<G, M>
where
    M: NormalisedMessage + Sync + Send + 'static,
    G: Sync + Send + 'static,
{
    pub fn run(mut self) -> JoinHandle<()> {
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    Some(ctrl) = self.control_rx.recv() =>  {
                        match ctrl {
                            ControlMessage::Stop => {
                                break;
                            },
                            ControlMessage::Subscribe(sender) => {
                                let counter = self.subscriptions.len() as u64;
                                self.subscriptions.insert(counter, sender);
                            },
                        }
                    }
                    val = self.substreams.next() => {
                        match val {
                            None => {
                                info!("Stream consumed");
                                break;
                            }
                            Some(Ok(BlockResponse::New(data))) => {
                                if let Ok(msg) = self.extractor.handle_tick_scoped_data(data).await {
                                    if let Some(msg) = msg {
                                        Self::propagate_msg(&self.subscriptions, msg).await
                                    }
                                } else {
                                    error!("Error while processing tick!");
                                    break;
                                }
                            }
                            Some(Ok(BlockResponse::Undo(undo_signal))) => {
                                if let Ok(msg) = self.extractor.handle_revert(undo_signal).await {
                                    if let Some(msg) = msg {
                                        Self::propagate_msg(&self.subscriptions, msg).await
                                    }
                                } else {
                                    error!("Error while processing revert!");
                                    break;
                                }
                            }
                            Some(Err(err)) => {
                                error!("Stream terminated with error {:?}", err);
                                break;
                            }
                        };
                    }
                }
            }
        })
    }

    async fn propagate_msg(subscribers: &HashMap<u64, Sender<Arc<M>>>, message: M) {
        let arced_message = Arc::new(message);
        for s in subscribers.values() {
            s.send(arced_message.clone())
                .await
                .unwrap();
        }
    }
}

struct ExtractorRunnerBuilder<G, M> {
    spkg_file: String,
    endpoint_url: String,
    module_name: String,
    start_block: i64,
    token: String,
    extractor: Arc<dyn Extractor<G, M>>,
}

impl<G, M> ExtractorRunnerBuilder<G, M>
where
    M: NormalisedMessage + Sync + Send + 'static,
    G: Sync + Send + 'static,
{
    pub fn new(spkg: &str, extractor: Arc<dyn Extractor<G, M>>) -> Self {
        Self {
            spkg_file: spkg.to_owned(),
            endpoint_url: "https://mainnet.eth.streamingfast.io:443".to_owned(),
            module_name: "map_changes".to_owned(),
            start_block: 0,
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
            0,
        );

        let (ctrl_tx, ctrl_rx) = mpsc::channel(1);
        let runner = ExtractorRunner {
            extractor: self.extractor,
            substreams: stream,
            subscriptions: HashMap::new(),
            control_rx: ctrl_rx,
        };

        Ok(ExtractorHandle { handle: runner.run(), control_tx: ctrl_tx })
    }
}
