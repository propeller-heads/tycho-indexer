use std::{
    collections::{HashMap, HashSet},
    env,
    fmt::Display,
    time::Duration,
};

use miette::{miette, IntoDiagnostic, WrapErr};
use rand::prelude::IteratorRandom;
use tokio::{sync::mpsc::Sender, task::JoinHandle, time::timeout};
use tracing::{debug, info, warn};
use tycho_common::{
    models::{token::Token, Chain},
    Bytes,
};
use tycho_simulation::rfq::{
    protocols::{
        bebop::{client_builder::BebopClientBuilder, state::BebopState},
        hashflow::{client::HashflowClient, state::HashflowState},
    },
    stream::RFQStreamBuilder,
};

use crate::stream_processor::{StreamUpdate, UpdateType};

#[derive(Debug, PartialEq, Eq, Hash)]
pub enum RfqProtocol {
    Bebop,
    Hashflow,
}

impl Display for RfqProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RfqProtocol::Bebop => write!(f, "Bebop"),
            RfqProtocol::Hashflow => write!(f, "Hashflow"),
        }
    }
}

pub struct RfqStreamProcessor {
    chain: Chain,
    tvl_threshold: f64,
    rfq_credentials: HashMap<RfqProtocol, (String, String)>,
    sample_size: usize,
    stream_sleep_time: Duration,
}

impl RfqStreamProcessor {
    pub fn new(chain: Chain, tvl_threshold: f64) -> miette::Result<Self> {
        let mut rfq_credentials = HashMap::new();
        let (bebop_user, bebop_key) = (env::var("BEBOP_USER").ok(), env::var("BEBOP_KEY").ok());
        if let (Some(user), Some(key)) = (bebop_user, bebop_key) {
            info!("Bebop RFQ credentials found.");
            rfq_credentials.insert(RfqProtocol::Bebop, (user, key));
        }
        let (hashflow_user, hashflow_key) =
            (env::var("HASHFLOW_USER").ok(), env::var("HASHFLOW_KEY").ok());
        if let (Some(user), Some(key)) = (hashflow_user, hashflow_key) {
            info!("Hashflow RFQ credentials found.");
            rfq_credentials.insert(RfqProtocol::Hashflow, (user, key));
        }
        if rfq_credentials.is_empty() {
            return Err(miette!("No RFQ credentials found. Please set BEBOP_USER and BEBOP_KEY or HASHFLOW_USER and HASHFLOW_KEY environment variables."));
        }
        Ok(Self {
            chain,
            tvl_threshold,
            rfq_credentials,
            sample_size: 10,
            stream_sleep_time: Duration::from_secs(5),
        })
    }

    pub async fn run_stream(
        &self,
        all_tokens: &HashMap<Bytes, Token>,
        stream_tx: Sender<StreamUpdate>,
    ) -> miette::Result<JoinHandle<()>> {
        // Set up RFQ stream
        let rfq_tokens: HashSet<Bytes> = all_tokens.keys().cloned().collect();
        let mut rfq_stream_builder = RFQStreamBuilder::new()
            .set_tokens(all_tokens.clone())
            .await;
        for (protocol, (user, key)) in &self.rfq_credentials {
            info!("Adding {protocol} RFQ client...");
            match protocol {
                RfqProtocol::Bebop => {
                    let bebop_client =
                        BebopClientBuilder::new(self.chain, user.clone(), key.clone())
                            .tokens(rfq_tokens.clone())
                            .tvl_threshold(self.tvl_threshold)
                            .build()
                            .into_diagnostic()
                            .wrap_err("Failed to create Bebop RFQ client")?;
                    rfq_stream_builder = rfq_stream_builder
                        .add_client::<BebopState>("bebop", Box::new(bebop_client));
                }
                RfqProtocol::Hashflow => {
                    let hashflow_client = HashflowClient::new(
                        self.chain,
                        rfq_tokens.clone(),
                        self.tvl_threshold,
                        Default::default(),
                        user.clone(),
                        key.clone(),
                        Duration::from_secs(1),
                    )
                    .into_diagnostic()
                    .wrap_err("Failed to create Hashflow RFQ client")?;
                    rfq_stream_builder = rfq_stream_builder
                        .add_client::<HashflowState>("hashflow", Box::new(hashflow_client))
                }
            }
        }

        // Start the RFQ stream
        let mut is_first_update = false;
        let (tx, mut rx) = tokio::sync::mpsc::channel(64);
        let _handle = tokio::spawn(rfq_stream_builder.build(tx));
        let sample_size = self.sample_size;
        let stream_sleep_time = self.stream_sleep_time;
        let mut next_stream_time = tokio::time::Instant::now();
        let handle = tokio::spawn(async move {
            while let Some(update) = rx.recv().await {
                // Drain any additional buffered messages to get the most recent one
                let mut latest_update = update;
                let mut drained_count = 0;
                while let Ok(newer_update) = timeout(Duration::from_millis(10), rx.recv()).await {
                    if let Some(newer_update) = newer_update {
                        latest_update = newer_update;
                        drained_count += 1;
                    } else {
                        break;
                    }
                }
                if drained_count > 0 {
                    debug!(
                        "Fast-forwarded through {drained_count} older RFQ updates to get latest prices"
                    );
                }
                let mut update = latest_update;

                let now = tokio::time::Instant::now();
                if now < next_stream_time {
                    continue;
                }
                next_stream_time = now + stream_sleep_time;

                // Sample random RFQ quotes
                update.states = update
                    .states
                    .into_iter()
                    .choose_multiple(&mut rand::rng(), sample_size)
                    .into_iter()
                    .collect();
                update
                    .new_pairs
                    .retain(|key, _| update.states.contains_key(key));

                // Send the latest update
                let update = StreamUpdate { update_type: UpdateType::Rfq, update, is_first_update };
                if is_first_update {
                    is_first_update = false;
                }
                if stream_tx.send(update).await.is_err() {
                    warn!("Receiver dropped, stopping stream processor");
                    _handle.abort();
                    break;
                }
            }
        });
        Ok(handle)
    }
}
