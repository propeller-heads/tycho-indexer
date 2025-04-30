use std::{
    collections::{HashMap, HashSet},
    env,
    time::Duration,
};

use thiserror::Error;
use tokio::{sync::mpsc::Receiver, task::JoinHandle};
use tracing::info;
use tycho_common::dto::{Chain, ExtractorIdentity, PaginationParams, ProtocolSystemsRequestBody};

use crate::{
    deltas::DeltasClient,
    feed::{
        component_tracker::ComponentFilter, synchronizer::ProtocolStateSynchronizer,
        BlockSynchronizer, FeedMessage,
    },
    rpc::RPCClient,
    HttpRPCClient, WsDeltasClient,
};

#[derive(Error, Debug)]
pub enum StreamError {
    #[error("Error during stream set up: {0}")]
    SetUpError(String),

    #[error("WebSocket client connection error: {0}")]
    WebSocketConnectionError(String),

    #[error("BlockSynchronizer error: {0}")]
    BlockSynchronizerError(String),

    #[error("Initialization error: {0}")]
    InitializationError(String),
}

pub struct TychoStreamBuilder {
    tycho_url: String,
    chain: Chain,
    exchanges: HashMap<String, ComponentFilter>,
    block_time: u64,
    timeout: u64,
    max_missed_blocks: u64,
    no_state: bool,
    auth_key: Option<String>,
    no_tls: bool,
}

impl TychoStreamBuilder {
    /// Creates a new `TychoStreamBuilder` with the given Tycho URL and blockchain network.
    /// Initializes the builder with default values for block time and timeout based on the chain.
    pub fn new(tycho_url: &str, chain: Chain) -> Self {
        let (block_time, timeout, max_missed_blocks) = Self::default_timing(&chain);
        Self {
            tycho_url: tycho_url.to_string(),
            chain,
            exchanges: HashMap::new(),
            block_time,
            timeout,
            max_missed_blocks,
            no_state: false,
            auth_key: None,
            no_tls: true,
        }
    }

    /// Returns the default block_time, timeout and max_missed_blocks values for the given
    /// blockchain network.
    fn default_timing(chain: &Chain) -> (u64, u64, u64) {
        match chain {
            Chain::Ethereum => (12, 36, 10),
            Chain::Starknet => (2, 8, 50),
            Chain::ZkSync => (3, 12, 50),
            Chain::Arbitrum => (1, 2, 100), // Typically closer to 0.25s
            Chain::Base => (2, 12, 50),
            Chain::Unichain => (1, 10, 100),
        }
    }

    /// Adds an exchange and its corresponding filter to the Tycho client.
    pub fn exchange(mut self, name: &str, filter: ComponentFilter) -> Self {
        self.exchanges
            .insert(name.to_string(), filter);
        self
    }

    /// Sets the block time for the Tycho client.
    pub fn block_time(mut self, block_time: u64) -> Self {
        self.block_time = block_time;
        self
    }

    /// Sets the timeout duration for network operations.
    pub fn timeout(mut self, timeout: u64) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn max_missed_blocks(mut self, max_missed_blocks: u64) -> Self {
        self.max_missed_blocks = max_missed_blocks;
        self
    }

    /// Configures the client to exclude state updates from the stream.
    pub fn no_state(mut self, no_state: bool) -> Self {
        self.no_state = no_state;
        self
    }

    /// Sets the API key for authenticating with the Tycho server.
    ///
    /// Optionally you can set the TYCHO_AUTH_TOKEN env var instead. Make sure to set no_tsl
    /// to false if you do this.
    pub fn auth_key(mut self, auth_key: Option<String>) -> Self {
        self.auth_key = auth_key;
        self.no_tls = false;
        self
    }

    /// Disables TLS/SSL for the connection, using `http` and `ws` protocols.
    pub fn no_tls(mut self, no_tls: bool) -> Self {
        self.no_tls = no_tls;
        self
    }

    /// Builds and starts the Tycho client, connecting to the Tycho server and
    /// setting up the synchronization of exchange components.
    pub async fn build(self) -> Result<(JoinHandle<()>, Receiver<FeedMessage>), StreamError> {
        if self.exchanges.is_empty() {
            return Err(StreamError::SetUpError(
                "At least one exchange must be registered.".to_string(),
            ));
        }

        // Attempt to read the authentication key from the environment variable if not provided
        let auth_key = self
            .auth_key
            .or_else(|| env::var("TYCHO_AUTH_TOKEN").ok());

        // Determine the URLs based on the TLS setting
        let (tycho_ws_url, tycho_rpc_url) = if self.no_tls {
            info!("Using non-secure connection: ws:// and http://");
            let tycho_ws_url = format!("ws://{}", self.tycho_url);
            let tycho_rpc_url = format!("http://{}", self.tycho_url);
            (tycho_ws_url, tycho_rpc_url)
        } else {
            info!("Using secure connection: wss:// and https://");
            let tycho_ws_url = format!("wss://{}", self.tycho_url);
            let tycho_rpc_url = format!("https://{}", self.tycho_url);
            (tycho_ws_url, tycho_rpc_url)
        };

        // Initialize the WebSocket client
        let ws_client = WsDeltasClient::new(&tycho_ws_url, auth_key.as_deref())
            .map_err(|e| StreamError::InitializationError(e.to_string()))?;
        let rpc_client = HttpRPCClient::new(&tycho_rpc_url, auth_key.as_deref())
            .map_err(|e| StreamError::InitializationError(e.to_string()))?;
        let ws_jh = ws_client
            .connect()
            .await
            .map_err(|e| StreamError::WebSocketConnectionError(e.to_string()))?;

        // Create and configure the BlockSynchronizer
        let mut block_sync = BlockSynchronizer::new(
            Duration::from_secs(self.block_time),
            Duration::from_secs(self.timeout),
            self.max_missed_blocks,
        );

        let available_protocols_set = rpc_client
            .get_protocol_systems(&ProtocolSystemsRequestBody {
                chain: self.chain,
                pagination: PaginationParams { page: 0, page_size: 100 },
            })
            .await
            .map_err(|e| {
                StreamError::InitializationError(format!("Failed to fetch protocol systems: {e}"))
            })?
            .protocol_systems
            .into_iter()
            .collect::<HashSet<_>>();

        let requested_protocol_set = self
            .exchanges
            .keys()
            .cloned()
            .collect::<HashSet<_>>();

        let not_requested_protocols = available_protocols_set
            .difference(&requested_protocol_set)
            .cloned()
            .collect::<Vec<_>>();

        if !not_requested_protocols.is_empty() {
            tracing::info!("Other available protocols: {}", not_requested_protocols.join(", "));
        }

        // Register each exchange with the BlockSynchronizer
        for (name, filter) in self.exchanges {
            info!("Registering exchange: {}", name);
            let id = ExtractorIdentity { chain: self.chain, name: name.clone() };
            let sync = ProtocolStateSynchronizer::new(
                id.clone(),
                true,
                filter,
                3,
                !self.no_state,
                rpc_client.clone(),
                ws_client.clone(),
                self.block_time + self.timeout,
            );
            block_sync = block_sync.register_synchronizer(id, sync);
        }

        // Start the BlockSynchronizer and monitor for disconnections
        let (sync_jh, rx) = block_sync
            .run()
            .await
            .map_err(|e| StreamError::BlockSynchronizerError(e.to_string()))?;

        // Monitor WebSocket and BlockSynchronizer futures
        let handle = tokio::spawn(async move {
            tokio::select! {
                res = ws_jh => {
                    let _ = res.map_err(|e| StreamError::WebSocketConnectionError(e.to_string()));
                }
                res = sync_jh => {
                    res.map_err(|e| StreamError::BlockSynchronizerError(e.to_string())).unwrap();
                }
            }
        });

        Ok((handle, rx))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_no_exchanges() {
        let receiver = TychoStreamBuilder::new("localhost:4242", Chain::Ethereum)
            .auth_key(Some("my_api_key".into()))
            .build()
            .await;
        assert!(receiver.is_err(), "Client should fail to build when no exchanges are registered.");
    }

    #[ignore = "require tycho gateway"]
    #[tokio::test]
    async fn teat_simple_build() {
        let token = env::var("TYCHO_AUTH_TOKEN").unwrap();
        let receiver = TychoStreamBuilder::new("tycho-beta.propellerheads.xyz", Chain::Ethereum)
            .exchange("uniswap_v2", ComponentFilter::with_tvl_range(100.0, 100.0))
            .auth_key(Some(token))
            .build()
            .await;

        dbg!(&receiver);

        assert!(receiver.is_ok(), "Client should build successfully with exchanges registered.");
    }
}
