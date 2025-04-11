use std::{collections::HashSet, str::FromStr, time::Duration};

use clap::Parser;
use tracing::{debug, info};
use tracing_appender::rolling;
use tycho_common::dto::{Chain, ExtractorIdentity, PaginationParams, ProtocolSystemsRequestBody};

use crate::{
    deltas::DeltasClient,
    feed::{
        component_tracker::ComponentFilter, synchronizer::ProtocolStateSynchronizer,
        BlockSynchronizer,
    },
    rpc::RPCClient,
    HttpRPCClient, WsDeltasClient,
};

#[derive(Parser, Debug, Clone, PartialEq)]
#[clap(version = env!("CARGO_PKG_VERSION"))]
struct CliArgs {
    /// Tycho server URL, without protocol. Example: localhost:4242
    #[clap(long, default_value = "localhost:4242", env = "TYCHO_URL")]
    tycho_url: String,

    /// Tycho gateway API key, used as authentication for both websocket and http connections.
    /// Can be set with TYCHO_AUTH_TOKEN env variable.
    #[clap(short = 'k', long, env = "TYCHO_AUTH_TOKEN")]
    auth_key: Option<String>,

    /// If set, use unsecured transports: http and ws instead of https and wss.
    #[clap(long)]
    no_tls: bool,

    /// The blockchain to index on
    #[clap(long, default_value = "ethereum")]
    pub chain: String,

    /// Specifies exchanges and optionally a pool address in the format name:address
    #[clap(long, number_of_values = 1)]
    exchange: Vec<String>,

    /// Specifies the minimum TVL to filter the components. Denoted in the native token (e.g.
    /// Mainnet -> ETH). Ignored if addresses or range tvl values are provided.
    #[clap(long, default_value = "10")]
    min_tvl: u32,

    /// Specifies the lower bound of the TVL threshold range. Denoted in the native token (e.g.
    /// Mainnet -> ETH). Components below this TVL will be removed from tracking.
    #[clap(long)]
    remove_tvl_threshold: Option<u32>,

    /// Specifies the upper bound of the TVL threshold range. Denoted in the native token (e.g.
    /// Mainnet -> ETH). Components above this TVL will be added to tracking.
    #[clap(long)]
    add_tvl_threshold: Option<u32>,

    /// Expected block time in seconds. For blockchains with consistent intervals,
    /// set to the average block time (e.g., "600" for a 10-minute interval).
    ///
    /// Adjusting `block_time` helps balance efficiency and responsiveness:
    /// - **Low values**: Increase sync frequency but may waste resources on retries.
    /// - **High values**: Reduce sync frequency but may delay updates on faster chains.
    #[clap(long, default_value = "600")]
    block_time: u64,

    /// Maximum wait time in seconds beyond the block time. Useful for handling
    /// chains with variable block intervals or network delays.
    #[clap(long, default_value = "1")]
    timeout: u64,

    /// Logging folder path.
    #[clap(long, default_value = "logs")]
    log_folder: String,

    /// Run the example on a single block with UniswapV2 and UniswapV3.
    #[clap(long)]
    example: bool,

    /// If set, only component and tokens are streamed, any snapshots or state updates
    /// are omitted from the stream.
    #[clap(long)]
    no_state: bool,

    /// Maximum amount of messages to process before exiting. Useful for debugging e.g.
    /// to easily get a state sync messages for a fixture. Alternatively this may be
    /// used to trigger a regular restart or resync.
    #[clap(short='n', long, default_value=None)]
    max_messages: Option<usize>,

    /// Maximum blocks an exchange can be absent for before it is marked as stale. Used
    /// in conjunction with block_time to calculate a timeout: block_time * max_missed_blocks.
    #[clap(long, default_value = "10")]
    max_missed_blocks: u64,

    /// If set, the synchronizer will include TVL in the messages.
    #[clap(long)]
    include_tvl: bool,
}

impl CliArgs {
    fn validate(&self) -> Result<(), String> {
        if self.remove_tvl_threshold.is_some() && self.add_tvl_threshold.is_none() {
            return Err("Both remove_tvl_threshold and add_tvl_threshold must be set.".to_string());
        }
        if self.remove_tvl_threshold.is_none() && self.add_tvl_threshold.is_some() {
            return Err("Both remove_tvl_threshold and add_tvl_threshold must be set.".to_string());
        }
        Ok(())
    }
}

pub async fn run_cli() {
    // Parse CLI Args
    let args: CliArgs = CliArgs::parse();
    if let Err(e) = args.validate() {
        panic!("{}", e);
    }

    // Setup Logging
    let (non_blocking, _guard) =
        tracing_appender::non_blocking(rolling::never(&args.log_folder, "dev_logs.log"));
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(non_blocking)
        .finish();

    tracing::subscriber::set_global_default(subscriber)
        .expect("Failed to set up logging subscriber");

    // Runs example if flag is set.
    if args.example {
        // Run a simple example of a block synchronizer.
        //
        // You need to port-forward tycho before running this:
        //
        // ```bash
        // kubectl port-forward -n dev-tycho deploy/tycho-indexer 8888:4242
        // ```
        let exchanges = vec![
            (
                "uniswap_v3".to_string(),
                Some("0x88e6a0c2ddd26feeb64f039a2c41296fcb3f5640".to_string()),
            ),
            (
                "uniswap_v2".to_string(),
                Some("0xa478c2975ab1ea89e8196811f51a7b7ade33eb11".to_string()),
            ),
        ];
        run(exchanges, args).await;
        return;
    }

    // Parse exchange name and addresses from name:address format.
    let exchanges: Vec<(String, Option<String>)> = args
        .exchange
        .iter()
        .filter_map(|e| {
            if e.contains('-') {
                let parts: Vec<&str> = e.split('-').collect();
                if parts.len() == 2 {
                    Some((parts[0].to_string(), Some(parts[1].to_string())))
                } else {
                    tracing::warn!("Ignoring invalid exchange format: {}", e);
                    None
                }
            } else {
                Some((e.to_string(), None))
            }
        })
        .collect();

    tracing::info!("Running with exchanges: {:?}", exchanges);

    run(exchanges, args).await;
}

async fn run(exchanges: Vec<(String, Option<String>)>, args: CliArgs) {
    //TODO: remove "or args.auth_key.is_none()" when our internal client use the no_tls flag
    let (tycho_ws_url, tycho_rpc_url) = if args.no_tls || args.auth_key.is_none() {
        info!("Using non-secure connection: ws:// and http://");
        let tycho_ws_url = format!("ws://{}", &args.tycho_url);
        let tycho_rpc_url = format!("http://{}", &args.tycho_url);
        (tycho_ws_url, tycho_rpc_url)
    } else {
        info!("Using secure connection: wss:// and https://");
        let tycho_ws_url = format!("wss://{}", &args.tycho_url);
        let tycho_rpc_url = format!("https://{}", &args.tycho_url);
        (tycho_ws_url, tycho_rpc_url)
    };

    let ws_client = WsDeltasClient::new(&tycho_ws_url, args.auth_key.as_deref()).unwrap();
    let rpc_client = HttpRPCClient::new(&tycho_rpc_url, args.auth_key.as_deref()).unwrap();
    let chain =
        Chain::from_str(&args.chain).unwrap_or_else(|_| panic!("Unknown chain {}", &args.chain));
    let ws_jh = ws_client
        .connect()
        .await
        .expect("ws client connection error");

    let mut block_sync = BlockSynchronizer::new(
        Duration::from_secs(args.block_time),
        Duration::from_secs(args.timeout),
        args.max_missed_blocks,
    );

    if let Some(mm) = &args.max_messages {
        block_sync.max_messages(*mm);
    }

    let available_protocols_set = rpc_client
        .get_protocol_systems(&ProtocolSystemsRequestBody {
            chain,
            pagination: PaginationParams { page: 0, page_size: 100 },
        })
        .await
        .unwrap()
        .protocol_systems
        .into_iter()
        .collect::<HashSet<_>>();

    let requested_protocol_set = exchanges
        .iter()
        .map(|(name, _)| name.clone())
        .collect::<HashSet<_>>();

    let not_requested_protocols = available_protocols_set
        .difference(&requested_protocol_set)
        .cloned()
        .collect::<Vec<_>>();

    if !not_requested_protocols.is_empty() {
        tracing::info!("Other available protocols: {}", not_requested_protocols.join(", "));
    }

    for (name, address) in exchanges {
        debug!("Registering exchange: {}", name);
        let id = ExtractorIdentity { chain, name: name.clone() };
        let filter = if address.is_some() {
            ComponentFilter::Ids(vec![address.unwrap()])
        } else if let (Some(remove_tvl), Some(add_tvl)) =
            (args.remove_tvl_threshold, args.add_tvl_threshold)
        {
            ComponentFilter::with_tvl_range(remove_tvl as f64, add_tvl as f64)
        } else {
            ComponentFilter::with_tvl_range(args.min_tvl as f64, args.min_tvl as f64)
        };
        let sync = ProtocolStateSynchronizer::new(
            id.clone(),
            true,
            filter,
            3,
            !args.no_state,
            rpc_client.clone(),
            ws_client.clone(),
            args.block_time + args.timeout,
            args.include_tvl,
        );
        block_sync = block_sync.register_synchronizer(id, sync);
    }

    let (sync_jh, mut rx) = block_sync
        .run()
        .await
        .expect("block sync start error");

    let msg_printer = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if let Ok(msg_json) = serde_json::to_string(&msg) {
                println!("{}", msg_json);
            } else {
                tracing::error!("Failed to serialize FeedMessage");
            }
        }
    });

    // Monitor the WebSocket, BlockSynchronizer and message printer futures.
    tokio::select! {
        res = ws_jh => {
            let _ = res.expect("WebSocket connection dropped unexpectedly");
        }
        res = sync_jh => {
            res.expect("BlockSynchronizer stopped unexpectedly");
        }
        res = msg_printer => {
            res.expect("Message printer stopped unexpectedly");
        }
    }

    tracing::debug!("RX closed");
}

#[cfg(test)]
mod cli_tests {
    use clap::Parser;

    use super::CliArgs;

    #[tokio::test]
    async fn test_cli_args() {
        let args = CliArgs::parse_from([
            "tycho-client",
            "--tycho-url",
            "localhost:5000",
            "--exchange",
            "uniswap_v2",
            "--min-tvl",
            "3000",
            "--block-time",
            "50",
            "--timeout",
            "5",
            "--log-folder",
            "test_logs",
            "--example",
            "--max-messages",
            "1",
        ]);
        let exchanges: Vec<String> = vec!["uniswap_v2".to_string()];
        assert_eq!(args.tycho_url, "localhost:5000");
        assert_eq!(args.exchange, exchanges);
        assert_eq!(args.min_tvl, 3000);
        assert_eq!(args.block_time, 50);
        assert_eq!(args.timeout, 5);
        assert_eq!(args.log_folder, "test_logs");
        assert_eq!(args.max_messages, Some(1));
        assert!(args.example);
    }
}
