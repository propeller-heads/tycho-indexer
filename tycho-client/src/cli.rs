use std::{collections::HashSet, str::FromStr, time::Duration};

use clap::Parser;
use tracing::{debug, error, info, warn};
use tracing_appender::rolling;
use tycho_common::dto::{Chain, ExtractorIdentity, PaginationParams, ProtocolSystemsRequestBody};

use crate::{
    deltas::DeltasClient,
    feed::{
        component_tracker::ComponentFilter, synchronizer::ProtocolStateSynchronizer,
        BlockSynchronizer,
    },
    rpc::{HttpRPCClientOptions, RPCClient},
    HttpRPCClient, WsDeltasClient,
};

/// Tycho Client CLI - A tool for indexing and tracking blockchain protocol data
///
/// This CLI tool connects to a Tycho server and tracks various blockchain protocols,
/// providing real-time updates about their state.
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
    #[clap(short = 'c', long, default_value = "ethereum")]
    pub chain: String,

    /// Specifies exchanges. Optionally also supply a pool address in the format
    /// {exchange}-{pool_address}
    #[clap(short = 'e', long, number_of_values = 1)]
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
    /// Enabling this option will increase the number of network requests made during start-up,
    /// which may result in increased start-up latency.
    #[clap(long)]
    include_tvl: bool,

    /// If set, disable compression for WebSocket messages.
    /// By default, messages are compressed using zstd.
    #[clap(long)]
    disable_compression: bool,

    /// Enable verbose logging. This will show more detailed information about the
    /// synchronization process and any errors that occur.
    #[clap(long)]
    verbose: bool,
}

impl CliArgs {
    fn validate(&self) -> Result<(), String> {
        // TVL thresholds must be set together - either both or neither
        match (self.remove_tvl_threshold, self.add_tvl_threshold) {
            (Some(remove), Some(add)) if remove >= add => {
                return Err("remove_tvl_threshold must be less than add_tvl_threshold".to_string());
            }
            (Some(_), None) | (None, Some(_)) => {
                return Err(
                    "Both remove_tvl_threshold and add_tvl_threshold must be set.".to_string()
                );
            }
            _ => {}
        }

        Ok(())
    }
}

pub async fn run_cli() -> Result<(), String> {
    // Parse CLI Args
    let args: CliArgs = CliArgs::parse();
    args.validate()?;

    // Setup Logging
    let log_level = if args.verbose { "debug" } else { "info" };
    let (non_blocking, _guard) =
        tracing_appender::non_blocking(rolling::never(&args.log_folder, "dev_logs.log"));
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(log_level)),
        )
        .with_writer(non_blocking)
        .finish();

    tracing::subscriber::set_global_default(subscriber)
        .map_err(|e| format!("Failed to set up logging subscriber: {e}"))?;

    // Build the list of exchanges.  When --example is provided, we seed the list with a fixed
    // pair of well-known pools, otherwise we parse user supplied values (either plain exchange
    // names or exchange-pool pairs in the {exchange}-{pool_address} format).
    let exchanges: Vec<(String, Option<String>)> = if args.example {
        // You will need to port-forward tycho to run the example:
        //
        // ```bash
        // kubectl port-forward -n dev-tycho deploy/tycho-indexer 8888:4242
        // ```
        vec![
            (
                "uniswap_v3".to_string(),
                Some("0x88e6a0c2ddd26feeb64f039a2c41296fcb3f5640".to_string()),
            ),
            (
                "uniswap_v2".to_string(),
                Some("0xa478c2975ab1ea89e8196811f51a7b7ade33eb11".to_string()),
            ),
        ]
    } else {
        args.exchange
            .iter()
            .filter_map(|e| {
                if e.contains('-') {
                    let parts: Vec<&str> = e.split('-').collect();
                    if parts.len() == 2 {
                        Some((parts[0].to_string(), Some(parts[1].to_string())))
                    } else {
                        warn!("Ignoring invalid exchange format: {}", e);
                        None
                    }
                } else {
                    Some((e.to_string(), None))
                }
            })
            .collect()
    };

    info!("Running with exchanges: {:?}", exchanges);

    run(exchanges, args).await?;
    Ok(())
}

async fn run(exchanges: Vec<(String, Option<String>)>, args: CliArgs) -> Result<(), String> {
    info!("Running with version: {}", option_env!("CARGO_PKG_VERSION").unwrap_or("unknown"));
    //TODO: remove "or args.auth_key.is_none()" when our internal client use the no_tls flag
    let (tycho_ws_url, tycho_rpc_url) = if args.no_tls || args.auth_key.is_none() {
        info!("Using non-secure connection: ws:// and http://");
        let tycho_ws_url = format!("ws://{url}", url = &args.tycho_url);
        let tycho_rpc_url = format!("http://{url}", url = &args.tycho_url);
        (tycho_ws_url, tycho_rpc_url)
    } else {
        info!("Using secure connection: wss:// and https://");
        let tycho_ws_url = format!("wss://{url}", url = &args.tycho_url);
        let tycho_rpc_url = format!("https://{url}", url = &args.tycho_url);
        (tycho_ws_url, tycho_rpc_url)
    };

    let ws_client = WsDeltasClient::new(&tycho_ws_url, args.auth_key.as_deref())
        .map_err(|e| format!("Failed to create WebSocket client: {e}"))?;
    let rpc_client = HttpRPCClient::new(
        &tycho_rpc_url,
        HttpRPCClientOptions::new()
            .with_auth_key(args.auth_key.clone())
            .with_compression(!args.disable_compression),
    )
    .map_err(|e| format!("Failed to create RPC client: {e}"))?;
    let chain = Chain::from_str(&args.chain)
        .map_err(|_| format!("Unknown chain: {chain}", chain = &args.chain))?;
    let ws_jh = ws_client
        .connect()
        .await
        .map_err(|e| format!("WebSocket client connection error: {e}"))?;

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
        .map_err(|e| format!("Failed to get protocol systems: {e}"))?
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
        info!("Other available protocols: {}", not_requested_protocols.join(", "));
    }

    for (name, address) in exchanges {
        debug!("Registering exchange: {}", name);
        let id = ExtractorIdentity { chain, name: name.clone() };
        let filter = if let Some(address) = address {
            ComponentFilter::Ids(vec![address])
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
            32,
            Duration::from_secs(args.block_time / 2),
            !args.no_state,
            args.include_tvl,
            !args.disable_compression,
            rpc_client.clone(),
            ws_client.clone(),
            args.block_time + args.timeout,
        );
        block_sync = block_sync.register_synchronizer(id, sync);
    }

    let (sync_jh, mut rx) = block_sync
        .run()
        .await
        .map_err(|e| format!("Failed to start block synchronizer: {e}"))?;

    let msg_printer = tokio::spawn(async move {
        while let Some(result) = rx.recv().await {
            let msg =
                result.map_err(|e| format!("Message printer received synchronizer error: {e}"))?;

            if let Ok(msg_json) = serde_json::to_string(&msg) {
                println!("{msg_json}");
            } else {
                // Log the error but continue processing further messages.
                error!("Failed to serialize FeedMessage");
            };
        }

        Ok::<(), String>(())
    });

    // Monitor the WebSocket, BlockSynchronizer and message printer futures.
    let (failed_task, shutdown_reason) = tokio::select! {
        res = ws_jh => (
            "WebSocket",
            extract_nested_error(res)
        ),
        res = sync_jh => (
            "BlockSynchronizer",
            extract_nested_error::<_, _, String>(Ok(res))
            ),
        res = msg_printer => (
            "MessagePrinter",
            extract_nested_error(res)
        )
    };

    debug!("RX closed");
    Err(format!(
        "{failed_task} task terminated: {}",
        shutdown_reason.unwrap_or("unknown reason".to_string())
    ))
}

#[inline]
fn extract_nested_error<T, E1: ToString, E2: ToString>(
    res: Result<Result<T, E1>, E2>,
) -> Option<String> {
    res.map_err(|e| e.to_string())
        .and_then(|r| r.map_err(|e| e.to_string()))
        .err()
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
        assert_eq!(args.disable_compression, false);
    }
}
