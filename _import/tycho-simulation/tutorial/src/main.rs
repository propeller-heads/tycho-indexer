use clap::Parser;
use ethers::types::U256;
use std::{
    collections::HashMap,
    env,
    panic::{self, AssertUnwindSafe},
    process,
    sync::mpsc,
    thread,
};
use tracing::{debug, error, info};
use tracing_subscriber::{fmt, EnvFilter};
use tycho_simulation::protocol::state::ProtocolSim;

use tycho_simulation::models::ERC20Token;

use tutorial::data_feed::{state::BlockState, tycho};

/// Graph based solver
#[derive(Parser)]
struct Cli {
    /// The tvl threshold to filter the graph by
    #[arg(short, long, default_value_t = 10.0)]
    tvl_threshold: f64,
}

pub fn process_ticks(rx: mpsc::Receiver<BlockState>) {
    let mut pool_graph: HashMap<ethers::types::H160, Box<dyn ProtocolSim>> = HashMap::new();

    loop {
        match rx.recv() {
            Ok(state) => {
                handle_state(state, &mut pool_graph);
            }

            Err(e) => {
                error!("Error receiving tick: {:?}", e);
            }
        }
    }
}

fn handle_state(
    block_state: BlockState,
    pool_graph: &mut HashMap<ethers::types::H160, Box<dyn ProtocolSim>>,
) {
    let usdc =
        ERC20Token::new("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", 6, "USDC", U256::from(10000));

    let weth = ERC20Token::new(
        "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
        18,
        "WETH",
        U256::from(15000),
    );

    info!("Received block update: {:?}", block_state.time);
    info!(
        "Found {:?} new pairs. Adding to the graph if they match the criteria",
        block_state.new_pairs.len()
    );
    for (address, component) in block_state.new_pairs {
        let state = block_state.states.get(&address);
        if state.is_none() {
            debug!("State not found for new pair: {:?}", address);
            continue;
        }
        // Check if token0.address == usdc and token1.address == weth
        if component.tokens[0].address == usdc.address &&
            component.tokens[1].address == weth.address
        {
            debug!("Found USDC-WETH pair: {:?}", address);
            pool_graph.insert(address, state.unwrap().clone());
        }
    }

    info!(
        "{:?} uniswap_v2 and uniswap_v3 pairs were updated on this block",
        block_state.states.len()
    );
    for (address, state) in block_state.states {
        if let std::collections::hash_map::Entry::Occupied(mut e) = pool_graph.entry(address) {
            info!(
                "USDC-WETH pair: {:?} price has changed on block: {:?}",
                address, block_state.time
            );
            e.insert(state.clone());
        }
    }

    info!("");
    info!("Found {} direct USDC-WETH pairs", pool_graph.len());

    let (mut best_price, mut worst_price) = (None, None);

    for (id, pair) in pool_graph.iter() {
        info!("USDC-WETH pair: {:?}", id);
        let spot_price = pair.spot_price(&weth, &usdc).unwrap();
        info!("Price: {:?}", spot_price);

        best_price = Some(best_price.map_or(spot_price, |bp: f64| bp.max(spot_price)));
        worst_price = Some(worst_price.map_or(spot_price, |wp: f64| wp.min(spot_price)));
    }

    info!("");
    info!("Best spot price: {:?}", best_price.unwrap());
    info!("Worst spot price: {:?}", worst_price.unwrap());
    info!("----------------------------------------------------");
}

pub async fn start_app() {
    // Parse command-line arguments into a Cli struct
    let cli = Cli::parse();

    let tycho_url = env::var("TYCHO_URL").expect("Please set 'TYCHO_URL' env variable!");
    let tycho_api_key: String =
        env::var("TYCHO_API_KEY").expect("Please set 'TYCHO_API_KEY' env variable!");

    // Create communication channels for inter-thread communication
    let (ctrl_tx, ctrl_rx) = mpsc::channel::<()>();
    let (tick_tx, tick_rx) = mpsc::channel::<BlockState>();

    // Spawn a new thread to process data feeds
    let feed_ctrl_tx = ctrl_tx.clone();
    let _feed_handler = thread::spawn(move || {
        info!("Starting data feed thread...");
        let _ = panic::catch_unwind(AssertUnwindSafe(move || {
            tycho::start(tycho_url, Some(tycho_api_key), tick_tx, cli.tvl_threshold);
        }));
        if feed_ctrl_tx.send(()).is_err() {
            error!("Fatal feed thread panicked and failed trying to communicate with main thread.");
            process::exit(1);
        }
    });

    let _graph_handler = thread::spawn(move || {
        info!("Starting graph thread...");
        let _ = panic::catch_unwind(AssertUnwindSafe(move || {
            process_ticks(tick_rx);
        }));
        if ctrl_tx.send(()).is_err() {
            error!("Fatal feed thread panicked and failed trying to communicate with main thread.");
            process::exit(1);
        }
    });

    // Wait for termination: If any of the threads panic and exit, the application will terminate
    if ctrl_rx.recv().is_ok() {
        process::exit(1);
    }
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let format = fmt::format()
        .with_level(true) // Show log levels
        .with_target(false) // Hide module paths
        .compact(); // Use a compact format

    fmt()
        .event_format(format)
        .with_env_filter(EnvFilter::from_default_env()) // Use RUST_LOG for log levels
        .init();

    info!("Starting application...");

    start_app().await;
    Ok(())
}
