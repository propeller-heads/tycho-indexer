use std::{
    env,
    panic::{self, AssertUnwindSafe},
    process,
    sync::{mpsc},
    thread,
};

use clap::{Parser};
use ethers::{
    types::{H160, U256},
};
use protosim::{
    data_feed, data_feed::tick::Tick, examples::graph::PoolGraph, models::ERC20Token,
    protocol::state::ProtocolSim, u256_num::u256_to_f64,
};
use tracing::{debug, error, info};
use tracing_subscriber::{fmt, EnvFilter};

/// Graph based solver
#[derive(Parser)]
struct Cli {
    /// The tvl threshold to filter the graph by
    #[arg(short, long, default_value_t = 10.0)]
    tvl_threshold: f64,
}

pub fn process_ticks(rx: mpsc::Receiver<Tick>) {
    let mut pool_graph = PoolGraph::new();

    let usdc =
        ERC20Token::new("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", 6, "USDC", U256::from(10000));

    let weth = ERC20Token::new(
        "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
        18,
        "WETH",
        U256::from(15000),
    );

    loop {
        match rx.recv() {
            Ok(tick) => {
                info!("Received tick: {:?}", tick.time);
                info!("Adding {:?} pairs to the graph", tick.new_pairs.len());
                for (address, tokens) in tick.new_pairs {
                    let state = tick.states.get(&address);
                    if state.is_none() {
                        error!("State not found for new pair: {:?}", address);
                        continue;
                    }
                    pool_graph.add_pool(
                        tokens.tokens[0].clone(),
                        tokens.tokens[1].clone(),
                        address,
                        state.unwrap().clone(),
                    );
                }
                info!("Removing {:?} pairs from the graph", tick.removed_pairs.len());
                for (address, _) in tick.removed_pairs {
                    pool_graph.remove_pool(address);
                }
                info!("Updating {:?} pairs on the graph", tick.states.len());
                for (address, state) in tick.states {
                    pool_graph.update_pool(address, state);
                }

                let usdc_weth_direct_paths = pool_graph.find_paths(&weth, &usdc, 1);
                info!("Found {} direct USDC-WETH pairs", usdc_weth_direct_paths.len());

                let (mut best_price, mut worst_price) = (None, None);

                for path in usdc_weth_direct_paths {
                    let (id, pair) = &path[0];
                    info!("USDC-WETH pair: {:?}", id);
                    let spot_price = pair.spot_price(&weth, &usdc);
                    info!("Price: {:?}", spot_price);

                    best_price = Some(best_price.map_or(spot_price, |bp: f64| bp.min(spot_price)));
                    worst_price =
                        Some(worst_price.map_or(spot_price, |wp: f64| wp.max(spot_price)));
                }

                info!("Best spot price: {:?}", best_price);
                info!("Worst spot price: {:?}", worst_price);

                let usdc_weth_solver_paths = pool_graph.find_paths(&weth, &usdc, 2);
                info!("Found {} USDC-WETH paths", usdc_weth_solver_paths.len());

                // TODO: Make amount_in, token_in and token_out configurable by user input
                let mut path_results = Vec::new();
                let initial_amount = U256::exp10(18); // Starting with 1 * 10^18

                for path in usdc_weth_solver_paths {
                    if let Some(amount) =
                        simulate_single_path(&path, &pool_graph, &weth, &usdc, initial_amount)
                    {
                        path_results.push(amount);
                    }
                }

                let highest_amount = path_results.iter().max_by_key(|r| r.amount_out);
                if let Some(res) = highest_amount {
                    info!(
                        "Highest amount: {} {}",
                        format_token_amount(res.amount_out, &usdc),
                        usdc.symbol
                    );
                    info!("Path: {:?}", res.path);
                    info!("Touched tokens: {:?}", res.touched_tokens);
                }
                return;
            }

            Err(e) => {
                error!("Error receiving tick: {:?}", e);
            }
        }
    }
}

struct SimulationResult {
    path: Vec<H160>,
    amount_out: U256,
    touched_tokens: Vec<ERC20Token>,
}

/// Simulates swaps along a single path.
///
/// # Returns
/// Option<U256> representing the final amount out, or None if the simulation failed.
fn simulate_single_path(
    path: &Vec<(H160, Box<dyn ProtocolSim>)>,
    pool_graph: &PoolGraph,
    initial_sell_token: &ERC20Token,
    final_buy_token: &ERC20Token,
    initial_amount: U256,
) -> Option<SimulationResult> {
    let mut sell_amount = initial_amount;
    let mut sell_token = initial_sell_token.clone();
    let mut buy_token = final_buy_token.clone();
    let mut current_amount_out = U256::zero();
    let mut touched_tokens = vec![sell_token.clone()];

    debug!("Starting simulation for path with {} hops", path.len());

    for (id, pair) in path {
        // Get pool tokens
        let (token_0, token_1) = match pool_graph.get_nodes_of_edge(*id) {
            Some(tokens) => tokens,
            None => {
                error!("Failed to get tokens for pool ID: {}", id);
                return None;
            }
        };

        // Determine swap direction
        let previous_sell_token = sell_token.clone();
        if previous_sell_token.address == token_0.address {
            sell_token = token_0.clone();
            buy_token = token_1.clone();
        } else if previous_sell_token.address == token_1.address {
            sell_token = token_1.clone();
            buy_token = token_0.clone();
        } else {
            error!("Sell token {:?} not found in pool {}", previous_sell_token.address, id);
            return None;
        }

        // Execute swap
        match pair.get_amount_out(sell_amount, &sell_token, &buy_token) {
            Ok(res) => {
                current_amount_out = res.amount;
                sell_amount = current_amount_out;
                sell_token = buy_token.clone();

                info!(
                    "Swap successful in pool {}: {} -> {} tokens",
                    id,
                    format_token_amount(sell_amount, &sell_token),
                    format_token_amount(current_amount_out, &buy_token)
                );
                touched_tokens.push(buy_token.clone());
            }
            Err(e) => {
                error!("Swap failed in pool {}: {:?}", id, e);
                return None;
            }
        }
    }

    info!(
        "Path simulation complete. Final amount: {} {}",
        format_token_amount(current_amount_out, final_buy_token),
        final_buy_token.symbol
    );

    Some(SimulationResult {
        path: path.iter().map(|(id, _)| *id).collect(),
        amount_out: current_amount_out,
        touched_tokens,
    })
}

/// Formats a token amount considering its decimals.
fn format_token_amount(amount: U256, token: &ERC20Token) -> f64 {
    u256_to_f64(amount) / 10f64.powi(token.decimals as i32)
}
pub async fn start_app() {
    // Parse command-line arguments into a Cli struct
    let cli = Cli::parse();

    let tycho_url = env::var("TYCHO_URL").expect("Please set 'TYCHO_URL' env variable!");
    let tycho_api_key: String =
        env::var("TYCHO_API_KEY").expect("Please set 'TYCHO_API_KEY' env variable!");

    // Create communication channels for inter-thread communication
    let (ctrl_tx, ctrl_rx) = mpsc::channel::<()>();
    let (tick_tx, tick_rx) = mpsc::channel::<Tick>();

    // Spawn a new thread to process data feeds
    let feed_ctrl_tx = ctrl_tx.clone();
    let _feed_handler = thread::spawn(move || {
        info!("Starting data feed thread...");
        let _ = panic::catch_unwind(AssertUnwindSafe(move || {
            data_feed::tycho::start(tycho_url, Some(tycho_api_key), tick_tx, cli.tvl_threshold);
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
