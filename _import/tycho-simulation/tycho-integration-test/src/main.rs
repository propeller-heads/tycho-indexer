mod execution;
mod metrics;
mod stream_processor;

use std::{
    fmt::Debug,
    num::NonZeroUsize,
    sync::{Arc, RwLock},
    time::Duration,
};

use alloy::{
    eips::BlockNumberOrTag,
    network::Ethereum,
    primitives::Address,
    providers::{Provider, ProviderBuilder, RootProvider},
    rpc::types::Block,
};
use alloy_chains::NamedChain;
use clap::Parser;
use dotenv::dotenv;
use itertools::Itertools;
use lru::LruCache;
use miette::{miette, IntoDiagnostic, NarratableReportHandler, WrapErr};
use num_bigint::BigUint;
use num_traits::{ToPrimitive, Zero};
use tokio::sync::Semaphore;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;
use tycho_common::simulation::protocol_sim::ProtocolSim;
use tycho_ethereum::entrypoint_tracer::{
    allowance_slot_detector::{AllowanceSlotDetectorConfig, EVMAllowanceSlotDetector},
    balance_slot_detector::{BalanceSlotDetectorConfig, EVMBalanceSlotDetector},
};
use tycho_simulation::{
    protocol::models::ProtocolComponent,
    rfq::protocols::hashflow::{client::HashflowClient, state::HashflowState},
    tycho_common::models::Chain,
    utils::load_all_tokens,
};

use crate::{
    execution::{encoding::encode_swap, simulate_swap_transaction, tenderly},
    stream_processor::{
        protocol_stream_processor::ProtocolStreamProcessor,
        rfq_stream_processor::RFQStreamProcessor, StreamUpdate, UpdateType,
    },
};

#[derive(Parser, Clone)]
struct Cli {
    /// The tvl threshold in ETH/native token units to filter the graph by
    #[arg(long, default_value_t = 100.0)]
    tvl_threshold: f64,

    #[arg(long, default_value = "ethereum")]
    chain: Chain,

    #[arg(
        long,
        env = "TYCHO_API_KEY",
        hide_env_values = true,
        default_value = "sampletoken",
        hide_default_value = true
    )]
    tycho_api_key: String,

    #[arg(long, env = "TYCHO_URL")]
    tycho_url: String,

    #[arg(long, env = "RPC_URL")]
    rpc_url: String,

    /// Disable on-chain protocols
    #[arg(long, default_value_t = false)]
    disable_onchain: bool,

    /// Disable RFQ protocols
    #[arg(long, default_value_t = false)]
    disable_rfq: bool,

    /// Port for the Prometheus metrics server
    #[arg(long, default_value_t = 9898)]
    metrics_port: u16,

    /// Maximum number of updates to process in parallel.
    /// Set to 1 to process sequentially.
    #[arg(long, default_value_t = 5, value_parser = clap::value_parser!(u8).range(1..))]
    parallel_updates: u8,

    /// Maximum number of simulations to run in parallel
    /// Set to 1 to process sequentially.
    #[arg(long, default_value_t = 5, value_parser = clap::value_parser!(u8).range(1..))]
    parallel_simulations: u8,

    /// Maximum number of simulations to run per protocol update
    #[arg(long, default_value_t = 10, value_parser = clap::value_parser!(u16).range(1..))]
    max_simulations: u16,

    /// The RFQ stream will skip messages for this duration (in seconds) after processing a message
    #[arg(long, default_value_t = 600)]
    skip_messages_duration: u64,
}

impl Debug for Cli {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Cli")
            .field("tvl_threshold", &self.tvl_threshold)
            .field("chain", &self.chain)
            .field("tycho_api_key", &"****")
            .field("tycho_url", &self.tycho_url)
            .field("rpc_url", &self.rpc_url)
            .field("metrics_port", &self.metrics_port)
            .finish()
    }
}

#[tokio::main]
async fn main() -> miette::Result<()> {
    miette::set_hook(Box::new(|_| Box::new(NarratableReportHandler::new())))?;
    dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();
    let cli = Cli::parse();

    // Initialize and start Prometheus metrics
    metrics::initialize_metrics();
    let metrics_task = metrics::create_metrics_exporter(cli.metrics_port).await?;

    // Run the main application logic and metrics server in parallel
    // If either fails, the other will be cancelled
    tokio::select! {
        result = run(cli) => {
            result?;
        }
        result = metrics_task => {
            result
                .into_diagnostic()
                .wrap_err("Metrics server task panicked")??;
        }
    }

    Ok(())
}

async fn run(cli: Cli) -> miette::Result<()> {
    info!("Starting integration test");

    let cli = Arc::new(cli);
    let chain = cli.chain;

    let rpc_tools = RPCTools::new(&cli.rpc_url, &chain).await?;

    // Load tokens from Tycho
    info!(%cli.tycho_url, "Loading tokens...");
    let all_tokens =
        load_all_tokens(&cli.tycho_url, false, Some(cli.tycho_api_key.as_str()), chain, None, None)
            .await;
    info!(%cli.tycho_url, "Loaded tokens");

    // Run streams in background tasks
    let (tx, mut rx) = tokio::sync::mpsc::channel(64);
    if !cli.disable_onchain {
        if let Ok(protocol_stream_processor) = ProtocolStreamProcessor::new(
            chain,
            cli.tycho_url.clone(),
            cli.tycho_api_key.clone(),
            cli.tvl_threshold,
        ) {
            protocol_stream_processor
                .run_stream(&all_tokens, tx.clone())
                .await?;
        }
    }
    if !cli.disable_rfq {
        if let Ok(rfq_stream_processor) = RFQStreamProcessor::new(
            chain,
            cli.tvl_threshold,
            cli.max_simulations as usize,
            Duration::from_secs(cli.skip_messages_duration),
        ) {
            rfq_stream_processor
                .run_stream(&all_tokens, tx)
                .await?;
        }
    }

    // Assuming a ProtocolComponent instance can be around 1KB (2 tokens, 2 contract_ids, 6 static
    // attributes) 250,000 entries would use 250MB of memory.
    // In a 25min test, the cache increased at a rate of ~2 items/minute, or ~3k items/day, so it
    // would take ~80 days to get full and start dropping the least used items.
    let protocol_pairs = Arc::new(RwLock::new(LruCache::new(
        NonZeroUsize::new(250_000).ok_or_else(|| miette!("Invalid NonZeroUsize"))?,
    )));

    // Process streams updates
    info!("Waiting for first protocol update...");
    let semaphore = Arc::new(Semaphore::new(cli.parallel_updates as usize));
    while let Some(update) = rx.recv().await {
        let update = match update {
            Ok(u) => Arc::new(u),
            Err(e) => {
                warn!("{}", format_error_chain(&e));
                continue;
            }
        };

        let cli = cli.clone();
        let rpc_tools = rpc_tools.clone();
        let protocol_pairs = protocol_pairs.clone();
        let permit = semaphore
            .clone()
            .acquire_owned()
            .await
            .into_diagnostic()
            .wrap_err("Failed to acquire permit")?;
        tokio::spawn(async move {
            if let Err(e) = process_update(cli, chain, rpc_tools, protocol_pairs, &update).await {
                warn!("{}", format_error_chain(&e));
            }
            drop(permit);
        });
    }

    Ok(())
}

async fn process_update(
    cli: Arc<Cli>,
    chain: Chain,
    rpc_tools: RPCTools,
    protocol_pairs: Arc<RwLock<LruCache<String, ProtocolComponent>>>,
    update: &StreamUpdate,
) -> miette::Result<()> {
    info!(
        "Got protocol update with block/timestamp {}, {} new pairs, and {} states",
        update.update.block_number_or_timestamp,
        update.update.new_pairs.len(),
        update.update.states.len()
    );

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .into_diagnostic()?
        .as_secs();
    let block = match rpc_tools
        .provider
        .get_block_by_number(BlockNumberOrTag::Latest)
        .await
        .into_diagnostic()
        .wrap_err("Failed to fetch latest block")
        .ok()
        .flatten()
    {
        Some(b) => Arc::new(b),
        None => {
            warn!("Failed to retrieve last block, continuing to next message...");
            return Ok(());
        }
    };

    if let UpdateType::Protocol = update.update_type {
        {
            let mut pairs = protocol_pairs
                .write()
                .map_err(|e| miette!("Failed to acquire write lock on protocol pairs: {e}"))?;
            let prev_size = pairs.len();
            for (id, comp) in update.update.new_pairs.iter() {
                pairs.put(id.clone(), comp.clone());
            }
            let new_size = pairs.len();
            let cap = pairs.cap().get();
            if new_size != prev_size {
                info!(size=%new_size, capacity=%cap, "Protocol components cache updated");
            }
            if new_size == cap {
                warn!(size=%new_size, capacity=%cap, "Protocol components cache reached capacity, \
                least recently used items will be evicted on new insertions");
            }
        }
        // Record block processing latency
        let latency_seconds = (now as i64 - block.header.timestamp as i64).abs() as f64;
        metrics::record_block_processing_duration(latency_seconds);

        let block_delay = block
            .header
            .number
            .abs_diff(update.update.block_number_or_timestamp);
        // Consume messages that are older than the current block, to give the stream a chance
        // to catch up
        if update.update.block_number_or_timestamp < block.header.number {
            warn!(
                "Update block ({}) is behind the current block ({}), skipping to catch up.",
                update.update.block_number_or_timestamp, block.header.number
            );
            metrics::record_protocol_update_skipped();
            return Ok(());
        }
        metrics::record_protocol_update_block_delay(block_delay);

        if update.is_first_update {
            info!("Skipping simulation on first protocol update...");
            return Ok(());
        }
    }

    for (protocol, sync_state) in update.update.sync_states.iter() {
        metrics::record_protocol_sync_state(protocol, sync_state);
    }

    // Process states in parallel
    let semaphore = Arc::new(Semaphore::new(cli.parallel_simulations as usize));
    for (id, state) in update
        .update
        .states
        .iter()
        .take(cli.max_simulations as usize)
    {
        let component = match update.update_type {
            UpdateType::Protocol => {
                let mut pairs = protocol_pairs
                    .write()
                    .map_err(|e| miette!("Failed to acquire read lock on protocol pairs: {e}"))?;
                match pairs.get(id) {
                    Some(comp) => comp.clone(),
                    None => {
                        warn!(id=%id, "Component not found in cached protocol pairs. Potential causes: \
                        there was an error decoding the component, the component was evicted from the cache, \
                        or the component was never added to the cache. Skipping...");
                        continue;
                    }
                }
            }
            UpdateType::Rfq => match update.update.new_pairs.get(id) {
                Some(comp) => comp.clone(),
                None => {
                    warn!(id=%id, "Component not found in update's new pairs. Potential cause: \
                    the `states` and `new_pairs` lists don't contain the same items. Skipping...");
                    continue;
                }
            },
        };
        let rpc_tools = rpc_tools.clone();
        let block = block.clone();
        let state_id = id.clone();
        let state = state.clone_box();
        let permit = semaphore
            .clone()
            .acquire_owned()
            .await
            .into_diagnostic()
            .wrap_err("Failed to acquire permit")?;
        tokio::spawn(async move {
            let simulation_id = generate_simulation_id(&component.protocol_system, &state_id);
            process_state(&simulation_id, rpc_tools, chain, component, &block, state_id, state)
                .await;
            drop(permit);
        });
    }

    Ok(())
}

#[tracing::instrument(skip_all, fields(simulation_id=%simulation_id))]
async fn process_state(
    simulation_id: &str,
    rpc_tools: RPCTools,
    chain: Chain,
    component: ProtocolComponent,
    block: &Block,
    state_id: String,
    state: Box<dyn ProtocolSim>,
) {
    info!(
        "Component has tokens: {}",
        component
            .tokens
            .iter()
            .map(|t| t.symbol.as_str())
            .join(", ")
    );
    let tokens_len = component.tokens.len();
    if tokens_len < 2 {
        error!("Component has less than 2 tokens, skipping...");
        return;
    }
    // Get all the possible swap directions
    let swap_directions = match component.protocol_system.as_str() {
        HashflowClient::PROTOCOL_SYSTEM => {
            // Hashflow only supports swaps between the requested base and quote tokens
            // WARN: we read from state because the component.tokens original order
            // is modified here: src/protocol/models.rs: ProtocolComponent::from_with_tokens
            let state = match state
                .as_any()
                .downcast_ref::<HashflowState>()
            {
                Some(s) => s.clone(),
                None => {
                    warn!("Failed to downcast state to HashflowState");
                    return;
                }
            };
            vec![(state.base_token, state.quote_token)]
        }
        _ => component
            .tokens
            .iter()
            .permutations(2)
            .map(|perm| (perm[0].clone(), perm[1].clone()))
            .collect(),
    };
    for (token_in, token_out) in swap_directions.iter() {
        info!(
            "Processing {} pool {state_id}, from {} to {}",
            component.protocol_system, token_in.symbol, token_out.symbol
        );

        // Get max input/output limits
        let (max_input, max_output) = match state
            .get_limits(token_in.address.clone(), token_out.address.clone())
            .into_diagnostic()
            .wrap_err(format!(
                "Error getting limits for token_in: {}, and token_out: {}",
                token_in.symbol, token_out.symbol
            )) {
            Ok(limits) => limits,
            Err(e) => {
                warn!(
                    protocol = %component.protocol_system,
                    component_id = %state_id,
                    block = %block.header.number,
                    token_in = %token_in.address,
                    token_out = %token_out.address,
                    "{}", format_error_chain(&e)
                );
                metrics::record_get_limits_failure(
                    simulation_id,
                    &component.protocol_system,
                    &state_id,
                    block.header.number,
                    &token_in.address,
                    &token_out.address,
                    format_error_chain(&e),
                );
                continue;
            }
        };
        info!(
            "Retrieved limits: max input {max_input} {}; max output {max_output} {}",
            token_in.symbol, token_out.symbol
        );

        // Calculate amount_in as 0.1% of max_input
        // For precision, multiply by 1000 then divide by 1000
        let percentage = 0.001;
        let percentage_biguint = BigUint::from((percentage * 1000.0) as u32);
        let thousand = BigUint::from(1000u32);
        let amount_in = (&max_input * &percentage_biguint) / &thousand;
        if amount_in.is_zero() {
            warn!("Calculated amount_in is zero, skipping...");
            continue;
        }
        info!("Calculated amount_in: {amount_in} {}", token_in.symbol);

        // Get expected amount out using tycho-simulation and measure duration
        let start_time = std::time::Instant::now();
        let amount_out_result = match state
            .get_amount_out(amount_in.clone(), token_in, token_out)
            .into_diagnostic()
            .wrap_err(format!(
                "Error calculating amount out at {:.1}% with input of {amount_in} {}.",
                percentage * 100.0,
                token_in.symbol,
            )) {
            Ok(res) => res,
            Err(e) => {
                warn!(
                    protocol = %component.protocol_system,
                    component_id = %state_id,
                    block = %block.header.number,
                    token_in = %token_in.address,
                    token_out = %token_out.address,
                    amount_in = %amount_in,
                    "{}", format_error_chain(&e)
                );
                metrics::record_get_amount_out_failure(
                    simulation_id,
                    &component.protocol_system,
                    &state_id,
                    block.header.number,
                    &token_in.address,
                    &token_out.address,
                    &amount_in,
                    format_error_chain(&e),
                );
                continue;
            }
        };
        metrics::record_get_amount_out_duration(
            simulation_id,
            &component.protocol_system,
            &state_id,
            start_time.elapsed().as_secs_f64(),
        );
        let expected_amount_out = amount_out_result.amount;
        info!("Calculated amount_out: {expected_amount_out} {}", token_out.symbol);

        // Simulate execution amount out against the RPC
        let (solution, transaction) = match encode_swap(
            &component,
            Arc::from(state.clone_box()),
            token_in,
            token_out,
            amount_in.clone(),
            expected_amount_out.clone(),
            chain,
        ) {
            Ok(res) => res,
            Err(e) => {
                warn!("{}", format_error_chain(&e));
                continue;
            }
        };
        let simulated_amount_out =
            match simulate_swap_transaction(&rpc_tools, &solution, &transaction, block).await {
                Ok(amount) => {
                    metrics::record_simulation_execution_success(
                        simulation_id,
                        &component.protocol_system,
                        &state_id,
                        block.header.number,
                    );
                    amount
                }
                Err((e, state_overwrites, metadata)) => {
                    let error_msg = e.to_string();

                    // Extract revert reason from error message
                    // Error format is typically "Transaction reverted: <reason>"
                    let revert_reason =
                        if let Some(reason) = error_msg.strip_prefix("Transaction reverted: ") {
                            reason
                        } else {
                            &error_msg
                        };

                    // Extract error name (first word or function signature)
                    let error_name = extract_error_name(revert_reason);

                    // Generate Tenderly URL for debugging without state overrides
                    let tenderly_url = tenderly::build_tenderly_url(
                        &tenderly::TenderlySimParams::default(),
                        Some(&transaction),
                        Some(block),
                        Address::from_slice(&solution.sender[..20]),
                    );
                    // Generate overwrites string with metadata
                    let overwrites_string = if let Some(overwrites) = state_overwrites.as_ref() {
                        tenderly::get_overwites_string(overwrites, metadata.as_ref())
                    } else {
                        String::new()
                    };

                    error!(
                        protocol = %component.protocol_system,
                        component_id = %state_id,
                        block = %block.header.number,
                        error_message = %revert_reason,
                        error_name = %error_name,
                        tenderly_url = %tenderly_url,
                        overwrites = %overwrites_string,
                        "Failed to simulate swap: {error_msg}"
                    );
                    metrics::record_simulation_execution_failure(
                        simulation_id,
                        &component.protocol_system,
                        &state_id,
                        block.header.number,
                        revert_reason,
                        &error_name,
                        &tenderly_url,
                        &overwrites_string,
                    );

                    continue;
                }
            };
        info!("Simulated amount_out: {simulated_amount_out} {}", token_out.symbol);

        // Calculate slippage
        let slippage = if simulated_amount_out > expected_amount_out {
            let diff = &simulated_amount_out - &expected_amount_out;
            (diff.clone() * BigUint::from(10000u32)) / expected_amount_out
        } else {
            let diff = &expected_amount_out - &simulated_amount_out;
            (diff.clone() * BigUint::from(10000u32)) / expected_amount_out
        };
        let slippage = slippage.to_f64().unwrap_or(0.0) / 100.0;

        metrics::record_execution_slippage(
            simulation_id,
            &component.protocol_system,
            &state_id,
            block.header.number,
            slippage,
        );
        info!("Slippage: {:.2}%", slippage);

        info!(
            "{} pool processed {state_id} from {} to {}",
            component.protocol_system, token_in.symbol, token_out.symbol
        );
    }
}

/// Extract the error name from a revert reason string
/// Examples:
/// - "TychoRouter__NegativeSlippage(1000, 990)" -> "TychoRouter__NegativeSlippage"
/// - "arithmetic underflow or overflow" -> "arithmetic underflow or overflow"
/// - "Error(string): insufficient balance" -> "Error"
fn extract_error_name(revert_reason: &str) -> String {
    // Check if it's a function-style error (e.g., "ErrorName(...)")
    if let Some(paren_pos) = revert_reason.find('(') {
        revert_reason[..paren_pos]
            .trim()
            .to_string()
    } else if let Some(colon_pos) = revert_reason.find(':') {
        // Handle "Error: message" format
        revert_reason[..colon_pos]
            .trim()
            .to_string()
    } else {
        // Return the whole message for simple errors
        revert_reason.trim().to_string()
    }
}

#[derive(Clone)]
struct RPCTools {
    rpc_url: String,
    provider: RootProvider<Ethereum>,
    evm_balance_slot_detector: Arc<EVMBalanceSlotDetector>,
    evm_allowance_slot_detector: Arc<EVMAllowanceSlotDetector>,
}

impl RPCTools {
    pub async fn new(rpc_url: &str, chain: &Chain) -> miette::Result<Self> {
        let provider: RootProvider<Ethereum> = ProviderBuilder::default()
            .with_chain(
                NamedChain::try_from(chain.id())
                    .into_diagnostic()
                    .wrap_err("Invalid chain")?,
            )
            .connect(rpc_url)
            .await
            .into_diagnostic()
            .wrap_err("Failed to connect to provider")?;
        let evm_balance_slot_detector = Arc::new(
            EVMBalanceSlotDetector::new(BalanceSlotDetectorConfig {
                rpc_url: rpc_url.to_string(),
                ..Default::default()
            })
            .into_diagnostic()?,
        );
        let evm_allowance_slot_detector = Arc::new(
            EVMAllowanceSlotDetector::new(AllowanceSlotDetectorConfig {
                rpc_url: rpc_url.to_string(),
                ..Default::default()
            })
            .into_diagnostic()?,
        );
        Ok(Self {
            rpc_url: rpc_url.to_string(),
            provider,
            evm_balance_slot_detector,
            evm_allowance_slot_detector,
        })
    }
}

/// Generate a unique simulation ID based on protocol system and state ID
fn generate_simulation_id(protocol_system: &str, state_id: &str) -> String {
    let random_number: u32 = rand::random::<u32>() % 90000 + 10000; // Range 10000-99999
    let component_prefix = state_id
        .chars()
        .take(8)
        .collect::<String>();
    format!("{}_{}_{}", protocol_system, component_prefix, random_number)
}

/// Format the full error chain into a single string, without newlines
fn format_error_chain(e: &miette::Error) -> String {
    let mut chain = vec![];
    for cause in e.chain() {
        chain.push(format!("{cause}"));
    }
    chain.join(" -> ")
}
