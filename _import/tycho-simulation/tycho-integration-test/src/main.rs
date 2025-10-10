mod execution_simulator;
mod four_byte_client;
mod metrics;
mod stream_processor;
mod swap_simulation;
mod tenderly;
mod traces;

use std::{collections::HashMap, fmt::Debug, sync::Arc, time::Duration};

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
use miette::{miette, IntoDiagnostic, NarratableReportHandler, WrapErr};
use num_bigint::BigUint;
use num_traits::{ToPrimitive, Zero};
use tokio::sync::Semaphore;
use tracing::{error, info, trace, warn};
use tracing_subscriber::EnvFilter;
use tycho_common::simulation::protocol_sim::ProtocolSim;
use tycho_simulation::{
    protocol::models::ProtocolComponent,
    rfq::protocols::hashflow::{client::HashflowClient, state::HashflowState},
    tycho_common::models::Chain,
    utils::{get_default_url, load_all_tokens},
};

use crate::{
    stream_processor::{
        protocol_stream_processor::ProtocolStreamProcessor,
        rfq_stream_processor::RFQStreamProcessor, StreamUpdate, UpdateType,
    },
    swap_simulation::{encode_swap, simulate_swap_transaction},
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

    /// Maximum number of updates to process in parallel
    #[arg(long, default_value_t = 5)]
    parallel_updates: usize,

    /// Maximum number of simulations to run in parallel
    #[arg(short, default_value_t = 5)]
    parallel_simulations: usize,

    /// Maximum number of simulations to run per protocol update
    #[arg(long, default_value_t = 10)]
    max_simulations: usize,

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
    metrics::init_metrics();
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

    let provider: RootProvider<Ethereum> = ProviderBuilder::default()
        .with_chain(
            NamedChain::try_from(chain.id())
                .into_diagnostic()
                .wrap_err("Invalid chain")?,
        )
        .connect(&cli.rpc_url)
        .await
        .into_diagnostic()
        .wrap_err("Failed to connect to provider")?;

    // Load tokens from Tycho
    let tycho_url =
        get_default_url(&chain).ok_or_else(|| miette!("No default Tycho URL for chain {chain}"))?;
    info!(%tycho_url, "Loading tokens...");
    let all_tokens =
        load_all_tokens(&tycho_url, false, Some(cli.tycho_api_key.as_str()), chain, None, None)
            .await;
    info!(%tycho_url, "Loaded tokens");

    // Run streams in background tasks
    let (tx, mut rx) = tokio::sync::mpsc::channel(64);
    if !cli.disable_onchain {
        if let Ok(protocol_stream_processor) = ProtocolStreamProcessor::new(
            chain,
            tycho_url.clone(),
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
            cli.max_simulations,
            Duration::from_secs(cli.skip_messages_duration),
        ) {
            rfq_stream_processor
                .run_stream(&all_tokens, tx)
                .await?;
        }
    }

    // Process streams updates
    info!("Waiting for first protocol update...");
    let semaphore = Arc::new(Semaphore::new(cli.parallel_updates));
    let protocol_pairs = Arc::new(std::sync::RwLock::new(HashMap::new()));
    while let Some(update) = rx.recv().await {
        let semaphore = semaphore.clone();
        let cli = cli.clone();
        let provider = provider.clone();
        let protocol_pairs = protocol_pairs.clone();
        tokio::spawn(async move {
            let update = match update {
                Ok(u) => Arc::new(u),
                Err(e) => {
                    warn!("{e:?}");
                    return;
                }
            };
            let _permit = semaphore.acquire().await.unwrap();
            if let Err(e) = process_update(cli, chain, provider, protocol_pairs, &update).await {
                warn!("{e:?}");
            }
        });
    }

    Ok(())
}

async fn process_update(
    cli: Arc<Cli>,
    chain: Chain,
    provider: RootProvider<Ethereum>,
    protocol_pairs: Arc<std::sync::RwLock<HashMap<String, ProtocolComponent>>>,
    update: &StreamUpdate,
) -> miette::Result<()> {
    info!(
        "Got protocol update with block {}, {} new pairs, and {} states",
        update.update.block_number_or_timestamp,
        update.update.new_pairs.len(),
        update.update.states.len()
    );

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .into_diagnostic()?
        .as_secs();
    let block = match provider
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

    // Record block processing latency
    let latency_seconds = (now as i64 - block.header.timestamp as i64).abs() as f64;
    metrics::record_block_processing_latency(latency_seconds);

    if let UpdateType::Protocol = update.update_type {
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
            metrics::record_skipped_update();
            return Ok(());
        }
        metrics::record_block_delay(block_delay);

        {
            let mut pairs = protocol_pairs.write().map_err(|e| {
                miette::miette!("Failed to acquire write lock on protocol pairs: {e}")
            })?;
            for (id, comp) in update.update.new_pairs.iter() {
                pairs
                    .entry(id.clone())
                    .or_insert_with(|| comp.clone());
            }
        }
        if update.is_first_update {
            info!("Skipping simulation on first protocol update...");
            return Ok(());
        }
    }

    for (protocol, sync_state) in update.update.sync_states.iter() {
        metrics::record_protocol_sync_state(protocol, sync_state);
    }

    // Process states in parallel
    let semaphore = Arc::new(Semaphore::new(cli.parallel_simulations));
    for (id, state) in update
        .update
        .states
        .iter()
        .take(cli.max_simulations)
    {
        let component = match update.update_type {
            UpdateType::Protocol => {
                let pairs = protocol_pairs.read().map_err(|e| {
                    miette::miette!("Failed to acquire read lock on protocol pairs: {e}")
                })?;
                match pairs.get(id) {
                    Some(comp) => comp.clone(),
                    None => {
                        trace!("Component not found in protocol pairs");
                        continue;
                    }
                }
            }
            UpdateType::Rfq => match update.update.new_pairs.get(id) {
                Some(comp) => comp.clone(),
                None => {
                    trace!("Component not found in RFQ pairs");
                    continue;
                }
            },
        };
        let semaphore = semaphore.clone();
        let cli = cli.clone();
        let block = block.clone();
        let state_id = id.clone();
        let state = state.clone_box();
        tokio::spawn(async move {
            let _permit = semaphore.acquire().await.unwrap();
            process_update_state(&cli, chain, component, &block, state_id, state).await;
        });
    }

    Ok(())
}

async fn process_update_state(
    cli: &Cli,
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
                warn!("{e:?}");
                metrics::record_get_limits_failures(
                    &component.protocol_system,
                    &state_id,
                    block.header.number,
                    &token_in.address,
                    &token_out.address,
                    e.to_string(),
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
                warn!("{e}");
                metrics::record_get_amount_out_failures(
                    &component.protocol_system,
                    &state_id,
                    block.header.number,
                    &token_in.address,
                    &token_out.address,
                    &amount_in,
                    e.to_string(),
                );
                continue;
            }
        };
        metrics::record_get_amount_out_duration(
            &component.protocol_system,
            start_time.elapsed().as_secs_f64(),
            &state_id,
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
                warn!("{e:?}");
                continue;
            }
        };
        let simulated_amount_out =
            match simulate_swap_transaction(&cli.rpc_url, &solution, &transaction, block).await {
                Ok(amount) => {
                    metrics::record_simulation_execution_success();
                    metrics::record_simulation_execution_success_detailed(
                        &component.protocol_system,
                        &state_id,
                        block.header.number,
                    );
                    amount
                }
                Err((e, state_overwrites, metadata)) => {
                    let error_msg = e.to_string();
                    error!("Failed to simulate swap: {error_msg}");

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

                    metrics::record_simulation_execution_failure(revert_reason);
                    metrics::record_simulation_execution_failure_detailed(
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

        metrics::record_slippage(
            block.header.number,
            &component.protocol_system,
            &state_id,
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
