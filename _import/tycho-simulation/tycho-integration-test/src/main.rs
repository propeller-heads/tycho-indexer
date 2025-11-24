mod metrics;
mod stream_processor;

use std::{
    collections::{HashMap, HashSet},
    fmt::Debug,
    str::FromStr,
    sync::{Arc, RwLock},
    time::Duration,
};

use alloy::{eips::BlockNumberOrTag, primitives::Address, providers::Provider, rpc::types::Block};
use clap::Parser;
use dotenv::dotenv;
use itertools::Itertools;
use miette::{miette, IntoDiagnostic, NarratableReportHandler, WrapErr};
use num_bigint::BigUint;
use num_traits::{ToPrimitive, Zero};
use rand::prelude::IndexedRandom;
use tokio::sync::Semaphore;
use tracing::{debug, error, info, warn};
use tracing_subscriber::EnvFilter;
use tycho_common::simulation::protocol_sim::ProtocolSim;
use tycho_simulation::{
    protocol::models::ProtocolComponent,
    rfq::protocols::hashflow::{client::HashflowClient, state::HashflowState},
    tycho_common::models::Chain,
    utils::load_all_tokens,
};
use tycho_test::validation::{batch_validate_components, get_validator, Validator};
use tycho_test::execution::{
    encoding::encode_swap,
    models::{TychoExecutionInput, TychoExecutionResult},
    simulate_swap_transaction, tenderly,
};

use crate::stream_processor::{
    protocol_stream_processor::ProtocolStreamProcessor, rfq_stream_processor::RFQStreamProcessor,
    StreamUpdate, UpdateType,
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

    /// Maximum number of simulations (of updated states) to run per update
    #[arg(long, default_value_t = 10, value_parser = clap::value_parser!(u16).range(1..))]
    max_simulations: u16,

    /// Maximum number of simulations (of stale states) to run per update per protocol
    #[arg(long, default_value_t = 10, value_parser = clap::value_parser!(u16).range(1..))]
    max_simulations_stale: u16,

    /// The RFQ stream will skip messages for this duration (in seconds) after processing a message
    #[arg(long, default_value_t = 600)]
    skip_messages_duration: u64,

    /// List of component IDs to always include in tests every block if not already selected
    #[arg(long, value_delimiter = ',')]
    always_test_components: Vec<String>,
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

#[derive(Default)]
struct TychoState {
    states: HashMap<String, Box<dyn ProtocolSim>>,
    components: HashMap<String, ProtocolComponent>,
    component_ids_by_protocol: HashMap<String, HashSet<String>>,
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

    let rpc_tools = tycho_test::RPCTools::new(&cli.rpc_url, &chain).await?;

    // Load tokens from Tycho
    info!(%cli.tycho_url, "Loading tokens...");
    let all_tokens = load_all_tokens(
        &cli.tycho_url,
        false,
        Some(cli.tycho_api_key.as_str()),
        true,
        chain,
        None,
        None,
    )
    .await
    .map_err(|e| miette!("Failed to load tokens: {e:?}"))?;
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

    let tycho_state = Arc::new(RwLock::new(TychoState::default()));

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
        let tycho_state = tycho_state.clone();
        let permit = semaphore
            .clone()
            .acquire_owned()
            .await
            .into_diagnostic()
            .wrap_err("Failed to acquire permit")?;
        tokio::spawn(async move {
            if let Err(e) = process_update(cli, chain, rpc_tools, tycho_state, &update).await {
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
    rpc_tools: tycho_test::RPCTools,
    tycho_state: Arc<RwLock<TychoState>>,
    update: &StreamUpdate,
) -> miette::Result<()> {
    info!(
        "Got protocol update with block/timestamp {}, {} new pairs, and {} states",
        update.update.block_number_or_timestamp,
        update.update.new_pairs.len(),
        update.update.states.len()
    );

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
            let mut current_state = tycho_state
                .write()
                .map_err(|e| miette!("Failed to acquire write lock on Tycho state: {e}"))?;
            for (id, comp) in update.update.new_pairs.iter() {
                current_state
                    .components
                    .insert(id.clone(), comp.clone());
                current_state
                    .component_ids_by_protocol
                    .entry(comp.protocol_system.clone())
                    .or_insert_with(HashSet::new)
                    .insert(id.clone());
            }
            for (id, state) in update.update.states.iter() {
                // this overwrites existing entries
                current_state
                    .states
                    .insert(id.clone(), state.clone());
            }
        }
        // Record block processing latency
        let latency_seconds =
            (update.received_at.as_secs_f64() - block.header.timestamp as f64).abs();
        metrics::record_block_processing_duration(latency_seconds);

        let block_delay = block
            .header
            .number
            .abs_diff(update.update.block_number_or_timestamp);
        metrics::record_protocol_update_block_delay(block_delay);
        // Consume messages that are older than the current block, to give the stream a chance
        // to catch up
        if block_delay > 0 {
            warn!(
                "Update block ({}) is behind the current block ({}), skipping to catch up.",
                update.update.block_number_or_timestamp, block.header.number
            );
            metrics::record_protocol_update_skipped();
            return Ok(());
        }

        if update.is_first_update {
            info!("Skipping simulation on first protocol update...");
            return Ok(());
        }
    }

    for (protocol, sync_state) in update.update.sync_states.iter() {
        metrics::record_protocol_sync_state(protocol, sync_state);
    }

    // Collect all components to process (both updated and stale) for batch validation
    let mut components_to_process: Vec<(String, ProtocolComponent, Box<dyn ProtocolSim>)> =
        Vec::new();

    // Collect updated components
    for (id, state) in update
        .update
        .states
        .iter()
        .take(cli.max_simulations as usize)
    {
        let component = match update.update_type {
            UpdateType::Protocol => {
                let states = &tycho_state
                    .read()
                    .map_err(|e| miette!("Failed to acquire read lock on Tycho state: {e}"))?
                    .components;
                match states.get(id) {
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
        components_to_process.push((id.clone(), component, state.clone_box()));
    }

    // Collect stale components (not updated in this block)
    let selected_ids = {
        let current_state = tycho_state
            .read()
            .map_err(|e| miette!("Failed to acquire write lock on Tycho state: {e}"))?;

        let mut all_selected_ids = Vec::new();

        for component_id in &cli.always_test_components {
            if !update
                .update
                .states
                .keys()
                .contains(component_id) &&
                current_state
                    .components
                    .contains_key(component_id)
            {
                all_selected_ids.push(component_id.clone());
            }
        }

        for component_ids in current_state
            .component_ids_by_protocol
            .values()
        {
            let available_ids: Vec<_> = component_ids
                .iter()
                .filter(|id| {
                    !update.update.states.keys().contains(id) && !all_selected_ids.contains(id)
                })
                .cloned()
                .collect();

            let protocol_selected_ids: Vec<_> = available_ids
                .choose_multiple(
                    &mut rand::rng(),
                    (cli.max_simulations_stale as usize).min(available_ids.len()),
                )
                .cloned()
                .collect();

            all_selected_ids.extend(protocol_selected_ids);
        }
        all_selected_ids
    };

    for id in &selected_ids {
        let (component, state) = {
            let current_state = tycho_state
                .read()
                .map_err(|e| miette!("Failed to acquire read lock on Tycho state: {e}"))?;

            match (current_state.components.get(id), current_state.states.get(id)) {
                (Some(comp), Some(state)) => (comp.clone(), state.clone()),
                (None, _) => {
                    error!(id=%id, "Component not found in saved protocol components.");
                    continue;
                }
                (_, None) => {
                    error!(id=%id, "State not found in saved protocol states");
                    continue;
                }
            }
        };
        components_to_process.push((id.clone(), component, state.clone_box()));
    }

    // Collect components that implement Validator for batch validation
    let mut validator_components: Vec<(
        &dyn Validator,
        tycho_common::Bytes,
        String, // protocol_system
    )> = Vec::new();

    for (id, component, state) in &components_to_process {
        let component_id = tycho_common::Bytes::from_str(id)
            .unwrap_or_else(|_| tycho_common::Bytes::from(id.as_bytes()));

        if let Some(validator) = get_validator(&component.protocol_system, state.as_ref()) {
            validator_components.push((validator, component_id, component.protocol_system.clone()));
        }
    }

    // Batch validate all components of this block in a single call
    if !validator_components.is_empty() {
        // Extract just the validator data (without protocol_system) for batch_validate_components
        let validator_data: Vec<_> = validator_components
            .iter()
            .map(|(validator, id, _protocol)| (*validator, id.clone()))
            .collect();

        let results =
            batch_validate_components(&cli.rpc_url, &validator_data, block.header.number).await;

        for (i, result) in results.iter().enumerate() {
            let component_id = &validator_components[i].1;
            let protocol = &validator_components[i].2;
            match result {
                Ok(passed) => {
                    if *passed {
                        info!(
                            component_id = %component_id,
                            "State validation passed"
                        );
                    } else {
                        error!(
                            component_id = %component_id,
                            "State validation failed"
                        );
                        metrics::record_validation_failure(protocol);
                    }
                }
                Err(e) => {
                    error!(
                        component_id = %component_id,
                        error = %e,
                        "Error validating component"
                    );
                    metrics::record_validation_failure(protocol);
                }
            }
        }
    }

    // Process all components (updated and stale) in parallel
    let semaphore = Arc::new(Semaphore::new(cli.parallel_simulations as usize));
    let mut tasks = Vec::new();

    for (id, component, state) in components_to_process {
        let block = block.clone();
        let permit = semaphore
            .clone()
            .acquire_owned()
            .await
            .into_diagnostic()
            .wrap_err("Failed to acquire permit")?;

        let task = tokio::spawn(async move {
            let simulation_id = generate_simulation_id(&component.protocol_system, &id);
            let result = process_state(&simulation_id, chain, component, &block, id, state).await;
            drop(permit);
            result
        });
        tasks.push(task);
    }

    let mut block_execution_info = HashMap::new();

    for task in tasks {
        match task.await {
            Ok(execution_data) => {
                block_execution_info.extend(execution_data);
            }
            Err(e) => {
                warn!("Task failed: {:?}", e);
            }
        }
    }

    if block_execution_info.is_empty() {
        warn!("No simulations were gathered for block {}", block.number());
        return Ok(())
    }

    let results =
        match simulate_swap_transaction(&rpc_tools, block_execution_info.clone(), &block, None)
            .await
        {
            Ok(results) => results,
            Err((e, _, _)) => return Err(e),
        };

    let mut n_reverts = 0;
    let mut n_failures = 0;
    let total_simulations = results.len();
    for (simulation_id, result) in &results {
        let execution_info = match block_execution_info.get(simulation_id) {
            Some(info) => info,
            None => {
                error!("Simulation ID {simulation_id} not found in execution_info HashMap");
                continue;
            }
        }
        .clone();

        let state_str = {
            let current_state = tycho_state
                .read()
                .map_err(|e| miette!("Failed to acquire read lock on Tycho state: {e}"))?;

            match current_state
                .states
                .get(&execution_info.component_id)
            {
                Some(state) => format!("{:?}", state),
                None => "".to_string(),
            }
        };
        process_execution_result(
            simulation_id,
            result,
            execution_info,
            state_str,
            (*block).clone(),
            chain.id().to_string(),
            &mut n_reverts,
            &mut n_failures,
        );
    }
    if n_reverts > 0 || n_failures > 0 {
        warn!("For block {}, simulated {total_simulations} executions, {n_reverts} simulations reverted, {n_failures} executions setup failed", block.number())
    }

    Ok(())
}

#[tracing::instrument(
    skip_all,
    fields(
        simulation_id = %simulation_id,
        protocol = %component.protocol_system,
        component_id = %state_id,
        block_number = %block.header.number,
    )
)]
async fn process_state(
    simulation_id: &str,
    chain: Chain,
    component: ProtocolComponent,
    block: &Block,
    state_id: String,
    state: Box<dyn ProtocolSim>,
) -> HashMap<String, TychoExecutionInput> {
    let tokens_len = component.tokens.len();
    if tokens_len < 2 {
        error!("Component has less than 2 tokens, skipping...");
        return HashMap::new();
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
                    return HashMap::new();
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
    let mut execution_infos = HashMap::new();
    for (i, (token_in, token_out)) in swap_directions.iter().enumerate() {
        debug!(
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
            Ok(limits) => {
                metrics::record_get_limits_success(&component.protocol_system);
                limits
            }
            Err(e) => {
                error!(
                    event_type = "get_limits_failure",
                    token_in = %token_in.address,
                    token_out = %token_out.address,
                    error = %format_error_chain(&e),
                    "Get limits operation failed: {}", format_error_chain(&e)
                );
                debug!(
                    event_type = "get_limits_failure",
                    state = ?state,
                    "Get limits operation failed: {}", format_error_chain(&e)
                );
                metrics::record_get_limits_failure(&component.protocol_system);
                continue;
            }
        };
        debug!(
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
            debug!("Calculated amount_in is zero, skipping...");
            continue;
        }

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
            Ok(res) => {
                metrics::record_get_amount_out_success(&component.protocol_system);
                res
            }
            Err(e) => {
                error!(
                    event_type = "get_amount_out_failure",
                    token_in = %token_in.address,
                    token_out = %token_out.address,
                    amount_in = %amount_in,
                    error = %format_error_chain(&e),
                    "Get amount out operation failed: {}", format_error_chain(&e)
                );
                debug!(
                    event_type = "get_amount_out_failure",
                    state = ?state,
                    "Get amount out operation failed: {}", format_error_chain(&e)
                );
                metrics::record_get_amount_out_failure(&component.protocol_system);
                continue;
            }
        };
        let duration_seconds = start_time.elapsed().as_secs_f64();
        let expected_amount_out = amount_out_result.amount;
        debug!(
            event_type = "get_amount_out_duration",
            token_in = %token_in.address,
            token_out = %token_out.address,
            amount_in = %amount_in,
            amount_out = %expected_amount_out,
            duration_seconds = duration_seconds,
            "Get amount out operation completed in {:.3}ms", duration_seconds * 1000.0
        );
        metrics::record_get_amount_out_duration(&component.protocol_system, duration_seconds);

        // Sometimes the expected amount out might be zero (e.g. pool is depleted in one direction)
        // Then execution will fail with TychoRouter__UndefinedMinAmountOut
        if expected_amount_out == BigUint::ZERO {
            continue
        }
        // Simulate execution amount out against the RPC
        let (solution, transaction) = match encode_swap(
            &component,
            Some(Arc::from(state.clone_box())),
            token_in,
            token_out,
            amount_in.clone(),
            chain,
            None,
            false,
        ) {
            Ok(res) => res,
            Err(e) => {
                warn!("{}", format_error_chain(&e));
                continue;
            }
        };
        execution_infos.insert(
            format!("{}-{:?}", simulation_id, i),
            TychoExecutionInput {
                solution,
                transaction,
                expected_amount_out,
                protocol_system: component.protocol_system.clone(),
                component_id: component.id.to_string(),
                token_in: token_in.address.to_string(),
                token_out: token_out.address.to_string(),
            },
        );
    }
    execution_infos
}

/// Processes the result of a Tycho simulation execution and emits metrics.
///
/// Handles success, revert, and failure cases by logging appropriate events and recording
/// metrics. Calculates slippage for successful executions and updates counters for
/// reverts and failures.
///
/// Returns updated counters for reverts and failures.
#[tracing::instrument(
    skip_all,
    fields(
        simulation_id = %simulation_id,
        protocol = %execution_info.protocol_system,
        block_number = %block.header.number,
        component_id = %execution_info.component_id,
    )
)]
#[allow(clippy::too_many_arguments)]
fn process_execution_result(
    simulation_id: &String,
    result: &TychoExecutionResult,
    execution_info: TychoExecutionInput,
    state_str: String,
    block: Block,
    chain_id: String,
    n_reverts: &mut i32,
    n_failures: &mut i32,
) {
    match result {
        TychoExecutionResult::Success { gas_used, amount_out } => {
            debug!(
                event_type = "simulation_execution_success",
                amount_out = amount_out.to_string(),
                gas_used = gas_used,
                "Simulation execution succeeded"
            );

            metrics::record_simulation_execution_success(&execution_info.protocol_system);

            // Calculate slippage: positive = simulated > expected, negative = simulated <
            // expected
            let slippage = if amount_out >= &execution_info.expected_amount_out {
                let diff = amount_out - &execution_info.expected_amount_out;
                ((diff.clone() * BigUint::from(10000u32)) / &execution_info.expected_amount_out)
                    .to_f64()
                    .unwrap_or(0.0) /
                    100.0
            } else {
                let diff = &execution_info.expected_amount_out - amount_out;
                -((diff.clone() * BigUint::from(10000u32)) / &execution_info.expected_amount_out)
                    .to_f64()
                    .unwrap_or(0.0) /
                    100.0
            };

            if !(-1.0..=1.0).contains(&slippage) {
                info!(
                    event_type = "execution_slippage",
                    token_in = %execution_info.token_in,
                    token_out = %execution_info.token_out,
                    simulated_amount  = %amount_out,
                    executed_amount = %execution_info.expected_amount_out,
                    slippage_ratio = slippage,
                    "Execution slippage: {:.2}%",
                    slippage
                );
                debug!(
                    event_type = "execution_slippage",
                    state = ?state_str,
                    "Execution slippage: {:.2}%",
                    slippage
                )
            } else {
                // don't show the state in this case to not overwhelm the logs
                debug!(
                    event_type = "execution_slippage",
                    token_in = %execution_info.token_in,
                    token_out = %execution_info.token_out,
                    simulated_amount  = %amount_out,
                    executed_amount = %execution_info.expected_amount_out,
                    slippage_ratio = slippage,
                    "Execution slippage: {:.2}%",
                    slippage
                );
            }

            metrics::record_execution_slippage(&execution_info.protocol_system, slippage);
        }
        TychoExecutionResult::Revert { reason, state_overwrites, overwrite_metadata } => {
            *n_reverts += 1;
            let error_msg = reason.to_string();

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
            let overrides =
                tenderly::TenderlySimParams { network: Some(chain_id), ..Default::default() };
            let tenderly_url = tenderly::build_tenderly_url(
                &overrides,
                Some(&execution_info.transaction),
                Some(&block),
                Address::from_slice(&execution_info.solution.sender[..20]),
            );

            let overwrites_string = if let Some(overwrites) = state_overwrites.as_ref() {
                tenderly::get_overwrites_string(overwrites, overwrite_metadata)
            } else {
                String::new()
            };
            let error_category = categorize_error(&error_name);
            error!(
                event_type = "simulation_execution_failure",
                error_message = %revert_reason,
                error_name = %error_name,
                error_category = %error_category,
                amount_in =%execution_info.solution.given_amount,
                token_in = %execution_info.token_in,
                token_out = %execution_info.token_out,
                tenderly_url = %tenderly_url,
                overwrites = %overwrites_string,
                "Failed to simulate swap: {error_msg}"
            );
            debug!(event_type = "simulation_execution_failure",
                state = ?state_str,
                "State of failed swap: {error_msg}");
            metrics::record_simulation_execution_failure(
                &execution_info.protocol_system,
                error_category,
            );
        }
        TychoExecutionResult::Failed { error_msg } => {
            *n_failures += 1;

            let error_category = categorize_error(error_msg);
            error!(
                event_type = "simulation_execution_failure",
                error_message = %error_msg,
                error_category = %error_category,
                amount_in =%execution_info.solution.given_amount,
                token_in = %execution_info.token_in,
                token_out = %execution_info.token_out,
                "Failed to simulate swap: {error_msg}"
            );
            metrics::record_simulation_execution_failure(
                &execution_info.protocol_system,
                error_category,
            );
        }
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

fn categorize_error(error_name: &str) -> &'static str {
    // We can add more categories here when we find new meaningful ones
    match error_name {
        e if e.contains("Couldn't find storage slot") => "Storage slot not found",
        e if e.contains("TychoRouter__NegativeSlippage") => "TychoRouter__NegativeSlippage",
        e if e.contains("0xf7bf5832") => "Fee token", /* Decodes to TychoRouter__AmountOutNotFullyReceived */
        e if e.contains("UniswapV2: K") => "Fee token",
        _ => "other",
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
