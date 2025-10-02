mod execution_simulator;
mod four_byte_client;
mod metrics;
mod traces;

use std::{collections::HashMap, fmt::Debug, str::FromStr};

use alloy::{
    eips::BlockNumberOrTag,
    network::Ethereum,
    primitives::{map::AddressHashMap, Address, Keccak256, U256},
    providers::{Provider, ProviderBuilder, RootProvider},
    rpc::types::{state::AccountOverride, Block, TransactionRequest},
    sol_types::SolValue,
};
use alloy_chains::NamedChain;
use clap::Parser;
use dotenv::dotenv;
use execution_simulator::ExecutionSimulator;
use futures::{Stream, StreamExt};
use itertools::Itertools;
use miette::{miette, IntoDiagnostic, WrapErr};
use num_bigint::BigUint;
use num_traits::{ToPrimitive, Zero};
use tokio_retry2::{
    strategy::{jitter, ExponentialFactorBackoff},
    Retry, RetryError,
};
use tracing::{debug, error, info, trace, warn};
use tracing_subscriber::EnvFilter;
use tycho_ethereum::entrypoint_tracer::{
    allowance_slot_detector::{AllowanceSlotDetectorConfig, EVMAllowanceSlotDetector},
    balance_slot_detector::{BalanceSlotDetectorConfig, EVMBalanceSlotDetector},
};
use tycho_execution::encoding::{
    evm::encoder_builders::TychoRouterEncoderBuilder,
    models::{EncodedSolution, Solution, SwapBuilder, Transaction, UserTransferType},
};
use tycho_simulation::{
    evm::{
        decoder::StreamDecodeError,
        engine_db::tycho_db::PreCachedDB,
        protocol::{
            ekubo::state::EkuboState,
            filters::{
                balancer_v2_pool_filter, curve_pool_filter, uniswap_v4_pool_with_hook_filter,
            },
            pancakeswap_v2::state::PancakeswapV2State,
            u256_num::biguint_to_u256,
            uniswap_v2::state::UniswapV2State,
            uniswap_v3::state::UniswapV3State,
            uniswap_v4::state::UniswapV4State,
            vm::state::EVMPoolState,
        },
        stream::ProtocolStreamBuilder,
    },
    protocol::models::{ProtocolComponent, Update},
    tycho_client::feed::component_tracker::ComponentFilter,
    tycho_common::{
        models::{token::Token, Chain},
        traits::{AllowanceSlotDetector, BalanceSlotDetector},
        Bytes,
    },
    utils::{get_default_url, load_all_tokens},
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

    /// Port for the Prometheus metrics server
    #[arg(long, default_value_t = 9898)]
    metrics_port: u16,
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
    dotenv().ok();

    // Initialize tracing
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

    let chain = cli.chain;

    // Load tokens from Tycho
    let tycho_url =
        get_default_url(&chain).ok_or_else(|| miette!("No default Tycho URL for chain {chain}"))?;
    info!(%tycho_url, "Loading tokens...");
    let all_tokens =
        load_all_tokens(&tycho_url, false, Some(cli.tycho_api_key.as_str()), chain, None, None)
            .await;
    info!(%tycho_url, "Loaded tokens");

    // Create provider
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

    // Init stream
    let mut pairs: HashMap<String, ProtocolComponent> = HashMap::new();
    let mut protocol_stream = build_protocol_stream(&cli, chain, &tycho_url, &all_tokens).await?;
    let mut first_message_skipped = false;

    while let Some(res) = protocol_stream.next().await {
        let message = match res {
            Ok(msg) => msg,
            Err(e) => {
                warn!("Error receiving message: {e:?}");
                warn!("Continuing to next message...");
                continue;
            }
        };
        info!("Received block {:?}", message.block_number_or_timestamp);
        for (id, comp) in message.new_pairs.iter() {
            pairs
                .entry(id.clone())
                .or_insert_with(|| comp.clone());
        }
        let block = match provider
            .get_block_by_number(BlockNumberOrTag::Latest)
            .await
            .into_diagnostic()
            .wrap_err("Failed to fetch latest block")
        {
            Ok(b) => b,
            Err(e) => {
                warn!("{e}");
                continue;
            }
        };
        let block = match block {
            Some(b) => b,
            None => {
                warn!("Failed to retrieve last block, continuing to next message...");
                continue;
            }
        };
        // TODO why do we do this? Don't we also want to simulate on the first block?
        if !first_message_skipped {
            first_message_skipped = true;
            info!("Skipping simulation on first block...");
            continue;
        }
        for (id, state) in message.states.iter() {
            let component = match pairs.get(id) {
                Some(comp) => comp.clone(),
                None => {
                    trace!("Component {id} not found in pairs");
                    continue;
                }
            };
            let tokens_len = component.tokens.len();
            if tokens_len < 2 {
                error!("Component {id} has less than 2 tokens, skipping...");
                continue;
            }
            let swap_directions: Vec<(Token, Token)> = component
                .tokens
                .iter()
                .permutations(2)
                .map(|perm| (perm[0].clone(), perm[1].clone()))
                .collect();
            for (token_in, token_out) in swap_directions.iter() {
                info!(
                    "Processing {} pool {id:?}, from {} to {}",
                    component.protocol_system, token_in.symbol, token_out.symbol
                );

                // Get max input/output limits
                let (max_input, max_output) = match state
                    .get_limits(token_in.address.clone(), token_out.address.clone())
                    .into_diagnostic()
                    .wrap_err(format!(
                        "Error getting limits for Pool {id:?} for in token: {}, and out token: {}",
                        token_in.address, token_out.address
                    )) {
                    Ok(limits) => limits,
                    Err(e) => {
                        warn!("{e}");
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

                // Get expected amount out using tycho-simulation
                let amount_out_result = match state
                    .get_amount_out(amount_in.clone(), token_in, token_out)
                    .into_diagnostic()
                    .wrap_err(format!(
                        "Error calculating amount out for Pool {id:?} at {:.1}% with input of {amount_in} {}.",
                        percentage * 100.0,
                        token_in.symbol,
                    )) {
                        Ok(res) => res,
                        Err(e) => {
                            warn!("{e}");
                            continue;
                        }
                };
                let expected_amount_out = amount_out_result.amount;
                info!("Calculated amount_out: {expected_amount_out} {}", token_out.symbol);

                // Simulate execution amount out against the RPC
                let (solution, transaction) = match encode_swap(
                    &component,
                    token_in,
                    token_out,
                    amount_in.clone(),
                    expected_amount_out.clone(),
                    chain,
                ) {
                    Ok(res) => res,
                    Err(e) => {
                        warn!("{e}");
                        continue;
                    }
                };
                let simulated_amount_out =
                    match simulate_swap_transaction(&cli.rpc_url, &solution, &transaction, &block)
                        .await
                    {
                        Ok(amount) => {
                            metrics::record_simulation_success();
                            amount
                        }
                        Err(e) => {
                            let error_msg = e.to_string();
                            error!("Failed to simulate swap: {error_msg}");

                            // Extract revert reason from error message
                            // Error format is typically "Transaction reverted: <reason>"
                            let revert_reason = if let Some(reason) =
                                error_msg.strip_prefix("Transaction reverted: ")
                            {
                                reason
                            } else {
                                &error_msg
                            };

                            metrics::record_simulation_failure(revert_reason);
                            continue;
                        }
                    };
                info!("Simulated amount_out: {simulated_amount_out} {}", token_out.symbol);

                // Calculate slippage
                let slippage = if simulated_amount_out > expected_amount_out {
                    let diff = &simulated_amount_out - &expected_amount_out;
                    let slippage = (diff.clone() * BigUint::from(10000u32)) / expected_amount_out;
                    format!("+{:.2}%", slippage.to_f64().unwrap_or(0.0) / 100.0)
                } else {
                    let diff = &expected_amount_out - &simulated_amount_out;
                    let slippage = (diff.clone() * BigUint::from(10000u32)) / expected_amount_out;
                    format!("-{:.2}%", slippage.to_f64().unwrap_or(0.0) / 100.0)
                };
                info!("Slippage: {slippage}");

                info!("Pool processed {id:?} from {} to {}", token_in.symbol, token_out.symbol);
            }
        }
    }

    Ok(())
}

async fn build_protocol_stream(
    cli: &Cli,
    chain: Chain,
    tycho_url: &str,
    all_tokens: &HashMap<Bytes, Token>,
) -> miette::Result<impl Stream<Item = Result<Update, StreamDecodeError>>> {
    let mut protocol_stream = ProtocolStreamBuilder::new(tycho_url, chain);
    let tvl_filter = ComponentFilter::with_tvl_range(cli.tvl_threshold, cli.tvl_threshold);

    match chain {
        Chain::Ethereum => {
            protocol_stream = protocol_stream
                .exchange::<UniswapV2State>("uniswap_v2", tvl_filter.clone(), None)
                .exchange::<UniswapV2State>("sushiswap_v2", tvl_filter.clone(), None)
                .exchange::<PancakeswapV2State>("pancakeswap_v2", tvl_filter.clone(), None)
                .exchange::<UniswapV3State>("uniswap_v3", tvl_filter.clone(), None)
                .exchange::<UniswapV3State>("pancakeswap_v3", tvl_filter.clone(), None)
                .exchange::<EVMPoolState<PreCachedDB>>(
                    "vm:balancer_v2",
                    tvl_filter.clone(),
                    Some(balancer_v2_pool_filter),
                )
                .exchange::<UniswapV4State>(
                    "uniswap_v4",
                    tvl_filter.clone(),
                    Some(uniswap_v4_pool_with_hook_filter),
                )
                .exchange::<EkuboState>("ekubo_v2", tvl_filter.clone(), None)
                .exchange::<EVMPoolState<PreCachedDB>>(
                    "vm:curve",
                    tvl_filter.clone(),
                    Some(curve_pool_filter),
                );
        }
        Chain::Base => {
            protocol_stream = protocol_stream
                .exchange::<UniswapV2State>("uniswap_v2", tvl_filter.clone(), None)
                .exchange::<UniswapV3State>("uniswap_v3", tvl_filter.clone(), None)
                .exchange::<UniswapV4State>(
                    "uniswap_v4",
                    tvl_filter.clone(),
                    Some(uniswap_v4_pool_with_hook_filter),
                )
        }
        Chain::Unichain => {
            protocol_stream = protocol_stream
                .exchange::<UniswapV2State>("uniswap_v2", tvl_filter.clone(), None)
                .exchange::<UniswapV3State>("uniswap_v3", tvl_filter.clone(), None)
                .exchange::<UniswapV4State>(
                    "uniswap_v4",
                    tvl_filter.clone(),
                    Some(uniswap_v4_pool_with_hook_filter),
                )
        }
        _ => {}
    }

    protocol_stream
        .auth_key(Some(cli.tycho_api_key.clone()))
        .skip_state_decode_failures(true)
        .set_tokens(all_tokens.clone())
        .await
        .build()
        .await
        .into_diagnostic()
        .wrap_err("Failed building protocol stream")
}

fn encode_swap(
    component: &ProtocolComponent,
    sell_token: &Token,
    buy_token: &Token,
    amount_in: BigUint,
    expected_amount_out: BigUint,
    chain: Chain,
) -> miette::Result<(Solution, Transaction)> {
    let solution = create_solution(
        component.clone(),
        sell_token.clone(),
        buy_token.clone(),
        amount_in.clone(),
        expected_amount_out.clone(),
    )?;
    let encoded_solution = {
        let encoder = TychoRouterEncoderBuilder::new()
            .chain(chain)
            .user_transfer_type(UserTransferType::TransferFrom)
            .build()
            .into_diagnostic()
            .wrap_err("Failed to build encoder")?;
        encoder
            .encode_solutions(vec![solution.clone()])
            .into_diagnostic()
            .wrap_err("Failed to encode router calldata")?
            .into_iter()
            .next()
            .ok_or_else(|| miette!("Missing solution"))?
    };
    let transaction =
        encoded_transaction(encoded_solution.clone(), &solution, chain.native_token().address)?;
    Ok((solution, transaction))
}

fn create_solution(
    component: ProtocolComponent,
    sell_token: Token,
    buy_token: Token,
    amount_in: BigUint,
    expected_amount_out: BigUint,
) -> miette::Result<Solution> {
    let user_address =
        Bytes::from_str("0xf847a638E44186F3287ee9F8cAF73FF4d4B80784").into_diagnostic()?;

    // Prepare data to encode. First we need to create a swap object
    let simple_swap =
        SwapBuilder::new(component, sell_token.address.clone(), buy_token.address.clone()).build();

    // Compute a minimum amount out
    //
    // # ⚠️ Important Responsibility Note
    // For maximum security, in production code, this minimum amount out should be computed
    // from a third-party source.
    let slippage = 0.0025; // 0.25% slippage
    let bps = BigUint::from(10_000u32);
    let slippage_percent = BigUint::from((slippage * 10000.0) as u32);
    let multiplier = &bps - slippage_percent;
    let min_amount_out = (expected_amount_out * &multiplier) / &bps;

    // Then we create a solution object with the previous swap
    Ok(Solution {
        sender: user_address.clone(),
        receiver: user_address,
        given_token: sell_token.address,
        given_amount: amount_in,
        checked_token: buy_token.address,
        exact_out: false, // it's an exact in solution
        checked_amount: min_amount_out,
        swaps: vec![simple_swap],
        ..Default::default()
    })
}

fn encoded_transaction(
    encoded_solution: EncodedSolution,
    solution: &Solution,
    native_address: Bytes,
) -> miette::Result<Transaction> {
    let given_amount = biguint_to_u256(&solution.given_amount);
    let min_amount_out = biguint_to_u256(&solution.checked_amount);
    let given_token = Address::from_slice(&solution.given_token);
    let checked_token = Address::from_slice(&solution.checked_token);
    let receiver = Address::from_slice(&solution.receiver);

    let method_calldata = (
        given_amount,
        given_token,
        checked_token,
        min_amount_out,
        false,
        false,
        receiver,
        true,
        encoded_solution.swaps,
    )
        .abi_encode();

    let contract_interaction = encode_input(&encoded_solution.function_signature, method_calldata);
    let value = if solution.given_token == native_address {
        solution.given_amount.clone()
    } else {
        BigUint::ZERO
    };
    Ok(Transaction { to: encoded_solution.interacting_with, value, data: contract_interaction })
}

/// Encodes the input data for a function call to the given function selector.
pub fn encode_input(selector: &str, mut encoded_args: Vec<u8>) -> Vec<u8> {
    let mut hasher = Keccak256::new();
    hasher.update(selector.as_bytes());
    let selector_bytes = &hasher.finalize()[..4];
    let mut call_data = selector_bytes.to_vec();
    // Remove extra prefix if present (32 bytes for dynamic data)
    // Alloy encoding is including a prefix for dynamic data indicating the offset or length
    // but at this point we don't want that
    if encoded_args.len() > 32 &&
        encoded_args[..32] ==
            [0u8; 31]
                .into_iter()
                .chain([32].to_vec())
                .collect::<Vec<u8>>()
    {
        encoded_args = encoded_args[32..].to_vec();
    }
    call_data.extend(encoded_args);
    call_data
}

async fn simulate_swap_transaction(
    rpc_url: &str,
    solution: &Solution,
    transaction: &Transaction,
    block: &Block,
) -> miette::Result<BigUint> {
    let user_address = Address::from_slice(&solution.sender[..20]);
    let request = swap_request(transaction, block, user_address)?;
    let state_overwrites =
        setup_user_overwrites(rpc_url, solution, transaction, block, user_address).await?;

    // Use debug_traceCall from the start with retry logic
    let retry_strategy = ExponentialFactorBackoff::from_millis(1000, 2.)
        .max_delay_millis(10000)
        .map(jitter)
        .take(10);

    let result = Retry::spawn(retry_strategy, move || {
        let mut simulator = ExecutionSimulator::new(rpc_url.to_string().clone());
        let request = request.clone();
        let state_overwrites = state_overwrites.clone();

        async move {
            match simulator
                .simulate_with_trace(request, Some(state_overwrites))
                .await
            {
                Ok(res) => Ok(res),
                Err(e) => Err(RetryError::transient(e)),
            }
        }
    })
    .await
    .map_err(|e| miette!("Failed to simulate transaction after retries: {e}"))?;

    match result {
        execution_simulator::SimulationResult::Success { return_data, gas_used } => {
            info!("Transaction succeeded, gas used: {gas_used}");
            let amount_out = U256::abi_decode(&return_data)
                .map_err(|e| miette!("Failed to decode swap amount: {e:?}"))?;
            BigUint::from_str(amount_out.to_string().as_str()).into_diagnostic()
        }
        execution_simulator::SimulationResult::Revert { reason } => {
            Err(miette!("Transaction reverted: {}", reason))
        }
    }
}

fn swap_request(
    transaction: &Transaction,
    block: &Block,
    user_address: Address,
) -> miette::Result<TransactionRequest> {
    let (max_fee_per_gas, max_priority_fee_per_gas) = calculate_gas_fees(block)?;
    Ok(TransactionRequest::default()
        .to(Address::from_slice(&transaction.to[..20]))
        .input(transaction.data.clone().into())
        .value(U256::from_str(&transaction.value.to_string()).unwrap_or_default())
        .from(user_address)
        .gas_limit(100_000_000)
        .max_fee_per_gas(
            max_fee_per_gas
                .try_into()
                .unwrap_or(u128::MAX),
        )
        .max_priority_fee_per_gas(
            max_priority_fee_per_gas
                .try_into()
                .unwrap_or(u128::MAX),
        ))
}

/// Calculate gas fees based on block base fee
fn calculate_gas_fees(block: &Block) -> miette::Result<(U256, U256)> {
    let base_fee = block
        .header
        .base_fee_per_gas
        .ok_or_else(|| miette::miette!("Block does not have base fee (pre-EIP-1559)"))?;
    // Set max_priority_fee_per_gas to a reasonable value (2 Gwei)
    let max_priority_fee_per_gas = U256::from(2_000_000_000u64);
    // Set max_fee_per_gas to base_fee * 2 + max_priority_fee_per_gas to handle fee fluctuations
    let max_fee_per_gas = U256::from(base_fee) * U256::from(2u64) + max_priority_fee_per_gas;
    info!(
        "Gas pricing: base_fee={}, max_priority_fee_per_gas={}, max_fee_per_gas={}",
        base_fee, max_priority_fee_per_gas, max_fee_per_gas
    );
    Ok((max_fee_per_gas, max_priority_fee_per_gas))
}

/// Set up all state overrides needed for simulation.
///
/// This includes balance overrides and allowance overrides of the sell token for the sender.
async fn setup_user_overwrites(
    rpc_url: &str,
    solution: &Solution,
    transaction: &Transaction,
    block: &Block,
    user_address: Address,
) -> miette::Result<AddressHashMap<AccountOverride>> {
    let mut overwrites = AddressHashMap::default();
    let token_address = Address::from_slice(&solution.given_token[..20]);
    // If given token is ETH, add the given amount + 1 ETH for gas
    if solution.given_token == Bytes::zero(20) {
        let eth_balance = biguint_to_u256(&solution.given_amount) +
            U256::from_str("1000000000000000000").unwrap(); // given_amount + 1 ETH for gas
        overwrites.insert(user_address, AccountOverride::default().with_balance(eth_balance));
    // if the given token is not ETH, do balance and allowance slots overwrites
    } else {
        let detector = EVMBalanceSlotDetector::new(BalanceSlotDetectorConfig {
            rpc_url: rpc_url.to_string(),
            ..Default::default()
        })
        .into_diagnostic()?;

        let results = detector
            .detect_balance_slots(
                std::slice::from_ref(&solution.given_token),
                (**user_address).into(),
                (*block.header.hash).into(),
            )
            .await;

        let (balance_storage_addr, balance_slot) =
            if let Some(Ok((storage_addr, slot))) = results.get(&solution.given_token.clone()) {
                (storage_addr, slot)
            } else {
                return Err(miette!("Couldn't find balance storage slot for token {token_address}"));
            };

        let detector = EVMAllowanceSlotDetector::new(AllowanceSlotDetectorConfig {
            rpc_url: rpc_url.to_string(),
            ..Default::default()
        })
        .into_diagnostic()?;

        let results = detector
            .detect_allowance_slots(
                std::slice::from_ref(&solution.given_token),
                (**user_address).into(),
                transaction.to.clone(), // tycho router
                (*block.header.hash).into(),
            )
            .await;

        let (allowance_storage_addr, allowance_slot) = if let Some(Ok((storage_addr, slot))) =
            results.get(&solution.given_token.clone())
        {
            (storage_addr, slot)
        } else {
            return Err(miette!("Couldn't find allowance storage slot for token {token_address}"));
        };

        // Use the exact given amount for balance and allowance (no buffer, no max)
        let token_balance = biguint_to_u256(&solution.given_amount);
        let token_allowance = biguint_to_u256(&solution.given_amount);

        let balance_storage_address = Address::from_slice(&balance_storage_addr[..20]);
        let allowance_storage_address = Address::from_slice(&allowance_storage_addr[..20]);

        info!(
            "Setting token override for {token_address}: balance={}, allowance={}, balance_storage={}, allowance_storage={}",
            token_balance, token_allowance, balance_storage_address, allowance_storage_address
        );

        // Apply balance and allowance overrides
        // If both storage addresses are the same, combine them into one override
        if balance_storage_address == allowance_storage_address {
            overwrites.insert(
                balance_storage_address,
                AccountOverride::default().with_state_diff(vec![
                    (
                        alloy::primitives::B256::from_slice(balance_slot),
                        alloy::primitives::B256::from_slice(&token_balance.to_be_bytes::<32>()),
                    ),
                    (
                        alloy::primitives::B256::from_slice(allowance_slot),
                        alloy::primitives::B256::from_slice(&token_allowance.to_be_bytes::<32>()),
                    ),
                ]),
            );
        } else {
            // Different storage addresses, apply separately
            overwrites.insert(
                balance_storage_address,
                AccountOverride::default().with_state_diff(vec![(
                    alloy::primitives::B256::from_slice(balance_slot),
                    alloy::primitives::B256::from_slice(&token_balance.to_be_bytes::<32>()),
                )]),
            );
            overwrites.insert(
                allowance_storage_address,
                AccountOverride::default().with_state_diff(vec![(
                    alloy::primitives::B256::from_slice(allowance_slot),
                    alloy::primitives::B256::from_slice(&token_allowance.to_be_bytes::<32>()),
                )]),
            );
        }

        // Add 1 ETH for gas for non-ETH token swaps
        let eth_balance = U256::from_str("1000000000000000000").unwrap(); // 1 ETH for gas
        overwrites.insert(user_address, AccountOverride::default().with_balance(eth_balance));
        info!("Setting ETH balance override for user {user_address}: {eth_balance} (for gas)");
    }

    Ok(overwrites)
}
