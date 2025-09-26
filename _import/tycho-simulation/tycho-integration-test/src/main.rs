use std::{collections::HashMap, fmt::Debug, str::FromStr};

use alloy::{
    eips::BlockNumberOrTag,
    network::{Ethereum, EthereumWallet},
    primitives::{map::AddressHashMap, Address, Keccak256, B256, U256},
    providers::{
        fillers::{FillProvider, JoinFill, WalletFiller},
        Identity, Provider, ProviderBuilder, RootProvider,
    },
    rpc::types::{
        simulate::{SimBlock, SimulatePayload},
        state::AccountOverride,
        Block, TransactionRequest,
    },
    signers::local::PrivateKeySigner,
    sol_types::SolValue,
};
use alloy_chains::NamedChain;
use clap::Parser;
use futures::{Stream, StreamExt};
use itertools::Itertools;
use miette::{miette, IntoDiagnostic, WrapErr};
use num_bigint::BigUint;
use num_traits::{ToPrimitive, Zero};
use tracing::{debug, info, trace, warn};
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
    /// The tvl threshold to filter the graph by
    #[arg(long, default_value_t = 100.0)]
    tvl_threshold: f64,

    #[arg(long, default_value = "ethereum")]
    chains: Vec<Chain>,

    #[arg(
        long,
        env = "TYCHO_API_KEY",
        hide_env_values = true,
        default_value = "sampletoken",
        hide_default_value = true
    )]
    tycho_api_key: String,

    #[arg(long, env = "PRIVATE_KEY", hide_env_values = true)]
    swapper_pk: String,

    #[arg(long, env = "RPC_URL")]
    rpc_url: String,
}

impl Debug for Cli {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Cli")
            .field("tvl_threshold", &self.tvl_threshold)
            .field("chains", &self.chains)
            .field("tycho_api_key", &"****")
            .field("swapper_pk", &"****")
            .field("rpc_url", &self.rpc_url)
            .finish()
    }
}

#[tokio::main]
async fn main() -> miette::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    debug!("parsed args: {:?}", cli);

    let mut handles = vec![];
    for chain in &cli.chains {
        let cli_clone = cli.clone();
        let chain_clone = *chain;
        handles.push(tokio::spawn(async move { test_chain(cli_clone, chain_clone).await }));
    }

    for handle in handles {
        handle
            .await
            .map_err(|e| miette!("Task join error: {e}"))??
    }

    Ok(())
}

#[tracing::instrument(skip(cli), fields(chain = %chain))]
async fn test_chain(cli: Cli, chain: Chain) -> miette::Result<()> {
    info!("starting integration test");

    // Load tokens from Tycho
    let tycho_url =
        get_default_url(&chain).ok_or_else(|| miette!("No default Tycho URL for chain {chain}"))?;
    info!(%tycho_url, "loading tokens...");
    let all_tokens =
        load_all_tokens(&tycho_url, false, Some(cli.tycho_api_key.as_str()), chain, None, None)
            .await;
    info!(%tycho_url, "loaded tokens");

    // Create signer
    let pk_str = cli.swapper_pk.as_str();
    let pk = B256::from_str(pk_str)
        .into_diagnostic()
        .wrap_err("Failed to convert swapper pk to B256")?;
    let signer = PrivateKeySigner::from_bytes(&pk)
        .into_diagnostic()
        .wrap_err("Failed to create PrivateKeySigner")?;
    let tx_signer = EthereumWallet::from(signer.clone());

    // Create provider
    let provider = ProviderBuilder::default()
        .with_chain(
            NamedChain::try_from(chain.id())
                .into_diagnostic()
                .wrap_err("Invalid chain")?,
        )
        .wallet(tx_signer)
        .connect(&cli.rpc_url)
        .await
        .into_diagnostic()
        .wrap_err("Failed to connect to provider")?;

    // Init stream
    let mut pairs: HashMap<String, ProtocolComponent> = HashMap::new();
    let _amounts_out: HashMap<String, BigUint> = HashMap::new();
    let mut protocol_stream = build_protocol_stream(&cli, chain, &tycho_url, &all_tokens).await?;
    let mut first_message_skipped = false;

    while let Some(res) = protocol_stream.next().await {
        let message = match res {
            Ok(msg) => msg,
            Err(e) => {
                warn!("error receiving message: {e:?}");
                warn!("continuing to next message...");
                continue;
            }
        };
        info!("received block {:?}", message.block_number_or_timestamp);
        for (id, comp) in message.new_pairs.iter() {
            pairs
                .entry(id.clone())
                .or_insert_with(|| comp.clone());
        }
        if !first_message_skipped {
            first_message_skipped = true;
            info!("skipping simulation on first block...");
            continue;
        }
        let block = provider
            .get_block_by_number(BlockNumberOrTag::Latest)
            .await
            .into_diagnostic()
            .wrap_err("Failed to fetch latest block")?;
        let block = match block {
            Some(b) => b,
            None => {
                warn!("failed to retrieve last block, continuing to next message...");
                continue;
            }
        };

        for (id, state) in message.states.iter() {
            let component = match pairs.get(id) {
                Some(comp) => comp.clone(),
                None => {
                    trace!("component {id} not found in pairs");
                    continue;
                }
            };
            let swap_directions: Vec<(Token, Token)> = component
                .tokens
                .clone()
                .into_iter()
                .permutations(2)
                .map(|perm| (perm[0].clone(), perm[1].clone())) //TODO: not assume two tokens?
                .collect();
            for (token_in, token_out) in swap_directions.iter() {
                info!(
                    "processing {} pool {id:?}, from {} to {}",
                    component.protocol_system, token_in.symbol, token_out.symbol
                );

                // Get max input/output limits
                let (max_input, max_output) = state
                    .get_limits(token_in.address.clone(), token_out.address.clone())
                    .into_diagnostic()
                    .wrap_err(format!(
                        "Error getting limits for Pool {id:?} for in token: {}, and out token: {}",
                        token_in.address, token_out.address
                    ))?;
                info!(
                    "retrieved limits: max input {max_input} {}; max output {max_output} {}",
                    token_in.symbol, token_out.symbol
                );

                // Calculate amount_in as 0.1% of max_input
                // For precision, multiply by 1000 then divide by 1000
                let percentage = 0.001;
                let percentage_biguint = BigUint::from((percentage * 1000.0) as u32);
                let thousand = BigUint::from(1000u32);
                let amount_in = (&max_input * &percentage_biguint) / &thousand;
                if amount_in.is_zero() {
                    warn!("calculated amount_in is zero, skipping...");
                    continue;
                }
                info!("calculated amount_in: {amount_in} {}", token_in.symbol);

                // Get amount_out
                let amount_out_result = state
                    .get_amount_out(amount_in.clone(), token_in, token_out)
                    .into_diagnostic()
                    .wrap_err(format!(
                        "Error calculating amount out for Pool {id:?} at {:.1}% with input of {amount_in} {}.",
                        percentage * 100.0,
                        token_in.symbol,
                    ))?;
                let expected_amount_out = amount_out_result.amount;
                info!("calculated amount_out: {expected_amount_out} {}", token_out.symbol);

                // Simulate amount_out
                let (solution, transaction) = encode_swap(
                    &component,
                    token_in,
                    token_out,
                    amount_in.clone(),
                    expected_amount_out.clone(),
                    &signer,
                    chain,
                )?;
                let simulated_amount_out = match simulate_swap_transaction(
                    provider.clone(),
                    &cli.rpc_url,
                    &solution,
                    &transaction,
                    &block,
                )
                .await
                {
                    Ok(amount) => amount,
                    Err(e) => {
                        warn!("failed to simulate swap: {e}");
                        continue;
                    }
                };
                info!("simulated amount_out: {simulated_amount_out} {}", token_out.symbol);

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
                info!("slippage: {slippage}");

                info!("pool processed {id:?} from {} to {}", token_in.symbol, token_out.symbol);
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
            // COMING SOON!
            // .exchange::<UniswapV4State>("uniswap_v4_hooks", tvl_filter.clone(),
            // Some(uniswap_v4_pool_with_euler_hook_filter));
            // .exchange::<EVMPoolState<PreCachedDB>>("vm:maverick_v2", tvl_filter.clone(), None);
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
    signer: &PrivateKeySigner,
    chain: Chain,
) -> miette::Result<(Solution, Transaction)> {
    let solution = create_solution(
        component.clone(),
        sell_token.clone(),
        buy_token.clone(),
        amount_in.clone(),
        expected_amount_out.clone(),
        Bytes::from(signer.address().to_vec()),
    );
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
    user_address: Bytes,
) -> Solution {
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
    Solution {
        sender: user_address.clone(),
        receiver: user_address,
        given_token: sell_token.address,
        given_amount: amount_in,
        checked_token: buy_token.address,
        exact_out: false, // it's an exact in solution
        checked_amount: min_amount_out,
        swaps: vec![simple_swap],
        ..Default::default()
    }
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
    provider: FillProvider<
        JoinFill<Identity, WalletFiller<EthereumWallet>>,
        RootProvider<Ethereum>,
    >,
    rpc_url: &str,
    solution: &Solution,
    transaction: &Transaction,
    block: &Block,
) -> miette::Result<BigUint> {
    let user_address = Address::from_slice(&solution.sender[..20]);
    let request = swap_request(transaction, block, user_address)?;
    let state_overwrites =
        setup_user_overwrites(rpc_url, solution, transaction, block, user_address).await?;
    let payload = SimulatePayload {
        block_state_calls: vec![SimBlock {
            block_overrides: None,
            state_overrides: Some(state_overwrites),
            calls: vec![request],
        }],
        trace_transfers: true,
        validation: true,
        return_full_transactions: true,
    };
    // TODO: add retry logic to handle rate limiting
    match provider.simulate(&payload).await {
        Ok(output) => {
            // TODO: can we assume there is only one block and one transaction?
            for block in output.iter() {
                info!("simulated block {}", block.inner.header.number);
                if let Some((idx, transaction)) = block.calls.iter().enumerate().next() {
                    use alloy::{primitives::U256, sol_types::SolValue};
                    info!(
                        "transaction {transaction_num}, status: {status:?}, gas used: {gas_used}",
                        transaction_num = idx + 1,
                        status = transaction.status,
                        gas_used = transaction.gas_used
                    );
                    if !transaction.status {
                        warn!("transaction: {transaction:?}");
                        return Err(miette!("Transaction status is false"));
                    }
                    let amount_out = U256::abi_decode(&transaction.return_data)
                        .map_err(|e| miette!("Failed to decode swap amount: {e:?}"))?;
                    return BigUint::from_str(amount_out.to_string().as_str()).into_diagnostic();
                }
            }
            Err(miette!("No blocks found in simulation output"))
        }
        Err(e) => Err(miette!("error during simulation: {e:?}")),
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
        "gas pricing: base_fee={}, max_priority_fee_per_gas={}, max_fee_per_gas={}",
        base_fee, max_priority_fee_per_gas, max_fee_per_gas
    );
    Ok((max_fee_per_gas, max_priority_fee_per_gas))
}

/// Set up all state overrides needed for simulation
async fn setup_user_overwrites(
    rpc_url: &str,
    solution: &Solution,
    transaction: &Transaction,
    block: &Block,
    user_address: Address,
) -> miette::Result<AddressHashMap<AccountOverride>> {
    let mut overwrites = AddressHashMap::default();
    // Add ETH balance override for the user to ensure they have enough gas funds
    let mut eth_balance = U256::from_str("100000000000000000000").unwrap(); // 100 ETH

    let token_address = Address::from_slice(&solution.given_token[..20]);
    // If given token is ETH, add the given amount to the balance
    if solution.given_token == Bytes::zero(20) {
        eth_balance += biguint_to_u256(&solution.given_amount);
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

        let balance_slot =
            if let Some(Ok((_storage_addr, slot))) = results.get(&solution.given_token.clone()) {
                slot
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

        let allowance_slot = if let Some(Ok((_storage_addr, slot))) =
            results.get(&solution.given_token.clone())
        {
            slot
        } else {
            return Err(miette!("Couldn't find allowance storage slot for token {token_address}"));
        };

        overwrites.insert(
            token_address,
            AccountOverride::default().with_state_diff(vec![
                (
                    alloy::primitives::B256::from_slice(allowance_slot),
                    alloy::primitives::B256::from_slice(&U256::MAX.to_be_bytes::<32>()),
                ),
                (
                    alloy::primitives::B256::from_slice(balance_slot),
                    alloy::primitives::B256::from_slice(
                        &biguint_to_u256(&solution.given_amount).to_be_bytes::<32>(),
                    ),
                ),
            ]),
        );
    }
    overwrites.insert(user_address, AccountOverride::default().with_balance(eth_balance));

    Ok(overwrites)
}
