use std::{
    collections::{HashMap, HashSet},
    default::Default,
    env,
    str::FromStr,
};

use alloy::{
    eips::BlockNumberOrTag,
    network::{Ethereum, EthereumWallet},
    providers::{
        fillers::{FillProvider, JoinFill, WalletFiller},
        Identity, Provider, ProviderBuilder, ReqwestProvider,
    },
    rpc::types::{
        simulate::{SimBlock, SimulatePayload},
        TransactionInput, TransactionRequest,
    },
    signers::local::PrivateKeySigner,
    transports::http::{Client, Http},
};
use alloy_primitives::{Address, Bytes as AlloyBytes, TxKind, B256, U256};
use alloy_sol_types::SolValue;
use clap::Parser;
use dialoguer::{theme::ColorfulTheme, Select};
use foundry_config::NamedChain;
use futures::StreamExt;
use num_bigint::BigUint;
use num_traits::ToPrimitive;
use tracing_subscriber::EnvFilter;
use tycho_common::Bytes;
pub mod utils;
use tycho_execution::encoding::{
    evm::{encoder_builders::TychoRouterEncoderBuilder, utils::encode_input},
    models::{Solution, Swap, Transaction},
};
use tycho_simulation::{
    evm::{
        engine_db::tycho_db::PreCachedDB,
        protocol::{
            ekubo::state::EkuboState,
            filters::{balancer_pool_filter, curve_pool_filter, uniswap_v4_pool_with_hook_filter},
            pancakeswap_v2::state::PancakeswapV2State,
            u256_num::biguint_to_u256,
            uniswap_v2::state::UniswapV2State,
            uniswap_v3::state::UniswapV3State,
            uniswap_v4::state::UniswapV4State,
            vm::state::EVMPoolState,
        },
        stream::ProtocolStreamBuilder,
    },
    models::Token,
    protocol::models::{BlockUpdate, ProtocolComponent},
    tycho_client::feed::component_tracker::ComponentFilter,
    tycho_common::models::Chain,
    utils::load_all_tokens,
};
use utils::get_default_url;

const FAKE_PK: &str = "0x123456789abcdef123456789abcdef123456789abcdef123456789abcdef1234";

#[derive(Parser)]
struct Cli {
    #[arg(short, long)]
    sell_token: Option<String>,
    #[arg(short, long)]
    buy_token: Option<String>,
    #[arg(short, long, default_value_t = 10.0)]
    sell_amount: f64,
    /// The tvl threshold to filter the graph by
    #[arg(short, long, default_value_t = 100.0)]
    tvl_threshold: f64,
    #[arg(short, long, default_value = FAKE_PK)]
    swapper_pk: String,
    #[arg(short, long, default_value = "ethereum")]
    chain: String,
}

impl Cli {
    fn with_defaults(mut self) -> Self {
        // By default, we swap a small amount of USDC to WETH on whatever chain we choose

        if self.buy_token.is_none() {
            self.buy_token = Some(match self.chain.as_str() {
                "ethereum" => "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2".to_string(),
                "base" => "0x4200000000000000000000000000000000000006".to_string(),
                "unichain" => "0x4200000000000000000000000000000000000006".to_string(),
                _ => panic!("Execution does not yet support chain {chain}", chain = self.chain),
            });
        }

        if self.sell_token.is_none() {
            self.sell_token = Some(match self.chain.as_str() {
                "ethereum" => "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48".to_string(),
                "base" => "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913".to_string(),
                "unichain" => "0x078d782b760474a361dda0af3839290b0ef57ad6".to_string(),
                _ => panic!("Execution does not yet support chain {chain}", chain = self.chain),
            });
        }

        self
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_target(false)
        .init();

    let cli = Cli::parse().with_defaults();

    let chain = Chain::from_str(&cli.chain)
        .unwrap_or_else(|_| panic!("Unknown chain {chain}", chain = cli.chain));

    let tycho_url = env::var("TYCHO_URL").unwrap_or_else(|_| {
        get_default_url(&chain)
            .unwrap_or_else(|| panic!("Unknown URL for chain {chain}", chain = cli.chain))
    });

    let tycho_api_key: String =
        env::var("TYCHO_API_KEY").unwrap_or_else(|_| "sampletoken".to_string());

    let tvl_filter = ComponentFilter::with_tvl_range(cli.tvl_threshold, cli.tvl_threshold);

    println!("Loading tokens from Tycho... {url}", url = tycho_url.as_str());
    let all_tokens =
        load_all_tokens(tycho_url.as_str(), false, Some(tycho_api_key.as_str()), chain, None, None)
            .await;
    println!("Tokens loaded: {num}", num = all_tokens.len());

    let sell_token_address = Bytes::from_str(
        &cli.sell_token
            .expect("Sell token not provided"),
    )
    .expect("Invalid address for sell token");
    let buy_token_address = Bytes::from_str(
        &cli.buy_token
            .expect("NBuy token not provided"),
    )
    .expect("Invalid address for buy token");
    let sell_token = all_tokens
        .get(&sell_token_address)
        .expect("Sell token not found")
        .clone();
    let buy_token = all_tokens
        .get(&buy_token_address)
        .expect("Buy token not found")
        .clone();
    let amount_in =
        BigUint::from((cli.sell_amount * 10f64.powi(sell_token.decimals as i32)) as u128);

    println!(
        "Looking for pool with best price for {amount} {sell_symbol} -> {buy_symbol}",
        amount = cli.sell_amount,
        sell_symbol = sell_token.symbol,
        buy_symbol = buy_token.symbol
    );
    let mut pairs: HashMap<String, ProtocolComponent> = HashMap::new();
    let mut amounts_out: HashMap<String, BigUint> = HashMap::new();

    let mut protocol_stream = ProtocolStreamBuilder::new(&tycho_url, chain);

    match chain {
        Chain::Ethereum => {
            protocol_stream = protocol_stream
                .exchange::<UniswapV2State>("uniswap_v2", tvl_filter.clone(), None)
                .exchange::<UniswapV2State>("sushiswap_v2", tvl_filter.clone(), None)
                .exchange::<PancakeswapV2State>("pancakeswap_v2", tvl_filter.clone(), None)
                .exchange::<UniswapV3State>("uniswap_v3", tvl_filter.clone(), None)
                .exchange::<UniswapV3State>("pancakeswap_v3", tvl_filter.clone(), None)
                .exchange::<EVMPoolState<PreCachedDB>>(
                    "vm:curve",
                    tvl_filter.clone(),
                    Some(curve_pool_filter),
                )
                .exchange::<EVMPoolState<PreCachedDB>>(
                    "vm:balancer_v2",
                    tvl_filter.clone(),
                    Some(balancer_pool_filter),
                )
                .exchange::<UniswapV4State>(
                    "uniswap_v4",
                    tvl_filter.clone(),
                    Some(uniswap_v4_pool_with_hook_filter),
                )
                .exchange::<EkuboState>("ekubo_v2", tvl_filter.clone(), None);
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

    let mut protocol_stream = protocol_stream
        .auth_key(Some(tycho_api_key.clone()))
        .skip_state_decode_failures(true)
        .set_tokens(all_tokens.clone())
        .await
        .build()
        .await
        .expect("Failed building protocol stream");

    // Initialize the encoder
    let encoder = TychoRouterEncoderBuilder::new()
        .chain(chain)
        .swapper_pk(cli.swapper_pk.clone())
        .build()
        .expect("Failed to build encoder");

    let wallet = PrivateKeySigner::from_bytes(
        &B256::from_str(&cli.swapper_pk).expect("Failed to convert swapper pk to B256"),
    )
    .expect("Failed to private key signer");
    let tx_signer = EthereumWallet::from(wallet.clone());
    let named_chain =
        NamedChain::from_str(&cli.chain.replace("ethereum", "mainnet")).expect("Invalid chain");
    let provider = ProviderBuilder::new()
        .with_chain(named_chain)
        .wallet(tx_signer.clone())
        .on_http(
            env::var("RPC_URL")
                .expect("RPC_URL env var not set")
                .parse()
                .expect("Failed to parse RPC_URL"),
        );

    while let Some(message_result) = protocol_stream.next().await {
        let message = match message_result {
            Ok(msg) => msg,
            Err(e) => {
                eprintln!("Error receiving message: {e:?}. Continuing to next message...");
                continue;
            }
        };

        let best_swap = get_best_swap(
            message,
            &mut pairs,
            amount_in.clone(),
            sell_token.clone(),
            buy_token.clone(),
            &mut amounts_out,
        );

        if let Some((best_pool, expected_amount)) = best_swap {
            let component = pairs
                .get(&best_pool)
                .expect("Best pool not found")
                .clone();

            // Clone expected_amount to avoid ownership issues
            let expected_amount_copy = expected_amount.clone();

            let solution = create_solution(
                component,
                sell_token.clone(),
                buy_token.clone(),
                amount_in.clone(),
                Bytes::from(wallet.address().to_vec()),
                expected_amount,
            );

            // Encode the solution
            let tx = encoder
                .encode_calldata(vec![solution.clone()])
                .expect("Failed to encode router calldata")[0]
                .clone();

            // Print token balances before showing the swap options
            if cli.swapper_pk != FAKE_PK {
                match get_token_balance(
                    &provider,
                    Address::from_slice(&sell_token.address),
                    wallet.address(),
                )
                .await
                {
                    Ok(balance) => {
                        let formatted_balance = format_token_amount(&balance, &sell_token);
                        println!(
                            "\nYour balance: {formatted_balance} {sell_symbol}",
                            sell_symbol = sell_token.symbol
                        );

                        if balance < amount_in {
                            let required = format_token_amount(&amount_in, &sell_token);
                            println!("⚠️ Warning: Insufficient balance for swap. You have {formatted_balance} {sell_symbol} but need {required} {sell_symbol}",
                                formatted_balance = formatted_balance,
                                sell_symbol = sell_token.symbol,
                            );
                        }
                    }
                    Err(e) => eprintln!("Failed to get token balance: {e}"),
                }

                // Also show buy token balance
                match get_token_balance(
                    &provider,
                    Address::from_slice(&buy_token.address),
                    wallet.address(),
                )
                .await
                {
                    Ok(balance) => {
                        let formatted_balance = format_token_amount(&balance, &buy_token);
                        println!(
                            "Your {buy_symbol} balance: {formatted_balance} {buy_symbol}",
                            buy_symbol = buy_token.symbol
                        );
                    }
                    Err(e) => eprintln!(
                        "Failed to get {buy_symbol} balance: {e}",
                        buy_symbol = buy_token.symbol
                    ),
                }
            }

            if cli.swapper_pk == FAKE_PK {
                println!(
                    "\nSigner private key was not provided. Skipping simulation/execution...\n"
                );
                continue;
            }
            println!("Would you like to simulate or execute this swap?");
            println!("Please be aware that the market might move while you make your decision, which might lead to a revert if you've set a min amount out or slippage.");
            println!("Warning: slippage is set to 0.25% during execution by default.\n");
            let options = vec!["Simulate the swap", "Execute the swap", "Skip this swap"];
            let selection = Select::with_theme(&ColorfulTheme::default())
                .with_prompt("What would you like to do?")
                .default(0)
                .items(&options)
                .interact()
                .unwrap_or(2); // Default to skip if error

            let choice = match selection {
                0 => "simulate",
                1 => "execute",
                _ => "skip",
            };

            match choice {
                "simulate" => {
                    println!("\nSimulating by performing an approval (for permit2) and a swap transaction...");

                    let (approval_request, swap_request) = get_tx_requests(
                        provider.clone(),
                        biguint_to_u256(&amount_in),
                        wallet.address(),
                        Address::from_slice(&sell_token_address),
                        tx.clone(),
                        named_chain as u64,
                    )
                    .await;

                    let payload = SimulatePayload {
                        block_state_calls: vec![SimBlock {
                            block_overrides: None,
                            state_overrides: None,
                            calls: vec![approval_request, swap_request],
                        }],
                        trace_transfers: true,
                        validation: true,
                        return_full_transactions: true,
                    };

                    match provider.simulate(&payload).await {
                        Ok(output) => {
                            for block in output.iter() {
                                println!(
                                    "\nSimulated Block {block_num}:",
                                    block_num = block.inner.header.number
                                );
                                for (j, transaction) in block.calls.iter().enumerate() {
                                    println!(
                                        "  Transaction {transaction_num}: Status: {status:?}, Gas Used: {gas_used}",
                                        transaction_num = j + 1,
                                        status = transaction.status,
                                        gas_used = transaction.gas_used
                                    );
                                }
                            }
                            println!(); // Add empty line after simulation results
                            continue;
                        }
                        Err(e) => {
                            eprintln!("\nSimulation failed: {e:?}");
                            println!("Your RPC provider does not support transaction simulation.");
                            println!("Do you want to proceed with execution instead?\n");
                            let yes_no_options = vec!["Yes", "No"];
                            let yes_no_selection = Select::with_theme(&ColorfulTheme::default())
                                .with_prompt("Do you want to proceed with execution instead?")
                                .default(1) // Default to No
                                .items(&yes_no_options)
                                .interact()
                                .unwrap_or(1); // Default to No if error

                            if yes_no_selection == 0 {
                                match execute_swap_transaction(
                                    provider.clone(),
                                    &amount_in,
                                    wallet.address(),
                                    &sell_token_address,
                                    tx.clone(),
                                    named_chain as u64,
                                )
                                .await
                                {
                                    Ok(_) => {
                                        println!("\n✅ Swap executed successfully! Exiting the session...\n");

                                        // Calculate the correct price ratio
                                        let (forward_price, _reverse_price) = format_price_ratios(
                                            &amount_in,
                                            &expected_amount_copy,
                                            &sell_token,
                                            &buy_token,
                                        );

                                        println!(
                                            "Summary: Swapped {formatted_in} {sell_symbol} → {formatted_out} {buy_symbol} at 
                                            a price of {forward_price:.6} {buy_symbol} per {sell_symbol}",
                                            formatted_in = format_token_amount(&amount_in, &sell_token),
                                            sell_symbol = sell_token.symbol,
                                            formatted_out = format_token_amount(&expected_amount_copy, &buy_token),
                                            buy_symbol = buy_token.symbol,
                                        );
                                        return; // Exit the program after successful execution
                                    }
                                    Err(e) => {
                                        eprintln!("\nFailed to execute transaction: {e:?}\n");
                                        continue;
                                    }
                                }
                            } else {
                                println!("\nSkipping this swap...\n");
                                continue;
                            }
                        }
                    }
                }
                "execute" => {
                    match execute_swap_transaction(
                        provider.clone(),
                        &amount_in,
                        wallet.address(),
                        &sell_token_address,
                        tx,
                        named_chain as u64,
                    )
                    .await
                    {
                        Ok(_) => {
                            println!("\n✅ Swap executed successfully! Exiting the session...\n");

                            // Calculate the correct price ratio
                            let (forward_price, _reverse_price) = format_price_ratios(
                                &amount_in,
                                &expected_amount_copy,
                                &sell_token,
                                &buy_token,
                            );

                            println!(
                                "Summary: Swapped {formatted_in} {sell_symbol} → {formatted_out} {buy_symbol} at 
                                a price of {forward_price:.6} {buy_symbol} per {sell_symbol}",
                                formatted_in = format_token_amount(&amount_in, &sell_token),
                                sell_symbol = sell_token.symbol,
                                formatted_out = format_token_amount(&expected_amount_copy, &buy_token),
                                buy_symbol = buy_token.symbol,
                            );
                            return; // Exit the program after successful execution
                        }
                        Err(e) => {
                            eprintln!("\nFailed to execute transaction: {e:?}\n");
                            continue;
                        }
                    }
                }
                "skip" => {
                    println!("\nSkipping this swap...\n");
                    continue;
                }
                _ => {
                    println!("\nInvalid input. Please choose 'simulate', 'execute' or 'skip'.\n");
                    continue;
                }
            }
        }
    }
}

fn get_best_swap(
    message: BlockUpdate,
    pairs: &mut HashMap<String, ProtocolComponent>,
    amount_in: BigUint,
    sell_token: Token,
    buy_token: Token,
    amounts_out: &mut HashMap<String, BigUint>,
) -> Option<(String, BigUint)> {
    println!(
        "\n==================== Received block {block:?} ====================",
        block = message.block_number
    );
    for (id, comp) in message.new_pairs.iter() {
        pairs
            .entry(id.clone())
            .or_insert_with(|| comp.clone());
    }
    if message.states.is_empty() {
        println!("No pools of interest were updated this block. The best swap is the previous one");
        return None;
    }
    for (id, state) in message.states.iter() {
        if let Some(component) = pairs.get(id) {
            let tokens = &component.tokens;
            if HashSet::from([&sell_token, &buy_token])
                .is_subset(&HashSet::from_iter(tokens.iter()))
            {
                let amount_out = state
                    .get_amount_out(amount_in.clone(), &sell_token, &buy_token)
                    .map_err(|e| eprintln!("Error calculating amount out for Pool {id:?}: {e:?}"))
                    .ok();
                if let Some(amount_out) = amount_out {
                    amounts_out.insert(id.clone(), amount_out.amount);
                }
                // If you would like to save spot prices instead of the amount out, do
                // let spot_price = state
                //     .spot_price(&tokens[0], &tokens[1])
                //     .ok();
            }
        }
    }
    if let Some((key, amount_out)) = amounts_out
        .iter()
        .max_by_key(|(_, value)| value.to_owned())
    {
        println!(
            "\nThe best swap (out of {amounts} possible pools) is:",
            amounts = amounts_out.len()
        );
        println!(
            "Protocol: {protocol}",
            protocol = pairs
                .get(key)
                .expect("Failed to get best pool")
                .protocol_system
        );
        println!("Pool address: {key:?}");
        let formatted_in = format_token_amount(&amount_in, &sell_token);
        let formatted_out = format_token_amount(amount_out, &buy_token);
        let (forward_price, reverse_price) =
            format_price_ratios(&amount_in, amount_out, &sell_token, &buy_token);

        println!(
            "Swap: {formatted_in} {sell_symbol} -> {formatted_out} {buy_symbol} \n
            Price: {forward_price:.6} {buy_symbol} per {sell_symbol}, 
            {reverse_price:.6} {sell_symbol} per {buy_symbol}",
            sell_symbol = sell_token.symbol,
            buy_symbol = buy_token.symbol,
        );
        Some((key.to_string(), amount_out.clone()))
    } else {
        println!("\nThere aren't pools with the tokens we are looking for");
        None
    }
}

#[allow(clippy::too_many_arguments)]
fn create_solution(
    component: ProtocolComponent,
    sell_token: Token,
    buy_token: Token,
    sell_amount: BigUint,
    user_address: Bytes,
    expected_amount: BigUint,
) -> Solution {
    // Prepare data to encode. First we need to create a swap object
    let simple_swap = Swap::new(
        component,
        sell_token.address.clone(),
        buy_token.address.clone(),
        // Split defines the fraction of the amount to be swapped. A value of 0 indicates 100% of
        // the amount or the total remaining balance.
        0f64,
    );

    // Then we create a solution object with the previous swap
    Solution {
        sender: user_address.clone(),
        receiver: user_address,
        given_token: sell_token.address,
        given_amount: sell_amount,
        checked_token: buy_token.address,
        slippage: Some(0.0025), // 0.25% slippage
        expected_amount: Some(expected_amount),
        exact_out: false,     // it's an exact in solution
        checked_amount: None, // the amount out will not be checked in execution
        swaps: vec![simple_swap],
        ..Default::default()
    }
}

async fn get_tx_requests(
    provider: FillProvider<
        JoinFill<Identity, WalletFiller<EthereumWallet>>,
        ReqwestProvider,
        Http<Client>,
        Ethereum,
    >,
    amount_in: U256,
    user_address: Address,
    sell_token_address: Address,
    tx: Transaction,
    chain_id: u64,
) -> (TransactionRequest, TransactionRequest) {
    let block = provider
        .get_block_by_number(BlockNumberOrTag::Latest, false)
        .await
        .expect("Failed to fetch latest block")
        .expect("Block not found");

    let base_fee = block
        .header
        .base_fee_per_gas
        .expect("Base fee not available");
    let max_priority_fee_per_gas = 1_000_000_000u64;
    let max_fee_per_gas = base_fee + max_priority_fee_per_gas;

    let approve_function_signature = "approve(address,uint256)";
    let args = (
        Address::from_str("0x000000000022D473030F116dDEE9F6B43aC78BA3")
            .expect("Couldn't convert to address"),
        amount_in,
    );
    let data = encode_input(approve_function_signature, args.abi_encode());
    let nonce = provider
        .get_transaction_count(user_address)
        .await
        .expect("Failed to get nonce");

    let approval_request = TransactionRequest {
        to: Some(TxKind::Call(sell_token_address)),
        from: Some(user_address),
        value: None,
        input: TransactionInput { input: Some(AlloyBytes::from(data)), data: None },
        gas: Some(100_000u64),
        chain_id: Some(chain_id),
        max_fee_per_gas: Some(max_fee_per_gas.into()),
        max_priority_fee_per_gas: Some(max_priority_fee_per_gas.into()),
        nonce: Some(nonce),
        ..Default::default()
    };

    let swap_request = TransactionRequest {
        to: Some(TxKind::Call(Address::from_slice(&tx.to))),
        from: Some(user_address),
        value: Some(biguint_to_u256(&tx.value)),
        input: TransactionInput { input: Some(AlloyBytes::from(tx.data)), data: None },
        gas: Some(800_000u64),
        chain_id: Some(chain_id),
        max_fee_per_gas: Some(max_fee_per_gas.into()),
        max_priority_fee_per_gas: Some(max_priority_fee_per_gas.into()),
        nonce: Some(nonce + 1),
        ..Default::default()
    };
    (approval_request, swap_request)
}

// Format token amounts to human-readable values
fn format_token_amount(amount: &BigUint, token: &Token) -> String {
    let decimal_amount = amount.to_f64().unwrap_or(0.0) / 10f64.powi(token.decimals as i32);
    format!("{decimal_amount:.6}")
}

// Calculate price ratios in both directions
fn format_price_ratios(
    amount_in: &BigUint,
    amount_out: &BigUint,
    token_in: &Token,
    token_out: &Token,
) -> (f64, f64) {
    let decimal_in = amount_in.to_f64().unwrap_or(0.0) / 10f64.powi(token_in.decimals as i32);
    let decimal_out = amount_out.to_f64().unwrap_or(0.0) / 10f64.powi(token_out.decimals as i32);

    if decimal_in > 0.0 && decimal_out > 0.0 {
        let forward = decimal_out / decimal_in;
        let reverse = decimal_in / decimal_out;
        (forward, reverse)
    } else {
        (0.0, 0.0)
    }
}

async fn get_token_balance(
    provider: &FillProvider<
        JoinFill<Identity, WalletFiller<EthereumWallet>>,
        ReqwestProvider,
        Http<Client>,
        Ethereum,
    >,
    token_address: Address,
    wallet_address: Address,
) -> Result<BigUint, Box<dyn std::error::Error>> {
    let balance_of_signature = "balanceOf(address)";
    let args = (wallet_address,);
    let data = encode_input(balance_of_signature, args.abi_encode());

    let result = provider
        .call(&TransactionRequest {
            to: Some(TxKind::Call(token_address)),
            input: TransactionInput { input: Some(AlloyBytes::from(data)), data: None },
            ..Default::default()
        })
        .await?;

    let balance = U256::from_be_bytes(
        result
            .to_vec()
            .try_into()
            .unwrap_or([0u8; 32]),
    );
    // Convert the U256 to BigUint
    Ok(num_bigint::BigUint::from_bytes_be(&balance.to_be_bytes::<32>()))
}

async fn execute_swap_transaction(
    provider: FillProvider<
        JoinFill<Identity, WalletFiller<EthereumWallet>>,
        ReqwestProvider,
        Http<Client>,
        Ethereum,
    >,
    amount_in: &BigUint,
    wallet_address: Address,
    sell_token_address: &Bytes,
    tx: Transaction,
    chain_id: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    // Check token balance first
    let token_contract = Address::from_slice(sell_token_address);
    let token_balance = get_token_balance(&provider, token_contract, wallet_address).await?;

    // Get a more human-readable representation of the balance check
    let decimal_balance = token_balance.to_f64().unwrap_or(0.0);
    let decimal_required = amount_in.to_f64().unwrap_or(0.0);

    if token_balance < *amount_in {
        return Err(format!(
            "\nInsufficient token balance. You have {decimal_balance} tokens but need {decimal_required} tokens 
            (raw values: have {token_balance}, need {amount_in})\n",
        ).into());
    }

    println!("\nExecuting by performing an approval (for permit2) and a swap transaction...");
    let (approval_request, swap_request) = get_tx_requests(
        provider.clone(),
        biguint_to_u256(amount_in),
        wallet_address,
        Address::from_slice(sell_token_address),
        tx.clone(),
        chain_id,
    )
    .await;

    let approval_receipt = provider
        .send_transaction(approval_request)
        .await?;

    let approval_result = approval_receipt.get_receipt().await?;
    println!(
        "\nApproval transaction sent with hash: {hash:?} and status: {status:?}",
        hash = approval_result.transaction_hash,
        status = approval_result.status()
    );

    let swap_receipt = provider
        .send_transaction(swap_request)
        .await?;

    let swap_result = swap_receipt.get_receipt().await?;
    println!(
        "\nSwap transaction sent with hash: {hash:?} and status: {status:?}\n",
        hash = swap_result.transaction_hash,
        status = swap_result.status()
    );

    if !swap_result.status() {
        return Err(format!(
            "Swap transaction with hash {hash:?} failed.",
            hash = swap_result.transaction_hash
        )
        .into());
    }

    Ok(())
}
