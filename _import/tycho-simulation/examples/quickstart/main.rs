use std::{
    collections::{HashMap, HashSet},
    default::Default,
    env, io,
    io::Write,
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
use alloy_primitives::{Address, Bytes as AlloyBytes, B256, U256};
use alloy_sol_types::SolValue;
use clap::Parser;
use futures::StreamExt;
use num_bigint::BigUint;
use tracing_subscriber::EnvFilter;
use tycho_core::Bytes;
use tycho_execution::encoding::{
    evm::{
        encoder_builder::EVMEncoderBuilder, tycho_encoder::EVMTychoEncoder, utils::encode_input,
    },
    models::{Solution, Swap, Transaction},
    tycho_encoder::TychoEncoder,
};
use tycho_simulation::{
    evm::{
        engine_db::tycho_db::PreCachedDB,
        protocol::{
            filters::{balancer_pool_filter, uniswap_v4_pool_with_hook_filter},
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
    tycho_core::models::Chain,
    utils::load_all_tokens,
};

const FAKE_PK: &str = "0x123456789abcdef123456789abcdef123456789abcdef123456789abcdef1234";

#[derive(Parser)]
struct Cli {
    #[arg(short, long, default_value = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2")]
    sell_token: String,
    #[arg(short, long, default_value = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")]
    buy_token: String,
    #[arg(short, long, default_value_t = 1.0)]
    sell_amount: f64,
    /// The tvl threshold to filter the graph by
    #[arg(short, long, default_value_t = 10.0)]
    tvl_threshold: f64,
    #[arg(short, long, default_value = FAKE_PK)]
    swapper_pk: String,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_target(false)
        .init();

    let tycho_url =
        env::var("TYCHO_URL").unwrap_or_else(|_| "tycho-beta.propellerheads.xyz".to_string());
    let tycho_api_key: String =
        env::var("TYCHO_API_KEY").unwrap_or_else(|_| "sampletoken".to_string());

    let cli = Cli::parse();
    let tvl_filter = ComponentFilter::with_tvl_range(cli.tvl_threshold, cli.tvl_threshold);

    let all_tokens = load_all_tokens(
        tycho_url.as_str(),
        false,
        Some(tycho_api_key.as_str()),
        Chain::Ethereum,
        None,
        None,
    )
    .await;

    let sell_token_address =
        Bytes::from_str(&cli.sell_token).expect("Invalid address for sell token");
    let buy_token_address = Bytes::from_str(&cli.buy_token).expect("Invalid address for buy token");
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
        "Looking for the best swap for {} {} -> {}",
        cli.sell_amount, sell_token.symbol, buy_token.symbol
    );
    let mut pairs: HashMap<String, ProtocolComponent> = HashMap::new();
    let mut amounts_out: HashMap<String, BigUint> = HashMap::new();

    let mut protocol_stream = ProtocolStreamBuilder::new(&tycho_url, Chain::Ethereum)
        .exchange::<UniswapV2State>("uniswap_v2", tvl_filter.clone(), None)
        .exchange::<UniswapV3State>("uniswap_v3", tvl_filter.clone(), None)
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
        .auth_key(Some(tycho_api_key.clone()))
        .skip_state_decode_failures(true)
        .set_tokens(all_tokens.clone())
        .await
        .build()
        .await
        .expect("Failed building protocol stream");

    // Initialize the encoder
    let encoder = EVMEncoderBuilder::new()
        .chain(Chain::Ethereum)
        .tycho_router_with_permit2(None, cli.swapper_pk.clone())
        .expect("Failed to create encoder builder")
        .build()
        .expect("Failed to build encoder");

    let wallet = PrivateKeySigner::from_bytes(
        &B256::from_str(&cli.swapper_pk).expect("Failed to convert swapper pk to B256"),
    )
    .expect("Failed to private key signer");
    let tx_signer = EthereumWallet::from(wallet.clone());

    let provider = ProviderBuilder::new()
        .wallet(tx_signer.clone())
        .on_http(
            env::var("ETH_RPC_URL")
                .expect("ETH_RPC_URL env var not set")
                .parse()
                .expect("Failed to parse ETH_RPC_URL"),
        );

    while let Some(message) = protocol_stream.next().await {
        let message = message.expect("Could not receive message");
        let best_pool = get_best_swap(
            message,
            &mut pairs,
            amount_in.clone(),
            sell_token.clone(),
            buy_token.clone(),
            &mut amounts_out,
        );

        if let Some(best_pool) = best_pool {
            let component = pairs
                .get(&best_pool)
                .expect("Best pool not found")
                .clone();

            let tx = encode(
                encoder.clone(),
                component,
                sell_token.clone(),
                buy_token.clone(),
                amount_in.clone(),
                Bytes::from(wallet.address().to_vec()),
            );

            if cli.swapper_pk == FAKE_PK {
                println!("Signer private key was not provided. Skipping simulation/execution...");
                continue
            }
            println!("Do you want to simulate, execute or skip this swap?");
            println!("Please be aware that the market might move while you make your decision. Which might lead to a revert if you've set a min amount out or slippage.");
            print!("(simulate/execute/skip): ");
            io::stdout().flush().unwrap();
            let mut input = String::new();
            io::stdin()
                .read_line(&mut input)
                .expect("Failed to read input");

            let input = input.trim().to_lowercase();

            match input.as_str() {
                "simulate" => {
                    println!("Simulating by performing an approval (for permit2) and a swap transaction...");
                    let (approval_request, swap_request) = get_tx_requests(
                        provider.clone(),
                        biguint_to_u256(&amount_in),
                        wallet.address(),
                        Address::from_slice(&sell_token_address),
                        tx,
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

                    let output = provider
                        .simulate(&payload)
                        .await
                        .expect("Failed to simulate transaction");

                    for block in output.iter() {
                        println!("Simulated Block {}:", block.inner.header.number);
                        for (j, transaction) in block.calls.iter().enumerate() {
                            println!(
                                "  Transaction {}: Status: {:?}, Gas Used: {}",
                                j + 1,
                                transaction.status,
                                transaction.gas_used
                            );
                        }
                    }
                    // println!("Full simulation logs: {:?}", output);
                    return;
                }
                "execute" => {
                    println!("Executing by performing an approval (for permit2) and a swap transaction...");
                    let (approval_request, swap_request) = get_tx_requests(
                        provider.clone(),
                        biguint_to_u256(&amount_in),
                        wallet.address(),
                        Address::from_slice(&sell_token_address),
                        tx,
                    )
                    .await;

                    let approval_receipt = provider
                        .send_transaction(approval_request)
                        .await
                        .expect("Failed to send transaction");

                    let approval_result = approval_receipt
                        .get_receipt()
                        .await
                        .expect("Failed to get approval receipt");
                    println!(
                        "Approval transaction sent with hash: {:?} and status: {:?}",
                        approval_result.transaction_hash,
                        approval_result.status()
                    );

                    let swap_receipt = provider
                        .send_transaction(swap_request)
                        .await
                        .expect("Failed to send transaction");

                    let swap_result = swap_receipt
                        .get_receipt()
                        .await
                        .expect("Failed to get swap receipt");
                    println!(
                        "Swap transaction sent with hash: {:?} and status: {:?}",
                        swap_result.transaction_hash,
                        swap_result.status()
                    );

                    return;
                }
                "skip" => {
                    println!("Skipping this swap...");
                    continue;
                }
                _ => {
                    println!("Invalid input. Please choose 'simulate', 'execute' or 'skip'.");
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
) -> Option<String> {
    println!("==================== Received block {:?} ====================", message.block_number);
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
            if HashSet::from([&sell_token, &buy_token]) == HashSet::from([&tokens[0], &tokens[1]]) {
                let amount_out = state
                    .get_amount_out(amount_in.clone(), &sell_token, &buy_token)
                    .map_err(|e| {
                        eprintln!("Error calculating amount out for Pool {:?}: {:?}", id, e)
                    })
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
        println!("The best swap (out of {} possible pools) is:", amounts_out.len());
        println!(
            "protocol: {:?}",
            pairs
                .get(key)
                .expect("Failed to get best pool")
                .protocol_system
        );
        println!("id: {:?}", key);
        println!(
            "swap: {:?} {:} -> {:?} {:}",
            amount_in, sell_token.symbol, amount_out, buy_token.symbol
        );
        Some(key.to_string())
    } else {
        println!("There aren't pools with the tokens we are looking for");
        None
    }
}

fn encode(
    encoder: EVMTychoEncoder,
    component: ProtocolComponent,
    sell_token: Token,
    buy_token: Token,
    sell_amount: BigUint,
    user_address: Bytes,
) -> Transaction {
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
    let solution = Solution {
        sender: user_address.clone(),
        receiver: user_address,
        given_token: sell_token.address,
        given_amount: sell_amount,
        checked_token: buy_token.address,
        exact_out: false,     // it's an exact in solution
        checked_amount: None, // the amount out will not be checked in execution
        swaps: vec![simple_swap],
        router_address: Bytes::from_str("0xFfA5ec2e444e4285108e4a17b82dA495c178427B")
            .expect("Failed to create router address"),
        ..Default::default()
    };

    // Encode the solution
    encoder
        .encode_router_calldata(vec![solution.clone()])
        .expect("Failed to encode router calldata")[0]
        .clone()
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

    let approval_request = TransactionRequest::default()
        .from(user_address)
        .to(sell_token_address)
        .input(TransactionInput { input: Some(AlloyBytes::from(data)), data: None })
        .gas_limit(50_000u64)
        .max_fee_per_gas(max_fee_per_gas.into())
        .max_priority_fee_per_gas(max_priority_fee_per_gas.into())
        .nonce(nonce);

    let swap_request = TransactionRequest::default()
        .to(Address::from_slice(&tx.to))
        .from(user_address)
        .value(biguint_to_u256(&tx.value))
        .input(TransactionInput { input: Some(AlloyBytes::from(tx.data)), data: None })
        .max_fee_per_gas(max_fee_per_gas.into())
        .max_priority_fee_per_gas(max_priority_fee_per_gas.into())
        .gas_limit(300_000u64)
        .nonce(nonce + 1);

    (approval_request, swap_request)
}
