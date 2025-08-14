use std::{collections::HashSet, env, str::FromStr};

use clap::Parser;
use dotenv::dotenv;
use num_bigint::BigUint;
use num_traits::ToPrimitive;
use tokio::sync::mpsc;
use tracing_subscriber::EnvFilter;
use tycho_common::{models::token::Token, simulation::protocol_sim::ProtocolSim, Bytes};
use tycho_execution::encoding::{
    evm::encoder_builders::TychoRouterEncoderBuilder,
    models::{Solution, SwapBuilder, UserTransferType},
};
use tycho_simulation::{
    protocol::models::{ProtocolComponent, Update},
    rfq::{
        protocols::bebop::{client_builder::BebopClientBuilder, state::BebopState},
        stream::RFQStreamBuilder,
    },
    tycho_common::models::Chain,
    utils::{get_default_url, load_all_tokens},
};

#[derive(Parser)]
struct Cli {
    #[arg(long)]
    sell_token: Option<String>,
    #[arg(long)]
    buy_token: Option<String>,
    #[arg(long, default_value_t = 10.0)]
    sell_amount: f64,
    /// The minimum TVL threshold for RFQ quotes in USD
    #[arg(long, default_value_t = 1.0)]
    tvl_threshold: f64,
    #[arg(long, default_value = "ethereum")]
    chain: Chain,
}

impl Cli {
    fn with_defaults(mut self) -> Self {
        // By default, we request quotes for USDC to WETH on whatever chain we choose

        if self.buy_token.is_none() {
            self.buy_token = Some(match self.chain {
                Chain::Ethereum => "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48".to_string(),
                Chain::Base => "0x4200000000000000000000000000000000000006".to_string(),
                _ => {
                    panic!("RFQ quickstart does not yet support chain {chain}", chain = self.chain)
                }
            });
        }

        if self.sell_token.is_none() {
            self.sell_token = Some(match self.chain {
                Chain::Base => "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913".to_string(),
                Chain::Ethereum => "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2".to_string(),
                _ => {
                    panic!("RFQ quickstart does not yet support chain {chain}", chain = self.chain)
                }
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

    let chain = cli.chain;

    dotenv().expect("Missing .env file");
    let tycho_url = env::var("TYCHO_URL").unwrap_or_else(|_| {
        get_default_url(&chain)
            .unwrap_or_else(|| panic!("Unknown URL for chain {chain}", chain = cli.chain))
    });

    let tycho_api_key: String =
        env::var("TYCHO_API_KEY").unwrap_or_else(|_| "sampletoken".to_string());

    // Get WebSocket credentials for any RFQ(s) we are using
    let bebop_user = env::var("BEBOP_USER")
        .expect("BEBOP_USER environment variable is required. Contact Bebop for credentials.");
    let bebop_key = env::var("BEBOP_KEY")
        .expect("BEBOP_KEY environment variable is required. Contact Bebop for credentials.");

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
            .expect("Buy token not provided"),
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
        "Looking for RFQ quotes for {amount} {sell_symbol} -> {buy_symbol} on {chain:?}",
        amount = cli.sell_amount,
        sell_symbol = sell_token.symbol,
        buy_symbol = buy_token.symbol
    );

    // Initialize the encoder
    let encoder = TychoRouterEncoderBuilder::new()
        .chain(chain)
        .user_transfer_type(UserTransferType::TransferFromPermit2)
        .build()
        .expect("Failed to build encoder");

    // Set up RFQ client using the builder pattern
    let mut rfq_tokens = HashSet::new();
    rfq_tokens.insert(sell_token_address.clone());
    rfq_tokens.insert(buy_token_address.clone());

    println!("Connecting to RFQ WebSocket...");
    let bebop_client = BebopClientBuilder::new(chain, bebop_user, bebop_key)
        .tokens(rfq_tokens)
        .tvl_threshold(cli.tvl_threshold)
        .build()
        .expect("Failed to create RFQ clients");

    let (tx, mut rx) = mpsc::channel::<Update>(100);

    let rfq_stream_builder = RFQStreamBuilder::new()
        .add_client::<BebopState>("bebop", Box::new(bebop_client))
        .set_tokens(all_tokens.clone())
        .await;

    println!("Connected to RFQs! Streaming live price levels...\n");

    // Start the RFQ stream in a background task
    tokio::spawn(rfq_stream_builder.build(tx));

    // Stream quotes from RFQ stream
    while let Some(update) = rx.recv().await {
        println!(
            "Received RFQ price levels with {} new pairs for block/timestamp {}",
            &update.states.len(),
            update.block_number_or_timestamp
        );

        // Process state updates
        for (comp_id, state) in &update.states {
            if let Some(component) = update.new_pairs.get(comp_id) {
                let tokens = &component.tokens;

                // Check if this component trades our desired pair
                if HashSet::from([&sell_token, &buy_token])
                    .is_subset(&HashSet::from_iter(tokens.iter()))
                {
                    // Try to calculate amount out using the state
                    if let Ok(amount_out_result) =
                        state.get_amount_out(amount_in.clone(), &sell_token, &buy_token)
                    {
                        let amount_out = amount_out_result.amount;

                        println!(
                            "Indicative price for swap {}: {} {} -> {} {}",
                            component.protocol_system,
                            format_token_amount(&amount_in, &sell_token),
                            sell_token.symbol,
                            format_token_amount(&amount_out, &buy_token),
                            buy_token.symbol
                        );

                        let solution = create_solution(
                            component.clone(),
                            state.as_ref(),
                            sell_token.clone(),
                            buy_token.clone(),
                            amount_in.clone(),
                            // TODO: pass real user here
                            Bytes::zero(20),
                            amount_out,
                        );
                        // Encode the swaps of the solution
                        let encoded_solution = encoder
                            .encode_solutions(vec![solution.clone()])
                            .expect("Failed to encode router calldata")[0]
                            .clone();
                        println!("We got an encoded solution yei {encoded_solution:?}");
                    }
                }
            } else {
                println!("No matching pair found in update.");
            }
        }

        println!("\nWaiting for more price levels... (Press Ctrl+C to exit)");
    }
}

// Format token amounts to human-readable values
fn format_token_amount(amount: &BigUint, token: &Token) -> String {
    let decimal_amount = amount.to_f64().unwrap_or(0.0) / 10f64.powi(token.decimals as i32);
    format!("{decimal_amount:.6}")
}

#[allow(clippy::too_many_arguments)]
fn create_solution<'a>(
    component: ProtocolComponent,
    state: &'a dyn ProtocolSim,
    sell_token: Token,
    buy_token: Token,
    sell_amount: BigUint,
    user_address: Bytes,
    expected_amount: BigUint,
) -> Solution<'a> {
    // Prepare data to encode. First we need to create a swap object
    let simple_swap =
        SwapBuilder::new(component, sell_token.address.clone(), buy_token.address.clone())
            .protocol_state(state)
            .estimated_amount_in(sell_amount.clone())
            .build();

    // Compute a minimum amount out
    //
    // # ⚠️ Important Responsibility Note
    // For maximum security, in production code, this minimum amount out should be computed
    // from a third-party source.
    let slippage = 0.0025; // 0.25% slippage
    let bps = BigUint::from(10_000u32);
    let slippage_percent = BigUint::from((slippage * 10000.0) as u32);
    let multiplier = &bps - slippage_percent;
    let min_amount_out = (expected_amount * &multiplier) / &bps;

    // Then we create a solution object with the previous swap
    Solution {
        sender: user_address.clone(),
        receiver: user_address,
        given_token: sell_token.address,
        given_amount: sell_amount,
        checked_token: buy_token.address,
        exact_out: false, // it's an exact in solution
        checked_amount: min_amount_out,
        swaps: vec![simple_swap],
        ..Default::default()
    }
}
