use std::{collections::HashSet, env, str::FromStr};

use clap::Parser;
use num_bigint::BigUint;
use num_traits::ToPrimitive;
use tokio::sync::mpsc;
use tracing_subscriber::EnvFilter;
use tycho_common::{models::token::Token, Bytes};
pub mod utils;
use tycho_simulation::{
    protocol::models::Update,
    rfq::{
        protocols::bebop::{client::BebopClient, state::BebopState},
        stream::RFQStreamBuilder,
    },
    tycho_common::models::Chain,
    utils::load_all_tokens,
};
use utils::get_default_url;

#[derive(Parser)]
struct Cli {
    #[arg(short, long)]
    sell_token: Option<String>,
    #[arg(short, long)]
    buy_token: Option<String>,
    #[arg(short, long, default_value_t = 10.0)]
    sell_amount: f64,
    /// The minimum TVL threshold for Bebop quotes
    #[arg(short, long, default_value_t = 1.0)]
    tvl_threshold: f64,
    #[arg(short, long, default_value = "ethereum")]
    chain: String,
}

impl Cli {
    fn with_defaults(mut self) -> Self {
        // By default, we request quotes for USDC to WETH on whatever chain we choose

        if self.buy_token.is_none() {
            self.buy_token = Some(match self.chain.as_str() {
                "ethereum" => "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48".to_string(),
                "base" => "0x4200000000000000000000000000000000000006".to_string(),
                _ => {
                    panic!("RFQ quickstart does not yet support chain {chain}", chain = self.chain)
                }
            });
        }

        if self.sell_token.is_none() {
            self.sell_token = Some(match self.chain.as_str() {
                "base" => "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913".to_string(),
                "ethereum" => "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2".to_string(),
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

    let chain = Chain::from_str(&cli.chain)
        .unwrap_or_else(|_| panic!("Unknown chain {chain}", chain = cli.chain));

    let tycho_url = env::var("TYCHO_URL").unwrap_or_else(|_| {
        get_default_url(&chain)
            .unwrap_or_else(|| panic!("Unknown URL for chain {chain}", chain = cli.chain))
    });

    let tycho_api_key: String =
        env::var("TYCHO_API_KEY").unwrap_or_else(|_| "sampletoken".to_string());

    // Get Bebop WebSocket credentials
    let bebop_ws_user = env::var("BEBOP_WS_USER")
        .expect("BEBOP_WS_USER environment variable is required. Contact Bebop for credentials.");
    let bebop_ws_key = env::var("BEBOP_WS_KEY")
        .expect("BEBOP_WS_KEY environment variable is required. Contact Bebop for credentials.");

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

    // Set up Bebop RFQ client
    let mut bebop_pairs = HashSet::new();
    bebop_pairs.insert((sell_token_address.to_string(), buy_token_address.to_string()));
    bebop_pairs.insert((buy_token_address.to_string(), sell_token_address.to_string()));

    let mut bebop_quote_tokens = HashSet::new();
    bebop_quote_tokens.insert(buy_token_address.to_string());

    println!("Connecting to Bebop RFQ WebSocket...");
    let bebop_client = BebopClient::new(
        chain.into(), // Convert from models::Chain to dto::Chain
        bebop_pairs,
        cli.tvl_threshold,
        bebop_ws_user,
        bebop_ws_key,
        bebop_quote_tokens,
    )
    .expect("Failed to create Bebop client");

    let (tx, mut rx) = mpsc::channel::<Update>(100);

    let rfq_stream_builder = RFQStreamBuilder::new()
        .add_client::<BebopState>("bebop", Box::new(bebop_client))
        .set_tokens(all_tokens.clone())
        .await;

    println!("Connected to Bebop RFQ! Streaming live quotes...\n");

    // Start the RFQ stream in a background task
    tokio::spawn(rfq_stream_builder.build(tx));

    // Stream quotes from RFQ stream
    while let Some(update) = rx.recv().await {
        println!(
            "Received RFQ quote with {} new pairs for block/timestamp {}",
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
                            "Quote from {}: {} {} -> {} {}",
                            component.protocol_system,
                            format_token_amount(&amount_in, &sell_token),
                            sell_token.symbol,
                            format_token_amount(&amount_out, &buy_token),
                            buy_token.symbol
                        );
                    }
                }
            } else {
                println!("No matching pair found in update.");
            }
        }

        println!("\nWaiting for more quotes... (Press Ctrl+C to exit)");
    }
}

// Format token amounts to human-readable values
fn format_token_amount(amount: &BigUint, token: &Token) -> String {
    let decimal_amount = amount.to_f64().unwrap_or(0.0) / 10f64.powi(token.decimals as i32);
    format!("{decimal_amount:.6}")
}
