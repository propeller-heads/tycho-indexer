use std::{
    collections::{HashMap, HashSet},
    env,
    str::FromStr,
};

use clap::Parser;
use futures::StreamExt;
use num_bigint::BigUint;
use tracing_subscriber::EnvFilter;
use tycho_core::Bytes;
use tycho_simulation::{
    evm::{
        engine_db::tycho_db::PreCachedDB,
        protocol::{
            filters::{balancer_pool_filter, uniswap_v4_pool_with_hook_filter},
            uniswap_v2::state::UniswapV2State,
            uniswap_v4::state::UniswapV4State,
            vm::state::EVMPoolState,
        },
        stream::ProtocolStreamBuilder,
    },
    models::Token,
    protocol::models::BlockUpdate,
    tycho_client::feed::component_tracker::ComponentFilter,
    tycho_core::models::Chain,
    utils::load_all_tokens,
};

#[derive(Parser)]
struct Cli {
    #[arg(short, long, default_value = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2")]
    sell_token: String,
    #[arg(short, long, default_value = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")]
    buy_token: String,
    #[arg(short, long, default_value_t = 1)]
    sell_amount: u32,
    /// The tvl threshold to filter the graph by
    #[arg(short, long, default_value_t = 100.0)]
    tvl_threshold: f64,
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
        BigUint::from(cli.sell_amount) * BigUint::from(10u32).pow(sell_token.decimals as u32);

    println!(
        "Looking for the best swap for {} {} -> {}",
        cli.sell_amount, sell_token.symbol, buy_token.symbol
    );
    let mut pairs: HashMap<String, Vec<Token>> = HashMap::new();
    let mut amounts_out: HashMap<String, BigUint> = HashMap::new();

    let mut protocol_stream = ProtocolStreamBuilder::new(&tycho_url, Chain::Ethereum)
        .exchange::<UniswapV2State>("uniswap_v2", tvl_filter.clone(), None)
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

    while let Some(message) = protocol_stream.next().await {
        let message = message.expect("Could not receive message");
        get_best_swap(
            message,
            &mut pairs,
            amount_in.clone(),
            sell_token.clone(),
            buy_token.clone(),
            &mut amounts_out,
        );
    }
}

fn get_best_swap(
    message: BlockUpdate,
    pairs: &mut HashMap<String, Vec<Token>>,
    amount_in: BigUint,
    sell_token: Token,
    buy_token: Token,
    amounts_out: &mut HashMap<String, BigUint>,
) {
    println!("==================== Received block {:?} ====================", message.block_number);
    for (id, comp) in message.new_pairs.iter() {
        pairs
            .entry(id.clone())
            .or_insert_with(|| comp.tokens.clone());
    }
    if message.states.is_empty() {
        println!("No pools of interest were updated this block. The best swap is the previous one");
        return
    }
    for (id, state) in message.states.iter() {
        if let Some(tokens) = pairs.get(id) {
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
    encode_best_amount_out(amounts_out);
}

fn encode_best_amount_out(amounts_out: &HashMap<String, BigUint>) {
    if let Some((key, amount_out)) = amounts_out
        .iter()
        .max_by_key(|(_, value)| value.to_owned())
    {
        println!(
            "Pool with the highest amount out: {} with {} (out of {} results)",
            key,
            amount_out,
            amounts_out.len()
        );
        // TODO: encode using tycho-execution
    } else {
        println!("There aren't pools with the tokens we are looking for");
    }
}
