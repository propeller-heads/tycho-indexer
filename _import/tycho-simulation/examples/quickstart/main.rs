use std::{collections::HashMap, env};

use futures::{future::select_all, StreamExt};
use num_bigint::BigUint;
use tokio::{sync::mpsc, task, task::JoinHandle};
use tracing_subscriber::EnvFilter;
use tycho_simulation::{
    evm::{
        engine_db::tycho_db::PreCachedDB,
        protocol::{
            filters::balancer_pool_filter, uniswap_v2::state::UniswapV2State,
            vm::state::EVMPoolState,
        },
        stream::ProtocolStreamBuilder,
    },
    models::Token,
    protocol::models::BlockUpdate,
    tycho_client::feed::component_tracker::ComponentFilter,
    tycho_core::dto::Chain,
    utils::load_all_tokens,
};

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

    let tvl_threshold = 10_000.0;

    let all_tokens = load_all_tokens(tycho_url.as_str(), Some(tycho_api_key.as_str())).await;

    // Communication channels
    let (tick_tx, mut tick_rx) = mpsc::channel::<BlockUpdate>(12);

    // Producer task: Fetch updates and send them via channel
    let tycho_message_processor: JoinHandle<anyhow::Result<()>> = tokio::spawn(async move {
        let tvl_filter = ComponentFilter::with_tvl_range(tvl_threshold, tvl_threshold);

        let mut protocol_stream = ProtocolStreamBuilder::new(&tycho_url, Chain::Ethereum)
            .exchange::<UniswapV2State>("uniswap_v2", tvl_filter.clone(), None)
            .exchange::<EVMPoolState<PreCachedDB>>(
                "vm:balancer_v2",
                tvl_filter.clone(),
                Some(balancer_pool_filter),
            )
            .auth_key(Some(tycho_api_key.clone()))
            .set_tokens(all_tokens.clone())
            .await
            .build()
            .await
            .expect("Failed building protocol stream");

        while let Some(msg) = protocol_stream.next().await {
            tick_tx
                .send(msg.unwrap())
                .await
                .expect("Sending tick failed!");
        }
        anyhow::Result::Ok(())
    });

    // Consumer task: Process messages and perform calculations
    let consumer_handle = task::spawn(async move {
        let mut pairs: HashMap<String, Vec<Token>> = HashMap::new();
        while let Some(message) = tick_rx.recv().await {
            println!(
                "==================== Received block {:?} ====================",
                message.block_number
            );
            for (id, comp) in message.new_pairs.iter() {
                pairs
                    .entry(id.clone())
                    .or_insert_with(|| comp.tokens.clone());
            }
            if message.states.is_empty() {
                println!("No pools were updated this block");
                continue;
            }
            println!("Using only pools that were updated this block...");
            for (id, state) in message.states.iter().take(10) {
                if let Some(tokens) = pairs.get(id) {
                    let formatted_token_str =
                        format!("{:}/{:}", &tokens[0].symbol, &tokens[1].symbol);
                    println!(
                        "Calculations for pool {:?} with tokens {:?}",
                        id, formatted_token_str
                    );
                    state
                        .spot_price(&tokens[0], &tokens[1])
                        .map(|price| println!("Spot price {:?}: {:?}", price, formatted_token_str))
                        .map_err(|e| {
                            eprintln!("Error calculating spot price for Pool {:?}: {:?}", id, e)
                        })
                        .ok();
                    let amount_in =
                        BigUint::from(1u32) * BigUint::from(10u32).pow(tokens[0].decimals as u32);
                    state
                        .get_amount_out(amount_in, &tokens[0], &tokens[1])
                        .map(|result| {
                            println!(
                                "Amount out for trading 1 {:?} -> {:?}: {:?} (takes {:?} gas)",
                                &tokens[0].symbol, &tokens[1].symbol, result.amount, result.gas
                            )
                        })
                        .map_err(|e| {
                            eprintln!("Error calculating amount out for Pool {:?}: {:?}", id, e)
                        })
                        .ok();
                }
            }
        }
        Ok(())
    });

    let tasks = [tycho_message_processor, consumer_handle];
    let _ = select_all(tasks).await;
}
