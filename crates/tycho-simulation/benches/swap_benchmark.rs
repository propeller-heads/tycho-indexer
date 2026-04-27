use std::{collections::HashMap, env, str::FromStr, time::Duration};

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use futures::StreamExt;
use num_bigint::BigUint;
use rand::Rng;
use tokio::runtime::Runtime;
use tracing::{debug, info, warn};
use tracing_subscriber::EnvFilter;
use tycho_common::{models::token::Token, simulation::protocol_sim::ProtocolSim, Bytes};
use tycho_simulation::{
    evm::{
        engine_db::tycho_db::PreCachedDB,
        protocol::{
            ekubo::state::EkuboState,
            filters::{balancer_v2_pool_filter, curve_pool_filter},
            uniswap_v2::state::UniswapV2State,
            uniswap_v3::state::UniswapV3State,
            uniswap_v4::state::UniswapV4State,
            vm::state::EVMPoolState,
        },
        stream::ProtocolStreamBuilder,
    },
    protocol::models::ProtocolComponent,
    rfq::{
        client::RFQClient,
        protocols::bebop::{
            client_builder::BebopClientBuilder, models::BebopPriceData, state::BebopState,
        },
    },
    tycho_client::feed::component_tracker::ComponentFilter,
    tycho_common::models::Chain,
    utils::load_all_tokens,
};

const DEFAULT_N_SWAPS: usize = 100;
const DEFAULT_TVL_THRESHOLD: f64 = 1000.0;

fn get_config() -> (usize, f64) {
    let n_swaps = env::var("BENCH_N_SWAPS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_N_SWAPS);

    let tvl_threshold = env::var("BENCH_TVL_THRESHOLD")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_TVL_THRESHOLD);

    (n_swaps, tvl_threshold)
}

#[derive(Clone)]
struct ProtocolBenchmarkData {
    pools: HashMap<String, Vec<Token>>,
    components: HashMap<String, ProtocolComponent>,
    states: HashMap<String, Box<dyn ProtocolSim>>,
}

type BenchmarkDataByProtocol = HashMap<String, ProtocolBenchmarkData>;

async fn load_all_benchmark_data() -> (BenchmarkDataByProtocol, HashMap<Bytes, Token>) {
    let (_, tvl_threshold) = get_config();

    let tycho_url =
        env::var("TYCHO_URL").unwrap_or_else(|_| "tycho-beta.propellerheads.xyz".to_string());
    let tycho_api_key = env::var("TYCHO_API_KEY").unwrap_or_else(|_| "sampletoken".to_string());

    let tvl_filter = ComponentFilter::with_tvl_range(tvl_threshold, tvl_threshold);

    let all_tokens = load_all_tokens(
        &tycho_url,
        false,
        Some(&tycho_api_key),
        false,
        Chain::Ethereum,
        None,
        None,
    )
    .await
    .expect("Failed to load tokens");

    let protocol_stream = ProtocolStreamBuilder::new(&tycho_url, Chain::Ethereum)
        .exchange::<UniswapV2State>("uniswap_v2", tvl_filter.clone(), None)
        .exchange::<UniswapV3State>("uniswap_v3", tvl_filter.clone(), None)
        .exchange::<UniswapV4State>("uniswap_v4", tvl_filter.clone(), None)
        .exchange::<EVMPoolState<PreCachedDB>>(
            "vm:balancer_v2",
            tvl_filter.clone(),
            Some(balancer_v2_pool_filter),
        )
        .exchange::<EVMPoolState<PreCachedDB>>(
            "vm:curve",
            tvl_filter.clone(),
            Some(curve_pool_filter),
        )
        .exchange::<EkuboState>("ekubo_v2", tvl_filter.clone(), None)
        .auth_key(Some(tycho_api_key))
        .set_tokens(all_tokens.clone())
        .await
        .skip_state_decode_failures(true)
        .build()
        .await
        .expect("Failed to build protocol stream");

    let mut stream = Box::pin(protocol_stream);

    let protocols = [
        "uniswap_v2",
        "uniswap_v3",
        "uniswap_v4",
        "balancer_v2",
        "curve",
        "ekubo_v2",
    ];

    let mut protocol_data: BenchmarkDataByProtocol = protocols
        .iter()
        .map(|p| {
            (
                p.to_string(),
                ProtocolBenchmarkData {
                    pools: HashMap::new(),
                    components: HashMap::new(),
                    states: HashMap::new(),
                },
            )
        })
        .collect();

    match stream.next().await {
        Some(Ok(message)) => {
            info!(
                "Loaded {} pairs and {} states",
                message.new_pairs.len(),
                message.states.len()
            );

            for (id, component) in message.new_pairs.iter() {
                let protocol_name =
                    map_protocol_system_to_protocol(&component.protocol_system);
                if let Some(data) = protocol_data.get_mut(&protocol_name) {
                    data.pools
                        .insert(id.clone(), component.tokens.clone());
                    data.components
                        .insert(id.clone(), component.clone());
                }
            }

            for (id, state) in message.states.into_iter() {
                for data in protocol_data.values_mut() {
                    if data.components.contains_key(&id) {
                        data.states.insert(id.clone(), state);
                        break;
                    }
                }
            }
        }
        Some(Err(e)) => {
            panic!("Error loading protocol data: {e:?}");
        }
        None => {
            panic!("No data received from protocol stream");
        }
    }

    (protocol_data, all_tokens)
}

struct BebopBenchmarkData {
    pools: HashMap<String, (Token, Token)>,
    states: HashMap<String, BebopState>,
}

async fn load_bebop_data(
    all_tokens: &HashMap<Bytes, Token>,
    tvl_threshold: f64,
) -> BebopBenchmarkData {
    let bebop_user = env::var("BEBOP_USER").expect("BEBOP_USER env var required");
    let bebop_key = env::var("BEBOP_KEY").expect("BEBOP_KEY env var required");

    let token_addresses: Vec<Bytes> = vec![
        "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2", // WETH
        "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", // USDC
        "0xdAC17F958D2ee523a2206206994597C13D831ec7", // USDT
        "0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599", // WBTC
        "0x6B175474E89094C44Da98b954EedeAC495271d0F", // DAI
    ]
    .into_iter()
    .filter_map(|addr| Bytes::from_str(addr).ok())
    .collect();

    let tokens_set = token_addresses.iter().cloned().collect();

    let client = BebopClientBuilder::new(Chain::Ethereum, bebop_user, bebop_key)
        .tokens(tokens_set)
        .tvl_threshold(tvl_threshold)
        .build()
        .expect("Failed to build BebopClient");

    info!("Connecting to Bebop WebSocket...");
    let mut stream = client.stream();

    let msg = tokio::time::timeout(Duration::from_secs(30), stream.next())
        .await
        .expect("Timed out waiting for Bebop pricing update")
        .expect("Stream ended without producing a message")
        .expect("Bebop stream error");

    let (_provider, sync_msg) = msg;

    info!(
        "Received {} components from Bebop",
        sync_msg.snapshots.states.len()
    );

    let mut pools = HashMap::new();
    let mut states = HashMap::new();
    let mut bid_depths: Vec<usize> = Vec::new();
    let mut ask_depths: Vec<usize> = Vec::new();

    for (component_id, component_with_state) in sync_msg.snapshots.states {
        let component = &component_with_state.component;

        if component.tokens.len() != 2 {
            continue;
        }

        let base_addr = &component.tokens[0];
        let quote_addr = &component.tokens[1];

        let Some(base_token) = all_tokens.get(base_addr) else {
            warn!("Base token not found: {base_addr}");
            continue;
        };
        let Some(quote_token) = all_tokens.get(quote_addr) else {
            warn!("Quote token not found: {quote_addr}");
            continue;
        };

        let state_attrs = &component_with_state.state.attributes;
        let empty_array: Bytes = "[]".as_bytes().to_vec().into();
        let bids_json = state_attrs.get("bids").unwrap_or(&empty_array);
        let asks_json = state_attrs.get("asks").unwrap_or(&empty_array);

        let bids: Vec<(f32, f32)> = match serde_json::from_slice(bids_json) {
            Ok(b) => b,
            Err(e) => {
                warn!("Failed to parse bids for {component_id}: {e}");
                continue;
            }
        };
        let asks: Vec<(f32, f32)> = match serde_json::from_slice(asks_json) {
            Ok(a) => a,
            Err(e) => {
                warn!("Failed to parse asks for {component_id}: {e}");
                continue;
            }
        };

        let price_data = BebopPriceData {
            base: base_token.address.to_vec(),
            quote: quote_token.address.to_vec(),
            last_update_ts: sync_msg.header.timestamp,
            bids: bids
                .iter()
                .flat_map(|(price, size)| [*price, *size])
                .collect(),
            asks: asks
                .iter()
                .flat_map(|(price, size)| [*price, *size])
                .collect(),
        };

        let bench_client = BebopClientBuilder::new(
            Chain::Ethereum,
            env::var("BEBOP_USER").unwrap_or_default(),
            env::var("BEBOP_KEY").unwrap_or_default(),
        )
        .build()
        .expect("Failed to build BebopClient for state");

        let state =
            BebopState::new(base_token.clone(), quote_token.clone(), price_data, bench_client);

        bid_depths.push(state.price_data.bids.len() / 2);
        ask_depths.push(state.price_data.asks.len() / 2);

        pools.insert(
            component_id.clone(),
            (base_token.clone(), quote_token.clone()),
        );
        states.insert(component_id, state);
    }

    let avg_bid = bid_depths.iter().sum::<usize>() as f64 / bid_depths.len().max(1) as f64;
    let avg_ask = ask_depths.iter().sum::<usize>() as f64 / ask_depths.len().max(1) as f64;
    let max_bid = bid_depths.iter().max().copied().unwrap_or(0);
    let max_ask = ask_depths.iter().max().copied().unwrap_or(0);
    info!(
        "Loaded {} Bebop pools — order book depth: bids avg={avg_bid:.1} max={max_bid}, asks avg={avg_ask:.1} max={max_ask}",
        states.len()
    );

    BebopBenchmarkData { pools, states }
}

fn map_protocol_system_to_protocol(protocol_system: &str) -> String {
    match protocol_system {
        "uniswap_v2" => "uniswap_v2",
        "uniswap_v3" => "uniswap_v3",
        "uniswap_v4" => "uniswap_v4",
        "vm:balancer_v2" => "balancer_v2",
        "vm:curve" => "curve",
        "ekubo_v2" => "ekubo_v2",
        other => other,
    }
    .to_string()
}

fn benchmark_protocol_swaps(c: &mut Criterion, protocol: &str, data: &ProtocolBenchmarkData) {
    let (n_swaps, _) = get_config();

    let mut group = c.benchmark_group(format!("{protocol}_swaps"));
    group
        .measurement_time(Duration::from_secs(10))
        .sample_size(n_swaps);

    let total_pools = data.pools.len();
    let working_states = data.states.len();
    info!("Protocol {protocol}: {total_pools} pools, {working_states} working states");

    let mut swap_scenarios: Vec<(String, BigUint, Token, Token, &Box<dyn ProtocolSim>)> =
        Vec::new();
    let mut rng = rand::rng();
    for (pool_id, tokens) in data.pools.iter().cycle().take(n_swaps) {
        let Some(state) = data.states.get(pool_id) else {
            continue;
        };
        if tokens.len() < 2 {
            continue;
        }
        let Ok((upper, _)) =
            state.get_limits(tokens[0].address.clone(), tokens[1].address.clone())
        else {
            continue;
        };
        if upper == BigUint::ZERO {
            continue;
        }
        let p: u32 = rng.random_range(1..=85);
        let amount_in = &upper * BigUint::from(p) / BigUint::from(100u32);
        swap_scenarios.push((
            pool_id.clone(),
            amount_in,
            tokens[0].clone(),
            tokens[1].clone(),
            state,
        ));
    }

    if swap_scenarios.is_empty() {
        info!("No valid swap scenarios for {protocol}, skipping");
        group.finish();
        return;
    }

    debug!("Sample swap scenarios for {protocol}:");
    for (i, (pool_id, amount_in, token_in, token_out, state)) in
        swap_scenarios.iter().take(5).enumerate()
    {
        match state.get_amount_out(amount_in.clone(), token_in, token_out) {
            Ok(result) => {
                debug!(
                    "  [{i}] Pool {}: {} {} -> {} {}",
                    &pool_id[..pool_id.len().min(8)],
                    amount_in,
                    token_in.symbol,
                    result.amount,
                    token_out.symbol,
                );
            }
            Err(e) => {
                warn!(
                    "  [{i}] Pool {} FAILED: {} {} -> {} error: {e}",
                    &pool_id[..pool_id.len().min(8)],
                    amount_in,
                    token_in.symbol,
                    token_out.symbol,
                );
            }
        }
    }

    group.bench_with_input(
        BenchmarkId::new(
            "get_amount_out",
            format!("{}_swaps_from_{}_pools", swap_scenarios.len(), total_pools),
        ),
        &swap_scenarios,
        |b, scenarios| {
            let mut scenario_iter = scenarios.iter().cycle();
            b.iter(|| {
                let (_, amount_in, token_in, token_out, state) =
                    scenario_iter.next().unwrap();
                state
                    .get_amount_out(amount_in.clone(), token_in, token_out)
                    .expect("swap failed");
            });
        },
    );

    group.finish();
}

fn benchmark_bebop_swaps(c: &mut Criterion, data: &BebopBenchmarkData) {
    let (n_swaps, _) = get_config();

    let mut group = c.benchmark_group("bebop_swaps");
    group
        .measurement_time(Duration::from_secs(10))
        .sample_size(n_swaps);

    let total_pools = data.pools.len();
    info!("Bebop: {total_pools} pools, {} working states", data.states.len());

    let mut swap_scenarios: Vec<(String, BigUint, Token, Token, &BebopState)> = Vec::new();
    let mut rng = rand::rng();
    for (pool_id, (base_token, quote_token)) in data.pools.iter().cycle().take(n_swaps) {
        let Some(state) = data.states.get(pool_id) else {
            continue;
        };
        let Ok((upper, _)) =
            state.get_limits(base_token.address.clone(), quote_token.address.clone())
        else {
            continue;
        };
        if upper == BigUint::ZERO {
            continue;
        }
        let p: u32 = rng.random_range(1..=85);
        let amount_in = &upper * BigUint::from(p) / BigUint::from(100u32);
        swap_scenarios.push((
            pool_id.clone(),
            amount_in,
            base_token.clone(),
            quote_token.clone(),
            state,
        ));
    }

    if swap_scenarios.is_empty() {
        info!("No valid swap scenarios for Bebop, skipping");
        group.finish();
        return;
    }

    debug!("Sample swap scenarios for Bebop:");
    for (i, (pool_id, amount_in, token_in, token_out, state)) in
        swap_scenarios.iter().take(5).enumerate()
    {
        match state.get_amount_out(amount_in.clone(), token_in, token_out) {
            Ok(result) => {
                debug!(
                    "  [{i}] Pool {}: {} {} -> {} {}",
                    &pool_id[..pool_id.len().min(8)],
                    amount_in,
                    token_in.symbol,
                    result.amount,
                    token_out.symbol,
                );
            }
            Err(e) => {
                warn!(
                    "  [{i}] Pool {} FAILED: {} {} -> {} error: {e}",
                    &pool_id[..pool_id.len().min(8)],
                    amount_in,
                    token_in.symbol,
                    token_out.symbol,
                );
            }
        }
    }

    group.bench_with_input(
        BenchmarkId::new(
            "get_amount_out",
            format!("{}_swaps_from_{}_pools", swap_scenarios.len(), total_pools),
        ),
        &swap_scenarios,
        |b, scenarios| {
            let mut scenario_iter = scenarios.iter().cycle();
            b.iter(|| {
                let (_, amount_in, token_in, token_out, state) =
                    scenario_iter.next().unwrap();
                state
                    .get_amount_out(amount_in.clone(), token_in, token_out)
                    .expect("swap failed");
            });
        },
    );

    group.finish();
}

fn swap_benchmarks(c: &mut Criterion) {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_target(false)
        .init();

    let rt = Runtime::new().expect("Failed to create tokio runtime");
    let (_, tvl_threshold) = get_config();

    let (benchmark_data, all_tokens) = rt.block_on(load_all_benchmark_data());
    let bebop_data = rt.block_on(load_bebop_data(&all_tokens, tvl_threshold));
    rt.shutdown_background();

    for (protocol, data) in &benchmark_data {
        benchmark_protocol_swaps(c, protocol, data);
    }
    benchmark_bebop_swaps(c, &bebop_data);
}

criterion_group!(benches, swap_benchmarks);
criterion_main!(benches);
