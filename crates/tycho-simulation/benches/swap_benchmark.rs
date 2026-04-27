use std::{
    collections::{HashMap, HashSet},
    env,
    time::Duration,
};

use chrono::NaiveDateTime;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use futures::StreamExt;
use num_bigint::BigUint;
use rand::Rng;
use tokio::runtime::Runtime;
use tokio::time::Duration as TokioDuration;
use tycho_common::Bytes;
use tracing::{debug, info, warn};
use tracing_subscriber::EnvFilter;
use tycho_common::{models::token::Token, simulation::protocol_sim::ProtocolSim};
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
    rfq::protocols::bebop::{client::BebopClient, models::BebopPriceData, state::BebopState},
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

async fn load_all_benchmark_data() -> BenchmarkDataByProtocol {
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
        .set_tokens(all_tokens)
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

    protocol_data
}

fn build_bebop_data(num_pools: usize) -> ProtocolBenchmarkData {
    let client = BebopClient::new(
        Chain::Ethereum,
        HashSet::new(),
        0.0,
        String::new(),
        String::new(),
        HashSet::new(),
        TokioDuration::from_secs(5),
    )
    .expect("Failed to create dummy BebopClient");

    let token_pairs: Vec<(Token, Token, f32)> = vec![
        (
            Token::new(
                &hex::decode("C02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2")
                    .unwrap()
                    .into(),
                "WETH",
                18,
                0,
                &[],
                Chain::Ethereum,
                100,
            ),
            Token::new(
                &hex::decode("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")
                    .unwrap()
                    .into(),
                "USDC",
                6,
                0,
                &[],
                Chain::Ethereum,
                100,
            ),
            3000.0,
        ),
        (
            Token::new(
                &hex::decode("2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599")
                    .unwrap()
                    .into(),
                "WBTC",
                8,
                0,
                &[],
                Chain::Ethereum,
                100,
            ),
            Token::new(
                &hex::decode("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")
                    .unwrap()
                    .into(),
                "USDC",
                6,
                0,
                &[],
                Chain::Ethereum,
                100,
            ),
            65000.0,
        ),
    ];

    let mut pools = HashMap::new();
    let mut components = HashMap::new();
    let mut states: HashMap<String, Box<dyn ProtocolSim>> = HashMap::new();
    let mut rng = rand::rng();

    for pool_idx in 0..num_pools {
        let (base, quote, mid_price) = &token_pairs[pool_idx % token_pairs.len()];
        let num_levels = 10;
        let half_spread = mid_price * 10.0 / 10_000.0 / 2.0;

        let mut bids = Vec::with_capacity(num_levels * 2);
        let mut asks = Vec::with_capacity(num_levels * 2);
        for i in 0..num_levels {
            bids.push(mid_price - half_spread - (i as f32 * mid_price * 0.001));
            bids.push(rng.random_range(0.1f32..5.0));
            asks.push(mid_price + half_spread + (i as f32 * mid_price * 0.001));
            asks.push(rng.random_range(0.1f32..5.0));
        }

        let price_data = BebopPriceData {
            base: base.address.to_vec(),
            quote: quote.address.to_vec(),
            last_update_ts: 1700000000,
            bids,
            asks,
        };

        let pool_id = format!("bebop_pool_{pool_idx}");
        let state = BebopState::new(base.clone(), quote.clone(), price_data, client.clone());

        pools.insert(pool_id.clone(), vec![base.clone(), quote.clone()]);
        #[allow(deprecated)]
        components.insert(
            pool_id.clone(),
            ProtocolComponent {
                address: Bytes::default(),
                id: Bytes::from(pool_id.as_bytes().to_vec()),
                tokens: vec![base.clone(), quote.clone()],
                protocol_system: "rfq:bebop".to_string(),
                protocol_type_name: "bebop_pool".to_string(),
                chain: Chain::Ethereum,
                contract_ids: vec![],
                static_attributes: HashMap::new(),
                creation_tx: Bytes::default(),
                created_at: NaiveDateTime::default(),
            },
        );
        states.insert(pool_id, Box::new(state));
    }

    ProtocolBenchmarkData { pools, components, states }
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

fn swap_benchmarks(c: &mut Criterion) {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_target(false)
        .init();

    let rt = Runtime::new().expect("Failed to create tokio runtime");
    let mut benchmark_data = rt.block_on(load_all_benchmark_data());
    rt.shutdown_background();

    benchmark_data.insert("bebop".to_string(), build_bebop_data(20));

    for (protocol, data) in &benchmark_data {
        benchmark_protocol_swaps(c, protocol, data);
    }
}

criterion_group!(benches, swap_benchmarks);
criterion_main!(benches);
