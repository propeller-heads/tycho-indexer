use std::{collections::HashMap, time::Duration};

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use num_bigint::BigUint;
use rand::Rng;
use tycho_common::{
    dto::{ChangeType, ProtocolComponent, ResponseProtocolState},
    models::{token::Token, Chain},
    simulation::protocol_sim::ProtocolSim,
    Bytes,
};
use tycho_simulation::{
    protocol::models::{DecoderContext, TryFromWithBlock},
    rfq::{models::TimestampHeader, protocols::bebop::state::BebopState},
    tycho_client::feed::synchronizer::ComponentWithState,
};

fn weth() -> Token {
    Token::new(
        &Bytes::from(hex::decode("C02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2").unwrap()),
        "WETH",
        18,
        0,
        &[],
        Chain::Ethereum,
        100,
    )
}

fn usdc() -> Token {
    Token::new(
        &Bytes::from(hex::decode("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48").unwrap()),
        "USDC",
        6,
        0,
        &[],
        Chain::Ethereum,
        100,
    )
}

fn wbtc() -> Token {
    Token::new(
        &Bytes::from(hex::decode("2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599").unwrap()),
        "WBTC",
        8,
        0,
        &[],
        Chain::Ethereum,
        100,
    )
}

fn generate_order_book_snapshot(
    base_token: &Token,
    quote_token: &Token,
    mid_price: f32,
    spread_bps: f32,
    num_levels: usize,
) -> ComponentWithState {
    let mut rng = rand::rng();
    let half_spread = mid_price * spread_bps / 10_000.0 / 2.0;

    let mut bids: Vec<(f32, f32)> = Vec::with_capacity(num_levels);
    let mut asks: Vec<(f32, f32)> = Vec::with_capacity(num_levels);

    for i in 0..num_levels {
        let bid_price = mid_price - half_spread - (i as f32 * mid_price * 0.001);
        let ask_price = mid_price + half_spread + (i as f32 * mid_price * 0.001);
        let bid_size: f32 = rng.random_range(0.1..5.0);
        let ask_size: f32 = rng.random_range(0.1..5.0);
        bids.push((bid_price, bid_size));
        asks.push((ask_price, ask_size));
    }

    let mut state_attributes = HashMap::new();
    state_attributes.insert(
        "bids".to_string(),
        serde_json::to_vec(&bids).expect("serialize bids").into(),
    );
    state_attributes.insert(
        "asks".to_string(),
        serde_json::to_vec(&asks).expect("serialize asks").into(),
    );

    let component_id = format!(
        "bebop_{}_{}_{}levels",
        base_token.symbol, quote_token.symbol, num_levels
    );

    ComponentWithState {
        state: ResponseProtocolState {
            attributes: state_attributes,
            component_id: component_id.clone(),
            balances: HashMap::new(),
        },
        component: ProtocolComponent {
            id: component_id,
            protocol_system: "bebop".to_string(),
            protocol_type_name: "bebop".to_string(),
            chain: tycho_common::dto::Chain::Ethereum,
            tokens: vec![base_token.address.clone(), quote_token.address.clone()],
            contract_ids: Vec::new(),
            static_attributes: HashMap::new(),
            change: ChangeType::Creation,
            creation_tx: Bytes::default(),
            created_at: chrono::NaiveDateTime::default(),
        },
        component_tvl: None,
        entrypoints: Vec::new(),
    }
}

struct BenchScenario {
    label: String,
    state: BebopState,
    base_token: Token,
    quote_token: Token,
    amounts_sell_base: Vec<BigUint>,
    amounts_sell_quote: Vec<BigUint>,
}

async fn build_scenarios() -> Vec<BenchScenario> {
    let mut scenarios = Vec::new();

    let pairs: Vec<(&str, Token, Token, f32)> =
        vec![("WETH/USDC", weth(), usdc(), 3000.0), ("WBTC/USDC", wbtc(), usdc(), 65000.0)];

    let level_counts = [3, 10, 200];
    let timestamp_header = TimestampHeader { timestamp: 1700000000 };
    let empty_balances = HashMap::new();
    let decoder_context = DecoderContext::new();

    let mut all_tokens = HashMap::new();
    for (_, base, quote, _) in &pairs {
        all_tokens.insert(base.address.clone(), base.clone());
        all_tokens.insert(quote.address.clone(), quote.clone());
    }

    let mut rng = rand::rng();

    for (pair_name, base_token, quote_token, mid_price) in &pairs {
        for &num_levels in &level_counts {
            let snapshot = generate_order_book_snapshot(
                base_token,
                quote_token,
                *mid_price,
                10.0,
                num_levels,
            );

            let state = BebopState::try_from_with_header(
                snapshot,
                timestamp_header.clone(),
                &empty_balances,
                &all_tokens,
                &decoder_context,
            )
            .await
            .expect("Failed to decode BebopState from snapshot");

            let (sell_limit, _) = state
                .get_limits(base_token.address.clone(), quote_token.address.clone())
                .expect("get_limits failed for sell-base");
            let (buy_limit, _) = state
                .get_limits(quote_token.address.clone(), base_token.address.clone())
                .expect("get_limits failed for sell-quote");

            let amounts_sell_base: Vec<BigUint> = (0..50)
                .map(|_| {
                    let pct: u32 = rng.random_range(1..=85);
                    &sell_limit * BigUint::from(pct) / BigUint::from(100u32)
                })
                .collect();

            let amounts_sell_quote: Vec<BigUint> = (0..50)
                .map(|_| {
                    let pct: u32 = rng.random_range(1..=85);
                    &buy_limit * BigUint::from(pct) / BigUint::from(100u32)
                })
                .collect();

            scenarios.push(BenchScenario {
                label: format!("{pair_name}_{num_levels}_levels"),
                state,
                base_token: base_token.clone(),
                quote_token: quote_token.clone(),
                amounts_sell_base,
                amounts_sell_quote,
            });
        }
    }

    scenarios
}

fn bench_get_amount_out(c: &mut Criterion) {
    std::env::set_var("BEBOP_USER", "bench_user");
    std::env::set_var("BEBOP_KEY", "bench_key");

    let rt = tokio::runtime::Runtime::new().expect("Failed to create tokio runtime");
    let scenarios = rt.block_on(build_scenarios());

    let mut group = c.benchmark_group("bebop_get_amount_out");
    group.measurement_time(Duration::from_secs(5));

    for scenario in &scenarios {
        group.bench_with_input(
            BenchmarkId::new("sell_base", &scenario.label),
            &scenario,
            |b, s| {
                let mut iter = s.amounts_sell_base.iter().cycle();
                b.iter(|| {
                    let amount = iter.next().unwrap();
                    let _ = s
                        .state
                        .get_amount_out(amount.clone(), &s.base_token, &s.quote_token);
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("sell_quote", &scenario.label),
            &scenario,
            |b, s| {
                let mut iter = s.amounts_sell_quote.iter().cycle();
                b.iter(|| {
                    let amount = iter.next().unwrap();
                    let _ = s
                        .state
                        .get_amount_out(amount.clone(), &s.quote_token, &s.base_token);
                });
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_get_amount_out);
criterion_main!(benches);
