use std::{collections::HashSet, time::Duration};

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use num_bigint::BigUint;
use rand::Rng;
use tokio::time::Duration as TokioDuration;
use tycho_common::{
    models::{token::Token, Chain},
    simulation::protocol_sim::ProtocolSim,
    Bytes,
};
use tycho_simulation::rfq::protocols::bebop::{
    client::BebopClient, models::BebopPriceData, state::BebopState,
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

fn dummy_client() -> BebopClient {
    BebopClient::new(
        Chain::Ethereum,
        HashSet::new(),
        0.0,
        String::new(),
        String::new(),
        HashSet::new(),
        TokioDuration::from_secs(5),
    )
    .expect("Failed to create dummy BebopClient")
}

fn generate_order_book(
    base_addr: &[u8],
    quote_addr: &[u8],
    mid_price: f32,
    spread_bps: f32,
    num_levels: usize,
) -> BebopPriceData {
    let mut rng = rand::rng();
    let half_spread = mid_price * spread_bps / 10_000.0 / 2.0;

    let mut bids = Vec::with_capacity(num_levels * 2);
    let mut asks = Vec::with_capacity(num_levels * 2);

    for i in 0..num_levels {
        let bid_price = mid_price - half_spread - (i as f32 * mid_price * 0.001);
        let ask_price = mid_price + half_spread + (i as f32 * mid_price * 0.001);
        let bid_size: f32 = rng.random_range(0.1..5.0);
        let ask_size: f32 = rng.random_range(0.1..5.0);
        bids.push(bid_price);
        bids.push(bid_size);
        asks.push(ask_price);
        asks.push(ask_size);
    }

    BebopPriceData {
        base: base_addr.to_vec(),
        quote: quote_addr.to_vec(),
        last_update_ts: 1700000000,
        bids,
        asks,
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

fn build_scenarios() -> Vec<BenchScenario> {
    let client = dummy_client();
    let mut scenarios = Vec::new();

    let pairs: Vec<(&str, Token, Token, f32)> =
        vec![("WETH/USDC", weth(), usdc(), 3000.0), ("WBTC/USDC", wbtc(), usdc(), 65000.0)];

    let level_counts = [3, 10, 50];

    let mut rng = rand::rng();

    for (pair_name, base_token, quote_token, mid_price) in &pairs {
        for &num_levels in &level_counts {
            let price_data = generate_order_book(
                &base_token.address,
                &quote_token.address,
                *mid_price,
                10.0,
                num_levels,
            );

            let state = BebopState::new(
                base_token.clone(),
                quote_token.clone(),
                price_data,
                client.clone(),
            );

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
    let scenarios = build_scenarios();

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
