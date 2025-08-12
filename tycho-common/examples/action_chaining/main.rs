//! Action Chaining Playground Example
//!
//! This example demonstrates the action chaining system by building and executing
//! chains of DeFi operations. It showcases type-safe chain construction and
//! sequential execution with state management.


use chrono::NaiveDateTime;
use num_bigint::BigUint;
use tycho_common::{
    action::{
        asset::Asset,
        chain::ChainBuilder,
        context::ActionContext,
        simulate::{DefaultInputs, SimulateForward},
    },
    asset::erc20::ERC20Asset,
    models::{blockchain::Block, token::Token, Chain},
    swap::action::{Swap, SwapParameters},
};

mod uniswap_v2;
use uniswap_v2::UniswapV2Pool;

/// Run the action chaining playground scenarios.
pub fn run_chaining_playground() {
    println!("🔗 Action Chaining Playground Examples");
    println!("======================================\n");

    // Create sample tokens
    let usdc = Token::new(
        &"0xa0b86a33e6ea9f8c9c8b01b30ec6a0e5a7f2e3d4".into(),
        "USDC",
        6,
        0,
        &[Some(21000u64)],
        Chain::Ethereum,
        100,
    );

    let eth = Token::new(
        &"0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2".into(),
        "ETH",
        18,
        0,
        &[Some(21000u64)],
        Chain::Ethereum,
        100,
    );

    let wbtc = Token::new(
        &"0x2260fac5e5542a773aa44fbcfedf7c193bc2c599".into(),
        "WBTC",
        8,
        0,
        &[Some(21000u64)],
        Chain::Ethereum,
        100,
    );

    // Create action context
    let context = ActionContext::new(
        Block {
            number: 18_500_000,
            chain: Chain::Ethereum,
            hash: "0x1234567890123456789012345678901234567890123456789012345678901234".into(),
            parent_hash: "0x0000000000000000000000000000000000000000000000000000000000000000"
                .into(),
            ts: NaiveDateTime::from_timestamp_opt(1640995200, 0).unwrap(),
        },
        Some("0x1234567890123456789012345678901234567890".into()),
        Default::default(),
    );

    // Scenario 1: Single step chain (swap only)
    single_step_chain(&usdc, &eth, &context);

    // Scenario 2: Two-hop swap chain (USDC → ETH → WBTC)
    two_hop_swap_chain(&usdc, &eth, &wbtc, &context);
}

fn single_step_chain(usdc: &Token, eth: &Token, context: &ActionContext) {
    println!("🔗 Scenario 1: Single Step Chain (Swap Only)");
    println!("============================================");

    // Create UniswapV2 pool: 1,000,000 USDC <-> 500 ETH
    let pool = UniswapV2Pool::new(
        usdc.clone(),
        eth.clone(),
        BigUint::from(1_000_000_000_000u64), // 1M USDC
        BigUint::from(500u64) * BigUint::from(10u64).pow(18), // 500 ETH
        BigUint::from(22360679775u64) * BigUint::from(10u64).pow(9), // sqrt(1M * 500) * 1e18
    );

    // Build a single-step chain
    let chain = ChainBuilder::new()
        .start_with::<Swap, _>(
            pool,
            SwapParameters::new(eth.clone()),
        )
        .build();

    println!("Chain built with {} step", chain.step_count());

    // Create input assets
    let input_amount = BigUint::from(10_000_000_000u64); // 10k USDC
    let inputs = DefaultInputs(vec![ERC20Asset::new(usdc.clone(), input_amount.clone())]);

    println!("Input: {} USDC ({:.2})", 
        input_amount,
        format_token_amount(&input_amount, usdc.decimals as u8)
    );

    // Execute the chain
    match chain.execute(inputs, context) {
        Ok(result) => {
            let outputs = result.outputs();
            if !outputs.produced().is_empty() {
                let eth_output = &outputs.produced()[0];
                println!("Output: {} ETH ({:.6})", 
                    eth_output.amount().unwrap(),
                    format_token_amount(eth_output.amount().unwrap(), eth.decimals as u8)
                );
                println!("Gas consumed: {}", outputs.gas_spent());
            }
        }
        Err(e) => println!("Chain execution failed: {:?}", e),
    }
    println!();
}

fn two_hop_swap_chain(usdc: &Token, eth: &Token, wbtc: &Token, context: &ActionContext) {
    println!("🔗 Scenario 2: Two-Hop Swap Chain (USDC → ETH → WBTC)");
    println!("====================================================");

    // Create two pools for the two-hop swap
    // Pool 1: USDC/ETH - 1,000,000 USDC : 500 ETH (ETH = $2000)
    let usdc_eth_pool = UniswapV2Pool::new(
        usdc.clone(),
        eth.clone(),
        BigUint::from(1_000_000_000_000u64), // 1M USDC (6 decimals)
        BigUint::from(500u64) * BigUint::from(10u64).pow(18), // 500 ETH (18 decimals)
        BigUint::from(22360679775u64) * BigUint::from(10u64).pow(9), // sqrt(1M * 500) * 1e18
    );

    // Pool 2: ETH/WBTC - 1000 ETH : 25 WBTC (WBTC = $40000, ETH = $2000)
    let eth_wbtc_pool = UniswapV2Pool::new(
        eth.clone(),
        wbtc.clone(),
        BigUint::from(1000u64) * BigUint::from(10u64).pow(18), // 1000 ETH (18 decimals)
        BigUint::from(25u64) * BigUint::from(10u64).pow(8), // 25 WBTC (8 decimals)
        BigUint::from(158113883008u64) * BigUint::from(10u64).pow(8), // sqrt(1000 * 25) * 1e18
    );

    // Build a true two-hop swap chain using the add_step method with OutputsToInputs converter
    println!("Building two-hop swap chain...");
    let chain = ChainBuilder::new()
        .start_with::<Swap, _>(
            usdc_eth_pool,
            SwapParameters::new(eth.clone()),
        )
        .add_step::<Swap, _>(
            eth_wbtc_pool,
            SwapParameters::new(wbtc.clone()),
        )
        .build();

    println!("Chain built with {} steps", chain.step_count());

    // Execute the two-hop swap as a single chain
    let input_amount = BigUint::from(10_000_000_000u64); // 10k USDC
    let inputs = DefaultInputs(vec![ERC20Asset::new(usdc.clone(), input_amount.clone())]);

    println!("Input: {} USDC ({:.2})", 
        input_amount,
        format_token_amount(&input_amount, usdc.decimals as u8)
    );

    match chain.execute(inputs, context) {
        Ok(result) => {
            let outputs = result.outputs();
            if !outputs.produced().is_empty() {
                let wbtc_asset = &outputs.produced()[0];
                println!("Final Output: {} WBTC ({:.8})", 
                    wbtc_asset.amount().unwrap(),
                    format_token_amount(wbtc_asset.amount().unwrap(), wbtc.decimals as u8)
                );
                println!("Gas consumed: {}", outputs.gas_spent());
            }
            println!("✅ Two-hop swap chain executed successfully!");
        }
        Err(e) => println!("❌ Two-hop swap chain failed: {:?}", e),
    }
    println!();
}

fn format_token_amount(amount: &BigUint, decimals: u8) -> f64 {
    let divisor = BigUint::from(10u32).pow(decimals as u32);
    let integer_part = amount / &divisor;
    let fractional_part = amount % &divisor;

    let integer_f64 = integer_part
        .to_string()
        .parse::<f64>()
        .unwrap_or(0.0);
    let fractional_f64 = fractional_part
        .to_string()
        .parse::<f64>()
        .unwrap_or(0.0) /
        divisor
            .to_string()
            .parse::<f64>()
            .unwrap_or(1.0);

    integer_f64 + fractional_f64
}

fn main() {
    run_chaining_playground();
}