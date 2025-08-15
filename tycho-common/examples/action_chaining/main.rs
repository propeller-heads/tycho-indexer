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
        chain::{converters::SwapOutputsPlusInventory, AssetInventory, ChainBuilder},
        context::ActionContext,
        simulate::{DefaultInputs, SimulateForward},
    },
    asset::erc20::{ERC20Asset, ERC20DefaultOutputs},
    liquidity_provision::action::{AddLiquidityFullRange, AddLiquidityFullRangeParameters},
    models::{blockchain::Block, token::Token, Chain},
    simulation::errors::SimulationError,
    swap::action::{Swap, SwapParameters},
};

mod uniswap_v2;
use uniswap_v2::UniswapV2Pool;

/// Run the action chaining playground scenarios.
pub fn run_chaining_playground() {
    println!("🔗 Action Chaining Playground");
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

    let mut inventory = AssetInventory::new();
    inventory
        .store(Box::new(ERC20Asset::new(usdc.clone(), BigUint::from(1000_000_000_000u64))))
        .unwrap();

    // Scenario 4: Same as 3 but using proper ChainBuilder
    let usdc_eth_pool = UniswapV2Pool::new(
        usdc.clone(),
        eth.clone(),
        BigUint::from(2_000_000_000_000u64), // 2M USDC
        BigUint::from(1000u64) * BigUint::from(10u64).pow(18), // 1000 ETH (ratio 1 ETH = 2000 USDC)
        BigUint::from(1414213562373u64) * BigUint::from(10u64).pow(12), // sqrt(2M * 1000) * 1e18
    );

    // Create the custom converter that combines swap outputs with inventory
    println!("Building chain with SwapOutputsPlusInventory converter...");
    let inventory_converter = SwapOutputsPlusInventory::new(
        usdc.clone(),
        BigUint::from(500_000_000_000u64), // 500 USDC from inventory
    );

    let chain = ChainBuilder::new()
        .with_inventory(inventory)
        .start_with::<Swap, _>(usdc_eth_pool.clone(), SwapParameters::new(eth.clone()))
        .add_step_with_linker::<AddLiquidityFullRange, _>(
            usdc_eth_pool,
            AddLiquidityFullRangeParameters,
            inventory_converter,
        )
        .build();

    println!("Chain built with {} steps", chain.step_count());

    // Execute the complete chain with 500 USDC input
    let input_amount = BigUint::from(500_000_000_000u64); // 500 USDC for swap
    let inputs = DefaultInputs(vec![ERC20Asset::new(usdc.clone(), input_amount.clone())]);

    println!(
        "Input: {} USDC ({:.2})",
        input_amount,
        format_token_amount(&input_amount, usdc.decimals as u8)
    );

    match chain.execute(inputs, &context) {
        Ok(result) => {
            let outputs = result.outputs();
            if !outputs.produced().is_empty() {
                let lp_asset = &outputs.produced()[0];
                println!(
                    "Final Output: {} LP tokens ({:.6})",
                    lp_asset.amount().unwrap(),
                    format_token_amount(lp_asset.amount().unwrap(), 18)
                );
                println!("Total gas consumed: {}", outputs.gas_spent());
            }
        }
        Err(e) => println!("❌ Chain execution failed: {:?}", e),
    }
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
