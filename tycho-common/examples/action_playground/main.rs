//! Action System Playground Example
//!
//! This example demonstrates the action trait system using a UniswapV2 implementation.
//! It showcases both swap operations and full-range liquidity provision operations,
//! serving as a reference for protocol integrators and a foundation for experimenting
//! with action chaining.

use chrono::NaiveDateTime;
use num_bigint::BigUint;
use tycho_common::{
    action::{
        asset::Asset,
        context::ActionContext,
        simulate::{DefaultInputs, SimulateForward},
    },
    asset::erc20::ERC20Asset,
    liquidity_provision::action::{
        AddLiquidityFullRange, AddLiquidityFullRangeParameters, LiquidityAmount,
        RemoveLiquidityFullRange, RemoveLiquidityParameters,
    },
    models::{blockchain::Block, token::Token, Chain},
    swap::action::{Swap, SwapParameters},
};

mod uniswap_v2;
use uniswap_v2::UniswapV2Pool;

/// Run the playground scenarios.
pub fn run_playground() {
    println!("🎮 Action System Playground - UniswapV2 Examples");
    println!("===============================================\n");

    // Create sample tokens
    let usdc = Token::new(
        &"0xa0b86a33e6ea9f8c9c8b01b30ec6a0e5a7f2e3d4".into(),
        "USDC",
        6,
        0,                 // no tax
        &[Some(21000u64)], // gas cost
        Chain::Ethereum,
        100, // good quality
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

    // Create a UniswapV2 pool: 1,000,000 USDC <-> 500 ETH (price: 1 ETH = 2000 USDC)
    let pool = UniswapV2Pool::new(
        usdc.clone(),
        eth.clone(),
        BigUint::from(1_000_000_000_000u64), // 1M USDC (6 decimals)
        BigUint::from(500u64) * BigUint::from(10u64).pow(18), // 500 ETH (18 decimals)
        BigUint::from(22360679775u64) * BigUint::from(10u64).pow(9), // sqrt(1M * 500) * 1e18
    );

    let context = ActionContext::new(
        Block {
            number: 18_500_000,
            chain: Chain::Ethereum,
            hash: "0x1234567890123456789012345678901234567890123456789012345678901234".into(),
            parent_hash: "0x0000000000000000000000000000000000000000000000000000000000000000"
                .into(),
            ts: NaiveDateTime::from_timestamp_opt(1640995200, 0).unwrap(), // Jan 1, 2022
        },
        Some("0x1234567890123456789012345678901234567890".into()),
        Default::default(),
    );

    // Scenario 1: Swap USDC for ETH
    swap_scenario_1(&pool, &context, &usdc, &eth);

    // Scenario 2: Swap ETH for USDC
    swap_scenario_2(&pool, &context, &usdc, &eth);

    // Scenario 3: Add liquidity
    liquidity_scenario_1(&pool, &context, &usdc, &eth);

    // Scenario 4: Remove liquidity
    liquidity_scenario_2(&pool, &context, &usdc, &eth);
}

fn swap_scenario_1(pool: &UniswapV2Pool, context: &ActionContext, usdc: &Token, eth: &Token) {
    println!("📊 Scenario 1: Swap USDC -> ETH");
    println!("Initial Pool State:");
    println!(
        "  USDC Reserve: {} ({:.2})",
        pool.reserve0,
        format_token_amount(&pool.reserve0, usdc.decimals as u8)
    );
    println!(
        "  ETH Reserve:  {} ({:.4})",
        pool.reserve1,
        format_token_amount(&pool.reserve1, eth.decimals as u8)
    );

    let swap_amount = BigUint::from(10_000_000_000u64); // 10k USDC
    println!("\nAction: Swap");
    println!(
        "  Input:  {} USDC ({:.2})",
        swap_amount,
        format_token_amount(&swap_amount, usdc.decimals as u8)
    );

    let input_asset = ERC20Asset::new(usdc.clone(), swap_amount);
    let inputs = DefaultInputs(vec![input_asset]);
    let params = SwapParameters::new(eth.clone());

    let result = SimulateForward::<Swap>::simulate_forward(pool, context, &params, &inputs);
    match result {
        Ok((outputs, new_state)) => {
            let produced = &outputs.produced()[0] as &ERC20Asset;
            println!(
                "  Output: {} ETH ({:.6})",
                produced.amount().unwrap(),
                format_token_amount(produced.amount().unwrap(), eth.decimals as u8)
            );
            println!("  Gas:    {}", outputs.gas_spent());

            println!("New Pool State:");
            println!(
                "  USDC Reserve: {} ({:.2})",
                new_state.reserve0,
                format_token_amount(&new_state.reserve0, usdc.decimals as u8)
            );
            println!(
                "  ETH Reserve:  {} ({:.4})",
                new_state.reserve1,
                format_token_amount(&new_state.reserve1, eth.decimals as u8)
            );
        }
        Err(e) => println!("  Error: {:?}", e),
    }
    println!();
}

fn swap_scenario_2(pool: &UniswapV2Pool, context: &ActionContext, usdc: &Token, eth: &Token) {
    println!("📊 Scenario 2: Swap ETH -> USDC");
    println!("Initial Pool State:");
    println!(
        "  USDC Reserve: {} ({:.2})",
        pool.reserve0,
        format_token_amount(&pool.reserve0, usdc.decimals as u8)
    );
    println!(
        "  ETH Reserve:  {} ({:.4})",
        pool.reserve1,
        format_token_amount(&pool.reserve1, eth.decimals as u8)
    );

    let swap_amount = BigUint::from(5u64) * BigUint::from(10u64).pow(18); // 5 ETH
    println!("\nAction: Swap");
    println!(
        "  Input:  {} ETH ({:.4})",
        swap_amount,
        format_token_amount(&swap_amount, eth.decimals as u8)
    );

    let input_asset = ERC20Asset::new(eth.clone(), swap_amount);
    let inputs = DefaultInputs(vec![input_asset]);
    let params = SwapParameters::new(usdc.clone());

    let result = SimulateForward::<Swap>::simulate_forward(pool, context, &params, &inputs);
    match result {
        Ok((outputs, new_state)) => {
            let produced = &outputs.produced()[0] as &ERC20Asset;
            println!(
                "  Output: {} USDC ({:.2})",
                produced.amount().unwrap(),
                format_token_amount(produced.amount().unwrap(), usdc.decimals as u8)
            );
            println!("  Gas:    {}", outputs.gas_spent());

            println!("New Pool State:");
            println!(
                "  USDC Reserve: {} ({:.2})",
                new_state.reserve0,
                format_token_amount(&new_state.reserve0, usdc.decimals as u8)
            );
            println!(
                "  ETH Reserve:  {} ({:.4})",
                new_state.reserve1,
                format_token_amount(&new_state.reserve1, eth.decimals as u8)
            );
        }
        Err(e) => println!("  Error: {:?}", e),
    }
    println!();
}

fn liquidity_scenario_1(pool: &UniswapV2Pool, context: &ActionContext, usdc: &Token, eth: &Token) {
    println!("💰 Scenario 3: Add Liquidity");
    println!("Initial Pool State:");
    println!(
        "  USDC Reserve:   {} ({:.2})",
        pool.reserve0,
        format_token_amount(&pool.reserve0, usdc.decimals as u8)
    );
    println!(
        "  ETH Reserve:    {} ({:.4})",
        pool.reserve1,
        format_token_amount(&pool.reserve1, eth.decimals as u8)
    );
    println!(
        "  LP Total Supply: {} ({:.4})",
        pool.lp_total_supply,
        format_token_amount(&pool.lp_total_supply, 18)
    );

    let usdc_amount = BigUint::from(20_000_000_000u64); // 20k USDC
    let eth_amount = BigUint::from(10u64) * BigUint::from(10u64).pow(18); // 10 ETH

    println!("\nAction: Add Liquidity");
    println!(
        "  Input USDC: {} ({:.2})",
        usdc_amount,
        format_token_amount(&usdc_amount, usdc.decimals as u8)
    );
    println!(
        "  Input ETH:  {} ({:.4})",
        eth_amount,
        format_token_amount(&eth_amount, eth.decimals as u8)
    );

    let inputs = DefaultInputs(vec![
        ERC20Asset::new(usdc.clone(), usdc_amount),
        ERC20Asset::new(eth.clone(), eth_amount),
    ]);
    let params = AddLiquidityFullRangeParameters;

    let result =
        SimulateForward::<AddLiquidityFullRange>::simulate_forward(pool, context, &params, &inputs);
    match result {
        Ok((outputs, new_state)) => {
            let lp_tokens = &outputs.produced()[0] as &ERC20Asset;
            println!(
                "  Output LP:  {} ({:.4})",
                lp_tokens.amount().unwrap(),
                format_token_amount(lp_tokens.amount().unwrap(), 18)
            );
            println!("  Gas:        {}", outputs.gas_spent());

            println!("New Pool State:");
            println!(
                "  USDC Reserve:    {} ({:.2})",
                new_state.reserve0,
                format_token_amount(&new_state.reserve0, usdc.decimals as u8)
            );
            println!(
                "  ETH Reserve:     {} ({:.4})",
                new_state.reserve1,
                format_token_amount(&new_state.reserve1, eth.decimals as u8)
            );
            println!(
                "  LP Total Supply: {} ({:.4})",
                new_state.lp_total_supply,
                format_token_amount(&new_state.lp_total_supply, 18)
            );
        }
        Err(e) => println!("  Error: {:?}", e),
    }
    println!();
}

fn liquidity_scenario_2(pool: &UniswapV2Pool, context: &ActionContext, usdc: &Token, eth: &Token) {
    println!("💸 Scenario 4: Remove Liquidity");

    // First add some liquidity to have LP tokens to remove
    let usdc_amount = BigUint::from(20_000_000_000u64); // 20k USDC
    let eth_amount = BigUint::from(10u64) * BigUint::from(10u64).pow(18); // 10 ETH
    let add_inputs = DefaultInputs(vec![
        ERC20Asset::new(usdc.clone(), usdc_amount),
        ERC20Asset::new(eth.clone(), eth_amount),
    ]);
    let add_params = AddLiquidityFullRangeParameters;

    let (add_outputs, pool_with_liquidity) =
        SimulateForward::<AddLiquidityFullRange>::simulate_forward(
            pool,
            context,
            &add_params,
            &add_inputs,
        )
        .unwrap();
    let lp_tokens_minted = add_outputs.produced()[0]
        .amount()
        .unwrap()
        .clone();

    println!("Pool State (after adding liquidity):");
    println!(
        "  USDC Reserve:    {} ({:.2})",
        pool_with_liquidity.reserve0,
        format_token_amount(&pool_with_liquidity.reserve0, usdc.decimals as u8)
    );
    println!(
        "  ETH Reserve:     {} ({:.4})",
        pool_with_liquidity.reserve1,
        format_token_amount(&pool_with_liquidity.reserve1, eth.decimals as u8)
    );
    println!(
        "  LP Total Supply: {} ({:.4})",
        pool_with_liquidity.lp_total_supply,
        format_token_amount(&pool_with_liquidity.lp_total_supply, 18)
    );

    // Remove half of the LP tokens
    let lp_to_remove = &lp_tokens_minted / BigUint::from(2u32);
    println!("\nAction: Remove Liquidity");
    println!(
        "  LP Tokens to Remove: {} ({:.4})",
        lp_to_remove,
        format_token_amount(&lp_to_remove, 18)
    );

    let lp_token = Token::new(
        &"0x1111111111111111111111111111111111111111".into(),
        &format!("{}/{}", usdc.symbol, eth.symbol),
        18,
        0,
        &[Some(50000u64)],
        Chain::Ethereum,
        100,
    );

    let lp_input = ERC20Asset::new(lp_token, lp_to_remove.clone());
    let params = RemoveLiquidityParameters { amount: LiquidityAmount::Exact(lp_to_remove) };

    let result = SimulateForward::<RemoveLiquidityFullRange>::simulate_forward(
        &*pool_with_liquidity,
        context,
        &params,
        &DefaultInputs(vec![lp_input.clone()]),
    );
    match result {
        Ok((outputs, new_state)) => {
            let output_usdc = &outputs.produced()[0] as &ERC20Asset;
            let output_eth = &outputs.produced()[1] as &ERC20Asset;
            println!(
                "  Output USDC: {} ({:.2})",
                output_usdc.amount().unwrap(),
                format_token_amount(output_usdc.amount().unwrap(), usdc.decimals as u8)
            );
            println!(
                "  Output ETH:  {} ({:.4})",
                output_eth.amount().unwrap(),
                format_token_amount(output_eth.amount().unwrap(), eth.decimals as u8)
            );
            println!("  Gas:         {}", outputs.gas_spent());

            println!("Final Pool State:");
            println!(
                "  USDC Reserve:    {} ({:.2})",
                new_state.reserve0,
                format_token_amount(&new_state.reserve0, usdc.decimals as u8)
            );
            println!(
                "  ETH Reserve:     {} ({:.4})",
                new_state.reserve1,
                format_token_amount(&new_state.reserve1, eth.decimals as u8)
            );
            println!(
                "  LP Total Supply: {} ({:.4})",
                new_state.lp_total_supply,
                format_token_amount(&new_state.lp_total_supply, 18)
            );
        }
        Err(e) => println!("  Error: {:?}", e),
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
    run_playground();
}
