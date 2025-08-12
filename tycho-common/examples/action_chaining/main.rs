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
        chain::{ChainBuilder, converters::SwapOutputsPlusInventory},
        context::ActionContext,
        simulate::{DefaultInputs, DefaultOutputs, SimulateForward},
    },
    asset::erc20::ERC20Asset,
    liquidity_provision::action::{AddLiquidityFullRange, AddLiquidityFullRangeParameters},
    models::{blockchain::Block, token::Token, Chain},
    simulation::errors::SimulationError,
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
    
    // Scenario 3: Split USDC, swap half to ETH, then add liquidity (manual version)
    split_swap_add_liquidity_chain(&usdc, &eth, &context);
    
    // Scenario 4: Same as 3 but using proper ChainBuilder
    chain_swap_add_liquidity_with_inventory(&usdc, &eth, &context);
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

fn split_swap_add_liquidity_chain(usdc: &Token, eth: &Token, context: &ActionContext) {
    println!("🔗 Scenario 3: Swap + Add Liquidity Chain with Inventory");
    println!("======================================================");
    println!("Strategy: Start with 500 USDC, swap to ETH, then add liquidity using ETH + 500 USDC from inventory");

    // Create USDC/ETH pool for both swapping and liquidity provision
    let usdc_eth_pool = UniswapV2Pool::new(
        usdc.clone(),
        eth.clone(),
        BigUint::from(2_000_000_000_000u64), // 2M USDC
        BigUint::from(1000u64) * BigUint::from(10u64).pow(18), // 1000 ETH (ratio 1 ETH = 2000 USDC)
        BigUint::from(1414213562373u64) * BigUint::from(10u64).pow(12), // sqrt(2M * 1000) * 1e18
    );

    println!("\nStep 1: Swap 500 USDC → ETH");
    
    // Start with 500 USDC for the swap
    let swap_amount = BigUint::from(500_000_000_000u64); // 500 USDC
    let swap_inputs = DefaultInputs(vec![ERC20Asset::new(usdc.clone(), swap_amount.clone())]);
    
    let swap_result: Result<(DefaultOutputs<ERC20Asset>, Box<UniswapV2Pool>), SimulationError> = 
        SimulateForward::<Swap>::simulate_forward(&usdc_eth_pool, context, &SwapParameters::new(eth.clone()), &swap_inputs);
    
    match swap_result {
        Ok((swap_outputs, updated_pool)) => {
            let eth_asset = &swap_outputs.produced()[0];
            let eth_received = eth_asset.amount().unwrap().clone();
            println!("  Input: {} USDC ({:.2})", swap_amount, format_token_amount(&swap_amount, usdc.decimals as u8));
            println!("  Output: {} ETH ({:.6})", eth_received, format_token_amount(&eth_received, eth.decimals as u8));

            println!("\nStep 2: Add liquidity using ETH + USDC from inventory");
            
            // Simulate retrieving 500 USDC from inventory
            let inventory_usdc = BigUint::from(500_000_000_000u64); // 500 USDC from inventory
            
            let lp_inputs = DefaultInputs(vec![
                ERC20Asset::new(usdc.clone(), inventory_usdc.clone()),
                ERC20Asset::new(eth.clone(), eth_received.clone()),
            ]);
            
            let lp_params = AddLiquidityFullRangeParameters;
            
            let lp_result: Result<(DefaultOutputs<ERC20Asset>, Box<UniswapV2Pool>), SimulationError> = 
                SimulateForward::<AddLiquidityFullRange>::simulate_forward(&*updated_pool, context, &lp_params, &lp_inputs);
            
            match lp_result {
                Ok((lp_outputs, _final_pool)) => {
                    let lp_tokens = lp_outputs.produced()[0].amount().unwrap();
                    println!("  Added liquidity:");
                    println!("    • {} USDC ({:.2}) from inventory", inventory_usdc, format_token_amount(&inventory_usdc, usdc.decimals as u8));
                    println!("    • {} ETH ({:.6}) from swap", eth_received, format_token_amount(&eth_received, eth.decimals as u8));
                    println!("  LP tokens received: {} ({:.6})", lp_tokens, format_token_amount(lp_tokens, 18));
                    println!("  Total gas consumed: {} + {} = {}", 
                        swap_outputs.gas_spent(),
                        lp_outputs.gas_spent(),
                        swap_outputs.gas_spent() + lp_outputs.gas_spent()
                    );
                    println!("✅ Swap + Add Liquidity chain completed successfully!");
                }
                Err(e) => println!("❌ Add liquidity failed: {:?}", e),
            }
        }
        Err(e) => println!("❌ Swap failed: {:?}", e),
    }
    
    println!("\n📝 Note: This demonstrates the inventory concept manually.");
    println!("   A full chain implementation would:");
    println!("   • Pre-populate inventory with 500 USDC");  
    println!("   • Execute swap and add liquidity as atomic steps");
    println!("   • Automatically combine assets from inventory with step outputs");
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

fn chain_swap_add_liquidity_with_inventory(usdc: &Token, eth: &Token, context: &ActionContext) {
    println!("🔗 Scenario 4: ChainBuilder with Custom Converter (Proper Implementation)");
    println!("==========================================================================");
    println!("Strategy: Use ChainBuilder with SwapOutputsPlusInventory converter for true chain integration");

    // Create pools for the chain
    let usdc_eth_pool_swap = UniswapV2Pool::new(
        usdc.clone(),
        eth.clone(),
        BigUint::from(2_000_000_000_000u64), // 2M USDC
        BigUint::from(1000u64) * BigUint::from(10u64).pow(18), // 1000 ETH (ratio 1 ETH = 2000 USDC)
        BigUint::from(1414213562373u64) * BigUint::from(10u64).pow(12), // sqrt(2M * 1000) * 1e18
    );

    let usdc_eth_pool_lp = usdc_eth_pool_swap.clone(); // Same pool for LP

    // Create the custom converter that combines swap outputs with inventory
    println!("Building chain with SwapOutputsPlusInventory converter...");
    let inventory_converter = SwapOutputsPlusInventory::new(
        usdc.clone(),
        BigUint::from(500_000_000_000u64), // 500 USDC from inventory
    );
    
    let chain = ChainBuilder::new()
        .start_with::<Swap, _>(
            usdc_eth_pool_swap,
            SwapParameters::new(eth.clone()),
        )
        .add_step_with_converter::<AddLiquidityFullRange, _, DefaultOutputs<ERC20Asset>>(
            usdc_eth_pool_lp,
            AddLiquidityFullRangeParameters,
            inventory_converter,
        )
        .build();

    println!("Chain built with {} steps", chain.step_count());

    // Execute the complete chain with 500 USDC input  
    let input_amount = BigUint::from(500_000_000_000u64); // 500 USDC for swap
    let inputs = DefaultInputs(vec![ERC20Asset::new(usdc.clone(), input_amount.clone())]);

    println!("Input: {} USDC ({:.2})", 
        input_amount,
        format_token_amount(&input_amount, usdc.decimals as u8)
    );

    match chain.execute(inputs, context) {
        Ok(result) => {
            let outputs = result.outputs();
            if !outputs.produced().is_empty() {
                let lp_asset = &outputs.produced()[0];
                println!("Final Output: {} LP tokens ({:.6})", 
                    lp_asset.amount().unwrap(),
                    format_token_amount(lp_asset.amount().unwrap(), 18)
                );
                println!("Total gas consumed: {}", outputs.gas_spent());
                println!("✅ ChainBuilder with custom converter executed successfully!");
            }
        }
        Err(e) => println!("❌ Chain execution failed: {:?}", e),
    }
    
    println!("\n📝 This demonstrates the PROPER ChainBuilder approach!");
    println!("   • Swap: 500 USDC → ETH");
    println!("   • Custom Converter: Combines ETH output + 500 USDC from inventory");  
    println!("   • Add Liquidity: Uses combined assets to mint LP tokens");
    println!("   • Everything executed as an atomic chain with proper state management!");
    println!();
}

fn main() {
    run_chaining_playground();
}