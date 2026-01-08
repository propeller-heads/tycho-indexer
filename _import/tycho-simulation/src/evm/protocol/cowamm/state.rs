use std::{any::Any, collections::HashMap, fmt::Debug};

use alloy::primitives::U256;
use num_bigint::{BigUint, ToBigUint};
use tycho_common::{
    dto::ProtocolStateDelta,
    models::token::Token,
    simulation::{
        errors::{SimulationError, TransitionError},
        protocol_sim::{Balances, GetAmountOutResult, ProtocolSim},
    },
    Bytes,
};

use crate::evm::protocol::{
    cowamm::{bmath::*, constants::BONE, error::CowAMMError},
    safe_math::{safe_add_u256, safe_div_u256, safe_mul_u256, safe_sub_u256},
    u256_num::{biguint_to_u256, u256_to_biguint, u256_to_f64},
};

const COWAMM_FEE: f64 = 0.0; // 0% fee
const MAX_IN_FACTOR: u64 = 50;
const MAX_OUT_FACTOR: u64 = 33;

// Token 3 tuple: (address, liquidity, weight)
type TokenInfo = (Bytes, U256, U256);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CowAMMState {
    /// The Pool Address
    pub address: Bytes,
    /// Token A information: (address, liquidity, weight)
    pub token_a: TokenInfo,
    /// Token B information: (address, liquidity, weight)
    pub token_b: TokenInfo,
    /// The Swap Fee on the Pool
    pub fee: u64,
    ///The lp token of the pool
    pub lp_token: Bytes,
    /// The Supply of the lp token
    pub lp_token_supply: U256,
}

impl CowAMMState {
    /// Creates a new `CowAMMState` instance.
    ///
    /// # Arguments
    /// - `token_a`: The address of the first token in the pair.
    /// - `token_b`: The address of the second token in the pair.
    /// - `liquidity_a`: Liquidity of the first token in the pair.
    /// - `liquidity_b`: Liquidity of the second token in the pair.
    /// - `lp_token`: The pool address (usually the LP token address).
    /// - `lp_token_supply`: The supply of the lp_token in the pool
    /// - `weight_a`: The denormalized weight of `token_a`.
    /// - `weight_b`: The denormalized weight of `token_b`.
    /// - `fee`: The swap fee for the pool.
    ///
    /// # Returns
    /// A new `CowAMMState` with token states initialized.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        address: Bytes,
        token_a_addr: Bytes,
        token_b_addr: Bytes,
        liquidity_a: U256,
        liquidity_b: U256,
        lp_token: Bytes,
        lp_token_supply: U256,
        weight_a: U256,
        weight_b: U256,
        fee: u64,
    ) -> Self {
        Self {
            address,
            token_a: (token_a_addr, liquidity_a, weight_a),
            token_b: (token_b_addr, liquidity_b, weight_b),
            lp_token,
            lp_token_supply,
            fee,
        }
    }
    /// Helper methods
    fn token_a_addr(&self) -> &Bytes {
        &self.token_a.0
    }

    fn liquidity_a(&self) -> U256 {
        self.token_a.1
    }

    fn liquidity_b(&self) -> U256 {
        self.token_b.1
    }

    fn weight_a(&self) -> U256 {
        self.token_a.2
    }

    fn weight_b(&self) -> U256 {
        self.token_b.2
    }

    /// Calculates the proportion of tokens a user receives when exiting the pool by burning LP
    /// tokens,
    ///
    ///
    /// Solidity reference:
    /// https://github.com/balancer/balancer-v2-monorepo/blob/master/pkg/core/contracts/pools/weighted/WeightedMath.sol#L299
    ///
    /// Formula:
    /// amountOut[i] = balances[i] * (lpTokenAmountIn / totalLpToken)
    ///
    /// # Arguments
    /// * `pool` - Reference to the pool containing balances and LP supply
    /// * `lp_token_in` - Amount of LP tokens to burn
    ///
    /// # Returns
    /// Tuple of `(amountOut_tokenA, amountOut_tokenB)`
    pub fn calc_tokens_out_given_exact_lp_token_in(
        &self,
        lp_token_in: U256,
    ) -> Result<(U256, U256), SimulationError> {
        println!("--- calc_tokens_out_given_exact_lp_token_in START ---");

        println!("Input lp_token_in: {}", lp_token_in);

        // Collect balances
        let liquidity_a = self.liquidity_a();
        let liquidity_b = self.liquidity_b();
        println!("Liquidity A: {}", liquidity_a);
        println!("Liquidity B: {}", liquidity_b);

        let balances = [liquidity_a, liquidity_b];

        let total_lp_token = self.lp_token_supply;
        println!("Total LP token supply: {}", total_lp_token);

        // lpTokenRatio = lp_token_in / total_lp_token
        println!(
            "Calculating lp_token_ratio = lp_token_in / total_lp_token = {} / {}",
            lp_token_in, total_lp_token
        );

        let lp_token_ratio = bdiv(lp_token_in, total_lp_token).map_err(|err| {
            println!(
                "ERROR: Failed to calculate lp_token_ratio. lp_token_in={}, total_lp_token={}, err={:?}",
                lp_token_in, total_lp_token, err
            );
            SimulationError::FatalError(format!(
                "Error in calculating LP token ratio {err:?}"
            ))
        })?;

        println!("Computed lp_token_ratio: {}", lp_token_ratio);

        // amountsOut[i] = balances[i] * lp_token_ratio
        let mut amounts_out = Vec::with_capacity(balances.len());

        for (i, balance) in balances.iter().enumerate() {
            println!(
                "Calculating amount_out[{}] = balance * lp_token_ratio = {} * {}",
                i, balance, lp_token_ratio
            );

            let amount = bmul(*balance, lp_token_ratio).map_err(|err| {
                println!(
                    "ERROR: Failed to calculate amount_out[{}]. balance={}, lp_token_ratio={}, err={:?}",
                    i, balance, lp_token_ratio, err
                );
                SimulationError::FatalError(format!(
                    "Total LP token supply missing {err:?}"
                ))
            })?;

            println!("Computed amount_out[{}]: {}", i, amount);
            amounts_out.push(amount);
        }

        println!(
            "Final outputs: token_a_out={}, token_b_out={}",
            amounts_out[0], amounts_out[1]
        );

        println!("--- calc_tokens_out_given_exact_lp_token_in END ---");

        Ok((amounts_out[0], amounts_out[1]))
    }

    //https://github.com/balancer/cow-amm/blob/main/src/contracts/BPool.sol#L174
    /// joinPool
    pub fn join_pool(
        &self,
        new_state: &mut CowAMMState,
        pool_amount_out: U256,
        max_amounts_in: &[U256],
    ) -> Result<(), CowAMMError> {
        let pool_total = self.lp_token_supply;
        let ratio = bdiv(pool_amount_out, pool_total)?;

        if ratio.is_zero() {
            return Err(CowAMMError::InvalidPoolRatio);
        }

        let balances = vec![self.liquidity_a(), self.liquidity_b()];

        for (i, bal) in balances.into_iter().enumerate() {
            let token_amount_in = bmul(ratio, bal)?;
            if token_amount_in.is_zero() {
                return Err(CowAMMError::InvalidTokenAmountIn);
            }
            if token_amount_in > max_amounts_in[i] {
                return Err(CowAMMError::TokenAmountInAboveMax);
            }

            // equivalent to _pullUnderlying
            if i == 0 {
                new_state.token_a.1 = badd(self.token_a.1, token_amount_in)?;
            } else {
                new_state.token_b.1 = badd(self.token_b.1, token_amount_in)?;
            }
        }

        // mint LP shares
        new_state.lp_token_supply = badd(self.lp_token_supply, pool_amount_out)?;
        Ok(())
    }

    /// exitPool
    pub fn exit_pool(
        &self,
        new_state: &mut CowAMMState,
        pool_amount_in: U256,
        min_amounts_out: &[U256],
        exit_fee: U256,
    ) -> Result<(), CowAMMError> {
        println!("--- exit_pool START ---");
        println!("Input pool_amount_in: {}", pool_amount_in);
        println!("Input min_amounts_out: {:?}", min_amounts_out);
        println!("Input exit_fee: {}", exit_fee);
        println!("Original LP token supply: {}", self.lp_token_supply);

        let pool_total = self.lp_token_supply;

        // calculate fee
        let fee = bmul(pool_amount_in, exit_fee)?;
        println!("Calculated fee: {}", fee);

        let pai_after_fee = bsub(pool_amount_in, fee)?;
        println!("Pool amount after fee (pai_after_fee): {}", pai_after_fee);

        let ratio = bdiv(pai_after_fee, pool_total)?;
        println!("Pool exit ratio: {}", ratio);

        if ratio.is_zero() {
            println!("ERROR: Exit ratio is zero, cannot exit pool");
            return Err(CowAMMError::InvalidPoolRatio);
        }

        // burn LP shares
        new_state.lp_token_supply = bsub(self.lp_token_supply, pai_after_fee)?;
        println!(
            "Updated LP token supply in new_state: {}",
            new_state.lp_token_supply
        );

        let balances = vec![self.liquidity_a(), self.liquidity_b()];
        println!("Pool balances: token_a={}, token_b={}", balances[0], balances[1]);

        for (i, bal) in balances.into_iter().enumerate() {
            let token_amount_out = bmul(ratio, bal)?;
            println!("Calculated token_amount_out[{}]: {}", i, token_amount_out);

            if token_amount_out.is_zero() {
                println!("ERROR: token_amount_out[{}] is zero", i);
                return Err(CowAMMError::InvalidTokenAmountOut);
            }

            if token_amount_out < min_amounts_out[i] {
                println!(
                    "ERROR: token_amount_out[{}] ({}) < min_amounts_out[{}] ({})",
                    i, token_amount_out, i, min_amounts_out[i]
                );
                return Err(CowAMMError::TokenAmountOutBelowMinAmountOut);
            }

            // Update new_state balances
            if i == 0 {
                new_state.token_a.1 = bsub(self.token_a.1, token_amount_out)?;
                println!(
                    "Updated new_state.token_a balance: {}",
                    new_state.token_a.1
                );
            } else {
                new_state.token_b.1 = bsub(self.token_b.1, token_amount_out)?;
                println!(
                    "Updated new_state.token_b balance: {}",
                    new_state.token_b.1
                );
            }
        }

            println!("--- exit_pool END ---");
            Ok(())
    }
    
    /// Calculates safe limits for LP token swaps that account for intermediate swap limits
    /// 
    /// Returns: (max_lp_in, max_token_out)
    /// - max_lp_in: Maximum LP tokens that can be redeemed without exceeding swap limits
    /// - max_token_out: Maximum token that can be received
    fn get_lp_swap_limits(
        &self,
        sell_token: Bytes,
        buy_token: Bytes,
    ) -> Result<(BigUint, BigUint), SimulationError> {
        let is_lp_sell = sell_token == self.address;
        let is_lp_buy = buy_token == self.address;

        //when we get the proportions, the first is max_in of the superfluous to swap - must not surpass 50% of source liquidity
        //when we get the amount_out the second max_out - must not surpass 33% of target liquidity

        if !is_lp_sell && !is_lp_buy {
            // Not an LP swap, use regular limits
            return Ok((BigUint::ZERO, BigUint::ZERO)); //huh
        }

        // For LP token swaps, we need to ensure the intermediate swap doesn't exceed limits
        
        if is_lp_sell {
            // Selling LP tokens (redeeming)
            // We need to find the max LP amount such that the intermediate swap stays within limits
            //token_a -> ARB
            //token_b -> WETH
            //is_token_a_out is false

            // Identify the tokens:
            // - unwanted_liquidity: The token we'll swap (INPUT to intermediate swap)
            // - wanted_liquidity: The token we want (OUTPUT from intermediate swap)
            let is_token_a_out = buy_token == *self.token_a_addr();
            
            let (unwanted_liquidity, wanted_liquidity) = if is_token_a_out {
                // Want token_a, will swap token_b → token_a
                // token_b is the swap input (must be ≤ 50% of token_a liquidity)
                (self.liquidity_b(), self.liquidity_a())
            } else {
                // Want token_b, will swap token_a → token_b  
                // token_a is the swap input (must be ≤ 50% of token_b liquidity)
                (self.liquidity_a(), self.liquidity_b())
            };

            // The intermediate swap has TWO constraints:
            // 1. INPUT: Can swap at most 50% of WANTED token's liquidity
            //    (This is the Balancer constant product constraint)
            // 2. OUTPUT: Can receive at most 33% of WANTED token's liquidity

            // Constraint 1: Max input to intermediate swap
            // We can swap at most 50% of the UNWANTED token's liquidity/balance of the pool
            // Maximum amount we can swap in the intermediate step
            
            println!("LP SWAP LIMIT CALC (REDEEM):");
            println!("  unwanted_liquidity (INPUT to swap): {}", unwanted_liquidity);
            println!("  wanted_liquidity (OUTPUT from swap): {}", wanted_liquidity);

            let max_intermediate_swap_in = safe_div_u256(
                safe_mul_u256(unwanted_liquidity, U256::from(MAX_IN_FACTOR))?,
                U256::from(100),
            )?;
            
            println!("  max_intermediate_swap_in ({}% of UNWANTED/INPUT): {}", 
             MAX_IN_FACTOR, max_intermediate_swap_in);

            //the only max limit (which will be the max_token_out) we need is 
            //the max_intermediate swap think of it this we, if we are exiting the pool 
            //and we want to do a BCow-50ARB-50WETH -> WETH swap 
            //when we redeem BCow-50ARB-50WETH and get ARB + WETH, then we swap 
            //the superfluous ARB to WETH
            //now swap_liquidity is WETH, and target_liquidity is ARB ((self.liquidity_b(), self.liquidity_a()))
            //so the max_intermediate_swap should use the target_liquidity, and the max_token_out, should use the swap liquidity
            //because the result is that, the max_token_out is the max_token_out for ARB (33% of target_liquidity, 33% of 286275852074040134274570 

            // Work backwards to find max LP:
            // proportional_unwanted = (LP_in / LP_supply) × unwanted_liquidity
            // We need: proportional_unwanted ≤ max_intermediate_swap_in
            // Therefore: LP_in ≤ (max_intermediate_swap_in × LP_supply) / unwanted_liquidity

            if unwanted_liquidity.is_zero() {
                return Ok((BigUint::ZERO, BigUint::ZERO));
            }

            // max_lp_in = (max_intermediate_swap_in * lp_token_supply) / target_liquidity
            let max_lp_in = safe_div_u256(
                safe_mul_u256(max_intermediate_swap_in, self.lp_token_supply)?,
                unwanted_liquidity,
            )?;

            println!("  lp_token_supply: {}", self.lp_token_supply);
            println!("  CALCULATED max_lp_in: {}", max_lp_in);

            // Constraint 2: MAX_OUT_FACTOR
            // "user can only swap out less than 33.33% of current balance of tokenOut"
            // We can receive at most 33% of WANTED (OUTPUT) token's liquidity
            let max_intermediate_swap_out = safe_div_u256(
                safe_mul_u256(wanted_liquidity, U256::from(MAX_OUT_FACTOR))?,
                U256::from(100),
            )?;

            println!("  max_intermediate_swap_out ({}% of WANTED/OUTPUT): {}", 
             MAX_OUT_FACTOR, max_intermediate_swap_out);

            // The max_token_out represents total wanted token user can receive
            let max_token_out = max_intermediate_swap_out;

            println!("  max_token_out: {}", max_token_out);

            return Ok((u256_to_biguint(max_lp_in), u256_to_biguint(max_token_out)));
        }

        if is_lp_buy {
            // Buying LP tokens (joining pool)
            // Example: ARB → LP means we swap some ARB→WETH, then join with ARB+WETH
            
            let is_token_a_in = sell_token == *self.token_a_addr();
            
            let (input_liquidity, needed_liquidity) = if is_token_a_in {
                // Selling token_a, will need to swap some to token_b
                (self.liquidity_b(), self.liquidity_a())
            } else {
                // Selling token_b, will need to swap some to token_a
                (self.liquidity_a(), self.liquidity_b())
            };

            println!("LP SWAP LIMIT CALC (JOIN):");
            println!("  input_liquidity (token selling): {}", input_liquidity);
            println!("  needed_liquidity (token needed): {}", needed_liquidity);

            // The intermediate swap's OUTPUT constraint:
            // We can receive at most 33% of the NEEDED token's liquidity
            let max_intermediate_swap_out = safe_div_u256(
                safe_mul_u256(needed_liquidity, U256::from(MAX_OUT_FACTOR))?,
                U256::from(100),
            )?;


            println!("  max_intermediate_swap_out ({}% of needed): {}", 
                 MAX_OUT_FACTOR, max_intermediate_swap_out);

            // The LP tokens we can mint are limited by how much we can swap
            // Work backwards to find max LP we can mint:
            // proportional_needed = (LP_out / LP_supply) × needed_liquidity
            // We need: proportional_needed ≤ max_intermediate_swap_out
            // Therefore: LP_out ≤ (max_intermediate_swap_out × LP_supply) / needed_liquidity

            if needed_liquidity.is_zero() {
                return Ok((BigUint::ZERO, BigUint::ZERO));
            }

            let max_lp_out = safe_div_u256(
                safe_mul_u256(max_intermediate_swap_out, self.lp_token_supply)?,
                needed_liquidity,
            )?;

            println!("  CALCULATED max_lp_out: {}", max_lp_out);

            // Max input is standard 50% of the token being sold
            let max_token_in = safe_div_u256(
                safe_mul_u256(input_liquidity,U256::from(MAX_IN_FACTOR))?,
                U256::from(100),
            )?;

            println!("  max_token_in ({}% of input): {}", MAX_IN_FACTOR, max_token_in);

            return Ok((u256_to_biguint(max_token_in), u256_to_biguint(max_lp_out)));
        }

        Ok((BigUint::ZERO, BigUint::ZERO)) //should this be even here 
    }
}

impl ProtocolSim for CowAMMState {
    fn fee(&self) -> f64 {
        COWAMM_FEE
    }
    /// Calculates a f64 representation of base token price in the AMM.
    /// ********************************************************************************************
    /// ** calcSpotPrice
    /// // sP = spotPrice
    /// // bI = tokenBalanceIn                ( bI / wI )         1
    /// // bO = tokenBalanceOut         sP =  -----------  *  ----------
    /// // wI = tokenWeightIn                 ( bO / wO )     ( 1 - sF )
    /// // wO = tokenWeightOut
    /// // sF = swapFee
    /// // *************************************************************************************
    /// *********/
    fn spot_price(&self, _base: &Token, _quote: &Token) -> Result<f64, SimulationError> {
        let numer = bdiv(self.liquidity_a(), self.weight_a()).map_err(|err| {
            SimulationError::FatalError(format!(
                "Error in numerator bdiv(balance_base / weight_base): {err:?}"
            ))
        })?;
        let denom = bdiv(self.liquidity_b(), self.weight_b()).map_err(|err| {
            SimulationError::FatalError(format!(
                "Error in denominator bdiv(balance_quote / weight_quote): {err:?}"
            ))
        })?;

        let ratio = bmul(
            bdiv(numer, denom).map_err(|err| {
                SimulationError::FatalError(format!("Error in (numer / denom): {err:?}"))
            })?,
            BONE,
        )
        .map_err(|err| {
            SimulationError::FatalError(format!("Error in bmul(ratio * scale): {err:?}"))
        })?;

        u256_to_f64(ratio)
    }

    fn get_amount_out(
        &self,
        amount_in: BigUint,
        token_in: &Token,
        token_out: &Token,
    ) -> Result<GetAmountOutResult, SimulationError> {
        println!("=== get_amount_out ENTER ===");
        println!("amount_in (BigUint) = {}", amount_in);
        println!("token_in.address  = {:?}", token_in.address);
        println!("token_out.address = {:?}", token_out.address);
        println!("pool.address      = {:?}", self.address);
        println!(
            "pool.liquidity_a = {:?}, liquidity_b = {:?}, lp_supply = {:?}",
            self.liquidity_a(),
            self.liquidity_b(),
            self.lp_token_supply
        );
        println!("fee = {}", self.fee);

        let amount_in = biguint_to_u256(&amount_in);
        println!("amount_in (U256) = {:?}", amount_in);

        if amount_in.is_zero() {
            println!("ERROR: amount_in is zero");
            return Err(SimulationError::InvalidInput(
                "Amount in cannot be zero".to_string(),
                None,
            ));
        }

        let is_lp_in = token_in.address == self.address;
        let is_lp_out = token_out.address == self.address;

        println!("is_lp_in  = {}", is_lp_in);
        println!("is_lp_out = {}", is_lp_out);

        if is_lp_in && is_lp_out {
            println!("ERROR: LP → LP swap attempted");
            return Err(SimulationError::InvalidInput(
                "Cannot swap LP token for LP token".into(),
                None,
            ));
        }

        let mut new_state = self.clone();
        println!("Cloned pool state");

        // ============================
        // EXIT POOL (LP → TOKEN) //explain better 
        // ============================
        if is_lp_in && !is_lp_out {
            println!("--- EXIT POOL PATH ---");

            let (pta, ptb) = self
                .calc_tokens_out_given_exact_lp_token_in(amount_in)
                .map_err(|e| {
                    println!("ERROR in calc_tokens_out_given_exact_lp_token_in: {:?}", e);
                    SimulationError::FatalError(format!(
                        "failed to calculate token proportions out error: {e:?}"
                    ))
                })?;

            println!(
                "Proportional tokens out: token_a = {:?}, token_b = {:?}",
                pta, ptb
            );

            let _ = self.exit_pool(
                &mut new_state,
                amount_in,
                &[pta, ptb],
                U256::from(self.fee),
            );

            println!(
                "State after exit_pool: liquidity_a = {:?}, liquidity_b = {:?}",
                new_state.liquidity_a(),
                new_state.liquidity_b()
            );

            let (amount_to_swap, is_token_a_swap) =
                if token_out.address == *self.token_a_addr() {
                    println!("Swapping token B → token A for exit");
                    (ptb, false)
                } else {
                    println!("Swapping token A → token B for exit");
                    (pta, true)
                };

            println!(
                "amount_to_swap = {:?}, is_token_a_swap = {}",
                amount_to_swap, is_token_a_swap
            );

                    // ============================
            // INVARIANT CHECK: Ensure amount_to_swap doesn't exceed MAX_IN_FACTOR
            // ============================
            // let (liquidity_in, liquidity_out) = if is_token_a_swap {
            //     (new_state.liquidity_a(), new_state.liquidity_b())
            // } else {
            //     (new_state.liquidity_b(), new_state.liquidity_a())
            // };

            //check whether it should be liquidity_in / liquidity_out
            // let max_swap_in = safe_div_u256(
            //     safe_mul_u256(liquidity_out, U256::from(MAX_IN_FACTOR))?,
            //     U256::from(100),
            // )?;

            // println!(
            //     "INVARIANT CHECK: amount_to_swap = {}, max_swap_in ({}% of liquidity_in {}) = {}",
            //     amount_to_swap, MAX_IN_FACTOR, liquidity_in, max_swap_in
            // );

            // if amount_to_swap > max_swap_in {
            //     println!(
            //         "ERROR: amount_to_swap ({}) exceeds max_swap_in ({})",
            //         amount_to_swap, max_swap_in
            //     );
            //     return Err(SimulationError::InvalidInput(
            //         format!(
            //             "LP redemption requires swapping {} tokens, which exceeds the maximum allowed swap amount of {} ({}% of pool liquidity {})",
            //             amount_to_swap, max_swap_in, MAX_IN_FACTOR, liquidity_in
            //         ),
            //         None,
            //     ));
            // }
            //when we put in pta amount of ARB, this is the WETH we get
            let amount_out = if is_token_a_swap {
                calculate_out_given_in(
                    new_state.liquidity_a(),
                    new_state.weight_a(),
                    new_state.liquidity_b(),
                    new_state.weight_b(),
                    amount_to_swap,
                    U256::from(self.fee),
                )
            } else {
                calculate_out_given_in(
                    new_state.liquidity_b(),
                    new_state.weight_b(),
                    new_state.liquidity_a(),
                    new_state.weight_a(),
                    amount_to_swap,
                    U256::from(self.fee),
                )
            }
            .map_err(|e| {
                println!("ERROR in calculate_out_given_in: {:?}", e);
                SimulationError::FatalError(format!("amount_out error: {e:?}"))
            })?;

            println!("amount_out = {:?}", amount_out);

        //in the pools perspective, arb increases, weth increases
        //liquidity_a increases, liquidity_b decreases so what is this logic here
        //what is wrong
        if is_token_a_swap {
                println!("--- is_token_a_swap branch ---");
                println!("new_state.liquidity_b(): {}", new_state.liquidity_b());
                println!("amount_to_swap: {}", amount_to_swap);
                let new_token_b = safe_sub_u256(new_state.liquidity_b(), amount_out)?;
                println!("Updated token_b after subtraction: {}", new_token_b);
                new_state.token_b.1 = new_token_b;

                println!("new_state.liquidity_a(): {}", new_state.liquidity_a());
                println!("amount_out: {}", amount_out);
                let new_token_a = safe_add_u256(new_state.liquidity_a(), amount_to_swap)?;
                println!("Updated token_a after addition: {}", new_token_a);
                new_state.token_a.1 = new_token_a;
            } else {
                //its supposed to be this case
                println!("--- else branch (token_b swap) ---");
                println!("new_state.liquidity_a(): {}", new_state.liquidity_a());
                println!("amount_to_swap: {}", amount_to_swap);
                let new_token_a = safe_sub_u256(new_state.liquidity_a(), amount_out)?;
                println!("Updated token_a after subtraction: {}", new_token_a);
                new_state.token_a.1 = new_token_a;

                println!("new_state.liquidity_b(): {}", new_state.liquidity_b());
                println!("amount_out: {}", amount_out);
                let new_token_b = safe_add_u256(new_state.liquidity_b(), amount_to_swap)?;
                println!("Updated token_b after addition: {}", new_token_b);
                new_state.token_b.1 = new_token_b;
            }

            println!(
                "Post-swap liquidity: A = {:?}, B = {:?}",
                new_state.liquidity_a(),
                new_state.liquidity_b()
            );

            let total_trade_amount = safe_add_u256(amount_out, pta)?;
            println!("total_trade_amount = {:?}", total_trade_amount);

            println!("=== get_amount_out EXIT (LP → TOKEN) ===");

            return Ok(GetAmountOutResult {
                amount: u256_to_biguint(total_trade_amount),
                gas: 194_140u64.to_biguint().unwrap(),
                new_state: Box::new(new_state),
            });
    }

    // ============================
    // JOIN POOL (TOKEN → LP)
    // ============================
    if is_lp_out && !is_lp_in {
        println!("--- JOIN POOL PATH ---");

        let (pta, ptb) = self
            .calc_tokens_out_given_exact_lp_token_in(amount_in)
            .map_err(|e| {
                println!("ERROR in calc_tokens_out_given_exact_lp_token_in: {:?}", e);
                SimulationError::FatalError(format!(
                    "failed to calculate token proportions out error: {e:?}"
                ))
            })?;

        println!(
            "Required proportional tokens: token_a = {:?}, token_b = {:?}",
            pta, ptb
        );

        let (amount_to_swap, is_token_a_swap) =
            if token_in.address == *new_state.token_a_addr() {
                println!("Swapping token B → token A for join");
                (ptb, false)
            } else {
                println!("Swapping token A → token B for join");
                (pta, true)
            };

        println!(
            "amount_to_swap = {:?}, is_token_a_swap = {}",
            amount_to_swap, is_token_a_swap
        );

        let amt_in = if is_token_a_swap {
            calculate_in_given_out(
                new_state.liquidity_b(),
                new_state.weight_b(),
                new_state.liquidity_a(),
                new_state.weight_a(),
                amount_to_swap,
                    U256::from(self.fee),
                )
            } else {
                calculate_in_given_out(
                    new_state.liquidity_a(),
                    new_state.weight_a(),
                    new_state.liquidity_b(),
                    new_state.weight_b(),
                    amount_to_swap,
                    U256::from(self.fee),
                )
            }
            .map_err(|e| {
                println!("ERROR in calculate_in_given_out: {:?}", e);
                SimulationError::FatalError(format!("amt_in error: {e:?}"))
            })?;

            println!("amt_in = {:?}", amt_in);

            if is_token_a_swap {
                new_state.token_a.1 = safe_sub_u256(new_state.liquidity_a(), amount_to_swap)?;
                new_state.token_b.1 = safe_add_u256(new_state.liquidity_b(), amt_in)?;
            } else {
                new_state.token_b.1 = safe_sub_u256(new_state.liquidity_b(), amount_to_swap)?;
                new_state.token_a.1 = safe_add_u256(new_state.liquidity_a(), amt_in)?;
            }

            let _ = self.join_pool(
                &mut new_state,
                amount_in,
                &[pta, ptb],
            );

            println!(
                "Post-join liquidity: A = {:?}, B = {:?}",
                new_state.liquidity_a(),
                new_state.liquidity_b()
            );

            println!("=== get_amount_out EXIT (TOKEN → LP) ===");

            return Ok(GetAmountOutResult {
                amount: u256_to_biguint(amt_in),
                gas: 120_000u64.to_biguint().unwrap(),
                new_state: Box::new(new_state),
            });
        }

        // ============================
        // NORMAL SWAP
        // ============================
        println!("--- NORMAL SWAP PATH ---");

        let amount_out = calculate_out_given_in(
            self.liquidity_a(),
            self.weight_a(),
            self.liquidity_b(),
            self.weight_b(),
            amount_in,
            U256::from(self.fee),
        )
        .map_err(|e| {
            println!("ERROR in calculate_out_given_in: {:?}", e);
            SimulationError::FatalError(format!("amount_out error: {e:?}"))
        })?;

        println!("amount_out = {:?}", amount_out);

        new_state.token_a.1 = safe_sub_u256(new_state.liquidity_a(), amount_in)?;
        new_state.token_b.1 = safe_add_u256(new_state.liquidity_b(), amount_out)?;

        println!(
            "Post-swap liquidity: A = {:?}, B = {:?}",
            new_state.liquidity_a(),
            new_state.liquidity_b()
        );

        println!("=== get_amount_out EXIT (NORMAL SWAP) ===");

        Ok(GetAmountOutResult {
            amount: u256_to_biguint(amount_out),
            gas: 120_000u64.to_biguint().unwrap(),
            new_state: Box::new(new_state),
        })
    }

    fn get_limits(
        &self,
        sell_token: Bytes,
        buy_token: Bytes,
    ) -> Result<(BigUint, BigUint), SimulationError> {
        if self.liquidity_a().is_zero() || self.liquidity_b().is_zero() {
            return Ok((BigUint::ZERO, BigUint::ZERO));
        }

        // Check if this is an LP token swap
        let is_lp_sell = sell_token == self.address;
        let is_lp_buy = buy_token == self.address;

        if is_lp_sell || is_lp_buy {
            // Use special LP swap limits that account for intermediate swaps
            return self.get_lp_swap_limits(sell_token, buy_token);
        }

        let max_in = safe_div_u256(
            safe_mul_u256(self.liquidity_a(), U256::from(MAX_IN_FACTOR))?,
            U256::from(100),
        )?;

        let max_out = safe_div_u256(
            safe_mul_u256(self.liquidity_b(), U256::from(MAX_OUT_FACTOR))?,
            U256::from(100),
        )?;

        Ok((u256_to_biguint(max_in), u256_to_biguint(max_out)))
    }

    fn delta_transition(
        &mut self,
        delta: ProtocolStateDelta,
        _tokens: &HashMap<Bytes, Token>,
        _balances: &Balances,
    ) -> Result<(), TransitionError<String>> {
        // liquidity_a, liquidity_b and lp_token_supply are considered required attributes and are
        // expected in every delta we process
        let liquidity_a = U256::from_be_slice(
            delta
                .updated_attributes
                .get("liquidity_a")
                .ok_or(TransitionError::MissingAttribute("liquidity_a".to_string()))?,
        );

        let liquidity_b = U256::from_be_slice(
            delta
                .updated_attributes
                .get("liquidity_b")
                .ok_or(TransitionError::MissingAttribute("liquidity_b".to_string()))?,
        );

        let lp_token_supply = U256::from_be_slice(
            delta
                .updated_attributes
                .get("lp_token_supply")
                .ok_or(TransitionError::MissingAttribute("lp_token_supply".to_string()))?,
        );

        self.token_a.1 = liquidity_a;
        self.token_b.1 = liquidity_b;
        self.lp_token_supply = lp_token_supply;

        Ok(())
    }

    fn clone_box(&self) -> Box<dyn ProtocolSim> {
        Box::new(self.clone())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn eq(&self, other: &dyn ProtocolSim) -> bool {
        other
            .as_any()
            .downcast_ref::<CowAMMState>()
            .is_some_and(|other_state| self == other_state)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{HashMap, HashSet},
        str::FromStr,
    };

    use alloy::primitives::U256;
    use approx::assert_ulps_eq;
    use num_bigint::BigUint;
    use num_traits::One;
    use rstest::rstest;
    use tycho_common::{
        dto::ProtocolStateDelta,
        models::{token::Token, Chain},
        simulation::errors::{SimulationError, TransitionError},
        Bytes,
    };
    use num_traits::ToPrimitive;
    use super::*;
    use crate::evm::protocol::{
        cowamm::state::{CowAMMState, ProtocolSim},
        u256_num::biguint_to_u256,
    };
    /// Converts a `BigUint` amount in wei to f64 ETH/WETH
    pub fn wei_to_eth(amount: &BigUint) -> f64 {
        // 1 ETH = 10^18 wei
        let divisor = 1e18_f64;
        amount.to_f64().unwrap_or(0.0) / divisor
    }

    fn create_test_tokens() -> (Token, Token, Token, Token, Token) {
        let t0 = Token::new(
            &Bytes::from_str("0xDEf1CA1fb7FBcDC777520aa7f396b4E015F497aB").unwrap(),
            "COW",
            18,
            0,
            &[Some(10_000)],
            Chain::Ethereum,
            100,
        );

        let t1 = Token::new(
            &Bytes::from_str("0x7f39C581F595B53c5cb19bD0b3f8dA6c935E2Ca0").unwrap(),
            "wstETH",
            18,
            0,
            &[Some(10_000)],
            Chain::Ethereum,
            100,
        );

        let t2 = Token::new(
            &Bytes::from_str("0x9bd702E05B9c97E4A4a3E47Df1e0fe7A0C26d2F1").unwrap(),
            "BCoW-50CoW-50wstETH",
            18,
            0,
            &[Some(199_999_999_999_999_990)],
            Chain::Ethereum,
            100,
        );
        let t3 = Token::new(
            &Bytes::from_str("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2").unwrap(),
            "WETH",
            18,
            0,
            &[Some(1_000_000)],
            Chain::Ethereum,
            100,
        );
        let t4 = Token::new(
            &Bytes::from_str("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48").unwrap(),
            "USDC",
            6,
            0,
            &[Some(10_000_000)],
            Chain::Ethereum,
            100,
        );
        (t0, t1, t2, t3, t4)
    }

    #[rstest]
    #[case::same_dec(
        U256::from_str("1547000000000000000000").unwrap(), //COW balance
        U256::from_str("100000000000000000").unwrap(), //wstETH balance
        0, 1, // token indices: t0 -> t1
        BigUint::from_str("5205849666").unwrap(),  //COW in
        BigUint::from_str("336513").unwrap(), //wstETH out
    )]
    #[case::diff_dec(
        U256::from_str("170286779513658066185").unwrap(), //WETH balance
        U256::from_str("413545982676").unwrap(), //USDC balance
        3, 4, // token indices: t3 -> t4
        BigUint::from_str("217679081735374278").unwrap(), //WETH in 
        BigUint::from_str("527964550").unwrap(), // USDC out (≈ 0.2177 WETH) for 527964550 USDC (≈ 527.96 USDC)
    )]
    fn test_get_amount_out(
        #[case] liq_a: U256,
        #[case] liq_b: U256,
        #[case] token_in_idx: usize,
        #[case] token_out_idx: usize,
        #[case] amount_in: BigUint,
        #[case] expected_out: BigUint,
    ) {
        let (t0, t1, t2, t3, t4) = create_test_tokens();
        let tokens = [&t0, &t1, &t2, &t3, &t4];
        let token_in = tokens[token_in_idx];
        let token_out = tokens[token_out_idx];

        let state = CowAMMState::new(
            Bytes::from("0x9bd702E05B9c97E4A4a3E47Df1e0fe7A0C26d2F1"),
            token_in.address.clone(),
            token_out.address.clone(),
            liq_a, //COW
            liq_b, //wstETH
            Bytes::from("0x9bd702E05B9c97E4A4a3E47Df1e0fe7A0C26d2F1"),
            U256::from_str("199999999999999999990").unwrap(),
            U256::from_str("1000000000000000000").unwrap(),
            U256::from_str("1000000000000000000").unwrap(),
            0,
        );

        let res = state
            .get_amount_out(amount_in.clone(), token_in, token_out)
            .unwrap();

        assert_eq!(res.amount, expected_out);

        let new_state = res
            .new_state
            .as_any()
            .downcast_ref::<CowAMMState>()
            .unwrap();

        assert_eq!(
            new_state.liquidity_a(),
            safe_sub_u256(liq_a, biguint_to_u256(&amount_in)).unwrap()
        );
        assert_eq!(
            new_state.liquidity_b(),
            safe_add_u256(liq_b, biguint_to_u256(&expected_out)).unwrap()
        );

        // Original state unchanged
        assert_eq!(state.liquidity_a(), liq_a);
        assert_eq!(state.liquidity_b(), liq_b);
    }

    ////new case 

    #[rstest]
    #[case::buy_lp_token( //buying lp token with COW == buying amounts of wstETH needed to join pool with COW, then joining pool with both tokens
        U256::from_str("1547000000000000000000").unwrap(),
        U256::from_str("100000000000000000").unwrap(),
        0, 2, // token indices: t0 -> t2
        BigUint::from_str("1000000000000000000").unwrap(), //Amount of lp_token being bought (received from joining pool)
        BigUint::from_str("7773869346733669088").unwrap(), //Amount of wstETH we buy to join the pool
    )]
    #[case::sell_lp_token( //selling (redeeming) lp_token for COW == exiting pool and converting excess COW to wstETH
        U256::from_str("1547000000000000000000").unwrap(),
        U256::from_str("100000000000000000").unwrap(),
        2, 0, // token indices: t2 -> t0
        BigUint::from_str("1000000000000000000").unwrap(), //Amount of lp_token being sold (redeeemd) 
        BigUint::from_str("15431325000000000000").unwrap(), //COW as output, verify that we sent this amount to the pool in total
    )]
    fn test_get_amount_out_lp_token(
        #[case] liq_a: U256,
        #[case] liq_b: U256,
        #[case] token_in_idx: usize,
        #[case] token_out_idx: usize,
        #[case] amount_in: BigUint,
        #[case] expected_out: BigUint,
    ) {
        let (t0, t1, t2, t3, t4) = create_test_tokens();
        let tokens = [&t0, &t1, &t2, &t3, &t4];

        let token_a = tokens[token_in_idx];
        let token_b = tokens[token_out_idx];

        let state = CowAMMState::new(
            Bytes::from("0x9bd702E05B9c97E4A4a3E47Df1e0fe7A0C26d2F1"),
            t0.address.clone(), //COW
            t1.address.clone(), //wstETH
            liq_a,              //COW
            liq_b,              //wstETH
            Bytes::from("0x9bd702E05B9c97E4A4a3E47Df1e0fe7A0C26d2F1"),
            U256::from_str("199999999999999999990").unwrap(),
            U256::from_str("1000000000000000000").unwrap(),
            U256::from_str("1000000000000000000").unwrap(),
            0,
        );

        let res = state
            .get_amount_out(amount_in.clone(), token_a, token_b)
            .unwrap();

        assert_eq!(res.amount, expected_out);
        //lp token supply reduced
        let new_state = res
            .new_state
            .as_any()
            .downcast_ref::<CowAMMState>()
            .unwrap();

        if token_a.address == t2.address {
            assert!(
                new_state.lp_token_supply < state.lp_token_supply,
                "LP token supply did not reduce"
            );
        } else {
            assert!(
                new_state.lp_token_supply > state.lp_token_supply,
                "LP token supply did not reduce"
            );
        }

        // Original state unchanged
        assert_eq!(state.liquidity_a(), liq_a);
        assert_eq!(state.liquidity_b(), liq_b);
    }

    #[test]
    fn test_get_amount_out_overflow() {
        let max = (BigUint::one() << 256) - BigUint::one();

        let (t0, t1, _, _, _) = create_test_tokens();

        let state = CowAMMState::new(
            Bytes::from("0x9bd702E05B9c97E4A4a3E47Df1e0fe7A0C26d2F1"),
            t0.address.clone(),
            t1.address.clone(),
            U256::from_str("886800000000000000").unwrap(),
            U256::from_str("50000000000000000").unwrap(),
            Bytes::from("0x9bd702E05B9c97E4A4a3E47Df1e0fe7A0C26d2F1"),
            U256::from_str("100000000000000000000").unwrap(),
            U256::from_str("1000000000000000000").unwrap(),
            U256::from_str("1000000000000000000").unwrap(),
            0,
        );

        let res = state.get_amount_out(max, &t0.clone(), &t1.clone());
        assert!(res.is_err());
        let err = res.err().unwrap();
        assert!(matches!(err, SimulationError::FatalError(_)));
    }

    #[rstest]
    #[case(17736000000000000000f64)]
    fn test_spot_price(#[case] expected: f64) {
        let (t0, t1, _, _, _) = create_test_tokens();
        let state = CowAMMState::new(
            Bytes::from("0x9bd702E05B9c97E4A4a3E47Df1e0fe7A0C26d2F1"),
            t0.address.clone(),
            t1.address.clone(),
            U256::from_str("886800000000000000").unwrap(),
            U256::from_str("50000000000000000").unwrap(),
            Bytes::from("0x9bd702E05B9c97E4A4a3E47Df1e0fe7A0C26d2F1"),
            U256::from_str("100000000000000000000").unwrap(),
            U256::from_str("1000000000000000000").unwrap(),
            U256::from_str("1000000000000000000").unwrap(),
            0,
        );

        let price = state.spot_price(&t0, &t1).unwrap();
        assert_ulps_eq!(price, expected);
    }

    #[test]
    fn test_fee() {
        let (t0, t1, _, _, _) = create_test_tokens();

        let state = CowAMMState::new(
            Bytes::from("0x9bd702E05B9c97E4A4a3E47Df1e0fe7A0C26d2F1"),
            t0.address.clone(),
            t1.address.clone(),
            U256::from_str("36925554990922").unwrap(),
            U256::from_str("30314846538607556521556").unwrap(),
            Bytes::from("0x7f39C581F595B53c5cb19bD0b3f8dA6c935E2Ca0"),
            U256::from_str("36925554990922").unwrap(),
            U256::from_str("30314846538607556521556").unwrap(),
            U256::from_str("30314846538607556521556").unwrap(),
            0,
        );

        let res = state.fee();

        assert_ulps_eq!(res, 0.0);
    }
    #[test]
    fn test_delta_transition() {
        let (t0, t1, _, _, _) = create_test_tokens();

        let mut state = CowAMMState::new(
            Bytes::from("0x9bd702E05B9c97E4A4a3E47Df1e0fe7A0C26d2F1"),
            t0.address.clone(),
            t1.address.clone(),
            U256::from_str("36925554990922").unwrap(),
            U256::from_str("30314846538607556521556").unwrap(),
            Bytes::from("0x7f39C581F595B53c5cb19bD0b3f8dA6c935E2Ca0"),
            U256::from_str("36925554990922").unwrap(),
            U256::from_str("30314846538607556521556").unwrap(),
            U256::from_str("30314846538607556521556").unwrap(),
            0,
        );
        let attributes: HashMap<String, Bytes> = vec![
            ("liquidity_a".to_string(), Bytes::from(15000_u64.to_be_bytes().to_vec())),
            ("liquidity_b".to_string(), Bytes::from(20000_u64.to_be_bytes().to_vec())),
            ("lp_token_supply".to_string(), Bytes::from(250000_u64.to_be_bytes().to_vec())),
        ]
        .into_iter()
        .collect();
        let delta = ProtocolStateDelta {
            component_id: "State1".to_owned(),
            updated_attributes: attributes,
            deleted_attributes: HashSet::new(),
        };

        let res = state.delta_transition(delta, &HashMap::new(), &Balances::default());

        assert!(res.is_ok());
        assert_eq!(state.liquidity_a(), U256::from_str("15000").unwrap());
        assert_eq!(state.liquidity_b(), U256::from_str("20000").unwrap());
        assert_eq!(state.lp_token_supply, U256::from_str("250000").unwrap());
    }

    #[test]
    fn test_delta_transition_missing_attribute() {
        let mut state = CowAMMState::new(
            Bytes::from("0x9bd702E05B9c97E4A4a3E47Df1e0fe7A0C26d2F1"),
            Bytes::from("0xDEf1CA1fb7FBcDC777520aa7f396b4E015F497aB"),
            Bytes::from("0x7f39C581F595B53c5cb19bD0b3f8dA6c935E2Ca0"),
            U256::from_str("36925554990922").unwrap(),
            U256::from_str("30314846538607556521556").unwrap(),
            Bytes::from("0x7f39C581F595B53c5cb19bD0b3f8dA6c935E2Ca0"),
            U256::from_str("36928554990972").unwrap(),
            U256::from_str("30314846538607556521556").unwrap(),
            U256::from_str("30314846538607556521556").unwrap(),
            0,
        );
        let attributes: HashMap<String, Bytes> = vec![(
            "liquidity_a".to_string(),
            Bytes::from(
                1500000000000000_u64
                    .to_be_bytes()
                    .to_vec(),
            ),
        )]
        .into_iter()
        .collect();

        let delta = ProtocolStateDelta {
            component_id: "State1".to_owned(),
            updated_attributes: attributes,
            deleted_attributes: HashSet::new(),
        };

        let res = state.delta_transition(delta, &HashMap::new(), &Balances::default());

        assert!(res.is_err());
        match res {
            Err(e) => {
                assert!(matches!(e, TransitionError::MissingAttribute(ref x) if x== "liquidity_b"))
            }
            _ => panic!("Test failed: was expecting an Err value"),
        };
    }

    #[test]
    fn test_get_limits_price_impact() {
        let (t0, t1, _, _, _) = create_test_tokens();

        let state = CowAMMState::new(
            Bytes::from("0x9bd702E05B9c97E4A4a3E47Df1e0fe7A0C26d2F1"),
            t0.address.clone(),
            t1.address.clone(),
            U256::from_str("886800000000000000").unwrap(),
            U256::from_str("50000000000000000").unwrap(),
            Bytes::from("0x9bd702E05B9c97E4A4a3E47Df1e0fe7A0C26d2F1"),
            U256::from_str("100000000000000000000").unwrap(),
            U256::from_str("1000000000000000000").unwrap(),
            U256::from_str("1000000000000000000").unwrap(),
            0,
        );

        let (amount_in, _) = state
            .get_limits(
                Bytes::from_str("0x0000000000000000000000000000000000000000").unwrap(),
                Bytes::from_str("0x0000000000000000000000000000000000000001").unwrap(),
            )
            .unwrap();

        let t0 = Token::new(
            &Bytes::from_str("0xDEf1CA1fb7FBcDC777520aa7f396b4E015F497aB").unwrap(),
            "COW",
            18,
            0,
            &[Some(10_000)],
            Chain::Ethereum,
            100,
        );

        let t1 = Token::new(
            &Bytes::from_str("0x7f39C581F595B53c5cb19bD0b3f8dA6c935E2Ca0").unwrap(),
            "wstETH",
            18,
            0,
            &[Some(10_000)],
            Chain::Ethereum,
            100,
        );

        let result = state
            .get_amount_out(amount_in.clone(), &t0, &t1)
            .unwrap();
        let new_state = result
            .new_state
            .as_any()
            .downcast_ref::<CowAMMState>()
            .unwrap();

        let initial_price = state.spot_price(&t0, &t1).unwrap();
        println!("Initial spot price (t0 -> t1): {}", initial_price);

        let new_price = new_state.spot_price(&t0, &t1).unwrap();

        println!("New spot price (t0 -> t1), floored: {}", new_price);

        assert!(new_price < initial_price);
    }
    #[test]
    fn test_arb_weth_lp_limits_calculation() {
        let arb = Token::new(
            &Bytes::from_str("0xb50721bcf8d664c30412cfbc6cf7a15145234ad1").unwrap(),
            "ARB", 18, 0, &[Some(10_000)], Chain::Ethereum, 100,
        );
        let weth = Token::new(
            &Bytes::from_str("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2").unwrap(),
            "WETH", 18, 0, &[Some(10_000)], Chain::Ethereum, 100,
        );
        let lp_token = Token::new(
            &Bytes::from_str("0x4359a8ea4c353d93245c0b6b8608a28bb48a05e2").unwrap(),
            "BCoW-50ARB-50WETH", 18, 0, &[Some(60_502_268_657_704_388)], Chain::Ethereum, 100,
        );

        let state = CowAMMState::new(
            Bytes::from_str("0x4359a8ea4c353d93245c0b6b8608a28bb48a05e2").unwrap(),
            arb.address.clone(),
            weth.address.clone(),
            U256::from_str("286275852074040134274570").unwrap(), //ARB
            U256::from_str("61694306956323018369").unwrap(), //WETH
            Bytes::from_str("0x4359a8ea4c353d93245c0b6b8608a28bb48a05e2").unwrap(),
            U256::from_str("60502268657704388057834").unwrap(),
            U256::from_str("1000000000000000000").unwrap(),
            U256::from_str("1000000000000000000").unwrap(),
            0,
        );

        // Get limits for LP → WETH
        //uses lp_limits 
        let (max_lp_in, max_weth_out) = state
            .get_limits(lp_token.address.clone(), weth.address.clone())
            .unwrap();

        println!("LP → WETH limits:");
        println!("  Max LP in: {}", max_lp_in);
        println!("  Max WETH out: {:.6} WETH", wei_to_eth(&max_weth_out));
        //30251134328852194028917
        //25000000000000000
        // Test with 10% of the SAFE max
        // let amount_in = max_lp_in.clone() / BigUint::from(0.1f64);
        // let amount_in = max_lp_in.clone() / BigUint::from(u64);
        let amount_in = max_lp_in.clone() / BigUint::from(10u64);
        println!("\nTesting with 10% of safe max: {}", amount_in);

        //why is it trying to substract from liquidity_b ?
        //
        let res = state
            .get_amount_out(amount_in.clone(), &lp_token, &weth)
            .expect("Should succeed with safe limit");
        
        // println!("✓ Successfully redeemed {} LP for {:.6} WETH", 
        //         amount_in, &res.amount) ;
    }
    #[test]
    fn test_arb_weth_lp_token_swap_overflow() {
        // Create tokens for ARB/WETH pool
        let arb = Token::new(
            &Bytes::from_str("0xb50721bcf8d664c30412cfbc6cf7a15145234ad1").unwrap(),
            "ARB",
            18,
            0,
            &[Some(10_000)],
            Chain::Ethereum,
            100,
        );

        let weth = Token::new(
            &Bytes::from_str("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2").unwrap(),
            "WETH",
            18,
            0,
            &[Some(10_000)],
            Chain::Ethereum,
            100,
        );

        let lp_token = Token::new(
            &Bytes::from_str("0x4359a8ea4c353d93245c0b6b8608a28bb48a05e2").unwrap(),
            "BCoW-50ARB-50WETH",
            18,
            0,
            &[Some(60_502_268_657_704_388)],
            Chain::Ethereum,
            100,
        );

        // Correct hex to decimal conversions:
        // liquidity_a (ARB): 0x3c9f0b8792debbb50e0a = 286,275,852,074,040,134,274,570
        // liquidity_b (WETH): 0x03582e354e6b8b5681 =  61,694,306,956,323,018,369
        // lp_token_supply: 0x0ccfd5a5756ca7d0daea = 60,502,268,657,704,388,057,834

        let state = CowAMMState::new(
            Bytes::from_str("0x4359a8ea4c353d93245c0b6b8608a28bb48a05e2").unwrap(),
            arb.address.clone(),      // token_a = ARB
            weth.address.clone(),     // token_b = WETH
            U256::from_str("286275852074040134274570").unwrap(),  // liquidity_a = ARB
            U256::from_str("61694306956323018369").unwrap(),       // liquidity_b = WETH
            Bytes::from_str("0x4359a8ea4c353d93245c0b6b8608a28bb48a05e2").unwrap(),
            U256::from_str("60502268657704388057834").unwrap(),   // lp_token_supply
            U256::from_str("1000000000000000000").unwrap(),       // weight_a = 50%
            U256::from_str("1000000000000000000").unwrap(),       // weight_b = 50%
            0,
        );

        // Calculate 0.1% of max LP tokens from the error log
        // Max input was: 143137926037020067137285
        // 0.1% of that = 143137926037020067137
        let amount_in = BigUint::from_str("143137926037020067137").unwrap();
        println!("Testing 0.1% LP token redemption (ARB/WETH pool)");
        println!("Amount in (LP): {}", amount_in);
        println!("LP token supply: {}", state.lp_token_supply);
        println!("Liquidity A (ARB): {}", state.liquidity_a());
        println!("Liquidity B (WETH): {}", state.liquidity_b());
        
        // Calculate what proportion this is
        let proportion = (amount_in.clone() * BigUint::from(10000u64)) / 
                        u256_to_biguint(state.lp_token_supply);
        println!("Proportion of LP supply: {}%", proportion.to_f64().unwrap() / 100.0);

        // This should fail with U256 arithmetic overflow
        let res = state.get_amount_out(amount_in.clone(), &lp_token, &weth);

        match res {
            Ok(result) => {
                println!("Unexpectedly succeeded with amount_out: {}", result.amount);
                panic!("Expected overflow error but got success");
            }
            Err(SimulationError::FatalError(msg)) => {
                assert!(
                    msg.contains("U256 arithmetic overflow") || msg.contains("overflow"),
                    "Expected overflow error but got: {}",
                    msg
                );
                println!("✓ Got expected overflow error: {}", msg);
            }
            Err(e) => {
                panic!("Got unexpected error type: {:?}", e);
            }
        }
    }
    
}
