//! UniswapV2 implementation for the action system playground.

use num_bigint::BigUint;
use std::ops::Div;

use tycho_common::{
    action::{
        asset::Asset,
        context::ActionContext,
        simulate::{DefaultInputs, DefaultOutputs, SimulateForward},
    },
    asset::erc20::ERC20Asset,
    liquidity_provision::action::{
        AddLiquidityFullRange, AddLiquidityFullRangeParameters, LiquidityAmount,
        RemoveLiquidityFullRange, RemoveLiquidityParameters,
    },
    models::{token::Token, Chain},
    simulation::errors::SimulationError,
    swap::action::{Swap, SwapParameters},
};

/// UniswapV2 pool state with core AMM functionality.
#[derive(Debug, Clone)]
pub struct UniswapV2Pool {
    /// First token in the pair (lexicographically sorted by address).
    pub token0: Token,
    /// Second token in the pair.
    pub token1: Token,
    /// Reserve amount for token0.
    pub reserve0: BigUint,
    /// Reserve amount for token1.
    pub reserve1: BigUint,
    /// Total supply of LP tokens.
    pub lp_total_supply: BigUint,
    /// Minimum liquidity locked forever (1000 wei).
    pub minimum_liquidity: BigUint,
}

impl UniswapV2Pool {
    /// Create a new UniswapV2 pool.
    pub fn new(
        token0: Token,
        token1: Token,
        reserve0: BigUint,
        reserve1: BigUint,
        lp_total_supply: BigUint,
    ) -> Self {
        Self {
            token0,
            token1,
            reserve0,
            reserve1,
            lp_total_supply,
            minimum_liquidity: BigUint::from(1000u32),
        }
    }

    /// Get the amount of output tokens for a given input amount (exact input swap).
    pub fn get_amount_out(&self, amount_in: &BigUint, reserve_in: &BigUint, reserve_out: &BigUint) -> Result<BigUint, SimulationError> {
        if amount_in == &BigUint::from(0u32) {
            return Err(SimulationError::InvalidInput("Input amount cannot be zero".into(), None));
        }
        if reserve_in == &BigUint::from(0u32) || reserve_out == &BigUint::from(0u32) {
            return Err(SimulationError::InvalidInput("Insufficient liquidity".into(), None));
        }

        // Apply 0.3% fee: amount_in_with_fee = amount_in * 997
        let amount_in_with_fee = amount_in * BigUint::from(997u32);
        let numerator = &amount_in_with_fee * reserve_out;
        let denominator = reserve_in * BigUint::from(1000u32) + &amount_in_with_fee;
        
        Ok(numerator.div(&denominator))
    }

    /// Get the required input amount for a desired output amount (exact output swap).
    pub fn get_amount_in(&self, amount_out: &BigUint, reserve_in: &BigUint, reserve_out: &BigUint) -> Result<BigUint, SimulationError> {
        if amount_out == &BigUint::from(0u32) {
            return Err(SimulationError::InvalidInput("Output amount cannot be zero".into(), None));
        }
        if reserve_in == &BigUint::from(0u32) || reserve_out <= amount_out {
            return Err(SimulationError::InvalidInput("Insufficient liquidity".into(), None));
        }

        let numerator = reserve_in * amount_out * BigUint::from(1000u32);
        let denominator = (reserve_out - amount_out) * BigUint::from(997u32);
        
        // Add 1 to round up
        Ok((numerator.div(&denominator)) + BigUint::from(1u32))
    }

    /// Calculate square root using Newton's method (for LP token calculations).
    fn sqrt(&self, value: &BigUint) -> BigUint {
        if value == &BigUint::from(0u32) {
            return BigUint::from(0u32);
        }
        
        let mut x = value.clone();
        let mut y = (value + BigUint::from(1u32)).div(&BigUint::from(2u32));
        
        while y < x {
            x = y.clone();
            y = (y.clone() + value.div(&y)).div(&BigUint::from(2u32));
        }
        
        x
    }

    /// Calculate LP tokens to mint for given token amounts.
    pub fn calculate_lp_tokens_to_mint(&self, amount0: &BigUint, amount1: &BigUint) -> Result<BigUint, SimulationError> {
        if self.lp_total_supply == BigUint::from(0u32) {
            // First liquidity addition
            let liquidity = self.sqrt(&(amount0 * amount1));
            if liquidity <= self.minimum_liquidity {
                return Err(SimulationError::InvalidInput("Insufficient liquidity minted".into(), None));
            }
            Ok(liquidity - &self.minimum_liquidity)
        } else {
            // Subsequent liquidity additions
            let liquidity0 = amount0 * &self.lp_total_supply / &self.reserve0;
            let liquidity1 = amount1 * &self.lp_total_supply / &self.reserve1;
            Ok(std::cmp::min(liquidity0, liquidity1))
        }
    }

    /// Calculate underlying token amounts for LP token burn.
    pub fn calculate_underlying_amounts(&self, lp_amount: &BigUint) -> Result<(BigUint, BigUint), SimulationError> {
        if lp_amount > &self.lp_total_supply {
            return Err(SimulationError::InvalidInput("Burn amount exceeds total supply".into(), None));
        }
        
        let amount0 = lp_amount * &self.reserve0 / &self.lp_total_supply;
        let amount1 = lp_amount * &self.reserve1 / &self.lp_total_supply;
        
        Ok((amount0, amount1))
    }

    /// Check if a token is token0 or token1.
    pub fn get_token_order(&self, token: &Token) -> Option<bool> {
        if token.address == self.token0.address {
            Some(true) // token0
        } else if token.address == self.token1.address {
            Some(false) // token1
        } else {
            None
        }
    }
}

// =============================================================================
// Swap Action Implementation
// =============================================================================

impl SimulateForward<Swap> for UniswapV2Pool {
    fn simulate_forward(
        &self,
        _context: &ActionContext,
        params: &SwapParameters,
        inputs: &DefaultInputs<ERC20Asset>,
    ) -> Result<(DefaultOutputs<ERC20Asset>, Box<Self>), SimulationError> {
        if inputs.0.len() != 1 {
            return Err(SimulationError::InvalidInput("Swap requires exactly one input token".into(), None));
        }

        let input_asset = &inputs.0[0];
        let input_is_token0 = self.get_token_order(input_asset.token())
            .ok_or_else(|| SimulationError::InvalidInput("Input token not in pool".into(), None))?;

        // Verify output token is the other token in the pair
        let expected_output = if input_is_token0 { &self.token1 } else { &self.token0 };
        if params.output_token().address != expected_output.address {
            return Err(SimulationError::InvalidInput("Output token not in pool".into(), None));
        }

        let input_amount = input_asset.amount().unwrap();
        let (reserve_in, reserve_out) = if input_is_token0 {
            (&self.reserve0, &self.reserve1)
        } else {
            (&self.reserve1, &self.reserve0)
        };

        let output_amount = self.get_amount_out(input_amount, reserve_in, reserve_out)?;
        
        // Create new pool state
        let mut new_pool = self.clone();
        if input_is_token0 {
            new_pool.reserve0 += input_amount;
            new_pool.reserve1 -= &output_amount;
        } else {
            new_pool.reserve1 += input_amount;
            new_pool.reserve0 -= &output_amount;
        }

        // Create output assets
        let used_assets = vec![input_asset.clone()];
        let produced_assets = vec![ERC20Asset::new(params.output_token().clone(), output_amount)];

        let outputs = DefaultOutputs::new(
            used_assets,
            produced_assets,
            BigUint::from(21000u32), // Typical swap gas cost
        );

        Ok((outputs, Box::new(new_pool)))
    }
}

// =============================================================================
// Liquidity Provision Action Implementations
// =============================================================================

impl SimulateForward<AddLiquidityFullRange> for UniswapV2Pool {
    fn simulate_forward(
        &self,
        _context: &ActionContext,
        _params: &AddLiquidityFullRangeParameters,
        inputs: &DefaultInputs<ERC20Asset>,
    ) -> Result<(DefaultOutputs<ERC20Asset>, Box<Self>), SimulationError> {
        if inputs.0.len() != 2 {
            return Err(SimulationError::InvalidInput("Add liquidity requires exactly two input tokens".into(), None));
        }

        // Sort inputs by token address to match pool order
        let mut sorted_inputs = inputs.0.clone();
        sorted_inputs.sort_by(|a, b| a.token().address.cmp(&b.token().address));

        let (amount0, amount1) = (
            sorted_inputs[0].amount().unwrap().clone(),
            sorted_inputs[1].amount().unwrap().clone(),
        );

        let lp_tokens_minted = self.calculate_lp_tokens_to_mint(&amount0, &amount1)?;

        // Create new pool state
        let mut new_pool = self.clone();
        new_pool.reserve0 += &amount0;
        new_pool.reserve1 += &amount1;
        new_pool.lp_total_supply += &lp_tokens_minted;

        // Create LP token (using a simple hash-like address)
        let lp_token = Token::new(
            &"0x1111111111111111111111111111111111111111".into(),
            &format!("{}/{}", self.token0.symbol, self.token1.symbol),
            18,
            0, // no tax
            &[Some(50000u64)], // LP operations gas cost
            Chain::Ethereum,
            100, // good quality
        );

        let outputs = DefaultOutputs::new(
            sorted_inputs,
            vec![ERC20Asset::new(lp_token, lp_tokens_minted)],
            BigUint::from(100000u32), // Typical add liquidity gas cost
        );

        Ok((outputs, Box::new(new_pool)))
    }
}

impl SimulateForward<RemoveLiquidityFullRange> for UniswapV2Pool {
    fn simulate_forward(
        &self,
        _context: &ActionContext,
        params: &RemoveLiquidityParameters,
        inputs: &ERC20Asset,
    ) -> Result<(DefaultOutputs<ERC20Asset>, Box<Self>), SimulationError> {
        let lp_amount = match &params.amount {
            LiquidityAmount::Exact(amount) => amount.clone(),
            LiquidityAmount::All => inputs.amount().unwrap().clone(),
        };

        if lp_amount > *inputs.amount().unwrap() {
            return Err(SimulationError::InvalidInput("LP amount exceeds input".into(), None));
        }

        let (amount0, amount1) = self.calculate_underlying_amounts(&lp_amount)?;

        // Create new pool state
        let mut new_pool = self.clone();
        new_pool.reserve0 -= &amount0;
        new_pool.reserve1 -= &amount1;
        new_pool.lp_total_supply -= &lp_amount;

        let used_lp_token = ERC20Asset::new(inputs.token().clone(), lp_amount);
        let underlying_tokens = vec![
            ERC20Asset::new(self.token0.clone(), amount0),
            ERC20Asset::new(self.token1.clone(), amount1),
        ];

        let outputs = DefaultOutputs::new(
            vec![used_lp_token],
            underlying_tokens,
            BigUint::from(80000u32), // Typical remove liquidity gas cost
        );

        Ok((outputs, Box::new(new_pool)))
    }
}

