use std::{collections::HashMap, fmt::Debug};
use std::any::Any;
use alloy::primitives::{Address, U256};
use num_bigint::{BigUint,ToBigUint};
use tycho_common::{
    dto::{ProtocolStateDelta},
    models::{Chain, token::Token},
    simulation::{
        protocol_sim::{GetAmountOutResult, Balances, ProtocolSim},
        errors::{SimulationError,TransitionError}
    },
    Bytes
}; 
use crate::{
    evm::protocol::{
        cowamm::{
            bmath::*,
            error::CowAMMError,
            constants::BONE,
        },
        u256_num::{u256_to_f64, u256_to_biguint, biguint_to_u256}, 
        safe_math::{div_mod_u256, safe_div_u256, safe_mul_u256, safe_add_u256, safe_sub_u256}
    },
};

const COWAMM_FEE: f64 = 0.0; // 0% fee 
const MAX_IN_FACTOR: u64 = 50;
const MAX_OUT_FACTOR: u64 = 33;

// Token 3 tuple: (address, liquidity, weight)
type TokenInfo = (Bytes, U256, U256);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CowAMMState {
     /// The Pool Address
    address: Bytes,
    /// Token A information: (address, liquidity, weight)
    token_a: TokenInfo,
    /// Token B information: (address, liquidity, weight)
    token_b: TokenInfo,
    /// The Swap Fee on the Pool
    fee: u64,
    ///The lp token of the pool
    lp_token: Bytes,
    /// The Supply of the lp token 
    lp_token_supply: U256
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
    
    fn token_b_addr(&self) -> &Bytes {
        &self.token_b.0
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
    
    /// Calculates the proportion of tokens a user receives when exiting the pool by burning LP tokens,
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
        // Collect balances
        let balances = vec![
            self.liquidity_a(), 
            self.liquidity_b()
        ];

        let total_lp_token = self.lp_token_supply;

        // lpTokenRatio = lp_token_in / total_lp_token
        let lp_token_ratio = bdiv(lp_token_in, total_lp_token)       
        .map_err(|err| SimulationError::FatalError(format!("Error in calculating LP token ratio {err:?}")))?;

        // amountsOut[i] = balances[i] * lp_token_ratio
        let mut amounts_out = Vec::with_capacity(balances.len());
        for balance in balances.iter() {
            let amount = bmul(*balance, lp_token_ratio)
            .map_err(|err| SimulationError::FatalError(format!("Total LP token supply missing {err:?}")))?;
            amounts_out.push(amount);
        }

        Ok((amounts_out[0], amounts_out[1]))
    }
}

impl ProtocolSim for CowAMMState {
    fn fee(&self) -> f64 {
        COWAMM_FEE
    } 
    /// Calculates a f64 representation of base token price in the AMM. 
    /// **********************************************************************************************
    /// calcSpotPrice                                                                             //
    /// sP = spotPrice                                                                            //
    /// bI = tokenBalanceIn                ( bI / wI )         1                                  //
    /// bO = tokenBalanceOut         sP =  -----------  *  ----------                             //
    /// wI = tokenWeightIn                 ( bO / wO )     ( 1 - sF )                             //
    /// wO = tokenWeightOut                                                                       //
    /// sF = swapFee                                                                              //
    ///**********************************************************************************************/
    fn spot_price(&self, base: &Token, quote: &Token) -> Result<f64, SimulationError> {
        let bone = u256_to_f64(BONE);
        // Normalize for token decimals to 18
        let norm_base = 10_f64.powi((18i32 - base.decimals as i32).max(0));
        let norm_quote = 10_f64.powi((18i32 - quote.decimals as i32).max(0));

        // Normalize weights
        let norm_weight_base = u256_to_f64(self.weight_a()) / norm_base;
        let norm_weight_quote = u256_to_f64(self.weight_b()) / norm_quote;

        // Get balances (liquidity)
        let balance_base = u256_to_f64(self.liquidity_a()); 
        let balance_quote = u256_to_f64(self.liquidity_b());
        
        // Fee as fraction: assume fee is in wei (1e18 = 100%)
        let fee_fraction = (self.fee as f64) / bone;
        
        // Apply spot price formula 
        let dividend = (balance_quote / norm_weight_quote) * bone;
        let divisor = (balance_base / norm_weight_base) * (bone * (1.0 - fee_fraction));
        
        let ratio = dividend / divisor; //swap this to match solidity version?

        Ok(ratio)
    }

    fn get_amount_out(
        &self,
        amount_in: BigUint,
        token_in: &Token, //sell_token
        token_out: &Token, //buy_token
    ) -> Result<GetAmountOutResult, SimulationError> {
        let amount_in = biguint_to_u256(&amount_in);
        
        if amount_in.is_zero() {
            return Err(SimulationError::InvalidInput("Amount in cannot be zero".to_string(), None));
        } 

        let is_lp_in = token_in.address == self.address;
        let is_lp_out = token_out.address == self.address;

        if is_lp_in && is_lp_out {
            return Err(SimulationError::InvalidInput("Cannot swap LP token for LP token".into(), None));
        }

        let mut new_state = self.clone();

        if is_lp_in && !is_lp_out {
            // Exit Pool (selling LP tokens for token_out)
            let (proportional_token_amount_a, proportional_token_amount_b) = self.calc_tokens_out_given_exact_lp_token_in(
                amount_in
            ).map_err(|e| SimulationError::FatalError(format!("failed to calculate token proportions out error: {e:?}")))?;
            println!("PROP A {}, PROP B {}", proportional_token_amount_a, proportional_token_amount_b);
            // Think of it from the pools perspective , when a user exits the pool, they get their tokens back and redeems the lp_token (lp token gets burnt)
            // Update state
            // The liquidity provision is double sided hence both reserves reduce by the proportional amounts for both tokens
            new_state.token_a.1 = safe_sub_u256(self.liquidity_a(), proportional_token_amount_a)?;
            new_state.token_b.1 = safe_sub_u256(self.liquidity_b(), proportional_token_amount_b)?;

            // When a user redeems LP tokens, those tokens are effectively burned, the internal lp_token_supply will decrease by the amount they redeem
            new_state.lp_token_supply = safe_sub_u256(self.lp_token_supply, amount_in)?;

            let (amount_to_swap, is_token_a_swap) = if token_out.address == *self.token_a_addr() { //if we are redeeming lp_token for COW (out address is COW), (if the token we want to receive and get the other one swapped to) from the redemption is 
                (proportional_token_amount_b, false) // Swap token B for token A // then swap the proportional amount of wstETH we received for COW 
            } else {
                (proportional_token_amount_a, true) // Swap token A for token B
            };

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
            .map_err(|e| SimulationError::FatalError(format!("amount_out error: {e:?}")))?;
            // Update state for the swap
            if is_token_a_swap {
                new_state.token_b.1 = safe_sub_u256(new_state.liquidity_b(), amount_to_swap)?;
                new_state.token_a.1 = safe_add_u256(new_state.liquidity_a(), amount_out)?;
            } else {
                new_state.token_a.1 = safe_sub_u256(new_state.liquidity_a(), amount_to_swap)?; 
                new_state.token_b.1 = safe_add_u256(new_state.liquidity_b(), amount_out)?;
            }

            let total_trade_amount = safe_add_u256(amount_out, proportional_token_amount_a)?;

            return Ok(GetAmountOutResult {
                amount: u256_to_biguint(total_trade_amount),
                gas: 194140u64.to_biguint().unwrap(),
                new_state: Box::new(new_state),
            });
        }

        if is_lp_out && !is_lp_in {
            //JOIN POOL
            let (proportional_token_amount_a, proportional_token_amount_b) = self.calc_tokens_out_given_exact_lp_token_in(
                amount_in
            ).map_err(|e| SimulationError::FatalError(format!("failed to calculate token proportions out error: {e:?}")))?;
            //Think of it from the pools perspective , when a user joins the pool, they send their tokens to the pool
            // HERE
            // The liquidity provision is double sided hence both reserves reduce by the proportional amounts for both tokens
            new_state.token_a.1 = safe_add_u256(new_state.liquidity_a(), proportional_token_amount_a)?;
            new_state.token_b.1 = safe_add_u256(new_state.liquidity_b(), proportional_token_amount_b)?;
            // supply changes only happens when tokens are minted are burned 

            // When a user joins the pool, the LP tokens are minted to the user , total lp_token supply increases
            new_state.lp_token_supply = safe_add_u256(new_state.lp_token_supply, amount_in)?;
            
            // Determine which token to swap based on token_in address
            let (amount_to_swap, is_token_a_swap) = if token_in.address == *new_state.token_a_addr() {
                (proportional_token_amount_b, false) // Swap extra token B for token A
            } else {
                (proportional_token_amount_a, true) // Swap extra token A for token B
            };
            //we need to add the limits
            //but it doesnt 
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
            .map_err(|e| SimulationError::FatalError(format!("amt_in error: {e:?}")))?;
            
            if is_token_a_swap {
                new_state.token_a.1 = safe_sub_u256(new_state.liquidity_a(), amount_to_swap)?;
                new_state.token_b.1 = safe_add_u256(new_state.liquidity_b(), amt_in)?;
            } else {
                new_state.token_b.1 = safe_sub_u256(new_state.liquidity_b(), amount_to_swap)?;
                new_state.token_a.1 = safe_add_u256(new_state.liquidity_a(), amt_in)?; 
            }

            return Ok(GetAmountOutResult {
                amount: u256_to_biguint(amt_in),
                gas: 120_000u64.to_biguint().unwrap(),
                new_state: Box::new(new_state),
            });
        }

        //for normal swaps 
        let amount_out = calculate_out_given_in(
            self.liquidity_a(),
            self.weight_a(),
            self.liquidity_b(),
            self.weight_b(),
            amount_in,
            U256::from(self.fee),
        )
        .map_err(|e| SimulationError::FatalError(format!("amount_out error: {e:?}")))?;

        new_state.token_a.1 = safe_sub_u256(new_state.liquidity_a(), amount_in)?;
        new_state.token_b.1 = safe_add_u256(new_state.liquidity_b(), amount_out)?;

        Ok(GetAmountOutResult {
            amount: u256_to_biguint(amount_out), 
            gas: 120_000u64.to_biguint().unwrap(),
            new_state: Box::new(new_state),
        })
    }

    fn get_limits(
        &self,
        _sell_token: Bytes,
        _buy_token: Bytes,
    ) -> Result<(BigUint, BigUint), SimulationError> {
        if self.liquidity_a().is_zero() || self.liquidity_b().is_zero() {
            return Ok((BigUint::ZERO, BigUint::ZERO));
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
        // liquidity_a, liquidity_b and lp_token_supply are considered required attributes and are expected in every delta
        // we process
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
    use std::{collections::{HashMap, HashSet}};
    use std::str::FromStr;

    use alloy::primitives::{Address, U256};
    use approx::assert_ulps_eq;
    use num_bigint::{BigUint, ToBigUint};
    use num_traits::One;
    use rstest::rstest;
    use tycho_common::{
        simulation::errors::{SimulationError, TransitionError},
        models::token::Token, dto::ProtocolStateDelta, 
        Bytes,
    };

    use super::*;
    use crate::{
        evm::protocol::cowamm::state::{CowAMMState, ProtocolSim},
        evm::protocol::u256_num::{biguint_to_u256, u256_to_biguint},
    };
       
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
            &[Some(199_999_999_999_999_990)], //removed _999
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
            &[Some(1_0000_000)],
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
            Bytes::from(token_in.address.clone()),
            Bytes::from(token_out.address.clone()),
            liq_a, //COW
            liq_b, //wstETH
            Bytes::from("0x9bd702E05B9c97E4A4a3E47Df1e0fe7A0C26d2F1"),
            U256::from_str("199999999999999999990").unwrap(),
            U256::from_str("1000000000000000000").unwrap(),
            U256::from_str("1000000000000000000").unwrap(),
            0,
        );

        let res = state.get_amount_out(amount_in.clone(), &token_in, &token_out).unwrap();

        println!("RES AMOUNT {}", res.amount);
        println!("EXPECTED AMOUNT {}", expected_out);

        assert_eq!(res.amount, expected_out);

        let new_state = res.new_state.as_any().downcast_ref::<CowAMMState>().unwrap();
        
        assert_eq!(new_state.liquidity_a(), safe_sub_u256(liq_a, biguint_to_u256(&amount_in)).unwrap());  
        assert_eq!(new_state.liquidity_b(), safe_add_u256(liq_b, biguint_to_u256(&expected_out)).unwrap());

        // Original state unchanged
        assert_eq!(state.liquidity_a(), liq_a);
        assert_eq!(state.liquidity_b(), liq_b);
    }
    
    #[rstest]
    #[case::buy_lp_token( //buying lp token with COW == joining pool and convert excess wstETH to COW
        U256::from_str("1547000000000000000000").unwrap(),
        U256::from_str("100000000000000000").unwrap(),
        0, 2, // token indices: t0 -> t2
        BigUint::from_str("1000000000000000000").unwrap(), //Amount of lp_token being sold (redeeemd) 
        BigUint::from_str("7773675000000000000").unwrap(), //Amount of COW tokens to send to swap exactly 5e14 wstETH
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
            Bytes::from(t0.address.clone()), //COW
            Bytes::from(t1.address.clone()), //wstETH
            liq_a, //COW
            liq_b, //wstETH
            Bytes::from("0x9bd702E05B9c97E4A4a3E47Df1e0fe7A0C26d2F1"),
            U256::from_str("199999999999999999990").unwrap(),
            U256::from_str("1000000000000000000").unwrap(),
            U256::from_str("1000000000000000000").unwrap(),
            0,
        );
  
        let res = state.get_amount_out(amount_in.clone(), &token_a, &token_b).unwrap();

        // println!("RES AMOUNT {}", res.amount);
        // println!("EXPECTED AMOUNT {}", expected_out);

        assert_eq!(res.amount, expected_out);
        //lp token supply reduced 
        let new_state = res.new_state.as_any().downcast_ref::<CowAMMState>().unwrap();

        if token_a.address == t2.address {
            assert!(new_state.lp_token_supply < state.lp_token_supply, "LP token supply did not reduce");
        }  else {
            assert!(new_state.lp_token_supply > state.lp_token_supply, "LP token supply did not reduce");
        }

        // Original state unchanged
        assert_eq!(state.liquidity_a(), liq_a);
        assert_eq!(state.liquidity_b(),  liq_b);
    }

    #[test]
    fn test_get_amount_out_overflow() {
        let max = (BigUint::one() << 256) - BigUint::one();

        let (t0, t1, _, _, _,) = create_test_tokens();
      
        let state = CowAMMState::new(
            Bytes::from("0x9bd702E05B9c97E4A4a3E47Df1e0fe7A0C26d2F1"),
            Bytes::from(t0.address.clone()),
            Bytes::from(t1.address.clone()),
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
        assert!(matches!(err, SimulationError::FatalError(_))); //huh
    }

    #[rstest]
    #[case(0.05638249887235002f64)]
    fn test_spot_price(#[case] expected: f64) {
        let (t0, t1, _, _, _,) = create_test_tokens();
        let state = CowAMMState::new(
            Bytes::from("0x9bd702E05B9c97E4A4a3E47Df1e0fe7A0C26d2F1"),
            Bytes::from(t0.address.clone()),
            Bytes::from(t1.address.clone()),
            U256::from_str("886800000000000000").unwrap(),
            U256::from_str("50000000000000000").unwrap(),
            Bytes::from("0x9bd702E05B9c97E4A4a3E47Df1e0fe7A0C26d2F1"),
            U256::from_str("100000000000000000000").unwrap(),
            U256::from_str("1000000000000000000").unwrap(),
            U256::from_str("1000000000000000000").unwrap(),
            0,
        );

        let price = state.spot_price(&t0, &t1).unwrap();
        println!("THIS IS THE PRICE: {}", price); //THIS IS THE PRICE: 0.05638249887235002
        let expected = expected;
        assert_ulps_eq!(price, expected);
    }

    #[test]
    fn test_fee() {
        let (t0, t1, _, _, _,) = create_test_tokens();

        let state = CowAMMState::new(
            Bytes::from("0x9bd702E05B9c97E4A4a3E47Df1e0fe7A0C26d2F1"),
            Bytes::from(t0.address.clone()),
            Bytes::from(t1.address.clone()),
            U256::from_str("36925554990922").unwrap(),
            U256::from_str("30314846538607556521556").unwrap(),
            Bytes::from("0x7f39C581F595B53c5cb19bD0b3f8dA6c935E2Ca0"),
            U256::from_str("36925554990922").unwrap(),
            U256::from_str("30314846538607556521556").unwrap(),
            U256::from_str("30314846538607556521556").unwrap(),
            0
        );

        let res = state.fee();

        assert_ulps_eq!(res, 0.0);
    }
      #[test]
    fn test_delta_transition() { 
        let (t0, t1, _, _, _,) = create_test_tokens();

        let mut state = CowAMMState::new(
            Bytes::from("0x9bd702E05B9c97E4A4a3E47Df1e0fe7A0C26d2F1"),
            Bytes::from(t0.address.clone()),
            Bytes::from(t1.address.clone()),
            U256::from_str("36925554990922").unwrap(),
            U256::from_str("30314846538607556521556").unwrap(),
            Bytes::from("0x7f39C581F595B53c5cb19bD0b3f8dA6c935E2Ca0"),
            U256::from_str("36925554990922").unwrap(),
            U256::from_str("30314846538607556521556").unwrap(),
            U256::from_str("30314846538607556521556").unwrap(),
            0
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
            0
        );
        let attributes: HashMap<String, Bytes> =
            vec![("liquidity_a".to_string(), Bytes::from(1500000000000000_u64.to_be_bytes().to_vec()))]
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
         let (t0, t1, _, _, _,) = create_test_tokens();

         let state = CowAMMState::new(
            Bytes::from("0x9bd702E05B9c97E4A4a3E47Df1e0fe7A0C26d2F1"),
            Bytes::from(t0.address.clone()),
            Bytes::from(t1.address.clone()),
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
            .get_amount_out(amount_in.clone(), &t1, &t0)
            .unwrap();
        let new_state = result
            .new_state
            .as_any()
            .downcast_ref::<CowAMMState>()
            .unwrap();
        println!("Amount in: {}", amount_in);
        println!("Result amount out: {}", result.amount);
        println!("New state: {:?}", new_state); // Make sure CowAMMState implements Debug
        let initial_price = state
            .spot_price(&t1, &t0)
            .unwrap();
        println!("Initial spot price (t0 -> t1): {}", initial_price);
        let new_price = new_state
            .spot_price(&t1, &t0)
            .unwrap();
            // .floor();
        println!("New spot price (t0 -> t1), floored: {}", new_price);
        let expected_price = initial_price / 10.0;
        println!("Expected price (90% impact): {}", expected_price);
        assert!(expected_price == new_price, "Price impact not 90%.");
    }
}

      
