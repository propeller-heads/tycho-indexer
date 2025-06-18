use std::{collections::HashMap, fmt::Debug};
use std::any::Any;
use alloy_primitives::{Address, U256};
use num_bigint::BigUint;
// use rug::{float::Round, Float};
use tycho_common::{dto::ProtocolStateDelta, Bytes};
use super::constants::{BONE};
use super::error::CowAMMError;
use super::bmath::calculate_out_given_in;

use crate::{
    evm::protocol::{
        cowamm::{
            bmath,
        },
        u256_num::{u256_to_f64, u256_to_biguint, biguint_to_u256}, 
        safe_math::{div_mod_u256, safe_div_u256, safe_mul_u256, safe_add_u256, safe_sub_u256}
    },
    models::{Balances, Token},
    protocol::{
        errors::{SimulationError, TransitionError},
        models::GetAmountOutResult,
        state::ProtocolSim,
    },
};

const COWAMM_FEE: f64 = 0.0; // 0% fee 
const MAX_IN_FACTOR: u64 = 50;
const MAX_OUT_FACTOR: u64 = 33;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenState {
    pub liquidity: U256,
    pub weight: U256,
    pub token: Token,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CowAMMPoolState {
     /// The Pool Address.
    address: Address,
    state: HashMap<Bytes, TokenState>, 
    /// The Swap Fee on the Pool.
    fee: u32,
}

impl ProtocolSim for CowAMMPoolState {
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
        //could have used the rug implementation but it causes a build error that'll most likely be not too relevant to fuck up the CI
        // and give other people issues 
        // let bone = u256_to_f64(BONE);
        // let norm_base = if base.decimals < 18 {
        //     Float::with_val(
        //         MPFR_T_PRECISION,
        //         10_u64.pow(18 - base.decimals as u32),
        //     )
        // } else {
        //     Float::with_val(MPFR_T_PRECISION, 1)
        // };
        // let norm_quote = if quote.decimals < 18 {
        //     Float::with_val(
        //         MPFR_T_PRECISION,
        //         10_u64.pow(18 - quote.decimals as u32),
        //     )
        // } else {
        //     Float::with_val(MPFR_T_PRECISION, 1)
        // };

        // let base_token = self.state.get(&base.address).ok_or(CowAMMError::TokenInDoesNotExist);
        // let quote_token = self.state.get(&quote.address).ok_or(CowAMMError::TokenOutDoesNotExist);
         
        // let norm_weight_base = u256_to_f64(base_token.weight) / norm_base;
        // let norm_weight_quote = u256_to_f64(quote_token.weight) / norm_quote;
        // let balance_base = u256_to_f64(base_token.liquidity); // how to get liquidity ? 
        // let balance_quote = u256_to_f64(quote_token.liquidity);

        // let dividend = (balance_quote / norm_weight_quote) * bone.clone();
        // let divisor = (balance_base / norm_weight_base)
        //     * (bone - Float::with_val(MPFR_T_PRECISION, self.fee));
        // let ratio = dividend / divisor;
        // Ok(ratio.to_f64_round(Round::Nearest))
        let bone = u256_to_f64(BONE);
        // Normalize for token decimals to 18
        let norm_base = 10_f64.powi((18i32 - base.decimals as i32).max(0));
        let norm_quote = 10_f64.powi((18i32 - quote.decimals as i32).max(0));

        let base_token = self
            .state
            .get(&base.address)
            .ok_or(CowAMMError::TokenInDoesNotExist)
            .map_err(|err| SimulationError::FatalError(format!("token not found: {err:?}")))?;
        let quote_token = self
            .state
            .get(&quote.address)
            .ok_or(CowAMMError::TokenOutDoesNotExist)
            .map_err(|err| SimulationError::FatalError(format!("token not found: {err:?}")))?;

        // Normalize weights
        let norm_weight_base = u256_to_f64(base_token.weight) / norm_base;
        let norm_weight_quote = u256_to_f64(quote_token.weight) / norm_quote;

        // Get balances (liquidity)
        let balance_base = u256_to_f64(base_token.liquidity); 
        let balance_quote = u256_to_f64(quote_token.liquidity);
        
        // Fee as fraction: assume fee is in wei (1e18 = 100%)
        let fee_fraction = (self.fee as f64) / bone;
        
        // Apply spot price formula
        let dividend = (balance_quote / norm_weight_quote) * bone;
        let divisor = (balance_base / norm_weight_base) * (bone * (1.0 - fee_fraction));
        
        let ratio = dividend / divisor;

        Ok(ratio)
    }

    fn get_amount_out(
        &self,
        amount_in: BigUint,
        token_in: &Token,
        token_out: &Token,
    ) -> Result<GetAmountOutResult, SimulationError> {
        let amount_in = biguint_to_u256(&amount_in);
        if amount_in == U256::from(0u64) {
            return Err(SimulationError::InvalidInput("Amount in cannot be zero".to_string(), None));
        }
        let token_in_state =  self
            .state
            .get(&token_in.address)
            .ok_or(CowAMMError::TokenInDoesNotExist)
            .map_err(|err| SimulationError::FatalError(format!("token not found: {err:?}")))?;

        let token_out_state = self
            .state
            .get(&token_out.address)
            .ok_or(CowAMMError::TokenOutDoesNotExist)
            .map_err(|err| SimulationError::FatalError(format!("token not found: {err:?}")))?;

  
        let amount_out = bmath::calculate_out_given_in(
            token_in_state.liquidity,
            token_in_state.weight,
            token_out_state.liquidity,
            token_out_state.weight,
            amount_in,
            U256::from(self.fee),
        ).map_err(|err| SimulationError::RecoverableError(format!("amount out calculation error: {err:?}")))?;

        let bal1 = token_in_state.liquidity;
        let bal2 = token_out_state.liquidity;
        
        let gas_used = U256::from(120000); //how can we determine the actual gas used? ans - (probably have to check calcInGivenOut() method when i run those unit test with -vvvvv in foundry)
        let mut new_state = self.clone();

        let mut liq1_mut = new_state
            .state
            .get_mut(&token_out.address)
            .ok_or(CowAMMError::TokenOutDoesNotExist)
            .map_err(|err| SimulationError::FatalError(format!("token not found: {err:?}")))?
            .liquidity;

        let mut liq2_mut = new_state
            .state
            .get_mut(&token_out.address)
            .ok_or(CowAMMError::TokenOutDoesNotExist)
            .map_err(|err| SimulationError::FatalError(format!("token not found: {err:?}")))?
            .liquidity;
        // let  = new_state.get_state_mut();

        liq1_mut = safe_add_u256(bal1, amount_in)?;
        liq2_mut = safe_sub_u256(bal2, amount_out)?;

        let res = GetAmountOutResult {
            amount: u256_to_biguint(amount_out),
            gas: u256_to_biguint(gas_used),
            new_state: Box::new(new_state),
        };

        Ok(res)
    }

    fn get_limits(
        &self,
        sell_token: Address,
        buy_token: Address,
    ) -> Result<(BigUint, BigUint), SimulationError> {
        let sell_token = self
            .state
            .get(&Bytes::from(sell_token.as_slice()))
            .ok_or(CowAMMError::TokenInDoesNotExist) //sell token does not exist
            .map_err(|err| SimulationError::FatalError(format!("token not found: {err:?}")))?; 
        let buy_token = self
            .state
            .get(&Bytes::from(buy_token.as_slice()))
            .ok_or(CowAMMError::TokenInDoesNotExist) //buy token does not exist 
            .map_err(|err| SimulationError::FatalError(format!("token not found: {err:?}")))?;

        if sell_token.liquidity.is_zero() || buy_token.liquidity.is_zero() {
            return Ok((BigUint::ZERO, BigUint::ZERO));
        }

        let max_in = safe_div_u256(
            safe_mul_u256(sell_token.liquidity, U256::from(MAX_IN_FACTOR))?,
            U256::from(100),
        )?;

        let max_out = safe_div_u256(
            safe_mul_u256(buy_token.liquidity, U256::from(MAX_OUT_FACTOR))?,
            U256::from(100),
        )?;

        Ok((u256_to_biguint(max_in), u256_to_biguint(max_out)))
    }
 
    fn delta_transition(
        &mut self,
        delta: ProtocolStateDelta,
        tokens: &HashMap<Bytes, Token>,
        balances: &Balances,
    ) -> Result<(), TransitionError<String>> {
        unimplemented!()
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
            .downcast_ref::<CowAMMPoolState>()
            .is_some_and(|other_state| self == other_state)
    }
}


#[cfg(test)]
mod tests {
    use std::{collections::{HashMap, HashSet}};
    use std::str::FromStr;

    use alloy_primitives::{Address, U256};
    use approx::assert_ulps_eq;
    use num_bigint::{BigUint, ToBigUint};
    use num_traits::One;
    use rstest::rstest;
    use tycho_common::{dto::ProtocolStateDelta, hex_bytes::Bytes};

    use super::*;
    use crate::{
        evm::protocol::cowamm::CowAMMPoolState,
        evm::protocol::u256_num::{biguint_to_u256, u256_to_biguint},
        models::Token,
        protocol::{errors::{SimulationError, TransitionError}, Balances, ProtocolSim, state::ProtocolSim as _}
    };

    #[rstest]
    #[case::same_dec(
        U256::from_str("6770398782322527849696614").unwrap(),
        U256::from_str("5124813135806900540214").unwrap(),
        18, 18,
        BigUint::from_str("10000000000000000000000").unwrap(),
        BigUint::from_str("7535635391574243447").unwrap()
    )]
    #[case::diff_dec(
        U256::from_str("33372357002392258830279").unwrap(),
        U256::from_str("43356945776493").unwrap(),
        18, 6,
        BigUint::from_str("10000000000000000000").unwrap(),
        BigUint::from_str("12949029867").unwrap()
    )]
    fn test_get_amount_out(
        #[case] r0: U256,
        #[case] r1: U256,
        #[case] dec0: usize,
        #[case] dec1: usize,
        #[case] amount_in: BigUint,
        #[case] expected_out: BigUint,
    ) {
        let t0 = Token::new("0x0000000000000000000000000000000000000000", dec0, "T0", BigUint::from(10_000u32));
        let t1 = Token::new("0x0000000000000000000000000000000000000001", dec1, "T1", BigUint::from(10_000u32));

        let mut state = CowAMMPoolState {
            address: Address::ZERO,
            state: {
                let mut m = HashMap::new();
                m.insert(Bytes::from(t0.address.as_slice()), TokenState { liquidity: r0, weight: U256::from(1u8), token: t0.clone() });
                m.insert(Bytes::from(t1.address.as_slice()), TokenState { liquidity: r1, weight: U256::from(1u8), token: t1.clone() });
                m
            },
            fee: 0,
        };

        let res = state.get_amount_out(amount_in.clone(), &t0, &t1).unwrap();
        assert_eq!(res.amount, expected_out);

        let new_state = res.new_state.as_any().downcast_ref::<CowAMMPoolState>().unwrap();
        assert_eq!(new_state.state[&Bytes::from(t0.address.as_slice())].liquidity, r0 + biguint_to_u256(&amount_in));
        assert_eq!(new_state.state[&Bytes::from(t1.address.as_slice())].liquidity, r1 - biguint_to_u256(&expected_out));
        // Original state unchanged
        assert_eq!(state.state[&Bytes::from(t0.address.as_slice())].liquidity, r0);
        assert_eq!(state.state[&Bytes::from(t1.address.as_slice())].liquidity, r1);
    }

    #[test]
    fn test_get_amount_out_overflow() {
        let r0 = U256::from_str("33372357002392258830279").unwrap();
        let r1 = U256::from_str("43356945776493").unwrap();
        let max = (BigUint::one() << 256) - BigUint::one();

        let t0 = Token::new("0x0000000000000000000000000000000000000000", 18, "T0", BigUint::one());
        let t1 = Token::new("0x0000000000000000000000000000000000000001", 16, "T1", BigUint::one());

        let mut state = CowAMMPoolState {
            address: Address::ZERO,
            state: {
                let mut m = HashMap::new();
                m.insert(Bytes::from(t0.address.as_slice()), TokenState { liquidity: r0, weight: U256::from(1u8), token: t0.clone() });
                m.insert(Bytes::from(t1.address.as_slice()), TokenState { liquidity: r1, weight: U256::from(1u8), token: t1.clone() });
                m
            },
            fee: 0,
        };

        let res = state.get_amount_out(max, &t0, &t1);
        assert!(matches!(res, Err(SimulationError::FatalError(_))));
    }

    #[rstest]
    #[case(true, 0.0)]
    #[case(false, 1.0)]
    fn test_spot_price(#[case] zero_to_one: bool, #[case] expected: f64) {
        let r0 = U256::from_str("1000").unwrap();
        let r1 = U256::from_str("100000").unwrap();

        let t0 = Token::new("0x0", 18, "T0", BigUint::one());
        let t1 = Token::new("0x1", 18, "T1", BigUint::one());

        let state = CowAMMPoolState {
            address: Address::ZERO,
            state: {
                let mut m = HashMap::new();
                m.insert(Bytes::from(t0.address.as_slice()), TokenState { liquidity: r0, weight: U256::from(1u8), token: t0.clone() });
                m.insert(Bytes::from(t1.address.as_slice()), TokenState { liquidity: r1, weight: U256::from(1u8), token: t1.clone() });
                m
            },
            fee: 0,
        };

        let price = if zero_to_one { state.spot_price(&t0, &t1).unwrap() } else { state.spot_price(&t1, &t0).unwrap() };
        let expected = expected;
        assert_ulps_eq!(price, expected);
    }

    #[test]
    fn test_fee() {
        let state = CowwV2State::new(
            U256::from_str("36925554990922").unwrap(),
            U256::from_str("30314846538607556521556").unwrap(),
        );

        let res = state.fee();

        assert_ulps_eq!(res, 0.0);
    }
      #[test]
    fn test_delta_transition() { // chane the internal logic here lol
        let mut state = CowAMMPoolState {
            address: Address::ZERO,
            state: HashMap::new(),
            fee: 0,
        };

        let mut attrs = HashMap::new();
        attrs.insert("some".to_string(), Bytes::from(vec![0u8]));

        let delta = ProtocolStateDelta {
            component_id: "foo".to_string(),
            updated_attributes: attrs,
            deleted_attributes: HashSet::new(),
        };

        let err = state.delta_transition(delta, &HashMap::new(), &Balances::default());
        assert!(matches!(err, Err(TransitionError::MissingAttribute(_))));
    }

    #[test]
    fn test_delta_transition_missing() {
        let mut state = CowAMMPoolState {
            address: Address::ZERO,
            state: HashMap::new(),
            fee: 0,
        };

        let mut attrs = HashMap::new();
        attrs.insert("some".to_string(), Bytes::from(vec![0u8]));

        let delta = ProtocolStateDelta {
            component_id: "foo".to_string(),
            updated_attributes: attrs,
            deleted_attributes: HashSet::new(),
        };

        let err = state.delta_transition(delta, &HashMap::new(), &Balances::default());
        assert!(matches!(err, Err(TransitionError::MissingAttribute(_))));
    }
        #[test]
    fn test_get_limits_price_impact() {
        let state = CowAMMState::new(U256::from_str("1000").unwrap(), U256::from_str("100000").unwrap());

        let (amount_in, _) = state
            .get_limits(
                Address::from_str("0x0000000000000000000000000000000000000000").unwrap(),
                Address::from_str("0x0000000000000000000000000000000000000001").unwrap(),
            )
            .unwrap();

        let token_0 = Token::new(
            "0x0000000000000000000000000000000000000000",
            18,
            "T0",
            10_000.to_biguint().unwrap(),
        );
        let token_1 = Token::new(
            "0x0000000000000000000000000000000000000001",
            18,
            "T1",
            10_000.to_biguint().unwrap(),
        );

        let result = state
            .get_amount_out(amount_in.clone(), &token_0, &token_1)
            .unwrap();
        let new_state = result
            .new_state
            .as_any()
            .downcast_ref::<CowAMMState>()
            .unwrap();

        let initial_price = state
            .spot_price(&token_0, &token_1)
            .unwrap();
        let new_price = new_state
            .spot_price(&token_0, &token_1)
            .unwrap()
            .floor();

        let expected_price = initial_price / 10.0;
        assert!(expected_price == new_price, "Price impact not 90%.");
    }
}

      
