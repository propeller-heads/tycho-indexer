use std::{any::Any, collections::HashMap};

use alloy::primitives::U256;
use num_bigint::BigUint;
use num_traits::Zero;
use serde::{Deserialize, Serialize};
use tycho_common::{
    dto::ProtocolStateDelta,
    models::token::Token,
    simulation::{
        errors::{SimulationError, TransitionError},
        protocol_sim::{
            Balances, GetAmountOutResult, PoolSwap, ProtocolSim, QueryPoolSwapParams,
            SwapConstraint,
        },
    },
    Bytes,
};

use crate::evm::protocol::{
    cpmm::protocol::{
        cpmm_fee, cpmm_get_amount_out, cpmm_get_limits, cpmm_spot_price, cpmm_swap_to_price,
        ProtocolFee,
    },
    safe_math::{safe_add_u256, safe_sub_u256},
    u256_num::{biguint_to_u256, u256_to_biguint},
    utils::add_fee_markup,
};

const FEE_PRECISION_BPS: u32 = 10_000;
const FEE_PRECISION: U256 = U256::from_limbs([10_000, 0, 0, 0]);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AerodromeV1State {
    pub reserve0: U256,
    pub reserve1: U256,
    pub fee_bps: u32,
}

impl AerodromeV1State {
    /// Creates a new instance of `AerodromeV1State` with the given reserves and fee.
    pub fn new(reserve0: U256, reserve1: U256, fee_bps: u32) -> Self {
        Self { reserve0, reserve1, fee_bps }
    }

    fn protocol_fee(&self) -> Result<ProtocolFee, SimulationError> {
        if self.fee_bps > FEE_PRECISION_BPS {
            return Err(SimulationError::FatalError(format!(
                "Invalid fee value {}, expected <= {} bps",
                self.fee_bps, FEE_PRECISION_BPS
            )));
        }

        Ok(ProtocolFee::new(U256::from(FEE_PRECISION_BPS - self.fee_bps), FEE_PRECISION))
    }
}

#[typetag::serde]
impl ProtocolSim for AerodromeV1State {
    fn fee(&self) -> f64 {
        cpmm_fee(self.fee_bps)
    }

    fn spot_price(&self, base: &Token, quote: &Token) -> Result<f64, SimulationError> {
        let price = cpmm_spot_price(base, quote, self.reserve0, self.reserve1)?;
        Ok(add_fee_markup(price, self.fee()))
    }

    fn get_amount_out(
        &self,
        amount_in: BigUint,
        token_in: &Token,
        token_out: &Token,
    ) -> Result<GetAmountOutResult, SimulationError> {
        let amount_in = biguint_to_u256(&amount_in);
        let zero2one = token_in.address < token_out.address;
        let (reserve_in, reserve_out) =
            if zero2one { (self.reserve0, self.reserve1) } else { (self.reserve1, self.reserve0) };
        let fee = self.protocol_fee()?;
        let amount_out = cpmm_get_amount_out(amount_in, reserve_in, reserve_out, fee)?;
        let mut new_state = self.clone();
        let (reserve0_mut, reserve1_mut) = (&mut new_state.reserve0, &mut new_state.reserve1);
        if zero2one {
            *reserve0_mut = safe_add_u256(self.reserve0, amount_in)?;
            *reserve1_mut = safe_sub_u256(self.reserve1, amount_out)?;
        } else {
            *reserve0_mut = safe_sub_u256(self.reserve0, amount_out)?;
            *reserve1_mut = safe_add_u256(self.reserve1, amount_in)?;
        };
        Ok(GetAmountOutResult::new(
            u256_to_biguint(amount_out),
            BigUint::from(120_000u32),
            Box::new(new_state),
        ))
    }

    fn get_limits(
        &self,
        sell_token: Bytes,
        buy_token: Bytes,
    ) -> Result<(BigUint, BigUint), SimulationError> {
        cpmm_get_limits(sell_token, buy_token, self.reserve0, self.reserve1, self.fee_bps)
    }

    fn delta_transition(
        &mut self,
        delta: ProtocolStateDelta,
        _tokens: &HashMap<Bytes, Token>,
        _balances: &Balances,
    ) -> Result<(), TransitionError> {
        if let Some(reserve0) = delta.updated_attributes.get("reserve0") {
            self.reserve0 = U256::from_be_slice(reserve0);
        }
        if let Some(reserve1) = delta.updated_attributes.get("reserve1") {
            self.reserve1 = U256::from_be_slice(reserve1);
        }
        if let Some(fee) = delta.updated_attributes.get("fee") {
            self.fee_bps = u32::from(fee.clone());
            if self.fee_bps > FEE_PRECISION_BPS {
                return Err(TransitionError::DecodeError(format!(
                    "Invalid fee value {}, expected <= {} bps",
                    self.fee_bps, FEE_PRECISION_BPS
                )));
            }
        }
        Ok(())
    }

    fn query_pool_swap(&self, params: &QueryPoolSwapParams) -> Result<PoolSwap, SimulationError> {
        match params.swap_constraint() {
            SwapConstraint::PoolTargetPrice {
                target: price,
                tolerance: _,
                min_amount_in: _,
                max_amount_in: _,
            } => {
                let zero2one = params.token_in().address < params.token_out().address;
                let (reserve_in, reserve_out) = if zero2one {
                    (self.reserve0, self.reserve1)
                } else {
                    (self.reserve1, self.reserve0)
                };

                let (amount_in, _) =
                    cpmm_swap_to_price(reserve_in, reserve_out, price, self.protocol_fee()?)?;
                if amount_in.is_zero() {
                    return Ok(PoolSwap::new(
                        BigUint::ZERO,
                        BigUint::ZERO,
                        Box::new(self.clone()),
                        None,
                    ));
                }

                let res =
                    self.get_amount_out(amount_in.clone(), params.token_in(), params.token_out())?;
                Ok(PoolSwap::new(amount_in, res.amount, res.new_state, None))
            }
            SwapConstraint::TradeLimitPrice { .. } => Err(SimulationError::InvalidInput(
                "AerodromeV1State does not support TradeLimitPrice constraint in query_pool_swap"
                    .to_string(),
                None,
            )),
        }
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
        if let Some(other_state) = other.as_any().downcast_ref::<Self>() {
            self.reserve0 == other_state.reserve0 &&
                self.reserve1 == other_state.reserve1 &&
                self.fee_bps == other_state.fee_bps
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};

    use alloy::primitives::U256;
    use num_bigint::BigUint;
    use num_traits::One;
    use tycho_common::{
        dto::ProtocolStateDelta,
        hex_bytes::Bytes,
        models::{token::Token, Chain},
        simulation::{
            errors::TransitionError,
            protocol_sim::{Balances, ProtocolSim},
        },
    };

    use super::AerodromeV1State;

    fn token_0() -> Token {
        Token::new(&Bytes::from([0_u8; 20]), "T0", 18, 0, &[Some(10_000)], Chain::Ethereum, 100)
    }

    fn token_1() -> Token {
        let mut addr = [0_u8; 20];
        addr[19] = 1;
        Token::new(&Bytes::from(addr), "T1", 18, 0, &[Some(10_000)], Chain::Ethereum, 100)
    }

    #[test]
    fn test_get_amount_out_works() {
        let state = AerodromeV1State::new(U256::from(2_000_000u32), U256::from(1_000_000u32), 30);
        let amount_in = BigUint::from(1_000u32);
        let result = state
            .get_amount_out(amount_in, &token_0(), &token_1())
            .expect("swap should succeed");
        assert!(result.amount > BigUint::from(0u32));
    }

    #[test]
    fn test_delta_transition_supports_fee_only_update() {
        let mut state =
            AerodromeV1State::new(U256::from(2_000_000u32), U256::from(1_000_000u32), 30);
        let delta = ProtocolStateDelta {
            component_id: "pool".to_string(),
            updated_attributes: HashMap::from([(
                "fee".to_string(),
                Bytes::from(5_u32.to_be_bytes().to_vec()),
            )]),
            deleted_attributes: HashSet::new(),
        };

        state
            .delta_transition(delta, &HashMap::new(), &Balances::default())
            .expect("fee-only update should succeed");
        assert_eq!(state.fee_bps, 5);
        assert_eq!(state.reserve0, U256::from(2_000_000u32));
        assert_eq!(state.reserve1, U256::from(1_000_000u32));
    }

    #[test]
    fn test_delta_transition_rejects_invalid_fee() {
        let mut state = AerodromeV1State::new(U256::ONE, U256::ONE, 30);
        let delta = ProtocolStateDelta {
            component_id: "pool".to_string(),
            updated_attributes: HashMap::from([(
                "fee".to_string(),
                Bytes::from(10_001_u32.to_be_bytes().to_vec()),
            )]),
            deleted_attributes: HashSet::new(),
        };

        let err = state
            .delta_transition(delta, &HashMap::new(), &Balances::default())
            .expect_err("invalid fee should fail");
        assert!(matches!(err, TransitionError::DecodeError(_)));
    }

    #[test]
    fn test_fee_fn_returns_fraction() {
        let state = AerodromeV1State::new(U256::ONE, U256::ONE, 30);
        assert_eq!(state.fee(), 0.003);
        let state = AerodromeV1State::new(U256::ONE, U256::ONE, 5);
        assert_eq!(state.fee(), 0.0005);
    }

    #[test]
    fn test_protocol_fee_accepts_zero() {
        let state = AerodromeV1State::new(U256::ONE, U256::ONE, 0);
        assert!(state.protocol_fee().is_ok());
    }

    #[test]
    fn test_protocol_fee_rejects_out_of_range() {
        let state = AerodromeV1State::new(U256::ONE, U256::ONE, 10_001);
        assert!(state.protocol_fee().is_err());
    }

    #[test]
    fn test_get_amount_out_no_fee() {
        let state = AerodromeV1State::new(U256::from(10_000u32), U256::from(10_000u32), 0);
        let out = state
            .get_amount_out(BigUint::one(), &token_0(), &token_1())
            .expect("swap should succeed");
        assert_eq!(
            out.amount,
            BigUint::one() * BigUint::from(10_000u32) / BigUint::from(10_001u32)
        );
    }
}
