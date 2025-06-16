use std::{any::Any, collections::HashMap, fmt::Debug};

use alloy_primitives::Address;
use num_bigint::BigUint;
use tycho_common::{dto::ProtocolStateDelta, Bytes};

use super::{
    pool::{base::BasePool, full_range::FullRangePool, oracle::OraclePool, EkuboPool},
    tick::ticks_from_attributes,
};
use crate::{
    evm::protocol::u256_num::u256_to_f64,
    models::{Balances, Token},
    protocol::{
        errors::{SimulationError, TransitionError},
        models::GetAmountOutResult,
        state::ProtocolSim,
    },
};


impl CowAMMState for ProtocolSim {
    fn fee(&self) -> f64 {
        0; 
    }
    fn spot_price(&self, base: &Token, quote: &Token) -> Result<f64, SimulationError> {

        let bone = u256_to_float(BONE)?;
        let norm_base = if base.decimals < 18 {
            Float::with_val(
                MPFR_T_PRECISION,
                10_u64.pow(18 - base.decimals as u32),
            )
        } else {
            Float::with_val(MPFR_T_PRECISION, 1)
        };
        let norm_quote = if quote.token.decimals < 18 {
            Float::with_val(
                MPFR_T_PRECISION,
                10_u64.pow(18 - quote.token.decimals as u32),
            )
        } else {
            Float::with_val(MPFR_T_PRECISION, 1)
        };

        let norm_weight_base = u256_to_float(bae.weight)? / norm_base;
        let norm_weight_quote = u256_to_float(quote.weight)? / norm_quote;
        let balance_base = u256_to_float(base.liquidity)?; // how to get liquidity ? 
        let balance_quote = u256_to_float(quote.liquidity)?;

        let dividend = (balance_quote / norm_weight_quote) * bone.clone();
        let divisor = (balance_base / norm_weight_base)
            * (bone - Float::with_val(MPFR_T_PRECISION, self.fee));
        let ratio = dividend / divisor;
        Ok(ratio.to_f64_round(Round::Nearest))
    }

    fn get_amount_out(
        &self,
        amount_in: BigUint,
        token_in: &Token,
        token_out: &Token,
    ) -> Result<GetAmountOutResult, SimulationError> {
        //how to get weight and liquidity?
         let token_in = self
            .state
            .get(&base_token)
            .ok_or(BalancerError::TokenInDoesNotExist)?;

        let token_out = self
            .state
            .get(&quote_token)
            .ok_or(BalancerError::TokenOutDoesNotExist)?;

        let out = bmath::calculate_out_given_in(
            token_in.liquidity,
            token_in.weight,
            token_out.liquidity,
            token_out.weight,
            amount_in,
            U256::from(self.fee),
        )?;

        self.state.get_mut(&base_token).unwrap().liquidity += amount_in;
        self.state.get_mut(&quote_token).unwrap().liquidity -= out;

        Ok(out)
    }

    fn get_limits(
        &self,
        sell_token: Address,
        buy_token: Address,
    ) -> Result<(BigUint, BigUint), SimulationError> {
        
    }

    fn delta_transition(
        &mut self,
        delta: ProtocolStateDelta,
        tokens: &HashMap<Bytes, Token>,
        balances: &Balances,
    ) -> Result<(), TransitionError<String>> {
        self.delta_transition(delta, tokens, balances)
    }
}