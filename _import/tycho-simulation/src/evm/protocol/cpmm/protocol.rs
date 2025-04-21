use std::{any::Any, collections::HashMap};

use alloy_primitives::{Address, U256};
use num_bigint::{BigUint, ToBigUint};
use num_traits::Zero;
use tycho_client::feed::{synchronizer::ComponentWithState, Header};
use tycho_common::{dto::ProtocolStateDelta, Bytes};

use super::reserve_price::spot_price_from_reserves;
use crate::{
    evm::protocol::{
        safe_math::{safe_add_u256, safe_div_u256, safe_mul_u256, safe_sub_u256},
        u256_num::{biguint_to_u256, u256_to_biguint},
    },
    models::{Balances, Token},
    protocol::{
        errors::{InvalidSnapshotError, SimulationError, TransitionError},
        models::{GetAmountOutResult, TryFromWithBlock},
        state::ProtocolSim,
    },
};

/// Trait for Constant Product Market Maker (CPMM) protocols
pub trait CPMMProtocol {
    /// Get the fee in basis points (e.g. 30 for 0.3%)
    fn get_fee_bps(&self) -> u32;

    /// Get the reserve of token 0
    fn get_reserve0(&self) -> U256;

    /// Get the reserve of token 1
    fn get_reserve1(&self) -> U256;

    /// Get mutable reference to reserve of token 0
    fn get_reserve0_mut(&mut self) -> &mut U256;

    /// Get mutable reference to reserve of token 1
    fn get_reserve1_mut(&mut self) -> &mut U256;

    /// Create a new instance with the given reserves
    fn new(reserve0: U256, reserve1: U256) -> Self;
}

impl<T: CPMMProtocol + Clone + 'static + std::fmt::Debug + Sync + Send>
    TryFromWithBlock<ComponentWithState> for T
{
    type Error = InvalidSnapshotError;

    /// Decodes a `ComponentWithState` into a CPMM protocol state. Errors with a
    /// `InvalidSnapshotError` if either reserve0 or reserve1 attributes are missing.
    async fn try_from_with_block(
        snapshot: ComponentWithState,
        _block: Header,
        _account_balances: &HashMap<Bytes, HashMap<Bytes, Bytes>>,
        _all_tokens: &HashMap<Bytes, Token>,
    ) -> Result<Self, Self::Error> {
        let reserve0 = U256::from_be_slice(
            snapshot
                .state
                .attributes
                .get("reserve0")
                .ok_or(InvalidSnapshotError::MissingAttribute("reserve0".to_string()))?,
        );

        let reserve1 = U256::from_be_slice(
            snapshot
                .state
                .attributes
                .get("reserve1")
                .ok_or(InvalidSnapshotError::MissingAttribute("reserve1".to_string()))?,
        );

        Ok(Self::new(reserve0, reserve1))
    }
}

impl<T: CPMMProtocol + Clone + 'static + std::fmt::Debug + Sync + Send> ProtocolSim for T {
    fn fee(&self) -> f64 {
        self.get_fee_bps() as f64 / 10000.0
    }

    fn spot_price(&self, base: &Token, quote: &Token) -> Result<f64, SimulationError> {
        if base < quote {
            Ok(spot_price_from_reserves(
                self.get_reserve0(),
                self.get_reserve1(),
                base.decimals as u32,
                quote.decimals as u32,
            ))
        } else {
            Ok(spot_price_from_reserves(
                self.get_reserve1(),
                self.get_reserve0(),
                base.decimals as u32,
                quote.decimals as u32,
            ))
        }
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
        let zero2one = token_in.address < token_out.address;
        let reserve_sell = if zero2one { self.get_reserve0() } else { self.get_reserve1() };
        let reserve_buy = if zero2one { self.get_reserve1() } else { self.get_reserve0() };

        if reserve_sell == U256::from(0u64) || reserve_buy == U256::from(0u64) {
            return Err(SimulationError::RecoverableError("No liquidity".to_string()));
        }

        let fee_multiplier = U256::from(10000 - self.get_fee_bps());
        let amount_in_with_fee = safe_mul_u256(amount_in, fee_multiplier)?;
        let numerator = safe_mul_u256(amount_in_with_fee, reserve_buy)?;
        let denominator =
            safe_add_u256(safe_mul_u256(reserve_sell, U256::from(10000))?, amount_in_with_fee)?;

        let amount_out = safe_div_u256(numerator, denominator)?;
        let mut new_state = self.clone();
        if zero2one {
            *new_state.get_reserve0_mut() = safe_add_u256(self.get_reserve0(), amount_in)?;
            *new_state.get_reserve1_mut() = safe_sub_u256(self.get_reserve1(), amount_out)?;
        } else {
            *new_state.get_reserve0_mut() = safe_sub_u256(self.get_reserve0(), amount_out)?;
            *new_state.get_reserve1_mut() = safe_add_u256(self.get_reserve1(), amount_in)?;
        };
        Ok(GetAmountOutResult::new(
            u256_to_biguint(amount_out),
            120_000
                .to_biguint()
                .expect("Expected an unsigned integer as gas value"),
            Box::new(new_state),
        ))
    }

    fn get_limits(
        &self,
        token_in: Address,
        token_out: Address,
    ) -> Result<(BigUint, BigUint), SimulationError> {
        if self.get_reserve0() == U256::from(0u64) || self.get_reserve1() == U256::from(0u64) {
            return Ok((BigUint::zero(), BigUint::zero()));
        }

        let zero_for_one = token_in < token_out;
        let (reserve_in, reserve_out) = if zero_for_one {
            (self.get_reserve0(), self.get_reserve1())
        } else {
            (self.get_reserve1(), self.get_reserve0())
        };

        // Soft limit for amount in is the amount to get a 90% price impact
        let amount_in =
            safe_div_u256(safe_mul_u256(reserve_in, U256::from(216))?, U256::from(100))?;
        let amount_out = safe_div_u256(
            safe_mul_u256(reserve_out, amount_in)?,
            safe_add_u256(reserve_in, amount_in)?,
        )?;

        Ok((u256_to_biguint(amount_in), u256_to_biguint(amount_out)))
    }

    fn delta_transition(
        &mut self,
        delta: ProtocolStateDelta,
        _tokens: &HashMap<Bytes, Token>,
        _balances: &Balances,
    ) -> Result<(), TransitionError<String>> {
        *self.get_reserve0_mut() = U256::from_be_slice(
            delta
                .updated_attributes
                .get("reserve0")
                .ok_or(TransitionError::MissingAttribute("reserve0".to_string()))?,
        );
        *self.get_reserve1_mut() = U256::from_be_slice(
            delta
                .updated_attributes
                .get("reserve1")
                .ok_or(TransitionError::MissingAttribute("reserve1".to_string()))?,
        );
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
        if let Some(other_state) = other.as_any().downcast_ref::<T>() {
            self.get_reserve0() == other_state.get_reserve0() &&
                self.get_reserve1() == other_state.get_reserve1() &&
                self.get_fee_bps() == other_state.get_fee_bps()
        } else {
            false
        }
    }
}
