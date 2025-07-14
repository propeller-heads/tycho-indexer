use alloy::primitives::U256;
use num_bigint::BigUint;
use num_traits::Zero;
use tycho_client::feed::synchronizer::ComponentWithState;
use tycho_common::{
    dto::ProtocolStateDelta,
    models::token::Token,
    simulation::errors::{SimulationError, TransitionError},
    Bytes,
};

use super::reserve_price::spot_price_from_reserves;
use crate::{
    evm::protocol::{
        safe_math::{safe_add_u256, safe_div_u256, safe_mul_u256},
        u256_num::u256_to_biguint,
    },
    protocol::errors::InvalidSnapshotError,
};

pub fn cpmm_try_from_with_block(
    snapshot: ComponentWithState,
) -> Result<(U256, U256), InvalidSnapshotError> {
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
    Ok((reserve0, reserve1))
}

pub fn cpmm_fee(fee_bps: u32) -> f64 {
    fee_bps as f64 / 10000.0
}

pub fn cpmm_spot_price(
    base: &Token,
    quote: &Token,
    reserve0: U256,
    reserve1: U256,
) -> Result<f64, SimulationError> {
    if base < quote {
        Ok(spot_price_from_reserves(reserve0, reserve1, base.decimals, quote.decimals))
    } else {
        Ok(spot_price_from_reserves(reserve1, reserve0, base.decimals, quote.decimals))
    }
}

pub fn cpmm_get_amount_out(
    amount_in: U256,
    zero2one: bool,
    reserve0: U256,
    reserve1: U256,
    fee_bps: u32,
) -> Result<U256, SimulationError> {
    if amount_in == U256::from(0u64) {
        return Err(SimulationError::InvalidInput("Amount in cannot be zero".to_string(), None));
    }
    let reserve_sell = if zero2one { reserve0 } else { reserve1 };
    let reserve_buy = if zero2one { reserve1 } else { reserve0 };

    if reserve_sell == U256::from(0u64) || reserve_buy == U256::from(0u64) {
        return Err(SimulationError::RecoverableError("No liquidity".to_string()));
    }

    let fee_multiplier = U256::from(10000 - fee_bps);
    let amount_in_with_fee = safe_mul_u256(amount_in, fee_multiplier)?;
    let numerator = safe_mul_u256(amount_in_with_fee, reserve_buy)?;
    let denominator =
        safe_add_u256(safe_mul_u256(reserve_sell, U256::from(10000))?, amount_in_with_fee)?;

    safe_div_u256(numerator, denominator)
}

pub fn cpmm_get_limits(
    sell_token: Bytes,
    buy_token: Bytes,
    reserve0: U256,
    reserve1: U256,
) -> Result<(BigUint, BigUint), SimulationError> {
    if reserve0 == U256::from(0u64) || reserve1 == U256::from(0u64) {
        return Ok((BigUint::zero(), BigUint::zero()));
    }

    let zero_for_one = sell_token < buy_token;
    let (reserve_in, reserve_out) =
        if zero_for_one { (reserve0, reserve1) } else { (reserve1, reserve0) };

    // Soft limit for amount in is the amount to get a 90% price impact.
    // The two equations to resolve are:
    // - 90% price impact: (reserve1 - y)/(reserve0 + x) = 0.1 × (reserve1/reserve0)
    // - Maintain constant product: (reserve0 + x) × (reserve1 - y) = reserve0 * reserve1
    //
    // This resolves into x = (√10 - 1) × reserve0 = 2.16 × reserve0
    let amount_in = safe_div_u256(safe_mul_u256(reserve_in, U256::from(216))?, U256::from(100))?;

    // Calculate amount_out using the constant product formula
    // The constant product formula requires:
    // (reserve_in + amount_in) × (reserve_out - amount_out) = reserve_in * reserve_out
    // Solving for amount_out:
    // amount_out = reserve_out - (reserve_in * reserve_out) (reserve_in + amount_in)
    // which simplifies to:
    // amount_out = (reserve_out * amount_in) / (reserve_in + amount_in)
    let amount_out = safe_div_u256(
        safe_mul_u256(reserve_out, amount_in)?,
        safe_add_u256(reserve_in, amount_in)?,
    )?;

    Ok((u256_to_biguint(amount_in), u256_to_biguint(amount_out)))
}

pub fn cpmm_delta_transition(
    delta: ProtocolStateDelta,
    reserve0_mut: &mut U256,
    reserve1_mut: &mut U256,
) -> Result<(), TransitionError<String>> {
    // reserve0 and reserve1 are considered required attributes and are expected in every delta
    // we process
    let reserve0 = U256::from_be_slice(
        delta
            .updated_attributes
            .get("reserve0")
            .ok_or(TransitionError::MissingAttribute("reserve0".to_string()))?,
    );
    let reserve1 = U256::from_be_slice(
        delta
            .updated_attributes
            .get("reserve1")
            .ok_or(TransitionError::MissingAttribute("reserve1".to_string()))?,
    );
    *reserve0_mut = reserve0;
    *reserve1_mut = reserve1;
    Ok(())
}
