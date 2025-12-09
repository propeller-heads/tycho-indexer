use alloy::primitives::{U256, U512};
use num_bigint::BigUint;
use num_traits::Zero;
use tycho_client::feed::synchronizer::ComponentWithState;
use tycho_common::{
    dto::ProtocolStateDelta,
    models::token::Token,
    simulation::{
        errors::{SimulationError, TransitionError},
        protocol_sim::{Price, Trade},
    },
    Bytes,
};

use super::reserve_price::spot_price_from_reserves;
use crate::{
    evm::protocol::{
        safe_math::{safe_add_u256, safe_div_u256, safe_mul_u256, safe_sub_u256, sqrt_u512},
        u256_num::{biguint_to_u256, u256_to_biguint},
    },
    protocol::errors::InvalidSnapshotError,
};

pub fn cpmm_try_from_with_header(
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
        spot_price_from_reserves(reserve0, reserve1, base.decimals, quote.decimals)
    } else {
        spot_price_from_reserves(reserve1, reserve0, base.decimals, quote.decimals)
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

/// Represents a protocol fee as a numerator and precision.
pub struct ProtocolFee {
    pub numerator: U256,
    pub precision: U256,
}

impl ProtocolFee {
    pub fn new(numerator: U256, precision: U256) -> Self {
        ProtocolFee { numerator, precision }
    }
}

/// Calculates the exact amount of token_in required to move the pool's marginal price down to
/// a target price.
///
/// See [`ProtocolSim::swap_to_price`] for the trait documentation.
///
/// # Algorithm
///
/// Derives how much to swap to reach a target price using the constant product formula.
/// **Note**: This method assumes k remains constant, but in reality fees accrue to the pool,
/// causing k to increase slightly. This simplification leads to a conservative
/// underestimation of the pool's supply capacity.
///
/// ## Base equations
/// 1. Constant product: `x * y = k` where x = reserve_in, y = reserve_out
/// 2. Swap with 0.3% fee: Only 99.7% of input affects price
/// 3. Marginal price after swap: `price = (x' * 1000) / (y' * 997)`
///
/// ## Derivation
/// We want the pool to reach target price: `price = sell_price / buy_price`
///
/// From marginal price formula:
/// ```text,no_run
/// x' / y' = (sell_price * 997) / (buy_price * 1000)  [call this target_price_w_fee]
/// ```
///
/// From constant product:
/// ```text,no_run
/// x' * y' = k
/// ```
///
///
/// Substituting the first into the second:
/// ```text,no_run
/// x' = target_price_w_fee * y'
/// (target_price_w_fee * y') * y' = k
/// y'^2 = k / target_price_w_fee
/// y' = sqrt(k / target_price_w_fee)
/// ```
///
/// Therefore:
/// ```text,no_run
/// x' = target_price_w_fee * y'
///    = target_price_w_fee * sqrt(k / target_price_w_fee)
///    = sqrt(k * target_price_w_fee)
/// ```
///
/// Amount to swap in:
/// ```text,no_run
/// amount_in = x' - x = sqrt(k * target_price_w_fee) - reserve_in
/// ```
///
/// where `target_price_w_fee = (sell_price * 997) / (buy_price * 1000)`
/// Then swap to get amount_out.
pub fn cpmm_swap_to_price(
    reserve_in: U256,
    reserve_out: U256,
    target_price: Price,
    fee: ProtocolFee,
) -> Result<Trade, SimulationError> {
    // Flip target pool price to swap price
    let swap_price_num = biguint_to_u256(&target_price.denominator);
    let swap_price_den = biguint_to_u256(&target_price.numerator);

    // Check reachability: target price must be above the spot price (with fees)
    // swap_price_num/swap_price_den >= (reserve_in * FEE_PRECISION) / (reserve_out *
    // FEE_NUMERATOR)
    // Cross-multiply to avoid division: swap_price_num * reserve_out * FEE_NUMERATOR >=
    // swap_price_den * reserve_in * FEE_PRECISION
    let target_price_cross_mult = swap_price_num
        .checked_mul(reserve_out)
        .and_then(|x| x.checked_mul(fee.numerator))
        .ok_or_else(|| SimulationError::FatalError("Overflow in price check".to_string()))?;
    let current_price_cross_mult = swap_price_den
        .checked_mul(reserve_in)
        .and_then(|x| x.checked_mul(fee.precision))
        .ok_or_else(|| SimulationError::FatalError("Overflow in price check".to_string()))?;

    if target_price_cross_mult < current_price_cross_mult {
        return Ok(Trade::new(BigUint::ZERO, BigUint::ZERO));
    }

    // Calculate new reserve_in: x' = sqrt(k * price_num * FEE_NUMERATOR / (price_den *
    // FEE_PRECISION))
    let k = U512::from(reserve_in) * U512::from(reserve_out);
    let k_times_price = k * U512::from(swap_price_num) * U512::from(fee.numerator) /
        (U512::from(swap_price_den) * U512::from(fee.precision));
    let x_prime_u512 = sqrt_u512(k_times_price);

    // Convert back to U256 and calculate amount_in
    let limbs = x_prime_u512.as_limbs();
    let x_prime = U256::from_limbs([limbs[0], limbs[1], limbs[2], limbs[3]]);

    if x_prime <= reserve_in {
        return Ok(Trade::new(BigUint::ZERO, BigUint::ZERO));
    }
    let amount_in = safe_sub_u256(x_prime, reserve_in)?;

    if amount_in == U256::ZERO {
        return Ok(Trade::new(BigUint::ZERO, BigUint::ZERO));
    }

    let implied_amount_out = (amount_in * swap_price_den)
        .checked_div(swap_price_num)
        .ok_or_else(|| {
            SimulationError::FatalError("Division by zero in implied_amount_out".to_string())
        })?;

    if implied_amount_out == U256::ZERO {
        return Ok(Trade::new(BigUint::ZERO, BigUint::ZERO));
    }
    Ok(Trade::new(u256_to_biguint(amount_in), u256_to_biguint(implied_amount_out)))
}
