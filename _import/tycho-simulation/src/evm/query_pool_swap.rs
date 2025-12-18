//! Generic query_pool_swap implementation using Brent's method.
//!
//! Provides a default `query_pool_swap` for protocols without analytical solutions.
//! Uses history-based Brent's method adapted for AMM price curves.

use num_bigint::BigUint;
use num_traits::{FromPrimitive, One, ToPrimitive, Zero};
use tycho_common::{
    models::token::Token,
    simulation::{
        errors::SimulationError,
        protocol_sim::{PoolSwap, ProtocolSim, QueryPoolSwapParams, SwapConstraint},
    },
};

/// A point in the search history: (amount_in, amount_out, price).
pub type PricePoint = (BigUint, BigUint, f64);

const MAX_ITERATIONS: u32 = 30;
const IQI_THRESHOLD: f64 = 0.01;

fn trade_price(amount_in: f64, amount_out: f64, decimals_in: u32, decimals_out: u32) -> f64 {
    if amount_in <= 0.0 {
        return f64::MAX;
    }
    (amount_out / amount_in) * 10_f64.powi(decimals_in as i32 - decimals_out as i32)
}

fn within_tolerance(actual: f64, target: f64, tolerance: f64) -> bool {
    actual >= target && actual <= target * (1.0 + tolerance)
}

fn geometric_mean(a: &BigUint, b: &BigUint) -> BigUint {
    let a_f64 = a.to_f64().unwrap_or(0.0);
    let b_f64 = b.to_f64().unwrap_or(f64::MAX);
    if a_f64 <= 0.0 || b_f64 <= 0.0 {
        return (a + b) / 2u32;
    }
    BigUint::from_f64((a_f64 * b_f64).sqrt()).unwrap_or_else(|| (a + b) / 2u32)
}

fn iqi(p: &[PricePoint], target: f64) -> Option<f64> {
    if p.len() != 3 {
        return None;
    }
    let (a0, a1, a2) = (
        p[0].0.to_f64().unwrap_or(0.0),
        p[1].0.to_f64().unwrap_or(0.0),
        p[2].0.to_f64().unwrap_or(0.0),
    );
    let (pr0, pr1, pr2) = (p[0].2, p[1].2, p[2].2);

    let d1 = (pr0 - pr1) * (pr0 - pr2);
    let d2 = (pr1 - pr0) * (pr1 - pr2);
    let d3 = (pr2 - pr0) * (pr2 - pr1);

    let result = a0 * (target - pr1) * (target - pr2) / d1
        + a1 * (target - pr0) * (target - pr2) / d2
        + a2 * (target - pr0) * (target - pr1) / d3;

    (result.is_finite() && result > 0.0).then_some(result)
}

fn secant(p: &[PricePoint], target: f64) -> Option<f64> {
    if p.len() != 2 {
        return None;
    }
    let (a0, a1) = (
        p[0].0.to_f64().unwrap_or(0.0),
        p[1].0.to_f64().unwrap_or(0.0),
    );
    let (pr0, pr1) = (p[0].2, p[1].2);
    let dp = pr1 - pr0;
    let result = a1 - (pr1 - target) * (a1 - a0) / dp;
    (result.is_finite() && result > 0.0).then_some(result)
}

fn next_amount(history: &[PricePoint], low: &BigUint, high: &BigUint, target: f64) -> BigUint {
    let low_f64 = low.to_f64().unwrap_or(0.0);
    let high_f64 = high.to_f64().unwrap_or(f64::MAX);
    let bracket = high_f64 - low_f64;
    let len = history.len();

    if len >= 3 {
        if let Some(est) = iqi(&history[len - 3..], target) {
            if est > low_f64 && est < high_f64 {
                let improvement = (est - low_f64).min(high_f64 - est);
                if improvement > bracket * IQI_THRESHOLD {
                    if let Some(amt) = BigUint::from_f64(est) {
                        if &amt > low && &amt < high {
                            return amt;
                        }
                    }
                }
            }
        }
    }

    if len >= 2 {
        if let Some(est) = secant(&history[len - 2..], target) {
            if est > low_f64 && est < high_f64 {
                if let Some(amt) = BigUint::from_f64(est) {
                    if &amt > low && &amt < high {
                        return amt;
                    }
                }
            }
        }
    }

    geometric_mean(low, high)
}

fn search(
    state: &dyn ProtocolSim,
    target_price: f64,
    tolerance: f64,
    token_in: &Token,
    token_out: &Token,
    use_trade_price: bool,
) -> Result<PoolSwap, SimulationError> {
    let spot = state.spot_price(token_in, token_out)?;

    if target_price > spot {
        return Err(SimulationError::InvalidInput(
            format!("Target {} > spot {}", target_price, spot),
            None,
        ));
    }

    let (max_in, _) = state.get_limits(token_in.address.clone(), token_out.address.clone())?;
    let limit_result = state.get_amount_out(max_in.clone(), token_in, token_out)?;

    let limit_price = if use_trade_price {
        trade_price(
            max_in.to_f64().unwrap_or(f64::MAX),
            limit_result.amount.to_f64().unwrap_or(0.0),
            token_in.decimals,
            token_out.decimals,
        )
    } else {
        limit_result.new_state.spot_price(token_in, token_out)?
    };

    if target_price < limit_price {
        return Err(SimulationError::InvalidInput(
            format!("Target {} < limit {}", target_price, limit_price),
            None,
        ));
    }

    let mut low = BigUint::zero();
    let mut high = max_in.clone();
    let mut price_points: Vec<PricePoint> = vec![
        (BigUint::zero(), BigUint::zero(), spot),
        (max_in, limit_result.amount.clone(), limit_price),
    ];

    let mut best: Option<PoolSwap> = Some(PoolSwap::new(
        BigUint::zero(),
        BigUint::zero(),
        state.clone_box(),
        Some(price_points.clone()),
    ));
    let mut best_error = (spot - target_price) / target_price;

    for _ in 0..MAX_ITERATIONS {
        let amount = next_amount(&price_points, &low, &high, target_price);
        let result = state.get_amount_out(amount.clone(), token_in, token_out)?;

        let price = if use_trade_price {
            trade_price(
                amount.to_f64().unwrap_or(0.0),
                result.amount.to_f64().unwrap_or(0.0),
                token_in.decimals,
                token_out.decimals,
            )
        } else {
            result.new_state.spot_price(token_in, token_out)?
        };

        price_points.push((amount.clone(), result.amount.clone(), price));

        if price >= target_price {
            let error = (price - target_price) / target_price;
            if error < best_error {
                best_error = error;
                best = Some(PoolSwap::new(
                    amount.clone(),
                    result.amount.clone(),
                    result.new_state.clone(),
                    Some(price_points.clone()),
                ));
            }
        }

        if within_tolerance(price, target_price, tolerance) {
            return Ok(PoolSwap::new(amount, result.amount, result.new_state, Some(price_points)));
        }

        if price > target_price {
            low = amount;
        } else {
            high = amount;
        }

        if &high - &low <= BigUint::one() {
            break;
        }
    }

    Ok(best.unwrap_or_else(|| PoolSwap::new(BigUint::zero(), BigUint::zero(), state.clone_box(), Some(price_points))))
}

/// Generic query_pool_swap using Brent's method.
///
/// Handles both `TradeLimitPrice` and `PoolTargetPrice` constraints.
pub fn query_pool_swap(
    state: &dyn ProtocolSim,
    params: &QueryPoolSwapParams,
) -> Result<PoolSwap, SimulationError> {
    let token_in = params.token_in();
    let token_out = params.token_out();

    match params.swap_constraint() {
        SwapConstraint::TradeLimitPrice { limit, tolerance, .. } => {
            let num = limit.numerator.to_f64().ok_or_else(|| {
                SimulationError::InvalidInput("Invalid limit numerator".into(), None)
            })?;
            let den = limit.denominator.to_f64().ok_or_else(|| {
                SimulationError::InvalidInput("Invalid limit denominator".into(), None)
            })?;
            let decimal_adj = 10_f64.powi(token_in.decimals as i32 - token_out.decimals as i32);
            let target = (num / den) * decimal_adj;

            search(state, target, *tolerance, token_in, token_out, true)
        }

        SwapConstraint::PoolTargetPrice { target, tolerance, .. } => {
            let num = target.numerator.to_f64().ok_or_else(|| {
                SimulationError::InvalidInput("Invalid target numerator".into(), None)
            })?;
            let den = target.denominator.to_f64().ok_or_else(|| {
                SimulationError::InvalidInput("Invalid target denominator".into(), None)
            })?;
            let decimal_adj = 10_f64.powi(token_in.decimals as i32 - token_out.decimals as i32);
            let target_price = (num / den) * decimal_adj;

            search(state, target_price, *tolerance, token_in, token_out, false)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_within_tolerance() {
        assert!(within_tolerance(1.0, 1.0, 0.001));
        assert!(within_tolerance(1.0005, 1.0, 0.001));
        assert!(!within_tolerance(0.999, 1.0, 0.001));
        assert!(!within_tolerance(1.002, 1.0, 0.001));
    }

    #[test]
    fn test_geometric_mean() {
        let a = BigUint::from(100u32);
        let b = BigUint::from(400u32);
        assert_eq!(geometric_mean(&a, &b), BigUint::from(200u32));
    }

    #[test]
    fn test_trade_price() {
        assert!((trade_price(50.0, 100.0, 18, 18) - 2.0).abs() < 0.001);
        assert_eq!(trade_price(0.0, 100.0, 18, 18), f64::MAX);
    }
}
