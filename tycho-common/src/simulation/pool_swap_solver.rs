//! Brent-style method for finding swap amounts to reach target prices.
//!
//! This module provides the default implementation for `query_pool_swap` in the `ProtocolSim` trait.
//!
//! # References
//!
//! - Brent, R.P. (1973). "Algorithms for Minimization without Derivatives", Chapter 4
//! - SciPy `brentq`: <https://docs.scipy.org/doc/scipy/reference/generated/scipy.optimize.brentq.html>
//! - Boost `brent_find_minima`: <https://www.boost.org/doc/libs/release/libs/math/doc/html/math_toolkit/roots_noderiv.html>
//!
//! # Algorithm
//!
//! At each iteration:
//! 1. Try Inverse Quadratic Interpolation (IQI) if a third point (x3, f3) exists
//! 2. Try secant method using the two bracket endpoints (x1, f1) and (x2, f2)
//! 3. Fall back to geometric mean bisection (log-space)
//! 4. Update bracket based on whether price is above/below target

use num_bigint::BigUint;
use num_traits::{FromPrimitive, One, ToPrimitive, Zero};

use crate::simulation::{
    errors::SimulationError,
    protocol_sim::{PoolSwap, Price, ProtocolSim, QueryPoolSwapParams, SwapConstraint},
};

// =============================================================================
// Constants
// =============================================================================

/// Maximum number of iterations before giving up.
const MAX_ITERATIONS: u32 = 30;

/// IQI acceptance threshold: fraction of bracket size.
/// IQI estimate is accepted if it improves the bracket by at least this fraction.
const IQI_THRESHOLD: f64 = 0.01;

// =============================================================================
// Helper Functions
// =============================================================================

/// Convert a Price struct to f64, adjusting for token decimals.
///
/// Price struct represents token_out/token_in in raw token units.
/// We normalize to account for decimal differences.
fn price_to_f64(price: &Price, decimals_in: u32, decimals_out: u32) -> f64 {
    let num = price.numerator.to_f64().unwrap_or(0.0);
    let den = price.denominator.to_f64().unwrap_or(1.0);
    if den == 0.0 {
        return f64::MAX;
    }
    let decimal_adjustment = 10_f64.powi(decimals_in as i32 - decimals_out as i32);
    (num / den) * decimal_adjustment
}

/// Calculate trade price normalized by token decimals.
///
/// Trade price = (amount_out / amount_in) * 10^(decimals_in - decimals_out)
fn calculate_trade_price(
    amount_in: f64,
    amount_out: f64,
    decimals_in: u32,
    decimals_out: u32,
) -> f64 {
    if amount_in <= 0.0 {
        return f64::MAX;
    }
    let decimal_adjustment = 10_f64.powi(decimals_in as i32 - decimals_out as i32);
    (amount_out / amount_in) * decimal_adjustment
}

/// Check if actual price is within tolerance of target price.
///
/// Target/limit is a hard floor (prices decrease, so actual >= target).
/// Tolerance allows early stopping: accept if actual is within tolerance above target.
fn within_tolerance(actual: f64, target: f64, tolerance: f64) -> bool {
    if actual < target {
        return false;
    }
    let upper_bound = target * (1.0 + tolerance);
    actual <= upper_bound
}

/// Geometric mean of two BigUint values (bisection in log space)
fn geometric_mean(a: &BigUint, b: &BigUint) -> BigUint {
    let a_f64 = a.to_f64().unwrap_or(0.0);
    let b_f64 = b.to_f64().unwrap_or(f64::MAX);

    if a_f64 <= 0.0 || b_f64 <= 0.0 {
        return (a + b) / 2u32;
    }

    let result = (a_f64 * b_f64).sqrt();
    BigUint::from_f64(result).unwrap_or_else(|| (a + b) / 2u32)
}

/// Inverse Quadratic Interpolation from 3 points
fn iqi(a1: f64, p1: f64, a2: f64, p2: f64, a3: f64, p3: f64, target: f64) -> Option<f64> {
    let denom1 = (p1 - p2) * (p1 - p3);
    let denom2 = (p2 - p1) * (p2 - p3);
    let denom3 = (p3 - p1) * (p3 - p2);

    let t1 = (target - p2) * (target - p3) / denom1;
    let t2 = (target - p1) * (target - p3) / denom2;
    let t3 = (target - p1) * (target - p2) / denom3;

    let result = a1 * t1 + a2 * t2 + a3 * t3;

    if result.is_finite() && result > 0.0 {
        Some(result)
    } else {
        None
    }
}

/// Secant method estimate
fn secant(a1: f64, p1: f64, a2: f64, p2: f64, target: f64) -> Option<f64> {
    let dp = p2 - p1;
    let result = a2 - (p2 - target) * (a2 - a1) / dp;
    if result.is_finite() && result > 0.0 {
        Some(result)
    } else {
        None
    }
}

/// Get price based on metric type (spot or trade price)
fn get_price(
    metric: PriceMetric,
    amount_in: &BigUint,
    amount_out: &BigUint,
    new_state: &dyn ProtocolSim,
    token_in: &crate::models::token::Token,
    token_out: &crate::models::token::Token,
) -> Result<f64, SimulationError> {
    match metric {
        PriceMetric::SpotPrice => new_state.spot_price(token_in, token_out),
        PriceMetric::TradePrice => {
            let in_f64 = amount_in.to_f64().unwrap_or(0.0);
            let out_f64 = amount_out.to_f64().unwrap_or(0.0);
            Ok(calculate_trade_price(in_f64, out_f64, token_in.decimals, token_out.decimals))
        }
    }
}

/// Compute the next amount using Brent-style method.
fn brent_next_amount(
    a: &BigUint,
    fa: f64,
    b: &BigUint,
    fb: f64,
    c: Option<&BigUint>,
    fc: Option<f64>,
    target: f64,
) -> BigUint {
    let fallback = geometric_mean(a, b);
    let a_f64 = a.to_f64().unwrap_or(0.0);
    let b_f64 = b.to_f64().unwrap_or(f64::MAX);

    // Try IQI (if we have a third point)
    if let (Some(c), Some(fc)) = (c, fc) {
        if let Some(estimate) = iqi(
            a_f64,
            fa,
            b_f64,
            fb,
            c.to_f64().unwrap_or(0.0),
            fc,
            target,
        ) {
            let bracket_size = b_f64 - a_f64;
            if estimate > a_f64 && estimate < b_f64 {
                let improvement = (estimate - a_f64).min(b_f64 - estimate);
                if improvement > bracket_size * IQI_THRESHOLD {
                    if let Some(amount) = BigUint::from_f64(estimate) {
                        if &amount > a && &amount < b {
                            return amount;
                        }
                    }
                }
            }
        }
    }

    // Try secant
    if let Some(estimate) = secant(a_f64, fa, b_f64, fb, target) {
        if estimate > a_f64 && estimate < b_f64 {
            if let Some(amount) = BigUint::from_f64(estimate) {
                if &amount > a && &amount < b {
                    return amount;
                }
            }
        }
    }

    fallback
}

// =============================================================================
// Main Search Algorithm
// =============================================================================

/// Which price metric to track during the search.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PriceMetric {
    SpotPrice,
    TradePrice,
}

/// Execute the Brent-style search algorithm for query_pool_swap.
pub fn query_pool_swap_brent(
    state: Box<dyn ProtocolSim>,
    params: &QueryPoolSwapParams,
) -> Result<PoolSwap, SimulationError> {
    let state = state.as_ref();
    let token_in = params.token_in();
    let token_out = params.token_out();

    // Determine metric and target from constraint
    let (metric, target_price, tolerance, min_bound, max_bound) = match params.swap_constraint() {
        SwapConstraint::TradeLimitPrice { limit, tolerance, min_amount_in, max_amount_in } => (
            PriceMetric::TradePrice,
            price_to_f64(limit, token_in.decimals, token_out.decimals),
            *tolerance,
            min_amount_in.clone(),
            max_amount_in.clone(),
        ),
        SwapConstraint::PoolTargetPrice { target, tolerance, min_amount_in, max_amount_in } => (
            PriceMetric::SpotPrice,
            price_to_f64(target, token_in.decimals, token_out.decimals),
            *tolerance,
            min_amount_in.clone(),
            max_amount_in.clone(),
        ),
    };

    // Get spot price (token_out per token_in)
    let spot_price = state.spot_price(token_in, token_out)?;

    // Get limits from pool
    let (pool_max_in, _) = state.get_limits(token_in.address.clone(), token_out.address.clone())?;

    // Apply bounds: default to 0/pool_max if not specified
    let min_amount = min_bound.unwrap_or_else(BigUint::zero);
    let max_amount = max_bound.unwrap_or(pool_max_in);

    // Validate bounds
    if min_amount > max_amount {
        return Err(SimulationError::InvalidInput(
            format!(
                "Invalid bounds: min_amount_in ({}) > max_amount_in ({})",
                min_amount, max_amount
            ),
            None,
        ));
    }

    // Check if we're already at target (for spot price metric with zero amount)
    if metric == PriceMetric::SpotPrice && within_tolerance(spot_price, target_price, tolerance)
    {
        return Ok(PoolSwap::new(
            BigUint::zero(),
            BigUint::zero(),
            state.clone_box(),
            Some(vec![(BigUint::zero(), BigUint::zero(), spot_price)]),
        ));
    }

    // Validate target price is below spot price (prices decrease with amount)
    if target_price > spot_price {
        return Err(SimulationError::InvalidInput(
            format!(
                "Target price {} is above spot price {}. Target must be below spot (prices decrease with amount).",
                target_price, spot_price
            ),
            None,
        ));
    }

    // Evaluate max_amount (b endpoint)
    let b_result = state.get_amount_out(max_amount.clone(), token_in, token_out)?;
    let fb = get_price(
        metric,
        &max_amount,
        &b_result.amount,
        b_result.new_state.as_ref(),
        token_in,
        token_out,
    )?;

    // Validate target is reachable (must be >= fb)
    if target_price < fb {
        return Err(SimulationError::InvalidInput(
            format!(
                "Target price {} is below limit price {} (spot: {}). Pool cannot reach such a low price.",
                target_price, fb, spot_price
            ),
            None,
        ));
    }

    // Evaluate min_amount (a endpoint) - use spot_price for zero, otherwise evaluate
    let (fa, a_result) = if min_amount.is_zero() {
        (spot_price, None)
    } else {
        let result = state.get_amount_out(min_amount.clone(), token_in, token_out)?;
        let price = get_price(
            metric,
            &min_amount,
            &result.amount,
            result.new_state.as_ref(),
            token_in,
            token_out,
        )?;
        (price, Some(result))
    };

    // Initialize bracket state (a = low price side, b = high price side)
    let mut a = min_amount.clone();
    let mut fa = fa;
    let mut b = max_amount.clone();
    let mut fb = fb;
    let mut c: Option<BigUint> = None;
    let mut fc: Option<f64> = None;

    // Price points output
    let mut price_points: Vec<(BigUint, BigUint, f64)> = vec![
        (
            min_amount.clone(),
            a_result.as_ref().map(|r| r.amount.clone()).unwrap_or_default(),
            fa,
        ),
        (max_amount.clone(), b_result.amount.clone(), fb),
    ];

    // Track best result (initialize with min_amount if valid)
    let mut best_result: Option<PoolSwap> = if fa >= target_price {
        if let Some(ref result) = a_result {
            Some(PoolSwap::new(
                a.clone(),
                result.amount.clone(),
                result.new_state.clone(),
                Some(price_points.clone()),
            ))
        } else if a.is_zero() {
            Some(PoolSwap::new(
                BigUint::zero(),
                BigUint::zero(),
                state.clone_box(),
                Some(price_points.clone()),
            ))
        } else {
            None
        }
    } else {
        None
    };
    let mut best_error = if fa >= target_price {
        (fa - target_price) / target_price
    } else {
        f64::MAX
    };

    // Main search loop
    for _iteration in 0..MAX_ITERATIONS {
        let next_amount = brent_next_amount(&a, fa, &b, fb, c.as_ref(), fc, target_price);

        let result = state.get_amount_out(next_amount.clone(), token_in, token_out)?;
        let price = get_price(
            metric,
            &next_amount,
            &result.amount,
            result.new_state.as_ref(),
            token_in,
            token_out,
        )?;

        price_points.push((next_amount.clone(), result.amount.clone(), price));

        // Check convergence
        if within_tolerance(price, target_price, tolerance) {
            return Ok(PoolSwap::new(
                next_amount,
                result.amount,
                result.new_state,
                Some(price_points),
            ));
        }

        // Track best result that satisfies the constraint (price >= target)
        if price >= target_price {
            let error = (price - target_price) / target_price;
            if error < best_error {
                best_error = error;
                best_result = Some(PoolSwap::new(
                    next_amount.clone(),
                    result.amount.clone(),
                    result.new_state.clone(),
                    Some(price_points.clone()),
                ));
            }
        }

        // Save old b as c (for IQI)
        c = Some(b.clone());
        fc = Some(fb);

        // Update bracket
        if price > target_price {
            a = next_amount;
            fa = price;
        } else {
            b = next_amount;
            fb = price;
        }

        // Precision limit reached
        if &b - &a <= BigUint::one() {
            break;
        }
    }

    // Return best result or error
    best_result.ok_or_else(|| {
        SimulationError::FatalError(format!(
            "Failed to converge within {} iterations. Target: {:.6e}, spot: {:.6e}",
            MAX_ITERATIONS, target_price, spot_price
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // Tests for within_tolerance
    // =========================================================================

    #[test]
    fn test_within_tolerance_exact() {
        assert!(within_tolerance(1.0, 1.0, 0.001));
        assert!(within_tolerance(1000.0, 1000.0, 0.001));
        assert!(within_tolerance(0.001, 0.001, 0.001));
    }

    #[test]
    fn test_within_tolerance_above_within_range() {
        let tolerance = 0.001; // 0.1%
        // Just above target (within tolerance) - should pass
        assert!(within_tolerance(1.0005, 1.0, tolerance)); // 0.05% above
        assert!(within_tolerance(1.001, 1.0, tolerance)); // 0.1% above (at boundary)
    }

    #[test]
    fn test_within_tolerance_above_out_of_range() {
        let tolerance = 0.001; // 0.1%
        // Above tolerance - should NOT pass
        assert!(!within_tolerance(1.002, 1.0, tolerance)); // 0.2% above
        assert!(!within_tolerance(1.01, 1.0, tolerance)); // 1% above
    }

    #[test]
    fn test_within_tolerance_below_target() {
        let tolerance = 0.001; // 0.1%
        // Below target - should NEVER pass (hard floor)
        assert!(!within_tolerance(0.999, 1.0, tolerance));
        assert!(!within_tolerance(0.9999, 1.0, tolerance));
        assert!(!within_tolerance(0.0, 1.0, tolerance));
    }

    #[test]
    fn test_within_tolerance_zero_tolerance() {
        // With zero tolerance, only exact match passes
        assert!(within_tolerance(1.0, 1.0, 0.0));
        assert!(!within_tolerance(1.0001, 1.0, 0.0));
    }

    // =========================================================================
    // Tests for geometric_mean
    // =========================================================================

    #[test]
    fn test_geometric_mean_basic() {
        let a = BigUint::from(100u32);
        let b = BigUint::from(400u32);
        let result = geometric_mean(&a, &b);
        // sqrt(100 * 400) = sqrt(40000) = 200
        assert_eq!(result, BigUint::from(200u32));
    }

    #[test]
    fn test_geometric_mean_same_values() {
        let a = BigUint::from(100u32);
        let result = geometric_mean(&a, &a);
        assert_eq!(result, BigUint::from(100u32));
    }

    #[test]
    fn test_geometric_mean_one_and_large() {
        let a = BigUint::one();
        let b = BigUint::from(1000000u32);
        let result = geometric_mean(&a, &b);
        // sqrt(1 * 1000000) = 1000
        assert_eq!(result, BigUint::from(1000u32));
    }

    #[test]
    fn test_geometric_mean_with_zero() {
        let a = BigUint::from(0u32);
        let b = BigUint::from(100u32);
        let result = geometric_mean(&a, &b);
        // Falls back to arithmetic mean: (0 + 100) / 2 = 50
        assert_eq!(result, BigUint::from(50u32));
    }

    #[test]
    fn test_geometric_mean_adjacent() {
        let a = BigUint::from(10u32);
        let b = BigUint::from(11u32);
        let result = geometric_mean(&a, &b);
        // sqrt(110) ≈ 10.49, truncates to 10
        assert!(result == BigUint::from(10u32) || result == BigUint::from(11u32));
    }

    // =========================================================================
    // Tests for price_to_f64
    // =========================================================================

    #[test]
    fn test_price_to_f64_same_decimals() {
        let price = Price::new(BigUint::from(1000u32), BigUint::one());
        let result = price_to_f64(&price, 18, 18);
        assert!((result - 1000.0).abs() < 0.001);
    }

    #[test]
    fn test_price_to_f64_more_decimals_out() {
        // token_in has 6 decimals, token_out has 18 decimals
        let price = Price::new(BigUint::from(1000u32), BigUint::one());
        let result = price_to_f64(&price, 6, 18);
        // 1000 * 10^(6-18) = 1000 * 10^-12 = 1e-9
        assert!((result - 1e-9).abs() < 1e-15);
    }

    #[test]
    fn test_price_to_f64_more_decimals_in() {
        // token_in has 18 decimals, token_out has 6 decimals
        let price = Price::new(BigUint::one(), BigUint::from(1000u32));
        let result = price_to_f64(&price, 18, 6);
        // (1/1000) * 10^(18-6) = 0.001 * 10^12 = 1e9
        assert!((result - 1e9).abs() < 1.0);
    }

    #[test]
    fn test_price_to_f64_fractional() {
        let price = Price::new(BigUint::from(3u32), BigUint::from(4u32));
        let result = price_to_f64(&price, 18, 18);
        assert!((result - 0.75).abs() < 0.001);
    }

    // =========================================================================
    // Tests for calculate_trade_price
    // =========================================================================

    #[test]
    fn test_calculate_trade_price_basic() {
        // 100 out for 50 in = 2.0 price
        let price = calculate_trade_price(50.0, 100.0, 18, 18);
        assert!((price - 2.0).abs() < 0.001);
    }

    #[test]
    fn test_calculate_trade_price_decimal_adjustment() {
        // Different decimals: 6 in, 18 out
        let price = calculate_trade_price(50.0, 100.0, 6, 18);
        // 2.0 * 10^(6-18) = 2e-12
        assert!((price - 2e-12).abs() < 1e-18);
    }

    #[test]
    fn test_calculate_trade_price_zero_input() {
        let price = calculate_trade_price(0.0, 100.0, 18, 18);
        assert_eq!(price, f64::MAX);
    }

    #[test]
    fn test_calculate_trade_price_negative_input() {
        let price = calculate_trade_price(-1.0, 100.0, 18, 18);
        assert_eq!(price, f64::MAX);
    }

    // =========================================================================
    // Tests for iqi (Inverse Quadratic Interpolation)
    // =========================================================================

    #[test]
    fn test_iqi_linear_function() {
        // For a linear function f(x) = 2x, IQI should find the root
        // Points: (1, 2), (2, 4), (3, 6)
        // Target: 3.5 (should give x ≈ 1.75)
        let result = iqi(1.0, 2.0, 2.0, 4.0, 3.0, 6.0, 3.5);
        assert!(result.is_some());
        let estimate = result.unwrap();
        assert!((estimate - 1.75).abs() < 0.1);
    }

    #[test]
    fn test_iqi_quadratic_function() {
        // Points on x^2: (1, 1), (2, 4), (3, 9)
        // Target: 2 (should give x ≈ 1.414)
        let result = iqi(1.0, 1.0, 2.0, 4.0, 3.0, 9.0, 2.0);
        assert!(result.is_some());
        let estimate = result.unwrap();
        assert!(estimate > 1.0 && estimate < 2.0);
    }

    #[test]
    fn test_iqi_identical_prices() {
        // When prices are identical, denominators become zero
        let result = iqi(1.0, 5.0, 2.0, 5.0, 3.0, 5.0, 5.0);
        // Should return None due to inf from division by zero, caught by is_finite
        assert!(result.is_none());
    }

    #[test]
    fn test_iqi_extrapolation() {
        // Points: (1, 10), (2, 5), (3, 2) - decreasing prices
        // Target 20 is way above all prices - IQI will extrapolate
        let result = iqi(1.0, 10.0, 2.0, 5.0, 3.0, 2.0, 20.0);
        // IQI extrapolates and may return a value, but it will be outside
        // typical bounds - the caller (brent_next_amount) handles bounds checking
        if let Some(estimate) = result {
            // The estimate exists but is likely negative or very small
            // This tests that IQI doesn't crash on extrapolation
            assert!(estimate.is_finite());
        }
    }

    #[test]
    fn test_iqi_returns_none_for_negative() {
        // Create points that definitely produce negative result
        // Points with positive slope that would need negative x for low target
        let result = iqi(10.0, 1.0, 20.0, 2.0, 30.0, 3.0, 0.0);
        // Target 0 with increasing prices would need negative x
        assert!(result.is_none());
    }

    // =========================================================================
    // Tests for secant
    // =========================================================================

    #[test]
    fn test_secant_basic() {
        // Linear function: points (1, 2), (3, 6), target 4 -> x = 2
        let result = secant(1.0, 2.0, 3.0, 6.0, 4.0);
        assert!(result.is_some());
        let estimate = result.unwrap();
        assert!((estimate - 2.0).abs() < 0.001);
    }

    #[test]
    fn test_secant_decreasing() {
        // Decreasing prices: (100, 2.0), (200, 1.5), target 1.75
        let result = secant(100.0, 2.0, 200.0, 1.5, 1.75);
        assert!(result.is_some());
        let estimate = result.unwrap();
        // Should interpolate to x = 150
        assert!((estimate - 150.0).abs() < 1.0);
    }

    #[test]
    fn test_secant_identical_prices() {
        // When prices are identical, dp = 0
        let result = secant(1.0, 5.0, 2.0, 5.0, 5.0);
        // Division by zero gives inf, caught by is_finite
        assert!(result.is_none());
    }

    #[test]
    fn test_secant_extrapolates_negative() {
        // Points that would extrapolate to negative
        let result = secant(1.0, 10.0, 2.0, 5.0, 20.0);
        // Target way above, would need negative x
        assert!(result.is_none());
    }

    // =========================================================================
    // Tests for brent_next_amount
    // =========================================================================

    #[test]
    fn test_brent_next_amount_no_third_point() {
        let a = BigUint::from(10u32);
        let fa = 10.0;
        let b = BigUint::from(1000u32);
        let fb = 1.0;

        let result = brent_next_amount(&a, fa, &b, fb, None, None, 5.0);
        // Should try secant or fall back to geometric mean
        assert!(result > a && result < b);
    }

    #[test]
    fn test_brent_next_amount_with_third_point() {
        let a = BigUint::from(100u32);
        let fa = 2.0;
        let b = BigUint::from(400u32);
        let fb = 1.0;
        let c = BigUint::from(250u32);
        let fc = 1.5;

        let result = brent_next_amount(&a, fa, &b, fb, Some(&c), Some(fc), 1.35);

        // Should try IQI or secant and get something in range
        assert!(result > a && result < b);
    }
}
