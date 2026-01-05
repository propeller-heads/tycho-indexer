//! Default `query_pool_swap` implementation for EVM protocols.
//!
//!
//! # Supported Constraints
//!
//! - [`SwapConstraint::PoolTargetPrice`]: Find amount to reach a target **spot price**
//! - [`SwapConstraint::TradeLimitPrice`]: Find max trade where **execution price** ≥ limit
//!
//! # Usage
//!
//! ```ignore
//! use tycho_simulation::evm::query_pool_swap::query_pool_swap;
//!
//! let result = query_pool_swap(&pool_state, &params)?;
//! let amount_in = result.amount_in();
//! let new_state = result.new_state();
//! ```

use num_bigint::BigUint;
use num_traits::{FromPrimitive, One, ToPrimitive, Zero};
use tycho_common::{
    models::token::Token,
    simulation::{
        errors::SimulationError,
        protocol_sim::{PoolSwap, Price, ProtocolSim, QueryPoolSwapParams, SwapConstraint},
    },
};

/// A point in the search history: (amount_in, amount_out, price).
pub type PricePoint = (BigUint, BigUint, f64);

const MAX_ITERATIONS: u32 = 30;
const IQI_THRESHOLD: f64 = 0.01;

/// Calculates the trade price as `amount_out / amount_in`, adjusted for decimal differences.
#[inline]
fn calculate_trade_price(amount_in: f64, amount_out: f64, decimals_in: u32, decimals_out: u32) -> f64 {
    if amount_in <= 0.0 {
        return f64::MAX;
    }
    (amount_out / amount_in) * 10_f64.powi(decimals_in as i32 - decimals_out as i32)
}

/// Returns true if `actual` is within `[target, target * (1 + tolerance)]`.
#[inline]
fn is_within_tolerance(actual: f64, target: f64, tolerance: f64) -> bool {
    actual >= target && actual <= target * (1.0 + tolerance)
}

/// Converts a Price to f64 with decimal adjustment for token pairs.
///
/// Applies decimal scaling in integer arithmetic before converting to f64 to preserve
/// precision for large numerator/denominator values.
///
/// # Arguments
/// * `price` - The price as a fraction (numerator/denominator)
/// * `decimals_in` - Decimals of the input token
/// * `decimals_out` - Decimals of the output token
///
/// # Returns
/// The price as f64, adjusted for decimal differences: `(num/den) * 10^(decimals_in - decimals_out)`
fn price_to_f64_with_decimals(
    price: &Price,
    decimals_in: u32,
    decimals_out: u32,
) -> Result<f64, SimulationError> {
    let (scaled_num, scaled_den) = if decimals_in >= decimals_out {
        let scale = BigUint::from(10u64).pow(decimals_in - decimals_out);
        (&price.numerator * scale, price.denominator.clone())
    } else {
        let scale = BigUint::from(10u64).pow(decimals_out - decimals_in);
        (price.numerator.clone(), &price.denominator * scale)
    };

    let num_f64 = scaled_num.to_f64().ok_or_else(|| {
        SimulationError::InvalidInput("Price numerator too large for f64".into(), None)
    })?;
    let den_f64 = scaled_den.to_f64().ok_or_else(|| {
        SimulationError::InvalidInput("Price denominator too large for f64".into(), None)
    })?;

    if den_f64 == 0.0 {
        return Err(SimulationError::InvalidInput(
            "Price denominator is zero".into(),
            None,
        ));
    }

    Ok(num_f64 / den_f64)
}

fn geometric_mean(a: &BigUint, b: &BigUint) -> BigUint {
    let a_f64 = a.to_f64().unwrap_or(0.0);
    let b_f64 = b.to_f64().unwrap_or(f64::MAX);
    if a_f64 <= 0.0 || b_f64 <= 0.0 {
        return (a + b) / 2u32;
    }
    BigUint::from_f64((a_f64 * b_f64).sqrt()).unwrap_or_else(|| (a + b) / 2u32)
}

/// Inverse Quadratic Interpolation (IQI) - estimates amount for target price.
///
/// Fits a quadratic through 3 points in (price, amount) space and solves for
/// the amount where price equals target. This is the "inverse" of standard
/// quadratic interpolation which would estimate price from amount.
///
/// Part of Brent's method. See: <https://en.wikipedia.org/wiki/Brent%27s_method>
fn iqi(p: &[PricePoint], target_price: f64) -> Option<f64> {
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

    let result = a0 * (target_price - pr1) * (target_price - pr2) / d1 +
        a1 * (target_price - pr0) * (target_price - pr2) / d2 +
        a2 * (target_price - pr0) * (target_price - pr1) / d3;

    (result.is_finite() && result > 0.0).then_some(result)
}

/// Secant method - linear interpolation to estimate amount for target price.
///
/// Uses 2 points to draw a line and find where it crosses the target price.
fn secant(p: &[PricePoint], target_price: f64) -> Option<f64> {
    if p.len() != 2 {
        return None;
    }
    let (a0, a1) = (p[0].0.to_f64().unwrap_or(0.0), p[1].0.to_f64().unwrap_or(0.0));
    let (pr0, pr1) = (p[0].2, p[1].2);
    let dp = pr1 - pr0;
    let result = a1 - (pr1 - target_price) * (a1 - a0) / dp;
    (result.is_finite() && result > 0.0).then_some(result)
}

/// Select next amount to evaluate using heuristics.
///
/// Tries methods in order of convergence speed:
/// 1. IQI (if 3+ points and estimate improves bracket by >1%)
/// 2. Secant (if 2+ points and estimate is within bracket)
/// 3. Geometric mean bisection (fallback)
fn next_amount(history: &[PricePoint], low: &BigUint, high: &BigUint, target_price: f64) -> BigUint {
    let low_f64 = low.to_f64().unwrap_or(0.0);
    let high_f64 = high.to_f64().unwrap_or(f64::MAX);
    let bracket = high_f64 - low_f64;
    let len = history.len();

    if len >= 3 {
        if let Some(est) = iqi(&history[len - 3..], target_price) {
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
        if let Some(est) = secant(&history[len - 2..], target_price) {
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

/// Core search using Brent's method adapted for AMM price curves.
///
/// Maintains a bracket [low, high] where price(low) > target > price(high).
/// Each iteration narrows the bracket using [`next_amount`] until convergence
/// or the bracket width reaches 1 (integer precision limit).
///
/// Based on the van Wijngaarden-Dekker-Brent method for root finding.
/// See: Brent, R.P. (1973). "Algorithms for Minimization without Derivatives"
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
        calculate_trade_price(
            max_in.to_f64().unwrap_or(f64::MAX),
            limit_result
                .amount
                .to_f64()
                .unwrap_or(0.0),
            token_in.decimals,
            token_out.decimals,
        )
    } else {
        limit_result
            .new_state
            .spot_price(token_in, token_out)?
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
            calculate_trade_price(
                amount.to_f64().unwrap_or(0.0),
                result.amount.to_f64().unwrap_or(0.0),
                token_in.decimals,
                token_out.decimals,
            )
        } else {
            result
                .new_state
                .spot_price(token_in, token_out)?
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

        if is_within_tolerance(price, target_price, tolerance) {
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

    Ok(best.unwrap_or_else(|| {
        PoolSwap::new(BigUint::zero(), BigUint::zero(), state.clone_box(), Some(price_points))
    }))
}

/// Find the swap amount to reach a target price.
/// 
/// Uses a history-based Brent's method adapted for AMM price curves.
/// Combines inverse quadratic interpolation (IQI) and secant methods
/// with bisection fallback for robust convergence. The criteria for 
/// choosing IQI over secant has been changed to a heuristic that performs 
/// best for the VM protocols based on internal benchmark testing.
///
/// See [`ProtocolSim::query_pool_swap`] for the trait method this implements.
///
/// # Constraints
///
/// - `PoolTargetPrice`: Returns amount needed to move **spot price** to target. The resulting spot
///   price will be within `tolerance` of target.
///
/// - `TradeLimitPrice`: Returns max amount where **execution price** ≥ limit. Execution price =
///   amount_out / amount_in (decimal-adjusted).
///
/// # Returns
///
/// A [`PoolSwap`] containing:
/// - `amount_in`: Input token amount
/// - `amount_out`: Output token amount
/// - `new_state`: Pool state after the swap
/// - `price_points`: Search history for debugging (includes 2 initial boundary points)
///
/// # Errors
///
/// Returns `SimulationError::InvalidInput` if target is unreachable (above spot or below limit).
pub fn query_pool_swap(
    state: &dyn ProtocolSim,
    params: &QueryPoolSwapParams,
) -> Result<PoolSwap, SimulationError> {
    let token_in = params.token_in();
    let token_out = params.token_out();

    match params.swap_constraint() {
        SwapConstraint::TradeLimitPrice { limit, tolerance, .. } => {
            let scaled_trade_limit_price =
                price_to_f64_with_decimals(limit, token_in.decimals, token_out.decimals)?;
            search(state, scaled_trade_limit_price, *tolerance, token_in, token_out, true)
        }

        SwapConstraint::PoolTargetPrice { target, tolerance, .. } => {
            let scaled_pool_target_price =
                price_to_f64_with_decimals(target, token_in.decimals, token_out.decimals)?;
            search(state, scaled_pool_target_price, *tolerance, token_in, token_out, false)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use alloy::primitives::U256;
    use tycho_common::{hex_bytes::Bytes, models::Chain, simulation::protocol_sim::Price};

    use super::*;
    use crate::evm::protocol::uniswap_v2::state::UniswapV2State;

    fn create_token(address: &str, symbol: &str, decimals: u32) -> Token {
        Token::new(
            &Bytes::from_str(address).unwrap(),
            symbol,
            decimals,
            0,
            &[Some(10_000)],
            Chain::Ethereum,
            100,
        )
    }

    fn token_0() -> Token {
        create_token("0x0000000000000000000000000000000000000000", "T0", 18)
    }

    fn token_1() -> Token {
        create_token("0x0000000000000000000000000000000000000001", "T1", 18)
    }

    // =========================================================================
    // Tests for within_tolerance
    // =========================================================================

    #[test]
    fn test_within_tolerance_exact() {
        assert!(is_within_tolerance(1.0, 1.0, 0.001));
        assert!(is_within_tolerance(1000.0, 1000.0, 0.001));
        assert!(is_within_tolerance(0.001, 0.001, 0.001));
    }

    #[test]
    fn test_within_tolerance_above_within_range() {
        let tolerance = 0.001;
        assert!(is_within_tolerance(1.0005, 1.0, tolerance));
        assert!(is_within_tolerance(1.001, 1.0, tolerance));
    }

    #[test]
    fn test_within_tolerance_above_out_of_range() {
        let tolerance = 0.001;
        assert!(!is_within_tolerance(1.002, 1.0, tolerance));
        assert!(!is_within_tolerance(1.01, 1.0, tolerance));
    }

    #[test]
    fn test_within_tolerance_below_target() {
        let tolerance = 0.001;
        assert!(!is_within_tolerance(0.999, 1.0, tolerance));
        assert!(!is_within_tolerance(0.9999, 1.0, tolerance));
        assert!(!is_within_tolerance(0.0, 1.0, tolerance));
    }

    #[test]
    fn test_within_tolerance_zero_tolerance() {
        assert!(is_within_tolerance(1.0, 1.0, 0.0));
        assert!(!is_within_tolerance(1.0001, 1.0, 0.0));
    }

    // =========================================================================
    // Tests for geometric_mean
    // =========================================================================

    #[test]
    fn test_geometric_mean_basic() {
        let a = BigUint::from(100u32);
        let b = BigUint::from(400u32);
        assert_eq!(geometric_mean(&a, &b), BigUint::from(200u32));
    }

    #[test]
    fn test_geometric_mean_same_values() {
        let a = BigUint::from(100u32);
        assert_eq!(geometric_mean(&a, &a), BigUint::from(100u32));
    }

    #[test]
    fn test_geometric_mean_one_and_large() {
        let a = BigUint::one();
        let b = BigUint::from(1000000u32);
        assert_eq!(geometric_mean(&a, &b), BigUint::from(1000u32));
    }

    #[test]
    fn test_geometric_mean_with_zero() {
        let a = BigUint::from(0u32);
        let b = BigUint::from(100u32);
        assert_eq!(geometric_mean(&a, &b), BigUint::from(50u32));
    }

    #[test]
    fn test_geometric_mean_adjacent() {
        let a = BigUint::from(10u32);
        let b = BigUint::from(11u32);
        let result = geometric_mean(&a, &b);
        assert!(result == BigUint::from(10u32) || result == BigUint::from(11u32));
    }

    // =========================================================================
    // Tests for trade_price
    // =========================================================================

    #[test]
    fn test_trade_price_basic() {
        let price = calculate_trade_price(50.0, 100.0, 18, 18);
        assert!((price - 2.0).abs() < 0.001);
    }

    #[test]
    fn test_trade_price_decimal_adjustment() {
        let price = calculate_trade_price(50.0, 100.0, 6, 18);
        assert!((price - 2e-12).abs() < 1e-18);
    }

    #[test]
    fn test_trade_price_reverse_decimal_adjustment() {
        let price = calculate_trade_price(50.0, 100.0, 18, 6);
        assert!((price - 2e12).abs() < 1.0);
    }

    #[test]
    fn test_trade_price_zero_input() {
        assert_eq!(calculate_trade_price(0.0, 100.0, 18, 18), f64::MAX);
    }

    #[test]
    fn test_trade_price_negative_input() {
        assert_eq!(calculate_trade_price(-1.0, 100.0, 18, 18), f64::MAX);
    }

    // =========================================================================
    // Tests for iqi (Inverse Quadratic Interpolation)
    // =========================================================================

    #[test]
    fn test_iqi_linear_data() {
        let points = vec![
            (BigUint::from(1u32), BigUint::zero(), 2.0),
            (BigUint::from(2u32), BigUint::zero(), 4.0),
            (BigUint::from(3u32), BigUint::zero(), 6.0),
        ];
        let result = iqi(&points, 3.5);
        assert!(result.is_some());
        assert!((result.unwrap() - 1.75).abs() < 0.1);
    }

    #[test]
    fn test_iqi_same_prices() {
        let points = vec![
            (BigUint::from(1u32), BigUint::zero(), 5.0),
            (BigUint::from(2u32), BigUint::zero(), 5.0),
            (BigUint::from(3u32), BigUint::zero(), 5.0),
        ];
        assert!(iqi(&points, 5.0).is_none());
    }

    #[test]
    fn test_iqi_two_points() {
        let points = vec![
            (BigUint::from(1u32), BigUint::zero(), 2.0),
            (BigUint::from(2u32), BigUint::zero(), 4.0),
        ];
        assert!(iqi(&points, 3.0).is_none());
    }

    #[test]
    fn test_iqi_quadratic_data() {
        let points = vec![
            (BigUint::from(100u32), BigUint::zero(), 1.0),
            (BigUint::from(200u32), BigUint::zero(), 0.5),
            (BigUint::from(400u32), BigUint::zero(), 0.25),
        ];
        let result = iqi(&points, 0.4);
        assert!(result.is_some());
        let est = result.unwrap();
        assert!(est > 200.0 && est < 400.0);
    }

    // =========================================================================
    // Tests for secant
    // =========================================================================

    #[test]
    fn test_secant_basic() {
        let points = vec![
            (BigUint::from(1u32), BigUint::zero(), 2.0),
            (BigUint::from(3u32), BigUint::zero(), 6.0),
        ];
        let result = secant(&points, 4.0);
        assert!(result.is_some());
        assert!((result.unwrap() - 2.0).abs() < 0.001);
    }

    #[test]
    fn test_secant_same_prices() {
        let points = vec![
            (BigUint::from(1u32), BigUint::zero(), 5.0),
            (BigUint::from(2u32), BigUint::zero(), 5.0),
        ];
        let result = secant(&points, 5.0);
        assert!(result.is_none());
    }

    #[test]
    fn test_secant_one_point() {
        let points = vec![(BigUint::from(1u32), BigUint::zero(), 2.0)];
        assert!(secant(&points, 3.0).is_none());
    }

    #[test]
    fn test_secant_negative_result() {
        let points = vec![
            (BigUint::from(1u32), BigUint::zero(), 2.0),
            (BigUint::from(2u32), BigUint::zero(), 1.0),
        ];
        let result = secant(&points, 5.0);
        assert!(result.is_none());
    }

    // =========================================================================
    // Tests for next_amount
    // =========================================================================

    #[test]
    fn test_next_amount_fallback_to_geometric_mean() {
        let history = vec![(BigUint::from(100u32), BigUint::zero(), 1.0)];
        let low = BigUint::from(100u32);
        let high = BigUint::from(400u32);
        let result = next_amount(&history, &low, &high, 0.5);
        assert_eq!(result, BigUint::from(200u32));
    }

    #[test]
    fn test_next_amount_uses_secant() {
        let history = vec![
            (BigUint::from(100u32), BigUint::zero(), 1.0),
            (BigUint::from(400u32), BigUint::zero(), 0.25),
        ];
        let low = BigUint::from(100u32);
        let high = BigUint::from(400u32);
        let result = next_amount(&history, &low, &high, 0.5);
        assert!(result > low && result < high);
    }

    // =========================================================================
    // Integration tests with UniswapV2State - PoolTargetPrice
    // =========================================================================

    #[test]
    fn test_query_pool_swap_pool_target_price_same_decimals() {
        let state = UniswapV2State::new(
            U256::from(1000u64) * U256::from(10u64).pow(U256::from(18u64)),
            U256::from(2_000_000u64) * U256::from(10u64).pow(U256::from(18u64)),
        );

        let weth = create_token("0x0000000000000000000000000000000000000000", "WETH", 18);
        let dai = create_token("0x0000000000000000000000000000000000000001", "DAI", 18);

        let spot_price = state.spot_price(&dai, &weth).unwrap();
        let target_price_f64 = spot_price * 0.99;
        let target_price = Price::new(
            BigUint::from((target_price_f64 * 1e18) as u128),
            BigUint::from(10u128.pow(18)),
        );

        let tolerance_bps = 10f64;
        let params = QueryPoolSwapParams::new(
            dai.clone(),
            weth.clone(),
            SwapConstraint::PoolTargetPrice {
                target: target_price,
                tolerance: tolerance_bps / 10000.0,
                min_amount_in: None,
                max_amount_in: None,
            },
        );

        let result = query_pool_swap(&state, &params);
        assert!(result.is_ok(), "query_pool_swap failed: {:?}", result.err());

        let pool_swap = result.unwrap();
        assert!(pool_swap.amount_in() > &BigUint::zero());

        let new_spot = pool_swap
            .new_state()
            .spot_price(&dai, &weth)
            .unwrap();
        let error_bps = ((new_spot - target_price_f64) / target_price_f64).abs() * 10000.0;
        assert!(
            error_bps < tolerance_bps,
            "New spot {} should be within {}bps of target {}, got {}bps",
            new_spot,
            tolerance_bps,
            target_price_f64,
            error_bps
        );
    }

    #[test]
    fn test_query_pool_swap_pool_target_price_different_decimals() {
        let state = UniswapV2State::new(
            U256::from(1000u64) * U256::from(10u64).pow(U256::from(18u64)),
            U256::from(2_000_000u64) * U256::from(10u64).pow(U256::from(6u64)),
        );

        let weth = create_token("0x0000000000000000000000000000000000000000", "WETH", 18);
        let usdc = create_token("0x0000000000000000000000000000000000000001", "USDC", 6);

        let spot_price = state.spot_price(&usdc, &weth).unwrap();
        let target_price_f64 = spot_price * 0.95;

        let decimal_adj = 10_f64.powi(usdc.decimals as i32 - weth.decimals as i32);
        let price_no_decimals = target_price_f64 / decimal_adj;
        let target_price = Price::new(
            BigUint::from((price_no_decimals * 1e12) as u128),
            BigUint::from(10u128.pow(12)),
        );

        let tolerance_bps = 10f64;
        let params = QueryPoolSwapParams::new(
            usdc.clone(),
            weth.clone(),
            SwapConstraint::PoolTargetPrice {
                target: target_price,
                tolerance: tolerance_bps / 10000.0,
                min_amount_in: None,
                max_amount_in: None,
            },
        );

        let result = query_pool_swap(&state, &params);
        assert!(result.is_ok(), "query_pool_swap failed: {:?}", result.err());

        let pool_swap = result.unwrap();
        let new_spot = pool_swap
            .new_state()
            .spot_price(&usdc, &weth)
            .unwrap();
        let error_bps = ((new_spot - target_price_f64) / target_price_f64).abs() * 10000.0;
        assert!(
            error_bps < tolerance_bps,
            "Error should be <{}bps, got {}bps",
            tolerance_bps,
            error_bps
        );
    }

    #[test]
    fn test_query_pool_swap_pool_target_price_unreachable() {
        let state = UniswapV2State::new(U256::from(2_000_000u32), U256::from(1_000_000u32));

        let token_in = token_0();
        let token_out = token_1();

        let target_price = Price::new(BigUint::from(1u32), BigUint::from(1u32));

        let params = QueryPoolSwapParams::new(
            token_in,
            token_out,
            SwapConstraint::PoolTargetPrice {
                target: target_price,
                tolerance: 0.0,
                min_amount_in: None,
                max_amount_in: None,
            },
        );

        let result = query_pool_swap(&state, &params);
        assert!(result.is_err(), "Should return error for unreachable price");
    }

    // =========================================================================
    // Integration tests with UniswapV2State - TradeLimitPrice
    // =========================================================================

    #[test]
    fn test_query_pool_swap_trade_limit_price_same_decimals() {
        let state = UniswapV2State::new(
            U256::from(1000u64) * U256::from(10u64).pow(U256::from(18u64)),
            U256::from(2_000_000u64) * U256::from(10u64).pow(U256::from(18u64)),
        );

        let weth = create_token("0x0000000000000000000000000000000000000000", "WETH", 18);
        let dai = create_token("0x0000000000000000000000000000000000000001", "DAI", 18);

        let spot_price = state.spot_price(&dai, &weth).unwrap();
        let limit_price_f64 = spot_price * 0.99;
        let limit_price = Price::new(
            BigUint::from((limit_price_f64 * 1e18) as u128),
            BigUint::from(10u128.pow(18)),
        );

        let params = QueryPoolSwapParams::new(
            dai.clone(),
            weth.clone(),
            SwapConstraint::TradeLimitPrice {
                limit: limit_price,
                tolerance: 0.001,
                min_amount_in: None,
                max_amount_in: None,
            },
        );

        let result = query_pool_swap(&state, &params);
        assert!(result.is_ok(), "query_pool_swap failed: {:?}", result.err());

        let pool_swap = result.unwrap();
        assert!(pool_swap.amount_in() > &BigUint::zero());
        assert!(pool_swap.amount_out() > &BigUint::zero());

        let actual_trade_price = calculate_trade_price(
            pool_swap.amount_in().to_f64().unwrap(),
            pool_swap.amount_out().to_f64().unwrap(),
            dai.decimals,
            weth.decimals,
        );
        assert!(
            actual_trade_price >= limit_price_f64,
            "Trade price {} should be >= limit {}",
            actual_trade_price,
            limit_price_f64
        );
    }

    #[test]
    fn test_query_pool_swap_trade_limit_price_different_decimals() {
        let state = UniswapV2State::new(
            U256::from(1000u64) * U256::from(10u64).pow(U256::from(18u64)),
            U256::from(2_000_000u64) * U256::from(10u64).pow(U256::from(6u64)),
        );

        let weth = create_token("0x0000000000000000000000000000000000000000", "WETH", 18);
        let usdc = create_token("0x0000000000000000000000000000000000000001", "USDC", 6);

        let spot_price = state.spot_price(&usdc, &weth).unwrap();
        let limit_price_f64 = spot_price * 0.95;

        let decimal_adj = 10_f64.powi(usdc.decimals as i32 - weth.decimals as i32);
        let price_no_decimals = limit_price_f64 / decimal_adj;
        let limit_price = Price::new(
            BigUint::from((price_no_decimals * 1e12) as u128),
            BigUint::from(10u128.pow(12)),
        );

        let params = QueryPoolSwapParams::new(
            usdc.clone(),
            weth.clone(),
            SwapConstraint::TradeLimitPrice {
                limit: limit_price,
                tolerance: 0.001,
                min_amount_in: None,
                max_amount_in: None,
            },
        );

        let result = query_pool_swap(&state, &params);
        assert!(result.is_ok(), "query_pool_swap failed: {:?}", result.err());

        let pool_swap = result.unwrap();

        let actual_trade_price = calculate_trade_price(
            pool_swap.amount_in().to_f64().unwrap(),
            pool_swap.amount_out().to_f64().unwrap(),
            usdc.decimals,
            weth.decimals,
        );
        assert!(
            actual_trade_price >= limit_price_f64,
            "Trade price {} should be >= limit {}",
            actual_trade_price,
            limit_price_f64
        );
    }

    #[test]
    fn test_query_pool_swap_trade_limit_price_maximizes_trade() {
        let state = UniswapV2State::new(
            U256::from(1000u64) * U256::from(10u64).pow(U256::from(18u64)),
            U256::from(2_000_000u64) * U256::from(10u64).pow(U256::from(18u64)),
        );

        let weth = create_token("0x0000000000000000000000000000000000000000", "WETH", 18);
        let dai = create_token("0x0000000000000000000000000000000000000001", "DAI", 18);

        let spot_price = state.spot_price(&dai, &weth).unwrap();

        let mut prev_amount = BigUint::zero();
        for multiplier in [0.99, 0.95, 0.90, 0.80] {
            let limit_price_f64 = spot_price * multiplier;
            let limit_price = Price::new(
                BigUint::from((limit_price_f64 * 1e18) as u128),
                BigUint::from(10u128.pow(18)),
            );

            let params = QueryPoolSwapParams::new(
                dai.clone(),
                weth.clone(),
                SwapConstraint::TradeLimitPrice {
                    limit: limit_price,
                    tolerance: 0.001,
                    min_amount_in: None,
                    max_amount_in: None,
                },
            );

            let result = query_pool_swap(&state, &params);
            assert!(result.is_ok(), "query_pool_swap failed at multiplier {}", multiplier);

            let amount = result.unwrap().amount_in().clone();
            assert!(
                amount >= prev_amount,
                "Lower price limit should allow larger trade: {} vs {}",
                amount,
                prev_amount
            );
            prev_amount = amount;
        }
    }

    // =========================================================================
    // Edge cases
    // =========================================================================

    #[test]
    fn test_query_pool_swap_at_spot_price() {
        let state = UniswapV2State::new(U256::from(2_000_000u32), U256::from(1_000_000u32));

        let token_in = token_0();
        let token_out = token_1();

        let spot = state
            .spot_price(&token_in, &token_out)
            .unwrap();
        let target_price =
            Price::new(BigUint::from((spot * 1e18) as u128), BigUint::from(10u128.pow(18)));

        let params = QueryPoolSwapParams::new(
            token_in,
            token_out,
            SwapConstraint::PoolTargetPrice {
                target: target_price,
                tolerance: 0.001,
                min_amount_in: None,
                max_amount_in: None,
            },
        );

        let result = query_pool_swap(&state, &params);
        assert!(result.is_ok());
        let pool_swap = result.unwrap();
        assert!(
            pool_swap.amount_in() <= &BigUint::from(1u32) ||
                pool_swap.amount_in() == &BigUint::zero()
        );
    }

    #[test]
    fn test_query_pool_swap_returns_price_points() {
        let state = UniswapV2State::new(
            U256::from(1000u64) * U256::from(10u64).pow(U256::from(18u64)),
            U256::from(2_000_000u64) * U256::from(10u64).pow(U256::from(18u64)),
        );

        let weth = create_token("0x0000000000000000000000000000000000000000", "WETH", 18);
        let dai = create_token("0x0000000000000000000000000000000000000001", "DAI", 18);

        let spot_price = state.spot_price(&dai, &weth).unwrap();
        let target_price = Price::new(
            BigUint::from((spot_price * 0.95 * 1e18) as u128),
            BigUint::from(10u128.pow(18)),
        );

        let params = QueryPoolSwapParams::new(
            dai,
            weth,
            SwapConstraint::PoolTargetPrice {
                target: target_price,
                tolerance: 0.001,
                min_amount_in: None,
                max_amount_in: None,
            },
        );

        let result = query_pool_swap(&state, &params).unwrap();
        let price_points = result.price_points();
        assert!(price_points.is_some());
        let pp = price_points.as_ref().unwrap();
        assert!(pp.len() >= 2, "Should have at least 2 boundary points");
    }

    #[test]
    fn test_query_pool_swap_large_reserves() {
        let state = UniswapV2State::new(
            U256::from_str("1000000000000000000000000").unwrap(),
            U256::from_str("2000000000000000000000000000").unwrap(),
        );

        let weth = create_token("0x0000000000000000000000000000000000000000", "WETH", 18);
        let dai = create_token("0x0000000000000000000000000000000000000001", "DAI", 18);

        let spot_price = state.spot_price(&dai, &weth).unwrap();
        let target_price = Price::new(
            BigUint::from((spot_price * 0.90 * 1e18) as u128),
            BigUint::from(10u128.pow(18)),
        );

        let params = QueryPoolSwapParams::new(
            dai.clone(),
            weth.clone(),
            SwapConstraint::PoolTargetPrice {
                target: target_price,
                tolerance: 0.001,
                min_amount_in: None,
                max_amount_in: None,
            },
        );

        let result = query_pool_swap(&state, &params);
        assert!(result.is_ok(), "Should handle large reserves");

        let pool_swap = result.unwrap();
        let new_spot = pool_swap
            .new_state()
            .spot_price(&dai, &weth)
            .unwrap();
        let target_f64 = spot_price * 0.90;
        let error_bps = ((new_spot - target_f64) / target_f64).abs() * 10000.0;
        assert!(error_bps < 10.0, "Error should be <10bps for large reserves");
    }
}
