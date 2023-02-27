//! Golden Section Search
use crate::protocol::errors::TradeSimulationError;
use crate::safe_math::{
    safe_add_i256, safe_div_i256, safe_div_u512, safe_mul_i256, safe_mul_u512, safe_sub_i256,
};
use ethers::types::{Sign, I256, U256, U512};
use std::mem::swap;

const INVPHI: i64 = 2654435769; // (math.sqrt(5) - 1) / 2 * 2 ** 32
const INVPHI2: i64 = 1640531526; // (3 - math.sqrt(5)) * 2 ** 32
const DENOM: U512 = U512([4294967296, 0, 0, 0, 0, 0, 0, 0]); // 2 ** 32

/// Golden Section Search
///
/// This function maximizes the function `f` using the Golden Section Search algorithm.
///
/// ## Parameters
///
/// - `f`: A function that takes a `I256` value as input and returns a `I256` value. The function to be maximized.
/// - `min_bound`: The lower bound of the search interval, represented as a `U256` value.
/// - `max_bound`: The upper bound of the search interval, represented as a `U256` value.
/// - `tol`: The tolerance level, represented as a `I256` value. The search will stop when the difference between the two brackets is less than this tolerance.
/// - `max_iter`: The maximum number of iterations to perform before stopping the search, represented as a `u64` value.
/// - `honour_bounds`: A `bool` value indicating whether the algorithm should honour the bounds or not. If true, the algorithm will not search for solutions outside of the `min_bound` and `max_bound` values.
///
/// ## Returns
///
/// A tuple of `U256` values representing the left and right brackets of the maximum value of the function.
pub fn golden_section_search<F: Fn(I256) -> I256>(
    f: F,
    mut min_bound: U256,
    mut max_bound: U256,
    tol: I256,
    max_iter: u64,
    honour_bounds: bool,
) -> Result<(U256, U256), TradeSimulationError> {
    let invphi_i256 = I256::from(INVPHI);
    let invphi2_i256 = I256::from(INVPHI2);

    if min_bound > max_bound {
        swap(&mut min_bound, &mut max_bound);
    }

    let mut min_bound = I256::checked_from_sign_and_abs(Sign::Positive, min_bound).unwrap();
    let mut max_bound = I256::checked_from_sign_and_abs(Sign::Positive, max_bound).unwrap();

    let mut h = max_bound - min_bound;
    if h <= tol {
        return Ok((i256_to_u256(min_bound), i256_to_u256(max_bound)));
    }

    let mut yc;
    let mut xc;

    if honour_bounds {
        xc = safe_add_i256(min_bound, mul_div(invphi2_i256, h, DENOM)?)?;
        yc = f(xc);
    } else {
        let brackets = bracket(&f, min_bound, max_bound);
        min_bound = brackets.0;
        max_bound = brackets.1;
        xc = brackets.2;
        yc = brackets.3;
    }

    let mut xd = safe_add_i256(min_bound, mul_div(invphi_i256, h, DENOM)?)?;
    let mut yd = f(xd);

    for _ in 0..max_iter {
        if yc > yd {
            max_bound = xd;
            xd = xc;
            yd = yc;
            h = mul_div(invphi_i256, h, DENOM)?;
            xc = safe_add_i256(min_bound, mul_div(invphi2_i256, h, DENOM)?)?;
            yc = f(xc);
        } else {
            min_bound = xc;
            xc = xd;
            yc = yd;
            h = mul_div(invphi_i256, h, DENOM)?;
            xd = safe_add_i256(min_bound, mul_div(invphi_i256, h, DENOM)?)?;
            yd = f(xd);
        }
    }

    if yc < yd {
        Ok((i256_to_u256(min_bound), i256_to_u256(xd)))
    } else {
        Ok((i256_to_u256(xc), i256_to_u256(max_bound)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gss() {
        let func = |x| ((x - I256::from(2)) * (I256::from(-1) * x + I256::from(10)));
        let min_bound = U256::from(0);
        let max_bound = U256::from(10);
        let tol = I256::from(0);
        let max_iter = 100;
        let honour_bounds = true;

        let res = golden_section_search(func, min_bound, max_bound, tol, max_iter, honour_bounds)
            .unwrap();

        assert!(res.0 >= U256::from(3) && res.0 <= U256::from(7));
        assert!(res.1 >= U256::from(3) && res.1 <= U256::from(7));
        assert!(res.0 <= res.1);
    }

    #[test]
    fn test_gss_multiple_minima() {
        let tol = I256::from(1u128);
        let max_iter = 500;
        let honour_bounds = false;

        let func = |x: I256| {
            ((x - I256::from(2)).pow(6) - (x - I256::from(2)).pow(4) - (x - I256::from(2)).pow(2))
                + I256::from(1)
        };

        let res = golden_section_search(
            func,
            U256::from(2u128),
            U256::from(2u128),
            tol,
            max_iter,
            honour_bounds,
        )
        .unwrap();

        assert!(res.0 >= U256::from(0) && res.0 <= U256::from(5));
        assert!(res.1 >= U256::from(0) && res.1 <= U256::from(5));
        assert!(res.0 <= res.1);
    }

    #[test]
    fn test_gss_large_interval() {
        let f = |x: I256| I256::minus_one() * I256::pow(I256::from(50) - x, 2);

        let res = golden_section_search(
            f,
            U256::from(0),
            U256::from(10000),
            I256::from(1u128),
            10000,
            true,
        )
        .unwrap();

        assert!(res.0 >= U256::from(45) && res.0 <= U256::from(55));
        assert!(res.1 >= U256::from(45) && res.1 <= U256::from(55));
        assert!(res.0 <= res.1)
    }

    #[test]
    fn test_gss_bracket() {
        let func = |x| (x - I256::from(2)) * (I256::from(-1) * x + I256::from(10));
        let res = golden_section_search(
            func,
            U256::from(0u128),
            U256::from(2u128),
            I256::from(1u128),
            100,
            false,
        )
        .unwrap();
        assert!(res.0 >= U256::from(0) && res.0 <= U256::from(10));
        assert!(res.1 >= U256::from(0) && res.1 <= U256::from(10));
    }
}

fn i256_to_u256(to_convert: I256) -> U256 {
    if to_convert <= I256::zero() {
        return U256::zero();
    }

    U256::from_dec_str(&to_convert.to_string()).unwrap()
}

pub fn bracket<F: Fn(I256) -> I256>(f: F, mut xa: I256, mut xb: I256) -> (I256, I256, I256, I256) {
    let _maxiter = 50;
    let _grow_limit = I256::from(110);
    let _golden_ratio: I256 = I256::from(6949403065_i64); // golden ratio: (1.0+sqrt(5.0))/2.0 *  2 ** 32
    let _w_max = I256::pow(I256::from(2), 96);

    let mut ya = f(xa);
    let mut yb = f(xb);

    if ya > yb {
        swap(&mut xa, &mut xb);
        swap(&mut ya, &mut yb)
    }

    let mut xc = xb + mul_div(_golden_ratio, xb - xa, DENOM);
    let mut yc = f(xc);
    let mut yw;
    let mut iter = 0;
    let mut w;

    while yb < yc {
        let tmp1 = (xb - xa) * (yb - yc);
        let tmp2 = (xb - xc) * (yb - ya);
        let val = tmp2 - tmp1;

        if val.abs() <= I256::zero() {
            w = (xb - xc) * tmp2 - (xb - xa) * tmp1;
            w = xb - w.saturating_mul(I256::from(5000));
        } else {
            w = xb - ((xb - xc) * tmp2 - (xb - xa) * tmp1) / (I256::from(2) * val);
        };

        if w.abs() > _w_max {
            let w_sign = w.sign();
            w = _w_max;
            if w_sign == Sign::Negative {
                w = I256::from(-1) * w
            }
        }

        let wlim = xb + _grow_limit * (xc - xb);

        if iter > _maxiter {
            panic!("Too many iterations!");
        }

        iter += 1;
        if (w - xc) * (xb - w) > I256::zero() {
            yw = f(w);
            if yw > yc {
                let min_bound = xb;
                let max_bound = w;
                return (max_bound, min_bound, xc, yc);
            } else if yw < yb {
                let xc = w;
                let yc = yw;
                return (xa, xb, xc, yc);
            }
            w = xc + mul_div(_golden_ratio, xc - xb, DENOM);
            yw = f(w);
        } else if (w - wlim) * (wlim - xc) >= I256::zero() {
            w = wlim;
            yw = f(w);
        } else if (w - wlim) * (xc - w) > I256::zero() {
            yw = f(w);
            if yw > yc {
                xb = xc;
                xc = w;
                w = xc + mul_div(_golden_ratio, xc - xb, DENOM);
                yb = yc;
                yc = yw;
                yw = f(w);
            }
        } else {
            w = xc + mul_div(_golden_ratio, xc - xb, DENOM);
            yw = f(w);
        }
        xa = xb;
        xb = xc;
        xc = w;
        ya = yb;
        yb = yc;
        yc = yw;
    }

    (xa, xb, xc, yc)
}

#[cfg(test)]
mod bracket_tests {
    use super::*;

    #[test]
    fn test_bracket() {
        let func = |x| (x - I256::from(2)) * (I256::from(-1) * x + I256::from(10));
        let min_bound = I256::from(2);
        let max_bound = I256::from(5);
        let res = bracket(func, min_bound, max_bound);

        assert!(res.0 < res.1 && res.1 < res.2);
        // xa
        assert_eq!(res.0, I256::from(2));
        // xb
        assert_eq!(res.1, I256::from(5));
        // xc
        assert_eq!(res.2, I256::from(9));
        // yc
        assert_eq!(res.3, I256::from(7));
    }

    #[test]
    fn test_bracket_negative_bound() {
        let func = |x| (x - I256::from(2)) * (I256::from(-1) * x + I256::from(10));
        let min_bound = I256::from(-10);
        let max_bound = I256::from(-5);
        let res = bracket(func, min_bound, max_bound);

        assert!(res.0 < res.1 && res.1 < res.2);
        // xa
        assert_eq!(res.0, I256::from(3));
        // xb
        assert_eq!(res.1, I256::from(6));
        // xc
        assert_eq!(res.2, I256::from(10));
        // yc
        assert_eq!(res.3, I256::from(0));
    }

    #[test]
    fn test_bracket_big_distance() {
        let func = |x| {
            I256::minus_one() * ((I256::pow(I256::from(100) - x, 2)) / I256::from(100))
                + I256::from(100)
        };

        let min_bound = I256::from(0);
        let max_bound = I256::from(-30);
        let res = bracket(func, min_bound, max_bound);

        assert!(res.0 < res.1 && res.1 < res.2);
        // xa
        assert_eq!(res.0, I256::from(48));
        // xb
        assert_eq!(res.1, I256::from(100));
        // xc
        assert_eq!(res.2, I256::from(184));
        // yc
        assert_eq!(res.3, I256::from(30));
    }

    #[test]
    #[should_panic]
    fn test_bracket_max_iteration() {
        let func = |x: I256| x;
        let min_bound = I256::from(0);
        let max_bound = I256::from(50);
        bracket(func, min_bound, max_bound);
    }
}

pub fn mul_div(a: I256, b: I256, denom: U512) -> Result<I256, TradeSimulationError> {
    let a_sign = a.sign();
    let b_sign = b.sign();

    let a_u512 = if a_sign == Sign::Negative {
        U512::from_dec_str(&(I256::from(-1) * a).to_string()).unwrap()
    } else {
        U512::from_dec_str(&a.to_string()).unwrap()
    };

    let b_u512 = if b_sign == Sign::Negative {
        U512::from_dec_str(&(I256::from(-1) * b).to_string()).unwrap()
    } else {
        U512::from_dec_str(&b.to_string()).unwrap()
    };

    let product = safe_mul_u512(a_u512, b_u512)?;

    let result: U256 = safe_div_u512(product, denom)?
        .try_into()
        .expect("Integer Overflow when casting from U512 to U256");
    let mut new_sign = Sign::Positive;
    if a_sign != b_sign {
        new_sign = Sign::Negative;
    }
    Ok(I256::checked_from_sign_and_abs(new_sign, result)
        .expect("Integer Overflow when casting from U256 to I256"))
}

#[cfg(test)]
mod mul_div_tests {
    use super::*;

    #[test]
    fn test_mul_div() {
        let a = I256::from(2147483648_i64); // 0.5 * 2 **32
        let b = I256::from(50);
        let res = mul_div(a, b, DENOM).unwrap();

        assert!(res == I256::from(25));
        assert!(res.sign() == Sign::Positive);
    }
    #[test]
    fn test_mul_div_negativ_mul() {
        let a = I256::from(-2147483648_i64); // 0.5 * 2 **32
        let b = I256::from(50);
        let res = mul_div(a, b, DENOM).unwrap();

        assert!(res == I256::from(-25));
        assert!(res.sign() == Sign::Negative);
    }

    #[test]
    fn test_mul_div_both_negativ_mul() {
        let a = I256::from(-2147483648_i64); // 0.5 * 2 **32
        let b = I256::from(-50);
        let res = mul_div(a, b, DENOM).unwrap();

        assert!(res == I256::from(25));
        assert!(res.sign() == Sign::Positive);
    }
}
