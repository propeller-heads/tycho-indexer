use ethers::types::{Sign, I256, U256};
use std::mem::swap;

const INVPHI: i64 = 2654435769; // (math.sqrt(5) - 1) / 2 * 2 ** 32
const INVPHI2: i64 = 1640531526; // (3 - math.sqrt(5)) * 2 ** 32
const DENOM: i64 = 4294967296; // 2 ** 32

pub fn gss<F: Fn(I256) -> I256>(
    f: F,
    mut min_bound: U256,
    mut max_bound: U256,
    tol: I256,
    max_iter: u64,
    honour_bounds: bool,
) -> (U256, U256) {
    let invphi_i256 = I256::from(INVPHI);
    let invphi2_i256 = I256::from(INVPHI2);
    let denom_i256 = I256::from(DENOM);

    if min_bound > max_bound {
        swap(&mut min_bound, &mut max_bound);
    }
    let mut min_bound = I256::from_raw(min_bound);
    let mut max_bound = I256::from_raw(max_bound);

    let mut h = max_bound - min_bound;
    if h <= tol {
        return (I256_to_U256(min_bound), I256_to_U256(max_bound));
    }

    let mut yc = I256::zero();
    let mut xc = I256::zero();

    if honour_bounds {
        xc = min_bound + mul_div(invphi2_i256, h, denom_i256);
        yc = f(xc);
    } else {
        let brackets = bracket(&f, min_bound, max_bound);
        min_bound = brackets.0;
        max_bound = brackets.1;
        xc = brackets.2;
        yc = brackets.3;
    }

    let mut xd = min_bound + mul_div(invphi_i256, h, denom_i256);
    let mut yd = f(xd);

    for _ in 0..max_iter {
        if yc > yd {
            max_bound = xd;
            xd = xc;
            yd = yc;
            h = mul_div(invphi_i256, h, denom_i256);
            xc = min_bound + mul_div(invphi2_i256, h, denom_i256);
            yc = f(xc);
        } else {
            min_bound = xc;
            xc = xd;
            yc = yd;
            h = mul_div(invphi_i256, h, denom_i256);
            xd = min_bound + mul_div(invphi_i256, h, denom_i256);
            yd = f(xd);
        }
    }

    if yc < yd {
        return (I256_to_U256(min_bound), I256_to_U256(xd));
    } else {
        return (I256_to_U256(xc), I256_to_U256(max_bound));
    };
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

        let res = gss(func, min_bound, max_bound, tol, max_iter, honour_bounds);

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

        let res = gss(
            func,
            U256::from(2u128),
            U256::from(2u128),
            tol,
            max_iter,
            honour_bounds,
        );

        assert!(res.0 >= U256::from(0) && res.0 <= U256::from(5));
        assert!(res.1 >= U256::from(0) && res.1 <= U256::from(5));
        assert!(res.0 <= res.1);
    }

    #[test]
    fn test_gss_large_interval() {
        let f = |x: I256| I256::minus_one() * I256::pow(I256::from(50) - x, 2);

        let res = gss(
            f,
            U256::from(0),
            U256::from(10000),
            I256::from(1u128),
            10000,
            true,
        );

        assert!(res.0 >= U256::from(45) && res.0 <= U256::from(55));
        assert!(res.1 >= U256::from(45) && res.1 <= U256::from(55));
        assert!(res.0 <= res.1)
    }

    #[test]
    fn test_gss_bracket() {
        let func = |x| (x - I256::from(2)) * (I256::from(-1) * x + I256::from(10));
        let res = gss(
            func,
            U256::from(0u128),
            U256::from(2u128),
            I256::from(1u128),
            100,
            false,
        );
        assert!(res.0 >= U256::from(0) && res.0 <= U256::from(10));
        assert!(res.1 >= U256::from(0) && res.1 <= U256::from(10));
    }
}

pub fn mul_div(a: I256, b: I256, denom: I256) -> I256 {
    let product = a * b;
    let result: I256 = (product / denom).try_into().expect("Integer Overflow");
    return result;
}

fn I256_to_U256(to_convert: I256) -> U256 {
    if to_convert <= I256::zero() {
        return U256::zero();
    }

    return U256::from_dec_str(&to_convert.to_string()).unwrap();
}

pub fn bracket<F: Fn(I256) -> I256>(
    f: F,
    mut min_bound: I256,
    mut max_bound: I256,
) -> (I256, I256, I256, I256) {
    let maxiter = 50;
    let grow_limit = I256::from(110);
    let _golden_ration: I256 = I256::from(6949403065_i64); // golden ratio: (1.0+sqrt(5.0))/2.0 *  2 ** 32
    let denom_i256 = I256::from(DENOM);

    let mut ya = f(min_bound);
    let mut yb = f(max_bound);

    if ya > yb {
        swap(&mut min_bound, &mut max_bound);
        swap(&mut ya, &mut yb)
    }

    let mut xc = max_bound + mul_div(_golden_ration, max_bound - min_bound, denom_i256);
    let mut yc = f(xc);
    let mut yw = I256::zero();
    let mut iter = 0;
    let mut w = I256::zero();
    while yb < yc {
        let tmp1 = (max_bound - min_bound) * (yb - yc);
        let tmp2 = (max_bound - xc) * (yb - ya);
        let val = tmp2 - tmp1;

        if val.abs() <= I256::zero() {
            w = ((max_bound - xc) * tmp2 - (max_bound - min_bound) * tmp1);
            w = max_bound - w.saturating_mul(I256::from(5000));
        } else {
            w = max_bound
                - ((max_bound - xc) * tmp2 - (max_bound - min_bound) * tmp1)
                    / (I256::from(2) * val);
        };

        if w.abs() > I256::pow(I256::from(2), 32) {
            let w_sign = w.sign();
            w = I256::from(-1) * I256::pow(I256::from(2), 32);
            if w_sign == Sign::Negative {
                w = I256::from(-1) * w
            }
        }

        let wlim = max_bound + grow_limit * (xc - max_bound);

        if iter > maxiter {
            panic!("Too many iterations!");
        }

        iter += 1;
        if (w - xc) * (max_bound - w) > I256::zero() {
            yw = f(w);
            if yw > yc {
                let min_bound = max_bound;
                let max_bound = w;
                return (max_bound, min_bound, xc, yc);
            } else if yw < yb {
                let xc = w;
                let yc = yw;
                return (min_bound, max_bound, xc, yc);
            }
            w = xc + mul_div(_golden_ration, xc - max_bound, denom_i256);
            yw = f(w);
        } else if (w - wlim) * (wlim - xc) >= I256::zero() {
            w = wlim;
            yw = f(w);
        } else if (w - wlim) * (xc - w) > I256::zero() {
            yw = f(w);
            if yw > yc {
                max_bound = xc;
                xc = w;
                w = xc + mul_div(_golden_ration, xc - max_bound, denom_i256);
                yb = yc;
                yc = yw;
                yw = f(w);
            }
        } else {
            w = xc + mul_div(_golden_ration, xc - max_bound, denom_i256);
            yw = f(w);
        }
        min_bound = max_bound;
        max_bound = xc;
        xc = w;
        ya = yb;
        yb = yc;
        yc = yw;
    }

    return (min_bound, max_bound, xc, yc);
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
        // min_bound
        assert_eq!(res.0, I256::from(2));
        // max_bound
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
        // min_bound
        assert_eq!(res.0, I256::from(3));
        // max_bound
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
        // min_bound
        assert_eq!(res.0, I256::from(48));
        // max_bound
        assert_eq!(res.1, I256::from(100));
        // xc
        assert_eq!(res.2, I256::from(184));
        // yc
        assert_eq!(res.3, I256::from(30));
    }

    #[test]
    #[should_panic]
    fn test_bracket_negative_gradient_function() {
        let func = |x: I256| x;
        let min_bound = I256::from(0);
        let max_bound = I256::from(50);
        let res = bracket(func, min_bound, max_bound);
    }
}
