use ethers::types::{I256, U256, U512};
use std::mem::swap;

// 2654435769, 1640531526, 4294967296
const INVPHI: U256 = U256([2654435769, 0, 0, 0]); // (math.sqrt(5) - 1) / 2 * 2 ** 32
const INVPHI2: U256 = U256([1640531526, 0, 0, 0]); // (3 - math.sqrt(5)) * 2 ** 32
const DENOM: U256 = U256([4294967296, 0, 0, 0]); // 2 ** 32

pub fn gss<F: Fn(U256) -> U256>(
    f: F,
    mut min_bound: U256,
    mut max_bound: U256,
    tol: U256,
    max_iter: u64,
    honour_bounds: bool,
) -> (U256, U256) {
    if min_bound > max_bound {
        swap(&mut min_bound, &mut max_bound);
    }

    let mut h = max_bound.abs_diff(min_bound);
    if h.le(&tol) {
        return (min_bound, max_bound);
    }

    let mut yc = U256::zero();
    let mut xc = U256::zero();

    if honour_bounds {
        xc = min_bound + mul_div(INVPHI2, h, DENOM);
        yc = f(xc);
    } else {
        let brackets = bracket(&f, min_bound, max_bound);
        min_bound = brackets.0;
        max_bound = brackets.1;
        xc = brackets.2;
        yc = brackets.3;
    }

    let mut xd = min_bound + mul_div(INVPHI, h, DENOM);
    let mut yd = f(xd);

    for _ in 0..max_iter {
        if yc < yd {
            max_bound = xd;
            xd = xc;
            yd = yc;
            h = mul_div(INVPHI, h, DENOM);
            xc = min_bound + mul_div(INVPHI2, h, DENOM);
            yc = f(xc);
        } else {
            min_bound = xc;
            xc = xd;
            yc = yd;
            h = mul_div(INVPHI, h, DENOM);
            xd = min_bound + mul_div(INVPHI, h, DENOM);
            yd = f(xd);
        }
    }
    if yc < yd {
        return (min_bound, xd);
    } else {
        return (xc, max_bound);
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    // Using the rounding in mul_div this test is unable to find the local minima, because it will keep rounding up to 1.
    // The opposite is true for test_gss_large_interval
    #[test]
    fn test_gss() {
        let func = |x| x * x;
        let min_bound = U256::from(0);
        let max_bound = U256::from(100);
        let tol = U256::from(0);
        let max_iter = 10;
        let honour_bounds = true;

        let res = gss(func, min_bound, max_bound, tol, max_iter, honour_bounds);
        assert_eq!(res.0, U256::from(0))
    }

    // Here we are unable to find one local minima, because the bounds are limited, since we get temporary negative values in the calculation of the provided function
    #[test]
    fn test_gss_multiple_minima() {
        let tol = U256::from(1u128);
        let max_iter = 500;
        let honour_bounds = false;

        let func = |x: U256| {
            ((x - U256::from(2)).pow(U256::from(6))
                - (x - U256::from(2)).pow(U256::from(4))
                - (x - U256::from(2)).pow(U256::from(2)))
                + U256::from(1)
        };

        let res = gss(
            func,
            U256::from(2u128),
            U256::from(2u128),
            tol,
            max_iter,
            honour_bounds,
        );

        assert_eq!(res.0, U256::from(2));
    }

    // This test uses an input function that can resolve into negative values and therefor limiting the max_bound to 10000.
    // Limiting the max bound and not using the rounnding in mul_div it is unable to find the local minima.
    #[test]
    fn test_gss_large_interval() {
        let f = |x: U256| -> U256 { (U256::from(10000) - x) * (U256::from(10000) - x) };
        f(U256::from(100));
        let res = gss(
            f,
            U256::from(0),
            U256::from(10000),
            U256::from(1u128),
            10000,
            true,
        );
        assert_eq!(res.0, U256::from(9987));
    }

    #[test]
    fn test_gss_honouring_bounds() {
        let f = |x| x * x;
        let res = gss(
            f,
            U256::from(10u128),
            U256::from(0u128),
            U256::from(1u128),
            100,
            true,
        );
        assert!(res.0 == U256::from(0u128));
    }
}

pub fn mul_div(a: U256, b: U256, denom: U256) -> U256 {
    let product = U512::from(a) * U512::from(b);

    let result: U256 = (product / U512::from(denom))
        .try_into()
        .expect("Integer Overflow");

    return result;
}

pub fn function_wrap<F: Fn(U256) -> U256>(f: F, x: I256) -> I256 {
    println!("{}", x);
    let y = f(U256::from_dec_str(&x.to_string()).unwrap());
    return I256::from_dec_str(&y.to_string()).unwrap();
}

pub fn bracket<F: Fn(U256) -> U256>(
    f: F,
    mut min_bound: U256,
    mut max_bound: U256,
) -> (U256, U256, U256, U256) {
    let mut min_bound = I256::from_dec_str(&min_bound.to_string()).unwrap();
    let mut max_bound = I256::from_dec_str(&max_bound.to_string()).unwrap();

    let maxiter = I256::from(1000);
    let grow_limit = I256::from(110);
    let GOLDEN_RATIO: I256 = I256::from(6949403065_i64); // golden ratio: (1.0+sqrt(5.0))/2.0 *  2 ** 32
    let denom_i526 = I256::from_dec_str(&DENOM.to_string()).unwrap();
    let _verysmall_num = I256::from(100);
    let _versmall_num_denom = I256::from_dec_str("100000000000000000000000").unwrap();

    let mut ya = function_wrap(&f, min_bound);
    let mut yb = function_wrap(&f, max_bound);

    if ya < yb {
        swap(&mut min_bound, &mut max_bound);
        swap(&mut ya, &mut yb)
    }
    let mut xc = max_bound + (GOLDEN_RATIO * (max_bound - min_bound)) / denom_i526;
    let mut yc = function_wrap(&f, xc);
    let mut yw = I256::zero();
    let mut iter = I256::zero();

    while yc < yb {
        let tmp1 = (max_bound - min_bound) * (yb - yc);
        let tmp2 = (max_bound - xc) * (yb - ya);
        let val = tmp2 - tmp1;
        let mut denom = if val < _verysmall_num {
            I256::from(2) * _verysmall_num
        } else {
            I256::from(2) * val
        };

        let mut w = max_bound - ((max_bound - xc) * tmp2 - (max_bound - min_bound) * tmp1) / denom;
        let wlim = max_bound + grow_limit * (xc - max_bound);

        if iter > maxiter {
            panic!("Too many iterations.");
        }

        iter = iter + I256::one();

        if (w - xc) * (max_bound - w) > I256::zero() {
            yw = function_wrap(&f, w);

            if yw < yc {
                let min_bound = U256::from_dec_str(&max_bound.to_string()).unwrap();
                let max_bound = U256::from_dec_str(&w.to_string()).unwrap();
                let xc = U256::from_dec_str(&xc.to_string()).unwrap();
                let yc = U256::from_dec_str(&yc.to_string()).unwrap();
                return (max_bound, min_bound, xc, yc);
            } else if yw > yb {
                let min_bound = U256::from_dec_str(&min_bound.to_string()).unwrap();
                let max_bound = U256::from_dec_str(&max_bound.to_string()).unwrap();
                let xc = U256::from_dec_str(&w.to_string()).unwrap();
                let yc = U256::from_dec_str(&yw.to_string()).unwrap();
                return (min_bound, max_bound, xc, yc);
            }
            w = xc + (GOLDEN_RATIO * (xc - max_bound)) / denom_i526;
            yw = function_wrap(&f, w);
        } else if (w - wlim) * (wlim - xc) >= I256::zero() {
            w = wlim;
            yw = function_wrap(&f, w);
        } else if (w - wlim) * (xc - w) > I256::zero() {
            yw = function_wrap(&f, w);
            if yw < yc {
                max_bound = xc;
                xc = w;
                w = xc + (GOLDEN_RATIO * (xc - max_bound)) / denom_i526;
                yb = yc;
                yc = yw;
                yw = function_wrap(&f, w);
            }
        } else {
            w = xc + (GOLDEN_RATIO * (xc - max_bound)) / denom_i526;
            yw = function_wrap(&f, w);
        }
        min_bound = max_bound;
        max_bound = xc;
        xc = w;
        ya = yb;
        yb = yc;
        yc = yw;
    }
    let min_bound = if min_bound > I256::zero() {
        U256::from_dec_str(&min_bound.to_string()).unwrap()
    } else {
        U256::zero()
    };
    let max_bound = if max_bound > I256::zero() {
        U256::from_dec_str(&max_bound.to_string()).unwrap()
    } else {
        U256::zero()
    };
    let xc = if xc > I256::zero() {
        U256::from_dec_str(&xc.to_string()).unwrap()
    } else {
        U256::zero()
    };
    let yc = if yc > I256::zero() {
        U256::from_dec_str(&yc.to_string()).unwrap()
    } else {
        U256::zero()
    };

    return (min_bound, max_bound, xc, yc);
}

#[cfg(test)]
mod bracket_tests {
    use super::*;

    #[test]
    fn test_bracket() {
        let func = |x: U256| x * x;
        let min_bound = U256::from(0);
        let max_bound = U256::from(10);
        let res = bracket(func, min_bound, max_bound);

        // max_bound
        assert_eq!(res.0, U256::from(10));
        // min_bound
        assert_eq!(res.1, U256::from(0));
        // xc should be -16.18034111
        assert_eq!(res.2, U256::from(0));
        // yc
        assert_eq!(res.3, U256::from(261));
    }
}
