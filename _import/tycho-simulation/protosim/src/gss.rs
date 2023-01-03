use ethers::types::{U256, U512};
use std::mem::swap;

const INVPHI: U256 = U256([632, 0, 0, 0]);
const INVPHI2: U256 = U256([391, 0, 0, 0]);
const PHI_DENOM: U256 = U256([1024, 0, 0, 0]); // 32 ** 2

pub fn gss<F: Fn(U256) -> U256>(
    f: F,
    mut min_bound: U256,
    mut max_bound: U256,
    tol: U256,
    max_iter: u64,
    honour_bounds: bool,
) -> U256 {
    if honour_bounds {
        if min_bound > max_bound {
            swap(&mut min_bound, &mut max_bound);
        }
    }

    let mut h = max_bound.abs_diff(min_bound);
    if h.le(&tol) {
        return min_bound;
    }
    let mut xc = min_bound + mul_div(INVPHI2, h, PHI_DENOM);
    let mut xd = min_bound + mul_div(INVPHI, h, PHI_DENOM);
    let mut yc = f(xc);
    let mut yd = f(xd);

    for _ in 0..max_iter {
        if yc < yd {
            xd = xc;
            yd = yc;
            h = mul_div(INVPHI, h, PHI_DENOM);
            xc = min_bound + mul_div(INVPHI2, h, PHI_DENOM);
            yc = f(xc);
        } else {
            min_bound = xc;
            xc = xd;
            yc = yd;
            h = mul_div(INVPHI, h, PHI_DENOM);
            xd = min_bound + mul_div(INVPHI, h, PHI_DENOM);
            yd = f(xd);
        }
    }

    if yc < yd {
        return min_bound;
    } else {
        return xc;
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
        let max_bound = U256::from(10);
        let tol = U256::from(0);
        let max_iter = 100;
        let honour_bounds = true;

        let res = gss(func, min_bound, max_bound, tol, max_iter, honour_bounds);
        assert_eq!(res, U256::from(0))
    }

    // Here we are able to find one local minima, but the bounds are limited, because of temporary negative values in the calculation of the provided function
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
        let min = gss(
            func,
            U256::from(2u128),
            U256::from(2u128),
            tol,
            max_iter,
            honour_bounds,
        );

        assert_eq!(min, U256::from(2));
    }

    // This test uses an input function that can resolve into negative values and therefor limiting the max_bound to 10000.
    // Limiting the max bound and not using the rounnding in mul_div it is unable to find the local minima.
    #[test]
    fn test_gss_large_interval() {
        let f = |x: U256| -> U256 { (U256::from(10000) - x) * (U256::from(10000) - x) };
        f(U256::from(100));
        let min = gss(
            f,
            U256::from(0),
            U256::from(10000),
            U256::from(1u128),
            10000,
            false,
        );
        assert_eq!(min, U256::from(9954));
    }

    #[test]
    fn test_gss_honouring_bounds() {
        let f = |x| x * x;
        let min = gss(
            f,
            U256::from(10u128),
            U256::from(0u128),
            U256::from(1u128),
            100,
            true,
        );
        assert!(min == U256::from(0u128));
    }
}

pub fn mul_div(a: U256, b: U256, denom: U256) -> U256 {
    let product = U512::from(a) * U512::from(b);
    //let rest: U512 = product % U512::from(denom);
    //let rounder = if rest > (U512::from(denom) / U512::from(2)) {
    //    U256::from(1)
    //} else {
    //   U256::from(0)
    //};
    let result: U256 = (product / U512::from(denom))
        .try_into()
        .expect("Integer Overflow");
    return result; //+ rounder;
}
