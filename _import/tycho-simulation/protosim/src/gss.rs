use ethers::types::{U256, U512};
use std::mem::swap;

const INVPHI: U256 = U256([632, 0, 0, 0]); //  632.866804479892380186356604099273681640625_f32
const INVPHI2: U256 = U256([391, 0, 0, 0]); // 391.133195520107619813643395900726318359375_f32
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
    println!("h={}", h);
    let mut xc = min_bound + mul_div(INVPHI2, h, PHI_DENOM);
    let mut xd = min_bound + mul_div(INVPHI, h, PHI_DENOM);
    println!("xc={}", xc);
    let mut yc = f(xc);
    println!("xd={}", xd);
    let mut yd = f(xd);
    println!("yc={}", yc);
    println!("yd={}", yd);

    for _ in 0..max_iter {
        if yc < yd {
            max_bound = xd;
            xd = xc;
            yd = yc;
            println!("mul_div H");
            h = mul_div(INVPHI, h, PHI_DENOM);
            println!("mul_div xc");
            xc = min_bound + mul_div(INVPHI2, h, PHI_DENOM);
            println!("f xc={}", xc);
            println!("min_bound={}", min_bound);
            yc = f(xc);
        } else {
            min_bound = xc;
            xc = xd;
            yc = yd;
            println!("mul_div H in else");
            h = mul_div(INVPHI, h, PHI_DENOM);
            println!("mul_div xd in else");
            xd = min_bound + mul_div(INVPHI, h, PHI_DENOM);
            println!("f xd={}", xd);
            println!("min_bound={}", min_bound);
            yd = f(xd);
        }
    }
    println!("min_bound={}", min_bound);
    println!("xc={}", xc);
    println!("yd={}", yd);
    println!("xd={}", xd);
    if yc < yd {
        return min_bound;
    } else {
        return xc;
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gss() {
        let func = |x| x * x;
        let min_bound = U256::from(0);
        let max_bound = U256::from(2);
        let tol = U256::from(0);
        let max_iter = 100;
        let honour_bounds = true;

        let res = gss(func, min_bound, max_bound, tol, max_iter, honour_bounds);
        assert_eq!(res, U256::from(0))
    }
    // Test a case where the function has multiple local minima
    #[test]
    fn test_gss_multiple_minima() {
        let tol = U256::from(1u128);
        let max_iter = 500;
        let honour_bounds = true;

        let func = |x: U256| {
            (x - U256::from(3))
                .pow(U256::from(4) - (x - U256::from(3)).pow(U256::from(2)) - (x - U256::from(3)))
        };
        let min = gss(
            func,
            U256::from(2u128),
            U256::from(5u128),
            tol,
            max_iter,
            honour_bounds,
        );

        assert_eq!(min, U256::from(2));
    }

    // Test a case where the search interval is very large
    #[test]
    fn test_gss_large_interval() {
        let f = |x: U256| -> U256 { (U256::from(100) - x) * (U256::from(100) - x) };
        f(U256::from(100));
        let min = gss(
            f,
            U256::from(0),
            U256::from(100),
            U256::from(1u128),
            10000,
            true,
        );
        assert_eq!(min, U256::from(100));
    }

    // Test a case where honour_bounds is set to false
    #[test]
    fn test_gss_not_honouring_bounds_positive_inputs() {
        let f = |x: U256| -> U256 { x * x - U256::from(2) * x + U256::from(1) };
        let min = gss(
            f,
            U256::from(1u128),
            U256::from(10u128),
            U256::from(1u128),
            10,
            false,
        );
        assert!(min == U256::from(1u128));
    }
}

pub fn mul_div(a: U256, b: U256, denom: U256) -> U256 {
    // do fractional math in U512 to allow for bigger range
    println!("-------");
    let product = U512::from(a) * U512::from(b);
    println!("product={}", product);
    let rest: U512 = product % U512::from(denom);
    println!("denom={}", denom);
    println!("rest={}", product);
    let rounder = if rest > (U512::from(denom) / U512::from(2)) {
        U256::from(1)
    } else {
        U256::from(0)
    };
    println!("rounder={}", rounder);
    let result: U256 = (product / U512::from(denom))
        .try_into()
        .expect("Integer Overflow");
    println!("result={}", result);
    println!("result + rounder={}", result + rounder);
    return result + rounder;
}
