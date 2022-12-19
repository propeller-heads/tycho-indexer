use ethers::types::U256;
use std::mem::swap;

pub fn gss<F: Fn(f64) -> f64>(
    f: F,
    mut min_bound: U256,
    mut max_bound: U256,
    tol: U256,
    max_iter: u64,
    honour_bounds: bool,
) -> (U256, U256) {
    let invphi = 0.6180339887498949_f64; // (f64::sqrt(5.0) - 1_f64) / 2_f64;
    let invphi2 = 0.3819660112501051_f64; // (3_f64 - f64::sqrt(5.0)) / 2_f64;

    if min_bound > max_bound {
        swap(&mut min_bound, &mut max_bound);
    }

    let h = max_bound - min_bound;
    if h.le(&tol) {
        return (min_bound, max_bound);
    }

    let mut min_bound_f64 = (min_bound.to_string().as_str()).parse::<f64>().unwrap();
    let mut max_bound_f64 = (max_bound.to_string().as_str()).parse::<f64>().unwrap();
    let mut h_f64 = (h.to_string().as_str()).parse::<f64>().unwrap();

    let mut xc = min_bound_f64 + invphi2 * h_f64;
    let mut xd = min_bound_f64 + invphi * h_f64;
    let mut yc = f(xc);
    let mut yd = f(xd);

    for _ in 0..max_iter {
        if yc < yd {
            max_bound_f64 = xd;
            xd = xc;
            yd = yc;
            h_f64 = invphi * h_f64;
            xc = min_bound_f64 + invphi2 * h_f64;
            if xc > max_bound_f64 && !honour_bounds {
                xc = max_bound_f64;
            }
            yc = f(xc);
        } else {
            min_bound_f64 = xc;
            xc = xd;
            yc = yd;
            h_f64 = invphi * h_f64;
            xd = min_bound_f64 + invphi * h_f64;
            if xd > max_bound_f64 && !honour_bounds {
                xd = max_bound_f64;
            }
            yd = f(xd);
        }
    }

    if yc < yd {
        return (
            U256::from(min_bound_f64.round() as u128),
            U256::from(yd.round() as u128),
        );
    } else {
        return (
            U256::from(xc.round() as u128),
            U256::from(max_bound_f64.round() as u128),
        );
    }
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
        assert_eq!(res, (U256::from(0), U256::from(0)))
    }
    // Test a case where the function has multiple local minima
    #[test]
    fn test_gss_multiple_minima() {
        let tol = U256::from(1u128);
        let max_iter = 500;
        let honour_bounds = true;

        let f = |x: f64| -> f64 { -1_f64 * (1.4_f64 * x - 1.4_f64).powi(2) + 2.0 };
        println!("{}", f(1.0));
        let (min, _) = gss(
            f,
            U256::from(0u128),
            U256::from(2u128),
            tol,
            max_iter,
            honour_bounds,
        );

        assert_eq!(min, U256::from(2));
    }

    // Test a case where the search interval is very large
    #[test]
    fn test_gss_large_interval() {
        let f = |x: f64| -> f64 { (300.0 - x).powi(2) - 2.0 };
        let (min, _) = gss(
            f,
            U256::from(1u128),
            U256::from(1000000u128),
            U256::from(1u128),
            5000,
            true,
        );
        println!("{:?}", min);
        assert_eq!(min, U256::from(300));
    }

    // Test a case where honour_bounds is set to false
    #[test]
    fn test_gss_not_honouring_bounds_positive_inputs() {
        let f = |x: f64| -> f64 { x * x - 2.0 * x + 1.0 };
        let (min, _) = gss(
            f,
            U256::from(1u128),
            U256::from(10u128),
            U256::from(1u128),
            10,
            false,
        );
        println!("{:?}", min);
        assert!(min == U256::from(1u128));
    }
}
