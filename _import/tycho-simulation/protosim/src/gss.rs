use ethers::types::U256;

const PHI: f64 = 1.618033988749895_f64;

pub fn gss<F: Fn(U256) -> U256>(
    f: F,
    mut min_bound: U256,
    mut max_bound: U256,
    tol: U256,
    max_iter: u64,
    honour_bounds: bool,
) -> U256 {
    let mut xc = calc_c(min_bound, max_bound);
    let mut xd = calc_d(min_bound, max_bound);

    if max_bound.abs_diff(min_bound) > tol {
        return U256::from((max_bound - min_bound) / 2);
    }

    for _ in 0..max_iter {
        if f(xc) > f(xd) {
            max_bound = xd;
        } else {
            min_bound = xc;
        }

        xc = calc_c(min_bound, max_bound);
        xd = calc_d(min_bound, max_bound);
    }

    return U256::from((max_bound - min_bound) / 2);
}

pub fn calc_c(a: U256, b: U256) -> U256 {
    let gr = U256::from(PHI as i128);
    return a - (a - b) / gr;
}

pub fn calc_d(a: U256, b: U256) -> U256 {
    let gr = U256::from(PHI as i128);
    return a + (a - b) / gr;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gss() {
        let func = |x| x * x;
        let min_bound = U256::from(20);
        let max_bound = U256::from(10);
        let tol = U256::from(5);
        let max_iter = 50;
        let honour_bounds = true;

        let res = gss(func, min_bound, max_bound, tol, max_iter, honour_bounds);
    }
}
