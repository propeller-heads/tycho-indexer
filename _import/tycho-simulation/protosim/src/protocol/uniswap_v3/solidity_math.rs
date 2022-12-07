use ethers::types::{U256, U512};

pub fn mul_div_rounding_up(a: U256, b: U256, denom: U256) -> U256 {
    let a_big = U512::from(a);
    let b_big = U512::from(b);
    let product = a_big * b_big;
    let (mut result, rest) = product.div_mod(U512::from(denom));
    if rest >= U512::zero() {
        result = result + U512::one();
    }
    let res_small = result.try_into().expect("Mul div overflow!!");
    return res_small;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mul_div_rounding_up() {
        // TODO: check U256 overflows and maybe U512?
        let a = U256::from(23);
        let b = U256::from(10);
        let denom = U256::from(50);
        let res = mul_div_rounding_up(a, b, denom);

        assert_eq!(res, U256::from(5));
    }

    #[test]
    fn test_mul_div_overflow_u256() {
        let (a, b) = (U256::MAX, U256::MAX);
        let denom = U256::from(1);

        let result = std::panic::catch_unwind(|| mul_div_rounding_up(a, b, denom));

        assert!(result.is_err());
    }
}
