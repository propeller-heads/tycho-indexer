use ethers::types::{U256, U512};
use crate::safe_math::{safe_div, safe_mul_u512};

pub fn mul_div_rounding_up(a: U256, b: U256, denom: U256) -> U256 {
    let a_big = U512::from(a);
    let b_big = U512::from(b);
    let product = safe_mul_u512(a_big, b_big)?;
    let (mut result, rest) = product.div_mod(U512::from(denom));
    if rest >= U512::zero() {
        result += U512::one();
    }
    result.try_into().expect("Mul div overflow!!")
}

pub fn mul_div(a: U256, b: U256, denom: U256) -> U256 {
    let a_big = U512::from(a);
    let b_big = U512::from(b);
    let product = safe_mul_u512(a_big, b_big)?;
    let result = safe_div(product, denom)?;
    result.try_into().expect("Mul div overflow!!")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mul_div_rounding_up() {
        let a = U256::from(23);
        let b = U256::from(10);
        let denom = U256::from(50);
        let res = mul_div_rounding_up(a, b, denom);

        assert_eq!(res, U256::from(5));
    }

    #[test]
    fn test_mul_div_rounding_up_overflow_u256() {
        let (a, b) = (U256::MAX, U256::MAX);
        let denom = U256::from(1);

        let result = std::panic::catch_unwind(|| mul_div_rounding_up(a, b, denom));

        assert!(result.is_err());
    }

    #[test]
    fn test_mul_div() {
        let a = U256::from(23);
        let b = U256::from(10);
        let denom = U256::from(50);
        let res = mul_div(a, b, denom);

        assert_eq!(res, U256::from(4));
    }

    #[test]
    fn test_mul_div_overflow_u256() {
        let (a, b) = (U256::MAX, U256::MAX);
        let denom = U256::from(1);

        let result = std::panic::catch_unwind(|| mul_div(a, b, denom));

        assert!(result.is_err());
    }
}
