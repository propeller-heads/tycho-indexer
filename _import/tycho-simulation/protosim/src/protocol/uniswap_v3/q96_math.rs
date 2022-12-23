use ethers::types::U256;

use crate::u256_num::u256_to_f64;

const MAX_U160: U256 = U256([0, 0, 4294967296, 0]);

/// Converts a sqrt price in Q96 representation to its approximate f64 representation
///
/// # Panics
/// Will panic if the `x` is bigger than U160.
pub fn sqrt_price_q96_to_f64(x: U256, token_0_decimals: u32, token_1_decimals: u32) -> f64 {
    assert!(x <= MAX_U160);
    let token_correction = 10f64.powi(token_0_decimals as i32 - token_1_decimals as i32);

    let price = u256_to_f64(x) / 2.0f64.powi(96);
    price.powi(2) * token_correction
}

#[cfg(test)]
mod tests {
    use approx::assert_ulps_eq;

    use super::*;

    struct TestCase {
        sqrt_price: U256,
        token_0_decimals: u32,
        token_1_decimals: u32,
        expected: f64,
    }

    #[test]
    fn test_q96_to_f64() {
        let cases = vec![
            // USDC/ETH
            TestCase {
                sqrt_price: U256::from_dec_str("2209221051636112667296733914466103").unwrap(),
                token_0_decimals: 6,
                token_1_decimals: 18,
                expected: 0.0007775336231174711f64,
            },
            // WBTC/ETH
            TestCase {
                sqrt_price: U256::from_dec_str("29654479368916176338227069900580738").unwrap(),
                token_0_decimals: 8,
                token_1_decimals: 18,
                expected: 14.00946143160293f64,
            },
            // WDOGE/ETH
            TestCase {
                sqrt_price: U256::from_dec_str("672045190479078414067608947").unwrap(),
                token_0_decimals: 18,
                token_1_decimals: 18,
                expected: 7.195115788867147e-5,
            },
            //SHIB/USDC
            TestCase {
                sqrt_price: U256::from_dec_str("231479673319799999440").unwrap(),
                token_0_decimals: 18,
                token_1_decimals: 6,
                expected: 8.536238764169166e-6,
            },
            // MIN Price
            TestCase {
                sqrt_price: U256::from(4295128740u64),
                token_0_decimals: 18,
                token_1_decimals: 18,
                expected: 2.9389568087743114e-39,
            },
            // MAX Price
            TestCase {
                sqrt_price: U256::from_dec_str("1461446703485210103287273052203988822378723970341")
                    .unwrap(),
                token_0_decimals: 18,
                token_1_decimals: 18,
                expected: 3.402567868363881e+38,
            },
        ];
        for case in cases {
            let res = sqrt_price_q96_to_f64(
                case.sqrt_price,
                case.token_0_decimals,
                case.token_1_decimals,
            );

            assert_ulps_eq!(res, case.expected, epsilon = f64::EPSILON);
        }
    }
}
