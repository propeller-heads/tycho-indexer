use ethers::{
    prelude::k256::sha2::digest::typenum::Pow,
    types::{U256, U512},
};

const MAX_U160: U256 = U256([0, 0, 4294967296, 0]);

/// Converts a sqrt price in Q96 representation to its approximate f64 representation
///
/// # Panics
/// Will panic if the `x` is bigger than U160. Or if an overflow is encountered when calculating `x**2`.
///
/// # Note
/// The conversion here is not losless and the obtained f64 value is just an approximation of the actual price.
pub fn sqrt_price_q96_to_f64(x: U256, token_0_decimals: u32, token_1_decimals: u32) -> f64 {
    assert!(x <= MAX_U160);
    let token_correction = 10f64.powi(token_0_decimals as i32 - token_1_decimals as i32);
    let price = U512::from(x).pow(U512::from(2));

    // shift right so the whole 64 numerator bits are filled - maximizing precision
    // note that we loose precision with a right shift
    let price_bits = price.bits();
    // theoretically price bits can be between 0 and 256...
    // if it is between 0 and 64 we don't have to compress things
    // we can simply divide by 2e192f64
    // TODO: should we short circuit if price_bits <= 64?
    // Currently we would probably inflate denom pow if it was < 64 unecessarily...
    let shr_b = price_bits - 64;
    if shr_b < 192 {
        // price is < 1.0, we assume nomin < denom
        // we use the formula price = (x^2) >> shr_b /(2^(192 - shr_b))
        let denom_pow = 192 - shr_b;

        let res = (price >> shr_b).as_u64() as f64;
        let denom = 2f64.powi(denom_pow as i32);
        res as f64 / denom * token_correction
    } else {
        // price >= 1.0, we assume nomin >= denom
        // we use the formula price = 2^2 * (x/2)^2 / 2^192
        // assuming price uses 320 bits we would need to do a
        // right shift by 320 - 64 = 256 bits we would need to
        // do the same for denom which would result in 0
        // We need to make the nominator use <= 32 bits then we can use previous formula and multiply the result with a power of 2
        // so if we use 320 bits, we shift right by 288 and then square now we should use at most 64 bits
        // the shift by 288 we have to convert into an additional factor price = x^2 = (2^288 * x/2^288)^2 = 2^288^2 * (x/2^288)^2
        let x_bits = x.bits();
        let shr_b2 = x_bits - 64;
        let factor = 2f64.powi(shr_b2 as i32);
        let nomin = (x >> shr_b2).as_u64() as f64;
        (factor * (nomin / 2f64.powi(96))).powi(2)
    }
}

#[cfg(test)]
mod tests {
    use approx::{assert_ulps_eq, relative_eq, ulps_eq};

    use super::*;
    // TODO test case were precision is negative

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
