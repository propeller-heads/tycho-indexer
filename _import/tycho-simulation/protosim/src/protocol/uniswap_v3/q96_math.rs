use ethers::types::U256;

const MAX_U160: U256 = U256([0, 0, 4294967296, 0]);

/// Converts a sqrt price in Q96 representation to its approximate f64 representation
///
/// # Panics
/// Will panic if the `x` is bigger than U160. Or if an overflow is encountered when calculating `x**2`.
///
/// # Note
/// The conversion here is not losless and the obtained f64 value is just an approximation of the actual price.
/// Max epsilon is 2^32/2^96 = 2^-64
pub fn sqrt_price_q96_to_f64(x: U256, token_0_decimals: u32, token_1_decimals: u32) -> f64 {
    assert!(x <= MAX_U160);
    let token_correction = 10f64.powi(token_0_decimals as i32 - token_1_decimals as i32);

    // if x.bits() < 128 it's square will not exceed 256
    let price = if x.bits() < 128 {
        // price is < 1.0, we assume nomin < denom
        // price = sqrt(price)^2
        // sqrt(price) = x / 2**96 ≈ x >> shr_b / 2^(96 - shr_b)
        // shr_b is chosen such that we can fit the number comfortably as a u64
        let nomin = x.as_u128() as f64;
        let denom = 2f64.powi(96);

        (nomin / denom).powi(2)
    } else {
        // price >= 1.0, we assume nomin >= denom
        // in this case above method won't work consider price uses 320 bits (=160*2)
        // we would need to do a right shift by 320 - 64 = 256 bits we would need to
        // do the same for denom which would result in 0
        // we instead will reduce the nominator in sqrt space and only square in the end
        // To reduce the nominator we do a right shift and introduce a power of two factor
        // price = sqrt(price)^2
        // sqrt(price) = x / 2^96 ≈ 2 ^ shr_b * (x >> shr_b) / 2^96
        let x_bits = x.bits();
        let shr_b = x_bits - 128;
        let factor = 2f64.powi(shr_b as i32);
        let nomin = (x >> shr_b).as_u128() as f64;
        (factor * (nomin / 2f64.powi(96))).powi(2)
    };
    price * token_correction
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
