use super::solidity_math::mul_div_rounding_up;
use ethers::types::U256;
const Q96: &str = "79228162514264337593543950336";

fn maybe_flip_ratios(a: U256, b: U256) -> (U256, U256) {
    if a > b {
        (b, a)
    } else {
        (a, b)
    }
}

fn div_rounding_up(a: U256, b: U256) -> U256 {
    let (result, rest) = a.div_mod(b);
    if rest > U256::zero() {
        return result + U256::one();
    } else {
        return result;
    }
}

pub fn get_amount0_delta(a: U256, b: U256, liquidity: U256, round_up: bool) -> U256 {
    let (sqrt_ratio_a, sqrt_ratio_b) = maybe_flip_ratios(a, b);

    let numerator1 = liquidity << U256::from(96);
    let numerator2 = sqrt_ratio_b - sqrt_ratio_a;

    if sqrt_ratio_a <= U256::zero() {
        // TODO raise an error
    }

    if round_up {
        div_rounding_up(
            mul_div_rounding_up(numerator1, numerator2, sqrt_ratio_b),
            sqrt_ratio_a,
        )
    } else {
        mul_div_rounding_up(numerator1, numerator2, sqrt_ratio_b) / sqrt_ratio_a
    }
}

pub fn get_amount1_delta(a: U256, b: U256, liquidity: U256, round_up: bool) -> U256 {
    let (sqrt_ratio_a, sqrt_ratio_b) = maybe_flip_ratios(a, b);
    let q96 = U256::from_dec_str(Q96).unwrap();
    if round_up {
        mul_div_rounding_up(liquidity, sqrt_ratio_b - sqrt_ratio_a, q96)
    } else {
        (liquidity * (sqrt_ratio_b - sqrt_ratio_a)) / q96
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestCase {
        args: (U256, U256, U256, bool),
        exp: U256,
    }

    #[test]
    fn test_maybe_flip() {
        let a = U256::from_dec_str("646922711029656030980122427077").unwrap();
        let b = U256::from_dec_str("78833030112140176575862854579").unwrap();
        let (a1, b1) = maybe_flip_ratios(a, b);

        assert_eq!(b, a1);
        assert_eq!(a, b1);
    }

    #[test]
    fn test_get_amount0_delta() {
        let cases = vec![
            TestCase {
                args: (
                    U256::from_dec_str("646922711029656030980122427077").unwrap(),
                    U256::from_dec_str("78833030112140176575862854579").unwrap(),
                    U256::from_dec_str("1000000000000").unwrap(),
                    true,
                ),
                exp: U256::from_dec_str("882542983628").unwrap(),
            },
            TestCase {
                args: (
                    U256::from_dec_str("646922711029656030980122427077").unwrap(),
                    U256::from_dec_str("78833030112140176575862854579").unwrap(),
                    U256::from_dec_str("1000000000000").unwrap(),
                    false,
                ),
                exp: U256::from_dec_str("882542983627").unwrap(),
            },
            TestCase {
                args: (
                    U256::from_dec_str("79224201403219477170569942574").unwrap(),
                    U256::from_dec_str("79394708140106462983274643745").unwrap(),
                    U256::from_dec_str("10000000").unwrap(),
                    true,
                ),
                exp: U256::from_dec_str("21477").unwrap(),
            },
            TestCase {
                args: (
                    U256::from_dec_str("79224201403219477170569942574").unwrap(),
                    U256::from_dec_str("79394708140106462983274643745").unwrap(),
                    U256::from_dec_str("10000000").unwrap(),
                    false,
                ),
                exp: U256::from_dec_str("21476").unwrap(),
            },
        ];

        for case in cases {
            let res = get_amount0_delta(case.args.0, case.args.1, case.args.2, case.args.3);
            assert_eq!(res, case.exp);
        }
    }

    #[test]
    fn test_get_amount1_delta() {
        let cases = vec![
            TestCase {
                args: (
                    U256::from_dec_str("79224201403219477170569942574").unwrap(),
                    U256::from_dec_str("79394708140106462983274643745").unwrap(),
                    U256::from_dec_str("10000000").unwrap(),
                    true,
                ),
                exp: U256::from_dec_str("21521").unwrap(),
            },
            TestCase {
                args: (
                    U256::from_dec_str("79224201403219477170569942574").unwrap(),
                    U256::from_dec_str("79394708140106462983274643745").unwrap(),
                    U256::from_dec_str("10000000").unwrap(),
                    false,
                ),
                exp: U256::from_dec_str("21520").unwrap(),
            },
            TestCase {
                args: (
                    U256::from_dec_str("646922711029656030980122427077").unwrap(),
                    U256::from_dec_str("78833030112140176575862854579").unwrap(),
                    U256::from_dec_str("1000000000000").unwrap(),
                    true,
                ),
                exp: U256::from_dec_str("7170299838965").unwrap(),
            },
            TestCase {
                args: (
                    U256::from_dec_str("646922711029656030980122427077").unwrap(),
                    U256::from_dec_str("78833030112140176575862854579").unwrap(),
                    U256::from_dec_str("1000000000000").unwrap(),
                    false,
                ),
                exp: U256::from_dec_str("7170299838964").unwrap(),
            },
        ];
        for case in cases {
            let res = get_amount1_delta(case.args.0, case.args.1, case.args.2, case.args.3);
            assert_eq!(res, case.exp);
        }
    }
}
