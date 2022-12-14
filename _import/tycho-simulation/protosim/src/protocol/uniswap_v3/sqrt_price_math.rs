use super::solidity_math::{mul_div, mul_div_rounding_up};
use ethers::types::U256;
const Q96: U256 = U256([0, 4294967296, 0, 0]);
const RESOLUTION: U256 = U256([96, 0, 0, 0]);
const U160_MAX: U256 = U256([u64::MAX, u64::MAX, 4294967295, 0]);

// TODO: work on types, especiall U128 and U160, currently we use U256 for those

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

pub fn get_amount0_delta(a: U256, b: U256, liquidity: u128, round_up: bool) -> U256 {
    let (sqrt_ratio_a, sqrt_ratio_b) = maybe_flip_ratios(a, b);

    let numerator1 = U256::from(liquidity) << RESOLUTION;
    let numerator2 = sqrt_ratio_b - sqrt_ratio_a;

    assert!(sqrt_ratio_a > U256::zero());

    if round_up {
        div_rounding_up(
            mul_div_rounding_up(numerator1, numerator2, sqrt_ratio_b),
            sqrt_ratio_a,
        )
    } else {
        mul_div_rounding_up(numerator1, numerator2, sqrt_ratio_b) / sqrt_ratio_a
    }
}

pub fn get_amount1_delta(a: U256, b: U256, liquidity: u128, round_up: bool) -> U256 {
    let (sqrt_ratio_a, sqrt_ratio_b) = maybe_flip_ratios(a, b);
    if round_up {
        mul_div_rounding_up(U256::from(liquidity), sqrt_ratio_b - sqrt_ratio_a, Q96)
    } else {
        (U256::from(liquidity) * (sqrt_ratio_b - sqrt_ratio_a)) / Q96
    }
}

pub fn get_next_sqrt_price_from_input(
    sqrt_price: U256,
    liquidity: u128,
    amount_in: U256,
    zero_for_one: bool,
) -> U256 {
    assert!(sqrt_price > U256::zero());
    assert!(liquidity > 0);

    if zero_for_one {
        get_next_sqrt_price_from_amount0_rounding_up(sqrt_price, liquidity, amount_in, true)
    } else {
        get_next_sqrt_price_from_amount1_rounding_down(sqrt_price, liquidity, amount_in, true)
    }
}

pub fn get_next_sqrt_price_from_output(
    sqrt_price: U256,
    liquidity: u128,
    amount_in: U256,
    zero_for_one: bool,
) -> U256 {
    assert!(sqrt_price > U256::zero());
    assert!(liquidity > 0);

    if zero_for_one {
        get_next_sqrt_price_from_amount1_rounding_down(sqrt_price, liquidity, amount_in, false)
    } else {
        get_next_sqrt_price_from_amount0_rounding_up(sqrt_price, liquidity, amount_in, false)
    }
}

fn get_next_sqrt_price_from_amount0_rounding_up(
    sqrt_price: U256,
    liquidity: u128,
    amount: U256,
    add: bool,
) -> U256 {
    if amount == U256::zero() {
        return sqrt_price;
    }
    let numerator1 = U256::from(liquidity) << RESOLUTION;

    if add {
        let (product, _) = amount.overflowing_mul(sqrt_price);
        if product / amount == sqrt_price {
            // No overflow case: liquidity * sqrtPX96 / (liquidity +- amount * sqrtPX96)
            let denominator = numerator1 + product;
            if denominator >= numerator1 {
                return mul_div_rounding_up(numerator1, sqrt_price, denominator);
            }
        }
        // Overflow: liquidity / (liquidity / sqrtPX96 +- amount)
        return div_rounding_up(numerator1, (numerator1 / sqrt_price) + amount);
    } else {
        let (product, _) = amount.overflowing_mul(sqrt_price);
        assert!(product / amount == sqrt_price && numerator1 > product);
        let denominator = numerator1 - product;
        // No overflow case: liquidity * sqrtPX96 / (liquidity +- amount * sqrtPX96)
        return mul_div_rounding_up(numerator1, sqrt_price, denominator);
    }
}

fn get_next_sqrt_price_from_amount1_rounding_down(
    sqrt_price: U256,
    liquidity: u128,
    amount: U256,
    add: bool,
) -> U256 {
    if add {
        let quotient = if amount <= U160_MAX {
            (amount << RESOLUTION) / U256::from(liquidity)
        } else {
            mul_div(amount, Q96, U256::from(liquidity))
        };

        return sqrt_price + quotient;
    } else {
        let quotient = if amount <= U160_MAX {
            div_rounding_up(amount << RESOLUTION, U256::from(liquidity))
        } else {
            mul_div_rounding_up(amount, Q96, U256::from(liquidity))
        };

        assert!(sqrt_price > quotient);
        return sqrt_price - quotient;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestCase {
        args: (U256, U256, u128, bool),
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
                    1000000000000u128,
                    true,
                ),
                exp: U256::from_dec_str("882542983628").unwrap(),
            },
            TestCase {
                args: (
                    U256::from_dec_str("646922711029656030980122427077").unwrap(),
                    U256::from_dec_str("78833030112140176575862854579").unwrap(),
                    1000000000000u128,
                    false,
                ),
                exp: U256::from_dec_str("882542983627").unwrap(),
            },
            TestCase {
                args: (
                    U256::from_dec_str("79224201403219477170569942574").unwrap(),
                    U256::from_dec_str("79394708140106462983274643745").unwrap(),
                    10000000u128,
                    true,
                ),
                exp: U256::from_dec_str("21477").unwrap(),
            },
            TestCase {
                args: (
                    U256::from_dec_str("79224201403219477170569942574").unwrap(),
                    U256::from_dec_str("79394708140106462983274643745").unwrap(),
                    10000000u128,
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
                    10000000,
                    true,
                ),
                exp: U256::from_dec_str("21521").unwrap(),
            },
            TestCase {
                args: (
                    U256::from_dec_str("79224201403219477170569942574").unwrap(),
                    U256::from_dec_str("79394708140106462983274643745").unwrap(),
                    10000000,
                    false,
                ),
                exp: U256::from_dec_str("21520").unwrap(),
            },
            TestCase {
                args: (
                    U256::from_dec_str("646922711029656030980122427077").unwrap(),
                    U256::from_dec_str("78833030112140176575862854579").unwrap(),
                    1000000000000,
                    true,
                ),
                exp: U256::from_dec_str("7170299838965").unwrap(),
            },
            TestCase {
                args: (
                    U256::from_dec_str("646922711029656030980122427077").unwrap(),
                    U256::from_dec_str("78833030112140176575862854579").unwrap(),
                    1000000000000,
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

    struct TestCase2 {
        args: (U256, u128, U256, bool),
        exp: U256,
    }
    #[test]
    fn test_get_next_sqrt_price_from_input() {
        let cases = vec![
            TestCase2 {
                args: (
                    U256::from_dec_str("79224201403219477170569942574").unwrap(),
                    1000000000000u128,
                    U256::from_dec_str("1000000").unwrap(),
                    true,
                ),
                exp: U256::from_dec_str("79224122183058203155816882540").unwrap(),
            },
            TestCase2 {
                args: (
                    U256::from_dec_str("79224201403219477170569942574").unwrap(),
                    1000000000000u128,
                    U256::from_dec_str("1000000").unwrap(),
                    false,
                ),
                exp: U256::from_dec_str("79224280631381991434907536117").unwrap(),
            },
        ];
        for case in cases {
            let res =
                get_next_sqrt_price_from_input(case.args.0, case.args.1, case.args.2, case.args.3);
            assert_eq!(res, case.exp);
        }
    }

    #[test]
    fn test_get_next_sqrt_price_from_output() {
        let cases = vec![
            TestCase2 {
                args: (
                    U256::from_dec_str("79224201403219477170569942574").unwrap(),
                    1000000000000,
                    U256::from_dec_str("1000000").unwrap(),
                    true,
                ),
                exp: U256::from_dec_str("79224122175056962906232349030").unwrap(),
            },
            TestCase2 {
                args: (
                    U256::from_dec_str("79224201403219477170569942574").unwrap(),
                    1000000000000,
                    U256::from_dec_str("1000000").unwrap(),
                    false,
                ),
                exp: U256::from_dec_str("79224280623539183744873644932").unwrap(),
            },
        ];
        for case in cases {
            let res =
                get_next_sqrt_price_from_output(case.args.0, case.args.1, case.args.2, case.args.3);
            assert_eq!(res, case.exp);
        }
    }
}
