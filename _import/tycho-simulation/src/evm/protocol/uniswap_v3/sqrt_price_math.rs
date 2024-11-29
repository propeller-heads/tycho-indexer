use ethers::types::U256;

use crate::{
    protocol::errors::SimulationError,
    safe_math::{safe_add_u256, safe_div_u256, safe_mul_u256, safe_sub_u256},
    u256_num::u256_to_f64,
};

use super::solidity_math::{mul_div, mul_div_rounding_up};

const Q96: U256 = U256([0, 4294967296, 0, 0]);
const RESOLUTION: U256 = U256([96, 0, 0, 0]);
const U160_MAX: U256 = U256([u64::MAX, u64::MAX, 4294967295, 0]);

fn maybe_flip_ratios(a: U256, b: U256) -> (U256, U256) {
    if a > b {
        (b, a)
    } else {
        (a, b)
    }
}

fn div_rounding_up(a: U256, b: U256) -> Result<U256, SimulationError> {
    let (result, rest) = a.div_mod(b);
    if rest > U256::zero() {
        let res = safe_add_u256(result, U256::one())?;
        Ok(res)
    } else {
        Ok(result)
    }
}

pub fn get_amount0_delta(
    a: U256,
    b: U256,
    liquidity: u128,
    round_up: bool,
) -> Result<U256, SimulationError> {
    let (sqrt_ratio_a, sqrt_ratio_b) = maybe_flip_ratios(a, b);

    let numerator1 = U256::from(liquidity) << RESOLUTION;
    let numerator2 = sqrt_ratio_b - sqrt_ratio_a;

    assert!(sqrt_ratio_a > U256::zero());

    if round_up {
        div_rounding_up(mul_div_rounding_up(numerator1, numerator2, sqrt_ratio_b)?, sqrt_ratio_a)
    } else {
        safe_div_u256(mul_div_rounding_up(numerator1, numerator2, sqrt_ratio_b)?, sqrt_ratio_a)
    }
}

pub fn get_amount1_delta(
    a: U256,
    b: U256,
    liquidity: u128,
    round_up: bool,
) -> Result<U256, SimulationError> {
    let (sqrt_ratio_a, sqrt_ratio_b) = maybe_flip_ratios(a, b);
    if round_up {
        mul_div_rounding_up(U256::from(liquidity), sqrt_ratio_b - sqrt_ratio_a, Q96)
    } else {
        safe_div_u256(
            safe_mul_u256(U256::from(liquidity), safe_sub_u256(sqrt_ratio_b, sqrt_ratio_a)?)?,
            Q96,
        )
    }
}

pub fn get_next_sqrt_price_from_input(
    sqrt_price: U256,
    liquidity: u128,
    amount_in: U256,
    zero_for_one: bool,
) -> Result<U256, SimulationError> {
    assert!(sqrt_price > U256::zero());

    if zero_for_one {
        Ok(get_next_sqrt_price_from_amount0_rounding_up(sqrt_price, liquidity, amount_in, true)?)
    } else {
        Ok(get_next_sqrt_price_from_amount1_rounding_down(sqrt_price, liquidity, amount_in, true)?)
    }
}

pub fn get_next_sqrt_price_from_output(
    sqrt_price: U256,
    liquidity: u128,
    amount_in: U256,
    zero_for_one: bool,
) -> Result<U256, SimulationError> {
    assert!(sqrt_price > U256::zero());
    assert!(liquidity > 0);

    if zero_for_one {
        Ok(get_next_sqrt_price_from_amount1_rounding_down(sqrt_price, liquidity, amount_in, false)?)
    } else {
        Ok(get_next_sqrt_price_from_amount0_rounding_up(sqrt_price, liquidity, amount_in, false)?)
    }
}

fn get_next_sqrt_price_from_amount0_rounding_up(
    sqrt_price: U256,
    liquidity: u128,
    amount: U256,
    add: bool,
) -> Result<U256, SimulationError> {
    if amount == U256::zero() {
        return Ok(sqrt_price);
    }
    let numerator1 = U256::from(liquidity) << RESOLUTION;

    if add {
        let (product, _) = amount.overflowing_mul(sqrt_price);
        if product / amount == sqrt_price {
            // No overflow case: liquidity * sqrtPX96 / (liquidity +- amount * sqrtPX96)
            let denominator = safe_add_u256(numerator1, product)?;
            if denominator >= numerator1 {
                return mul_div_rounding_up(numerator1, sqrt_price, denominator);
            }
        }
        // Overflow: liquidity / (liquidity / sqrtPX96 +- amount)
        div_rounding_up(numerator1, safe_add_u256(safe_div_u256(numerator1, sqrt_price)?, amount)?)
    } else {
        let (product, _) = amount.overflowing_mul(sqrt_price);
        assert!(safe_div_u256(product, amount)? == sqrt_price && numerator1 > product);
        let denominator = safe_sub_u256(numerator1, product)?;
        // No overflow case: liquidity * sqrtPX96 / (liquidity +- amount * sqrtPX96)
        mul_div_rounding_up(numerator1, sqrt_price, denominator)
    }
}

fn get_next_sqrt_price_from_amount1_rounding_down(
    sqrt_price: U256,
    liquidity: u128,
    amount: U256,
    add: bool,
) -> Result<U256, SimulationError> {
    if add {
        let quotient = if amount <= U160_MAX {
            safe_div_u256(amount << RESOLUTION, U256::from(liquidity))
        } else {
            mul_div(amount, Q96, U256::from(liquidity))
        };

        safe_add_u256(sqrt_price, quotient?)
    } else {
        let quotient = if amount <= U160_MAX {
            div_rounding_up(amount << RESOLUTION, U256::from(liquidity))?
        } else {
            mul_div_rounding_up(amount, Q96, U256::from(liquidity))?
        };

        assert!(sqrt_price > quotient);
        safe_sub_u256(sqrt_price, quotient)
    }
}

/// Converts a sqrt price in Q96 representation to its approximate f64 representation
///
/// # Panics
/// Will panic if the `x` is bigger than U160.
pub fn sqrt_price_q96_to_f64(x: U256, token_0_decimals: u32, token_1_decimals: u32) -> f64 {
    assert!(x < U160_MAX);
    let token_correction = 10f64.powi(token_0_decimals as i32 - token_1_decimals as i32);

    let price = u256_to_f64(x) / 2.0f64.powi(96);
    price.powi(2) * token_correction
}

#[cfg(test)]
mod tests {
    use super::*;
    use approx::assert_ulps_eq;
    use rstest::rstest;

    fn u256(s: &str) -> U256 {
        U256::from_dec_str(s).unwrap()
    }

    #[test]
    fn test_maybe_flip() {
        let a = U256::from_dec_str("646922711029656030980122427077").unwrap();
        let b = U256::from_dec_str("78833030112140176575862854579").unwrap();
        let (a1, b1) = maybe_flip_ratios(a, b);

        assert_eq!(b, a1);
        assert_eq!(a, b1);
    }

    #[rstest]
    #[case(
        u256("646922711029656030980122427077"),
        u256("78833030112140176575862854579"),
        1000000000000u128,
        true,
        u256("882542983628")
    )]
    #[case(
        u256("646922711029656030980122427077"),
        u256("78833030112140176575862854579"),
        1000000000000u128,
        false,
        u256("882542983627")
    )]
    #[case(
        u256("79224201403219477170569942574"),
        u256("79394708140106462983274643745"),
        10000000u128,
        true,
        u256("21477")
    )]
    #[case(
        u256("79224201403219477170569942574"),
        u256("79394708140106462983274643745"),
        10000000u128,
        false,
        u256("21476")
    )]
    fn test_get_amount0_delta(
        #[case] a: U256,
        #[case] b: U256,
        #[case] liquidity: u128,
        #[case] round_up: bool,
        #[case] exp: U256,
    ) {
        let res = get_amount0_delta(a, b, liquidity, round_up).unwrap();
        assert_eq!(res, exp);
    }

    #[rstest]
    #[case(
        u256("79224201403219477170569942574"),
        u256("79394708140106462983274643745"),
        10000000u128,
        true,
        u256("21521")
    )]
    #[case(
        u256("79224201403219477170569942574"),
        u256("79394708140106462983274643745"),
        10000000u128,
        false,
        u256("21520")
    )]
    #[case(
        u256("646922711029656030980122427077"),
        u256("78833030112140176575862854579"),
        1000000000000u128,
        true,
        u256("7170299838965")
    )]
    #[case(
        u256("646922711029656030980122427077"),
        u256("78833030112140176575862854579"),
        1000000000000u128,
        false,
        u256("7170299838964")
    )]
    fn test_get_amount1_delta(
        #[case] a: U256,
        #[case] b: U256,
        #[case] liquidity: u128,
        #[case] round_up: bool,
        #[case] exp: U256,
    ) {
        let res = get_amount1_delta(a, b, liquidity, round_up).unwrap();
        assert_eq!(res, exp);
    }

    #[rstest]
    #[case(
        u256("79224201403219477170569942574"),
        1000000000000u128,
        u256("1000000"),
        true,
        u256("79224122183058203155816882540")
    )]
    #[case(
        u256("79224201403219477170569942574"),
        1000000000000u128,
        u256("1000000"),
        false,
        u256("79224280631381991434907536117")
    )]
    fn test_get_next_sqrt_price_from_input(
        #[case] sqrt_price: U256,
        #[case] liquidity: u128,
        #[case] amount_in: U256,
        #[case] zero_for_one: bool,
        #[case] exp: U256,
    ) {
        let res =
            get_next_sqrt_price_from_input(sqrt_price, liquidity, amount_in, zero_for_one).unwrap();
        assert_eq!(res, exp);
    }

    #[rstest]
    #[case(
        u256("79224201403219477170569942574"),
        1000000000000u128,
        u256("1000000"),
        true,
        u256("79224122175056962906232349030")
    )]
    #[case(
        u256("79224201403219477170569942574"),
        1000000000000u128,
        u256("1000000"),
        false,
        u256("79224280623539183744873644932")
    )]
    fn test_get_next_sqrt_price_from_output(
        #[case] sqrt_price: U256,
        #[case] liquidity: u128,
        #[case] amount_in: U256,
        #[case] zero_for_one: bool,
        #[case] exp: U256,
    ) {
        let res = get_next_sqrt_price_from_output(sqrt_price, liquidity, amount_in, zero_for_one)
            .unwrap();
        assert_eq!(res, exp);
    }

    #[rstest]
    #[case::usdc_eth(u256("2209221051636112667296733914466103"), 6, 18, 0.0007775336231174711f64)]
    #[case::wbtc_eth(u256("29654479368916176338227069900580738"), 8, 18, 14.00946143160293f64)]
    #[case::wdoge_eth(u256("672045190479078414067608947"), 18, 18, 7.195115788867147e-5)]
    #[case::shib_usdc(u256("231479673319799999440"), 18, 6, 8.536238764169166e-6)]
    #[case::min_price(u256("4295128740"), 18, 18, 2.9389568087743114e-39f64)]
    #[case::max_price(
        u256("1461446703485210103287273052203988822378723970341"),
        18,
        18,
        3.402_567_868_363_881e38_f64
    )]
    fn test_q96_to_f64(
        #[case] sqrt_price: U256,
        #[case] t0d: u32,
        #[case] t1d: u32,
        #[case] exp: f64,
    ) {
        let res = sqrt_price_q96_to_f64(sqrt_price, t0d, t1d);

        assert_ulps_eq!(res, exp, epsilon = f64::EPSILON);
    }
}
