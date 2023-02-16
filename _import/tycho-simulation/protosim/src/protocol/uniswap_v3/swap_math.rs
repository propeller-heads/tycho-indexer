use ethers::types::{I256, U256};

use super::{
    solidity_math::{mul_div, mul_div_rounding_up},
    sqrt_price_math,
};

pub fn compute_swap_step(
    sqrt_ratio_current: U256,
    sqrt_ratio_target: U256,
    liquidity: u128,
    amount_remaining: I256,
    fee_pips: u32,
) -> (U256, U256, U256, U256) {
    let zero_for_one = sqrt_ratio_current >= sqrt_ratio_target;
    let exact_in = amount_remaining >= I256::zero();
    let sqrt_ratio_next: U256;
    let mut amount_in = U256::zero();
    let mut amount_out = U256::zero();
    let fee_amount: U256;

    if exact_in {
        let amount_remaining_less_fee = mul_div(
            amount_remaining.into_raw(),
            U256::from(1_000_000 - fee_pips),
            U256::from(1_000_000),
        );
        amount_in = if zero_for_one {
            sqrt_price_math::get_amount0_delta(
                sqrt_ratio_target,
                sqrt_ratio_current,
                liquidity,
                true,
            )
        } else {
            sqrt_price_math::get_amount1_delta(
                sqrt_ratio_current,
                sqrt_ratio_target,
                liquidity,
                true,
            )
        };
        if amount_remaining_less_fee >= amount_in {
            sqrt_ratio_next = sqrt_ratio_target
        } else {
            sqrt_ratio_next = sqrt_price_math::get_next_sqrt_price_from_input(
                sqrt_ratio_current,
                liquidity,
                amount_remaining_less_fee,
                zero_for_one,
            )
        }
    } else {
        amount_out = if zero_for_one {
            sqrt_price_math::get_amount1_delta(
                sqrt_ratio_target,
                sqrt_ratio_current,
                liquidity,
                false,
            )
        } else {
            sqrt_price_math::get_amount0_delta(
                sqrt_ratio_current,
                sqrt_ratio_target,
                liquidity,
                false,
            )
        };
        if amount_remaining.abs().into_raw() > amount_out {
            sqrt_ratio_next = sqrt_ratio_target;
        } else {
            sqrt_ratio_next = sqrt_price_math::get_next_sqrt_price_from_output(
                sqrt_ratio_current,
                liquidity,
                amount_remaining.abs().into_raw(),
                zero_for_one,
            );
        }
    }

    let max = sqrt_ratio_target == sqrt_ratio_next;

    if zero_for_one {
        amount_in = if max && exact_in {
            amount_in
        } else {
            sqrt_price_math::get_amount0_delta(sqrt_ratio_next, sqrt_ratio_current, liquidity, true)
        };
        amount_out = if max && !exact_in {
            amount_out
        } else {
            sqrt_price_math::get_amount1_delta(
                sqrt_ratio_next,
                sqrt_ratio_current,
                liquidity,
                false,
            )
        }
    } else {
        amount_in = if max && exact_in {
            amount_in
        } else {
            sqrt_price_math::get_amount1_delta(sqrt_ratio_current, sqrt_ratio_next, liquidity, true)
        };
        amount_out = if max && !exact_in {
            amount_out
        } else {
            sqrt_price_math::get_amount0_delta(
                sqrt_ratio_current,
                sqrt_ratio_next,
                liquidity,
                false,
            )
        };
    }

    if !exact_in && amount_out > amount_remaining.abs().into_raw() {
        amount_out = amount_remaining.abs().into_raw();
    }

    if exact_in && sqrt_ratio_next != sqrt_ratio_target {
        fee_amount = amount_remaining.abs().into_raw() - amount_in;
    } else {
        fee_amount = mul_div_rounding_up(
            amount_in,
            U256::from(fee_pips),
            U256::from(1_000_000 - fee_pips),
        )
    }
    return (sqrt_ratio_next, amount_in, amount_out, fee_amount);
}

#[cfg(test)]
mod tests {
    use std::ops::Neg;

    use crate::protocol::uniswap_v3::enums::FeeAmount;

    use super::*;

    struct TestCase {
        price: U256,
        target: U256,
        liquidity: u128,
        remaining: I256,
        fee: FeeAmount,
        exp: (U256, U256, U256, U256),
    }

    #[test]
    fn test_compute_swap_step() {
        let cases = vec![
            TestCase {
                price: U256::from_dec_str("1917240610156820439288675683655550").unwrap(),
                target: U256::from_dec_str("1919023616462402511535565081385034").unwrap(),
                liquidity: 23130341825817804069u128,
                remaining: I256::exp10(18),
                fee: FeeAmount::Low,
                exp: (
                    U256::from_dec_str("1917244033735642980420262835667387").unwrap(),
                    U256::from_dec_str("999500000000000000").unwrap(),
                    U256::from_dec_str("1706820897").unwrap(),
                    U256::from_dec_str("500000000000000").unwrap(),
                ),
            },
            TestCase {
                price: U256::from_dec_str("1917240610156820439288675683655550").unwrap(),
                target: U256::from_dec_str("1919023616462402511535565081385034").unwrap(),
                liquidity: 23130341825817804069u128,
                remaining: I256::exp10(18).neg(),
                fee: FeeAmount::Low,
                exp: (
                    U256::from_dec_str("1919023616462402511535565081385034").unwrap(),
                    U256::from_dec_str("520541484453545253034").unwrap(),
                    U256::from_dec_str("888091216672").unwrap(),
                    U256::from_dec_str("260400942698121688").unwrap(),
                ),
            },
            TestCase {
                price: U256::from_dec_str("1917240610156820439288675683655550").unwrap(),
                target: U256::from_dec_str("1908498483466244238266951834509291").unwrap(),
                liquidity: 23130341825817804069u128,
                remaining: I256::exp10(18).neg(),
                fee: FeeAmount::Low,
                exp: (
                    U256::from_dec_str("1917237184865352164019453920762266").unwrap(),
                    U256::from_dec_str("1707680836").unwrap(),
                    U256::from_dec_str("1000000000000000000").unwrap(),
                    U256::from_dec_str("854268").unwrap(),
                ),
            },
            TestCase {
                price: U256::from_dec_str("1917240610156820439288675683655550").unwrap(),
                target: U256::from_dec_str("1908498483466244238266951834509291").unwrap(),
                liquidity: 23130341825817804069u128,
                remaining: I256::exp10(18),
                fee: FeeAmount::Low,
                exp: (
                    U256::from_dec_str("1908498483466244238266951834509291").unwrap(),
                    U256::from_dec_str("4378348149175").unwrap(),
                    U256::from_dec_str("2552228553845698906796").unwrap(),
                    U256::from_dec_str("2190269210").unwrap(),
                ),
            },
            TestCase {
                price: U256::from_dec_str("1917240610156820439288675683655550").unwrap(),
                target: U256::from_dec_str("1908498483466244238266951834509291").unwrap(),
                liquidity: 0u128,
                remaining: I256::exp10(18),
                fee: FeeAmount::Low,
                exp: (
                    U256::from_dec_str("1908498483466244238266951834509291").unwrap(),
                    U256::from_dec_str("1").unwrap(),
                    U256::from_dec_str("0").unwrap(),
                    U256::from_dec_str("1").unwrap(),
                ),
            },
        ];

        for case in cases {
            let res = compute_swap_step(
                case.price,
                case.target,
                case.liquidity,
                case.remaining,
                case.fee as u32,
            );

            assert_eq!(res, case.exp);
        }
    }
}
