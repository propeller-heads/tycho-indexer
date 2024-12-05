//! Safe Math
//!
//! This module contains basic functions to perform arithmetic operations on
//! numerical types of the ethers crate and preventing them from overflowing.
//! Should an operation cause an overflow a result containing TradeSimulationError
//! will be returned.
//! Functions for the types I256, U256, U512 are available.
use crate::protocol::errors::SimulationError;
use alloy_primitives::{I256, U256, U512};

pub fn safe_mul_u256(a: U256, b: U256) -> Result<U256, SimulationError> {
    let res = a.checked_mul(b);
    _construc_result_u256(res)
}

pub fn safe_div_u256(a: U256, b: U256) -> Result<U256, SimulationError> {
    let res = a.checked_div(b);
    _construc_result_u256(res)
}

pub fn safe_add_u256(a: U256, b: U256) -> Result<U256, SimulationError> {
    let res = a.checked_add(b);
    _construc_result_u256(res)
}

pub fn safe_sub_u256(a: U256, b: U256) -> Result<U256, SimulationError> {
    let res = a.checked_sub(b);
    _construc_result_u256(res)
}

pub fn div_mod_u256(a: U256, b: U256) -> Result<(U256, U256), SimulationError> {
    if b.is_zero() {
        return Err(SimulationError::FatalError("Division by zero".to_string()));
    }
    let result = a / b;
    let rest = a % b;
    Ok((result, rest))
}

pub fn _construc_result_u256(res: Option<U256>) -> Result<U256, SimulationError> {
    match res {
        None => Err(SimulationError::FatalError("U256 arithmetic overflow".to_string())),
        Some(value) => Ok(value),
    }
}

pub fn safe_mul_u512(a: U512, b: U512) -> Result<U512, SimulationError> {
    let res = a.checked_mul(b);
    _construc_result_u512(res)
}

pub fn safe_div_u512(a: U512, b: U512) -> Result<U512, SimulationError> {
    let res = a.checked_div(b);
    _construc_result_u512(res)
}

pub fn safe_add_u512(a: U512, b: U512) -> Result<U512, SimulationError> {
    let res = a.checked_add(b);
    _construc_result_u512(res)
}

pub fn safe_sub_u512(a: U512, b: U512) -> Result<U512, SimulationError> {
    let res = a.checked_sub(b);
    _construc_result_u512(res)
}

pub fn div_mod_u512(a: U512, b: U512) -> Result<(U512, U512), SimulationError> {
    if b.is_zero() {
        return Err(SimulationError::FatalError("Division by zero".to_string()));
    }
    let result = a / b;
    let rest = a % b;
    Ok((result, rest))
}

pub fn _construc_result_u512(res: Option<U512>) -> Result<U512, SimulationError> {
    match res {
        None => Err(SimulationError::FatalError("U256 arithmetic overflow".to_string())),
        Some(value) => Ok(value),
    }
}

pub fn safe_mul_i256(a: I256, b: I256) -> Result<I256, SimulationError> {
    let res = a.checked_mul(b);
    _construc_result_i256(res)
}

pub fn safe_div_i256(a: I256, b: I256) -> Result<I256, SimulationError> {
    let res = a.checked_div(b);
    _construc_result_i256(res)
}

pub fn safe_add_i256(a: I256, b: I256) -> Result<I256, SimulationError> {
    let res = a.checked_add(b);
    _construc_result_i256(res)
}

pub fn safe_sub_i256(a: I256, b: I256) -> Result<I256, SimulationError> {
    let res = a.checked_sub(b);
    _construc_result_i256(res)
}

pub fn _construc_result_i256(res: Option<I256>) -> Result<I256, SimulationError> {
    match res {
        None => Err(SimulationError::FatalError("U256 arithmetic overflow".to_string())),
        Some(value) => Ok(value),
    }
}

#[cfg(test)]
mod safe_math_tests {
    use super::*;
    use std::str::FromStr;

    use rstest::rstest;

    const U256_MAX: U256 = U256::from_limbs([u64::MAX, u64::MAX, u64::MAX, u64::MAX]);
    const U512_MAX: U512 = U512::from_limbs([
        u64::MAX,
        u64::MAX,
        u64::MAX,
        u64::MAX,
        u64::MAX,
        u64::MAX,
        u64::MAX,
        u64::MAX,
    ]);
    /// I256 maximum value: 2^255 - 1
    const I256_MAX: I256 = I256::from_raw(U256::from_limbs([
        u64::MAX,
        u64::MAX,
        u64::MAX,
        9223372036854775807u64, // 2^63 - 1 in the highest limb
    ]));

    /// I256 minimum value: -2^255
    const I256_MIN: I256 = I256::from_raw(U256::from_limbs([
        0,
        0,
        0,
        9223372036854775808u64, // 2^63 in the highest limb
    ]));

    fn u256(s: &str) -> U256 {
        U256::from_str(s).unwrap()
    }

    #[rstest]
    #[case(U256_MAX, u256("2"), true, false, u256("0"))]
    #[case(u256("3"), u256("2"), false, true, u256("6"))]
    fn test_safe_mul_u256(
        #[case] a: U256,
        #[case] b: U256,
        #[case] is_err: bool,
        #[case] is_ok: bool,
        #[case] expected: U256,
    ) {
        let res = safe_mul_u256(a, b);
        assert_eq!(res.is_err(), is_err);
        assert_eq!(res.is_ok(), is_ok);

        if is_ok {
            assert_eq!(res.unwrap(), expected);
        }
    }

    #[rstest]
    #[case(U256_MAX, u256("2"), true, false, u256("0"))]
    #[case(u256("3"), u256("2"), false, true, u256("5"))]
    fn test_safe_add_u256(
        #[case] a: U256,
        #[case] b: U256,
        #[case] is_err: bool,
        #[case] is_ok: bool,
        #[case] expected: U256,
    ) {
        let res = safe_add_u256(a, b);
        assert_eq!(res.is_err(), is_err);
        assert_eq!(res.is_ok(), is_ok);

        if is_ok {
            assert_eq!(res.unwrap(), expected);
        }
    }

    #[rstest]
    #[case(u256("0"), u256("2"), true, false, u256("0"))]
    #[case(u256("10"), u256("2"), false, true, u256("8"))]
    fn test_safe_sub_u256(
        #[case] a: U256,
        #[case] b: U256,
        #[case] is_err: bool,
        #[case] is_ok: bool,
        #[case] expected: U256,
    ) {
        let res = safe_sub_u256(a, b);
        assert_eq!(res.is_err(), is_err);
        assert_eq!(res.is_ok(), is_ok);

        if is_ok {
            assert_eq!(res.unwrap(), expected);
        }
    }

    #[rstest]
    #[case(u256("1"), u256("0"), true, false, u256("0"))]
    #[case(u256("10"), u256("2"), false, true, u256("5"))]
    fn test_safe_div_u256(
        #[case] a: U256,
        #[case] b: U256,
        #[case] is_err: bool,
        #[case] is_ok: bool,
        #[case] expected: U256,
    ) {
        let res = safe_div_u256(a, b);
        assert_eq!(res.is_err(), is_err);
        assert_eq!(res.is_ok(), is_ok);

        if is_ok {
            assert_eq!(res.unwrap(), expected);
        }
    }

    fn u512(s: &str) -> U512 {
        U512::from_str(s).unwrap()
    }

    #[rstest]
    #[case(U512_MAX, u512("2"), true, false, u512("0"))]
    #[case(u512("3"), u512("2"), false, true, u512("6"))]
    fn test_safe_mul_u512(
        #[case] a: U512,
        #[case] b: U512,
        #[case] is_err: bool,
        #[case] is_ok: bool,
        #[case] expected: U512,
    ) {
        let res = safe_mul_u512(a, b);
        assert_eq!(res.is_err(), is_err);
        assert_eq!(res.is_ok(), is_ok);

        if is_ok {
            assert_eq!(res.unwrap(), expected);
        }
    }

    #[rstest]
    #[case(U512_MAX, u512("2"), true, false, u512("0"))]
    #[case(u512("3"), u512("2"), false, true, u512("5"))]
    fn test_safe_add_u512(
        #[case] a: U512,
        #[case] b: U512,
        #[case] is_err: bool,
        #[case] is_ok: bool,
        #[case] expected: U512,
    ) {
        let res = safe_add_u512(a, b);
        assert_eq!(res.is_err(), is_err);
        assert_eq!(res.is_ok(), is_ok);

        if is_ok {
            assert_eq!(res.unwrap(), expected);
        }
    }

    #[rstest]
    #[case(u512("0"), u512("2"), true, false, u512("0"))]
    #[case(u512("10"), u512("2"), false, true, u512("8"))]
    fn test_safe_sub_u512(
        #[case] a: U512,
        #[case] b: U512,
        #[case] is_err: bool,
        #[case] is_ok: bool,
        #[case] expected: U512,
    ) {
        let res = safe_sub_u512(a, b);
        assert_eq!(res.is_err(), is_err);
        assert_eq!(res.is_ok(), is_ok);

        if is_ok {
            assert_eq!(res.unwrap(), expected);
        }
    }

    #[rstest]
    #[case(u512("1"), u512("0"), true, false, u512("0"))]
    #[case(u512("10"), u512("2"), false, true, u512("5"))]
    fn test_safe_div_u512(
        #[case] a: U512,
        #[case] b: U512,
        #[case] is_err: bool,
        #[case] is_ok: bool,
        #[case] expected: U512,
    ) {
        let res = safe_div_u512(a, b);
        assert_eq!(res.is_err(), is_err);
        assert_eq!(res.is_ok(), is_ok);

        if is_ok {
            assert_eq!(res.unwrap(), expected);
        }
    }

    fn i256(s: &str) -> I256 {
        I256::from_str(s).unwrap()
    }

    #[rstest]
    #[case(I256_MAX, i256("2"), true, false, i256("0"))]
    #[case(i256("3"), i256("2"), false, true, i256("6"))]
    fn test_safe_mul_i256(
        #[case] a: I256,
        #[case] b: I256,
        #[case] is_err: bool,
        #[case] is_ok: bool,
        #[case] expected: I256,
    ) {
        let res = safe_mul_i256(a, b);
        assert_eq!(res.is_err(), is_err);
        assert_eq!(res.is_ok(), is_ok);

        if is_ok {
            assert_eq!(res.unwrap(), expected);
        }
    }

    #[rstest]
    #[case(I256_MAX, i256("2"), true, false, i256("0"))]
    #[case(i256("3"), i256("2"), false, true, i256("5"))]
    fn test_safe_add_i256(
        #[case] a: I256,
        #[case] b: I256,
        #[case] is_err: bool,
        #[case] is_ok: bool,
        #[case] expected: I256,
    ) {
        let res = safe_add_i256(a, b);
        assert_eq!(res.is_err(), is_err);
        assert_eq!(res.is_ok(), is_ok);

        if is_ok {
            assert_eq!(res.unwrap(), expected);
        }
    }

    #[rstest]
    #[case(I256_MIN, i256("2"), true, false, i256("0"))]
    #[case(i256("10"), i256("2"), false, true, i256("8"))]
    fn test_safe_sub_i256(
        #[case] a: I256,
        #[case] b: I256,
        #[case] is_err: bool,
        #[case] is_ok: bool,
        #[case] expected: I256,
    ) {
        let res = safe_sub_i256(a, b);
        assert_eq!(res.is_err(), is_err);
        assert_eq!(res.is_ok(), is_ok);

        if is_ok {
            assert_eq!(res.unwrap(), expected);
        }
    }

    #[rstest]
    #[case(i256("1"), i256("0"), true, false, i256("0"))]
    #[case(i256("10"), i256("2"), false, true, i256("5"))]
    fn test_safe_div_i256(
        #[case] a: I256,
        #[case] b: I256,
        #[case] is_err: bool,
        #[case] is_ok: bool,
        #[case] expected: I256,
    ) {
        let res = safe_div_i256(a, b);
        assert_eq!(res.is_err(), is_err);
        assert_eq!(res.is_ok(), is_ok);

        if is_ok {
            assert_eq!(res.unwrap(), expected);
        }
    }
}
