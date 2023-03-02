//! Safe Math
//! This module contains basic functions to perform arithmetic operations on
//! numerical types of the ethers crate and preventing them from overflowing.
//! Should an operation cause an overflow a result containing TradeSimulationError
//! will be returned.
//! Functions for the types I256, U256, U512 are available.

use crate::protocol::errors::{TradeSimulationError, TradeSimulationErrorKind};
use ethers::types::{I256, U256, U512};

pub fn safe_mul_u256(a: U256, b: U256) -> Result<U256, TradeSimulationError> {
    let res = a.checked_mul(b);
    _construc_result_u256(res)
}

pub fn safe_div_u256(a: U256, b: U256) -> Result<U256, TradeSimulationError> {
    let res = a.checked_div(b);
    _construc_result_u256(res)
}

pub fn safe_add_u256(a: U256, b: U256) -> Result<U256, TradeSimulationError> {
    let res = a.checked_add(b);
    _construc_result_u256(res)
}

pub fn safe_sub_u256(a: U256, b: U256) -> Result<U256, TradeSimulationError> {
    let res = a.checked_sub(b);
    _construc_result_u256(res)
}

pub fn _construc_result_u256(res: Option<U256>) -> Result<U256, TradeSimulationError> {
    match res {
        None => Err(TradeSimulationError::new(
            TradeSimulationErrorKind::U256Overflow,
            None,
        )),
        Some(value) => Ok(value),
    }
}

pub fn safe_mul_u512(a: U512, b: U512) -> Result<U512, TradeSimulationError> {
    let res = a.checked_mul(b);
    _construc_result_u512(res)
}

pub fn safe_div_u512(a: U512, b: U512) -> Result<U512, TradeSimulationError> {
    let res = a.checked_div(b);
    _construc_result_u512(res)
}

pub fn safe_add_u512(a: U512, b: U512) -> Result<U512, TradeSimulationError> {
    let res = a.checked_add(b);
    _construc_result_u512(res)
}

pub fn safe_sub_u512(a: U512, b: U512) -> Result<U512, TradeSimulationError> {
    let res = a.checked_sub(b);
    _construc_result_u512(res)
}

pub fn _construc_result_u512(res: Option<U512>) -> Result<U512, TradeSimulationError> {
    match res {
        None => Err(TradeSimulationError::new(
            TradeSimulationErrorKind::U256Overflow,
            None,
        )),
        Some(value) => Ok(value),
    }
}

pub fn safe_mul_i256(a: I256, b: I256) -> Result<I256, TradeSimulationError> {
    let res = a.checked_mul(b);
    _construc_result_i256(res)
}

pub fn safe_div_i256(a: I256, b: I256) -> Result<I256, TradeSimulationError> {
    let res = a.checked_div(b);
    _construc_result_i256(res)
}

pub fn safe_add_i256(a: I256, b: I256) -> Result<I256, TradeSimulationError> {
    let res = a.checked_add(b);
    _construc_result_i256(res)
}

pub fn safe_sub_i256(a: I256, b: I256) -> Result<I256, TradeSimulationError> {
    let res = a.checked_sub(b);
    _construc_result_i256(res)
}

pub fn _construc_result_i256(res: Option<I256>) -> Result<I256, TradeSimulationError> {
    match res {
        None => Err(TradeSimulationError::new(
            TradeSimulationErrorKind::U256Overflow,
            None,
        )),
        Some(value) => Ok(value),
    }
}


#[cfg(test)]
mod safe_math_tests {
    use super::*;
    use rstest::rstest;

    fn u256(s: &str) -> U256 {
        U256::from_dec_str(s).unwrap()
    }

    #[rstest]
    #[case(U256::max_value(), u256("2"), true, false, u256("0"))]
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
    #[case(U256::max_value(), u256("2"), true, false, u256("0"))]
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
        U512::from_dec_str(s).unwrap()
    }

    #[rstest]
    #[case(U512::max_value(), u512("2"), true, false, u512("0"))]
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
    #[case(U512::max_value(), u512("2"), true, false, u512("0"))]
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
        I256::from_dec_str(s).unwrap()
    }

    #[rstest]
    #[case(I256::max_value(), i256("2"), true, false, i256("0"))]
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
    #[case(I256::max_value(), i256("2"), true, false, i256("0"))]
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
    #[case(I256::min_value(), i256("2"), true, false, i256("0"))]
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
