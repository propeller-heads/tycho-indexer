use crate::protocol::errors::{TradeSimulationError, TradeSimulationErrorKind};
use ethers::core::k256::elliptic_curve::bigint::CheckedMul;
use ethers::core::k256::elliptic_curve::subtle::CtOption;
use ethers::types::U256;
use std::ops::{Add, Div, Mul, Sub};
use std::panic;

pub fn safe_mul<T>(a: T, b: T) -> Result<T, TradeSimulationError>
where
    T: Mul<Output = T> + panic::UnwindSafe + Copy + panic::RefUnwindSafe,
{
    let result = panic::catch_unwind(|| {
        a * b;
    });

    if result.is_ok() {
        return Ok(a * b);
    } else {
        return Err(TradeSimulationError::new(
            TradeSimulationErrorKind::U256Overflow,
            None,
        ));
    }
}

pub fn safe_div<T>(a: T, b: T) -> Result<T, TradeSimulationError>
where
    T: Div<Output = T> + panic::UnwindSafe + Copy + panic::RefUnwindSafe,
{
    let result = panic::catch_unwind(|| {
        a / b;
    });

    if result.is_ok() {
        return Ok(a / b);
    } else {
        return Err(TradeSimulationError::new(
            TradeSimulationErrorKind::U256Overflow,
            None,
        ));
    }
}
pub fn safe_add<T>(a: T, b: T) -> Result<T, TradeSimulationError>
where
    T: Add<Output = T> + panic::UnwindSafe + Copy + panic::RefUnwindSafe,
{
    let result = panic::catch_unwind(|| {
        a + b;
    });

    if result.is_ok() {
        return Ok(a + b);
    } else {
        return Err(TradeSimulationError::new(
            TradeSimulationErrorKind::U256Overflow,
            None,
        ));
    }
}

pub fn safe_sub<T>(a: T, b: T) -> Result<T, TradeSimulationError>
where
    T: Sub<Output = T> + panic::UnwindSafe + Copy + panic::RefUnwindSafe,
{
    let result = panic::catch_unwind(|| {
        a - b;
    });

    if result.is_ok() {
        return Ok(a - b);
    } else {
        return Err(TradeSimulationError::new(
            TradeSimulationErrorKind::U256Overflow,
            None,
        ));
    }
}

#[cfg(test)]
mod bracket_tests {
    use super::*;
    use ethers::prelude::ens::resolve;
    use rstest::rstest;

    fn u256(s: &str) -> U256 {
        U256::from_dec_str(s).unwrap()
    }

    #[rstest]
    #[case(U256::max_value(), u256("2"), true, false, u256("0"))]
    #[case(u256("3"), u256("2"), false, true, u256("6"))]
    fn test_safe_mul(
        #[case] a: U256,
        #[case] b: U256,
        #[case] is_err: bool,
        #[case] is_ok: bool,
        #[case] expected: U256,
    ) {
        let res = safe_mul(a, b);
        assert_eq!(res.is_err(), is_err);
        assert_eq!(res.is_ok(), is_ok);

        if is_ok {
            assert_eq!(res.unwrap(), expected);
        }
    }

    #[rstest]
    #[case(U256::max_value(), u256("2"), true, false, u256("0"))]
    #[case(u256("3"), u256("2"), false, true, u256("5"))]
    fn test_safe_add(
        #[case] a: U256,
        #[case] b: U256,
        #[case] is_err: bool,
        #[case] is_ok: bool,
        #[case] expected: U256,
    ) {
        let res = safe_add(a, b);
        assert_eq!(res.is_err(), is_err);
        assert_eq!(res.is_ok(), is_ok);

        if is_ok {
            assert_eq!(res.unwrap(), expected);
        }
    }

    #[rstest]
    #[case(u256("0"), u256("2"), true, false, u256("0"))]
    #[case(u256("10"), u256("2"), false, true, u256("8"))]
    fn test_safe_sub(
        #[case] a: U256,
        #[case] b: U256,
        #[case] is_err: bool,
        #[case] is_ok: bool,
        #[case] expected: U256,
    ) {
        let res = safe_sub(a, b);
        assert_eq!(res.is_err(), is_err);
        assert_eq!(res.is_ok(), is_ok);

        if is_ok {
            assert_eq!(res.unwrap(), expected);
        }
    }

    #[rstest]
    #[case(u256("1"), u256("0"), true, false, u256("0"))]
    #[case(u256("10"), u256("2"), false, true, u256("5"))]
    fn test_safe_div(
        #[case] a: U256,
        #[case] b: U256,
        #[case] is_err: bool,
        #[case] is_ok: bool,
        #[case] expected: U256,
    ) {
        let res = safe_div(a, b);
        assert_eq!(res.is_err(), is_err);
        assert_eq!(res.is_ok(), is_ok);

        if is_ok {
            assert_eq!(res.unwrap(), expected);
        }
    }
}
