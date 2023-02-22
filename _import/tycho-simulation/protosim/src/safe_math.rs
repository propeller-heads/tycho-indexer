use crate::protocol::errors::{TradeSimulationError, TradeSimulationErrorKind};
use ethers::types::U256;

pub fn safe_mul(a: U256, b: U256) -> Result<U256, TradeSimulationError> {
    let res = a.checked_mul(b);
    _construc_result(res)
}

pub fn safe_div(a: U256, b: U256) -> Result<U256, TradeSimulationError> {
    let res = a.checked_div(b);
    _construc_result(res)
}

pub fn safe_add(a: U256, b: U256) -> Result<U256, TradeSimulationError> {
    let res = a.checked_add(b);
    _construc_result(res)
}

pub fn safe_sub(a: U256, b: U256) -> Result<U256, TradeSimulationError> {
    let res = a.checked_sub(b);
    _construc_result(res)
}

pub fn _construc_result(res: Option<U256>) -> Result<U256, TradeSimulationError> {
    match res {
        None => Err(TradeSimulationError::new(
            TradeSimulationErrorKind::U256Overflow,
            None,
        )),
        Some(value) => Ok(value),
    }
}

#[cfg(test)]
mod bracket_tests {
    use ethers::prelude::ens::resolve;
    use super::*;
    use rstest::rstest;

    fn u256(s: &str) -> U256 {
        U256::from_dec_str(s).unwrap()
    }

    #[rstest]
    #[case(U256::max_value(), u256("2"), true, false, u256("0"))]
    #[case(u256("3"), u256("2"), false, true, u256("6"))]
    fn test_safe_mul(#[case] a: U256, #[case] b: U256, #[case] is_err: bool, #[case] is_ok: bool, #[case] expected: U256) {
        let res = safe_mul(a, b);
        assert_eq!(res.is_err(), is_err);
        assert_eq!(res.is_ok(), is_ok);

        if is_ok{
            assert_eq!(res.unwrap(), expected);
        }
    }

    #[rstest]
    #[case(U256::max_value(), u256("2"), true, false, u256("0"))]
    #[case(u256("3"), u256("2"), false, true, u256("5"))]
    fn test_safe_add(#[case] a: U256, #[case] b: U256, #[case] is_err: bool, #[case] is_ok: bool, #[case] expected: U256) {
        let res = safe_add(a, b);
        assert_eq!(res.is_err(), is_err);
        assert_eq!(res.is_ok(), is_ok);

        if is_ok{
            assert_eq!(res.unwrap(), expected);
        }
    }

    #[rstest]
    #[case(u256("0"), u256("2"), true, false, u256("0"))]
    #[case(u256("10"), u256("2"), false, true, u256("8"))]
    fn test_safe_sub(#[case] a: U256, #[case] b: U256, #[case] is_err: bool, #[case] is_ok: bool, #[case] expected: U256) {
        let res = safe_sub(a, b);
        assert_eq!(res.is_err(), is_err);
        assert_eq!(res.is_ok(), is_ok);

        if is_ok{
            assert_eq!(res.unwrap(), expected);
        }
    }

    #[rstest]
    #[case(u256("1"), u256("0"), true, false, u256("0"))]
    #[case(u256("10"), u256("2"), false, true, u256("5"))]
    fn test_safe_div(#[case] a: U256, #[case] b: U256, #[case] is_err: bool, #[case] is_ok: bool, #[case] expected: U256) {
        let res = safe_div(a, b);
        assert_eq!(res.is_err(), is_err);
        assert_eq!(res.is_ok(), is_ok);

        if is_ok{
            assert_eq!(res.unwrap(), expected);
        }
    }
}
