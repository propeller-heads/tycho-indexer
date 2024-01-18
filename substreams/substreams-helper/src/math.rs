use std::ops::{Div, Mul};
use std::str::FromStr;

use num_bigint::BigUint;
use pad::PadStr;
use substreams::scalar::{BigDecimal, BigInt};
use substreams_ethereum::pb::eth::v2::BalanceChange;

use crate::convert::BigIntDeserializeExt;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Utf8(#[from] std::str::Utf8Error),

    #[error(transparent)]
    ParseBigDecimal(#[from] bigdecimal::ParseBigDecimalError),
}

pub fn safe_div(amount0: &BigDecimal, amount1: &BigDecimal) -> BigDecimal {
    let big_decimal_zero: &BigDecimal = &BigDecimal::zero();
    if amount1.eq(big_decimal_zero) {
        BigDecimal::zero()
    } else {
        amount0.clone().div(amount1.clone())
    }
}

// converts the string representation (in bytes) of a decimal
pub fn decimal_from_bytes(value: &[u8]) -> Result<BigDecimal, Error> {
    decimal_from_str(std::str::from_utf8(value)?)
}

pub fn decimal_from_str(price_str: &str) -> Result<BigDecimal, Error> {
    Ok(BigDecimal::from_str(price_str)?.with_prec(100))
}

pub fn decimal_from_hex_be_bytes(price_bytes: &Vec<u8>) -> BigDecimal {
    let big_uint_amount = BigUint::from_bytes_be(price_bytes.as_slice()); // TODO: Get rid of BigUint dependency
    BigDecimal::from_str(big_uint_amount.to_string().as_str())
        .unwrap()
        .with_prec(100)
}

pub fn exponent_to_big_decimal(decimals: u8) -> BigDecimal {
    let mut result = BigDecimal::one();
    let big_decimal_ten: &BigDecimal = &BigDecimal::from(10);
    for _i in 0..decimals {
        result = result.mul(big_decimal_ten.clone());
    }

    result
}

pub fn divide_by_decimals(big_float_amount: BigDecimal, decimals: u64) -> BigDecimal {
    let bd = BigDecimal::from_str(
        "1".pad_to_width_with_char((decimals + 1) as usize, '0')
            .as_str(),
    )
    .unwrap()
    .with_prec(100);

    big_float_amount.div(bd).with_prec(100)
}

pub fn get_balance_gain(balance_change: &BalanceChange) -> BigInt {
    match (
        balance_change.old_value.as_ref(),
        balance_change.new_value.as_ref(),
    ) {
        (Some(old_value_raw), Some(new_value_raw)) => {
            let old_value = old_value_raw.deserialize();
            let new_value = new_value_raw.deserialize();
            new_value - old_value
        }
        (Some(old_value), None) => old_value.deserialize(), // Maybe we should panic if this happens also..
        (None, Some(new_value)) => new_value.deserialize(),
        (None, None) => BigInt::zero(),
    }
}

pub trait NumberModulo<T> {
    fn modulo(&self, other: T) -> Self;
}

impl<T> NumberModulo<T> for BigInt
where
    T: Into<BigInt> + Clone,
{
    fn modulo(&self, other: T) -> Self {
        let division = self.to_owned() / other.clone();
        self.to_owned() - division * other
    }
}
