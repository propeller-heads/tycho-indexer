//! Models safe arithmetic like [checked_subtract].

use crate::error::Error;

/// Normal subtraction (`a - b`) in solidity version 0.8 is safe
/// and reverts if it would underflow (`b > a`).
/// Use [checked_subtract] instead of `a - b` when modeling subtraction
/// outside of solidity `unchecked` blocks.
/// Subtraction inside solidity `unchecked` blocks would require
/// the implementation of another helper function `unchecked_subtract`
/// that models underflow.
pub fn checked_subtract(minuend: i64, subtrahend: i64) -> Result<i64, Error> {
    if subtrahend > minuend {
        Err(Error::revert("checked_subtract: subtrahend > minuend"))
    } else {
        Ok(minuend - subtrahend)
    }
}
