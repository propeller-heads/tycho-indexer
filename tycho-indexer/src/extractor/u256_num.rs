//! # Numeric methods for the U256 type
//!
//! Taken and adjusted from the protosim crate. Internally still depends on the ethers U256 type
//! this is not ideal but does the job for now.

use std::{cmp::max, panic};

use ethers::types::U256;
use tracing::warn;

/// Converts a U256 integer into it's closest floating point representation
///
/// Rounds to "nearest even" if the number has to be truncated (number uses more than 53 bits).
///
/// ## Rounding rules
/// This function converts a `U256` value to a `f64` value by applying a rounding
/// rule to the least significant bits of the `U256` value. The general rule when
/// rounding binary fractions to the n-th place prescribes to check the digit
/// following the n-th place in the number (round_bit). If it’s 0, then the number
/// should always be rounded down. If, instead, the digit is 1 and any of the
/// following digits (sticky_bits) are also 1, then the number should be rounded up.
/// If, however, all of the following digits are 0’s, then a tie breaking rule is
/// applied using the least significant bit (lsb) and usually it’s the ‘ties to even’.
/// This rule says that we should round to the number that has 0 at the n-th place.
/// If after rounding, the significand uses more than 53 bits, the significand is
/// shifted to the right and the exponent is decreased by 1.
///
/// ## Additional Reading
/// - [Double-precision floating-point format](https://en.wikipedia.org/wiki/Double-precision_floating-point_format)
/// - [Converting uint to float bitwise on SO](https://stackoverflow.com/a/20308114/8648259 )
/// - [Int to Float rounding on SO](https://stackoverflow.com/a/42032175/8648259)
/// - [How to round binary numbers](https://indepth.dev/posts/1017/how-to-round-binary-numbers)
/// - [Paper: "What Every Computer Scientist Should Know About Floating Point Arithmetic"](http://www.validlab.com/goldberg/paper.pdf)
pub fn bytes_to_f64(data: &[u8]) -> Option<f64> {
    if data.len() > 32 {
        warn!(?data, "Received invalid balance bytes!");
        return None;
    }
    let x = U256::from(data);
    let res = panic::catch_unwind(|| {
        if x == U256::zero() {
            return Some(0.0);
        }

        let x_bits = x.bits();
        let n_shifts = 53i32 - x_bits as i32;
        let mut exponent = (1023 + 52 - n_shifts) as u64;

        let mut significant = if n_shifts >= 0 {
            // shift left if pos, no rounding needed
            (x << n_shifts).as_u64()
        } else {
            /*
            shift right if neg, dropping LSBs, round to nearest even

            The general rule when rounding binary fractions to the n-th place prescribes to check
            the digit following the n-th place in the number (round_bit). If it’s 0, then the
            number should always be rounded down. If, instead, the digit is 1 and any of the
            following digits (sticky_bits) are also 1, then the number should be rounded up.
            If, however, all of the following digits are 0’s, then a tie breaking rule must
            be applied and usually it’s the ‘ties to even’. This rule says that we should
            round to the number that has 0 at the n-th place.
            */
            // least significant bit is be used as tiebreaker
            let lsb = (x >> n_shifts.abs()) & U256::one();
            let round_bit = (x >> (n_shifts.abs() - 1)) & U256::one();

            // build mask for sticky bit, handle case when no data for sticky bit is available
            let sticky_bit = x & ((U256::one() << max(n_shifts.abs() - 2, 0)) - U256::one());

            let rounded_torwards_zero = (x >> n_shifts.abs()).as_u64();
            if round_bit == U256::one() {
                if sticky_bit == U256::zero() {
                    // tiebreaker: round up if lsb is 1 and down if lsb is 0
                    if lsb == U256::zero() {
                        rounded_torwards_zero
                    } else {
                        rounded_torwards_zero + 1
                    }
                } else {
                    rounded_torwards_zero + 1
                }
            } else {
                rounded_torwards_zero
            }
        };

        // due to rounding rules significand might be using 54 bits instead of 53 if
        // this is the case we shift to the right once more and decrease the exponent.
        if significant & (1 << 53) > 0 {
            significant >>= 1;
            exponent += 1;
        }

        let merged = (exponent << 52) | (significant & 0xFFFFFFFFFFFFFu64);
        Some(f64::from_bits(merged))
    });
    res.unwrap_or(None)
}

#[cfg(test)]
mod test {

    use super::*;
    use rstest::rstest;
    use tycho_core::Bytes;

    #[rstest]
    #[case::one(U256::one(), 1.0f64)]
    #[case::two(U256::from(2), 2.0f64)]
    #[case::zero(U256::zero(), 0.0f64)]
    #[case::two_pow1024(U256::from(2).pow(U256::from(190)), 2.0f64.powi(190))]
    #[case::max32(U256([u32::MAX as u64, 0, 0, 0]), u32::MAX as f64)]
    #[case::max64(U256([u64::MAX, 0, 0, 0]), u64::MAX as f64)]
    #[case::edge_54bits_trailing_zeros(U256::from(2u64.pow(53)), 2u64.pow(53) as f64)]
    #[case::edge_54bits_trailing_ones(U256::from(2u64.pow(54) - 1), (2u64.pow(54) - 1) as f64)]
    #[case::edge_53bits_trailing_zeros(U256::from(2u64.pow(52)), 2u64.pow(52) as f64)]
    #[case::edge_53bits_trailing_ones(U256::from(2u64.pow(53) - 1), (2u64.pow(53) - 1) as f64)]
    fn test_convert(#[case] inp: U256, #[case] out: f64) {
        let data = Bytes::from(inp).to_vec();
        let res = bytes_to_f64(&data).unwrap();

        assert_eq!(res, out);
    }
}
