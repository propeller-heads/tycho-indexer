use std::cmp::max;

use ethers::types::U256;

const MAX_U160: U256 = U256([0, 0, 4294967296, 0]);
const Q192_F64: f64 = 6.2771017353866808E+57;

pub fn sqrt_price_q96_to_f64(x: U256, token_0_decimals: u32, token_1_decimals: u32) -> f64 {
    // TODO: types and doc, in which instances does this err?
    let token_correction = 10f64.powi(token_0_decimals as i32 - token_1_decimals as i32);
    let price = x.pow(U256::from(2));

    // TODO: basically shift right so the last 64 bits are filled - maximizing precision
    let bits_needed_after_192_rshift = price.bits() - 192;

    let available_bits = 64 - bits_needed_after_192_rshift;

    let shr_b = 192 - available_bits;

    let res = (price >> shr_b).as_u64();
    let denom = 2u64.pow(available_bits as u32);

    println!("{} / {}", res, denom);
    res as f64 / denom as f64 * token_correction
}

pub fn sqrt_price_q96_to_f64_2(x: U256) -> f64 {
    // Idea do a right shift to get the biggest possible significand,
    // then subtract the positions shifted from 192 to create the exponent

    let price = x.pow(U256::from(2));
    let bits_needed = price.bits();
    let shr_by = bits_needed - 52;
    let significant = (price >> shr_by).as_u64();
    let exponent = (1023 - (192 - shr_by)) as u64;

    println!("0.15625     {:#066b}", 0.15625f64.to_bits());

    println!("Significant {:#066b}", significant);
    println!("Exponent    {:#066b}", exponent << 52);
    println!("Combined    {:#066b}", exponent << 52 | significant);

    f64::from_bits(exponent << 53 | significant)
}

#[cfg(test)]
mod tests {
    use super::*;
    // TODO test case were precision is negative

    #[test]
    fn test_q96_to_f64() {
        let q96_price = U256::from_dec_str("2209221051636112667296733914466103").unwrap();
        let res = sqrt_price_q96_to_f64(q96_price, 6, 18);

        println!("{}", res)
    }

    fn test_q96_to_f64_2() {
        let q96_price = U256::from_dec_str("2209221051636112667296733914466103").unwrap();
        let res = sqrt_price_q96_to_f64_2(q96_price);

        println!("{}", res)
    }
}

// 777533623.1174711551666406785
// 777533623
