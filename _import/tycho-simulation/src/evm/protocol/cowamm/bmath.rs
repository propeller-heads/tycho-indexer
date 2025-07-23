use alloy::primitives::U256;
use super::constants::{BONE, U256_1, U256_10E_10, U256_2};
use super::error::CowAMMError;
use crate::tycho_common::Bytes;

// https://github.com/darkforestry/amms-rs/blob/main/src/amms/balancer/bmath.rs
pub fn btoi(a: U256) -> U256 {
    a / BONE
}

#[inline]
pub fn badd(a: U256, b: U256) -> Result<U256, CowAMMError> {
    let c = a + b;
    if c < a {
        return Err(CowAMMError::AddOverflow);
    }
    Ok(c)
}

#[inline]
pub fn bpowi(a: U256, n: U256) -> Result<U256, CowAMMError> {
    let mut z = if n % U256_2 != U256::ZERO { a } else { BONE };

    let mut a = a;
    let mut n = n / U256_2;
    while n != U256::ZERO {
        a = bmul(a, a)?;
        if n % U256_2 != U256::ZERO {
            z = bmul(z, a)?;
        }
        n /= U256_2;
    }
    Ok(z)
}

#[inline]
pub fn bpow(base: U256, exp: U256) -> Result<U256, CowAMMError> {
    let whole = bfloor(exp);
    let remain = bsub(exp, whole)?;
    let whole_pow = bpowi(base, btoi(whole))?;
    if remain == U256::ZERO {
        return Ok(whole_pow);
    }
    let precision = BONE / U256_10E_10;
    let partial_result = bpow_approx(base, remain, precision)?;
    bmul(whole_pow, partial_result)
}

#[inline]
pub fn bpow_approx(base: U256, exp: U256, precision: U256) -> Result<U256, CowAMMError> {
    let a = exp;
    let (x, xneg) = bsub_sign(base, BONE);
    let mut term = BONE;
    let mut sum = term;
    let mut negative = false;
    let mut i = U256_1;
    while term >= precision {
        let big_k = U256::from(i) * BONE;
        let (c, cneg) = bsub_sign(a, bsub(big_k, BONE)?);
        term = bmul(term, bmul(c, x)?)?;
        term = bdiv(term, big_k)?;
        if term == U256::ZERO {
            break;
        }
        negative ^= xneg ^ cneg;
        if negative {
            sum = bsub(sum, term)?;
        } else {
            sum = badd(sum, term)?;
        }
        i += U256_1;
    }
    Ok(sum)
}

#[inline]
pub fn bfloor(a: U256) -> U256 {
    btoi(a) * BONE
}

// Reference:
// https://github.com/balancer/balancer-core/blob/f4ed5d65362a8d6cec21662fb6eae233b0babc1f/contracts/BNum.sol#L75
#[inline]
pub fn bdiv(a: U256, b: U256) -> Result<U256, CowAMMError> {
    if b == U256::ZERO {
        return Err(CowAMMError::DivZero);
    }
    let c0 = a * BONE;
    if a != U256::ZERO && c0 / a != BONE {
        return Err(CowAMMError::DivInternal);
    }
    let c1 = c0 + (b / U256_2);
    if c1 < c0 {
        return Err(CowAMMError::DivInternal);
    }
    Ok(c1 / b)
}

// Reference:
// https://github.com/balancer/balancer-core/blob/f4ed5d65362a8d6cec21662fb6eae233b0babc1f/contracts/BNum.sol#L43
#[inline]
pub fn bsub(a: U256, b: U256) -> Result<U256, CowAMMError> {
    let (c, flag) = bsub_sign(a, b);
    if flag {
        return Err(CowAMMError::SubUnderflow);
    }
    Ok(c)
}

// Reference:
// https://github.com/balancer/balancer-core/blob/f4ed5d65362a8d6cec21662fb6eae233b0babc1f/contracts/BNum.sol#L52
#[inline]
pub fn bsub_sign(a: U256, b: U256) -> (U256, bool) {
    if a >= b {
        (a - b, false)
    } else {
        (b - a, true)
    }
} 

// Reference:
// https://github.com/balancer/balancer-core/blob/f4ed5d65362a8d6cec21662fb6eae233b0babc1f/contracts/BNum.sol#L63C4-L73C6
#[inline]
pub fn bmul(a: U256, b: U256) -> Result<U256, CowAMMError> {
    let c0 = a * b;
    if a != U256::ZERO && c0 / a != b {
        return Err(CowAMMError::MulOverflow);
    }
    let c1 = c0 + (BONE / U256_2);
    if c1 < c0 {
        return Err(CowAMMError::MulOverflow);
    }
    Ok(c1 / BONE)
}

/**********************************************************************************************
// calcSpotPrice                                                                             //
// sP = spotPrice                                                                            //
// bI = tokenBalanceIn                ( bI / wI )         1                                  //
// bO = tokenBalanceOut         sP =  -----------  *  ----------                             //
// wI = tokenWeightIn                 ( bO / wO )     ( 1 - sF )                             //
// wO = tokenWeightOut                                                                       //
// sF = swapFee                                                                              //
 **********************************************************************************************/
pub fn calculate_price(
    b_i: U256,
    w_i: U256,
    b_o: U256,
    w_o: U256,
    s_f: U256,
) -> Result<U256, CowAMMError> {
    let numer = bdiv(b_i, w_i)?;
    let denom = bdiv(b_o, w_o)?;
    let ratio = bdiv(numer, denom)?;
    let scale = bdiv(BONE, bsub(BONE, s_f)?)?;
    bmul(ratio, scale)
}

/**********************************************************************************************
// calcOutGivenIn                                                                            //
// aO = tokenAmountOut                                                                       //
// bO = tokenBalanceOut                                                                      //
// bI = tokenBalanceIn              /      /            bI             \    (wI / wO) \      //
// aI = tokenAmountIn    aO = bO * |  1 - | --------------------------  | ^            |     //
// wI = tokenWeightIn               \      \ ( bI + ( aI * ( 1 - sF )) /              /      //
// wO = tokenWeightOut                                                                       //
// sF = swapFee                                                                              //
 **********************************************************************************************/
pub fn calculate_out_given_in(
    token_balance_in: U256,
    token_weight_in: U256,
    token_balance_out: U256,
    token_weight_out: U256,
    token_amount_in: U256,
    swap_fee: U256,
) -> Result<U256, CowAMMError> {
    let weight_ratio = bdiv(token_weight_in, token_weight_out)?;
    let adjusted_in = bsub(BONE, swap_fee)?;
    let adjusted_in = bmul(token_amount_in, adjusted_in)?;
    let y = bdiv(token_balance_in, badd(token_balance_in, adjusted_in)?)?;
    let x = bpow(y, weight_ratio)?;
    let z = bsub(BONE, x)?;
    bmul(token_balance_out, z)
}