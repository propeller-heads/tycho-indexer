use super::solidity_math::mul_div_rounding_up;
use ethers::types::{U256, U512};

fn maybe_flip_ratios(a: U256, b: U256) -> (U256, U256) {
    if a > b {
        (b, a)
    } else {
        (a, b)
    }
}

fn div_rounding_up(a: U256, b: U256) -> U256 {
    let (result, rest) = a.div_mod(b);
    if rest > U256::zero() {
        return result + U256::one();
    } else {
        return result;
    }
}

fn get_amount0_delta(a: U256, b: U256, liquidity: U256, round_up: bool) -> U256 {
    let (sqrt_ratio_a, sqrt_ratio_b) = maybe_flip_ratios(a, b);

    let numerator1 = liquidity << 96;
    let numerator2 = b - a;

    if sqrt_ratio_a <= U256::zero() {
        // TODO raise an error
    }
    let res;
    if round_up {
        res = div_rounding_up(
            mul_div_rounding_up(numerator1, numerator2, sqrt_ratio_b),
            sqrt_ratio_a,
        );
    } else {
        res = mul_div_rounding_up(numerator1, numerator2, sqrt_ratio_b);
    }
    return res;
}
