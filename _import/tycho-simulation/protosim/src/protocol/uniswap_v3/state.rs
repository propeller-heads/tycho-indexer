use ethers::types::{I256, U256, U512};

const UINT160_MAX: &str = "1461501637330902918203684832716283019655932542975";
const Q96: &str = "79228162514264337593543950336";
const Q192: &str = "6277101735386680763835789423207666416102355444464034512896";
const MAX_FEE: u64 = 1_000_000;

// Solidity spec: function addDelta(uint128 x, int128 y) internal pure returns (uint128 z) {
fn add_liquidity_delta(x: u128, y: i128) -> u128 {
    if y < 0 {
        x - (-y as u128)
    } else {
        x + (y as u128)
    }
}

pub struct UniswapV3State {}

#[cfg(test)]
mod tests {
    use crate::protocol::uniswap_v3::solidity_math::mul_div_rounding_up;

    use super::*;

    #[test]
    fn test_add_liquidity_delta() {
        // TODO: check more cases. e.g. overflowing 128 bits
        let x = 10000;
        let y = -1000;

        let res = add_liquidity_delta(x, y);

        assert_eq!(res, 9000);
    }

    #[test]
    fn test_mul_div_rounding_up() {
        // TODO: check U256 overflows and maybe U512?
        let a = U256::from(5);
        let b = U256::from(5);
        let denom = U256::from(5);
        let res = mul_div_rounding_up(a, b, denom);

        assert_eq!(res, U256::from(5));
    }

    #[test]
    fn test_mul_div_overflow_u256() {
        let (a, b) = (U256::MAX, U256::MAX);
        let denom = U256::from(1);

        let result = std::panic::catch_unwind(|| mul_div_rounding_up(a, b, denom));

        assert!(result.is_err());
    }
}
