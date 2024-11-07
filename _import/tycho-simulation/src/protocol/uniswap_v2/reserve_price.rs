use ethers::types::U256;

use crate::u256_num::u256_to_f64;

/// Computes a spot price given two token reserves
///
/// To find the most accurate spot price possible:
///     1. The nominator and denominator are converted to float (this conversion is lossy)
///     2. The price is computed by using float division
///     3. Finally the price is correct for difference in token decimals.
///
/// # Example
/// ```
/// use ethers::types::U256;
/// use tycho_simulation::protocol::uniswap_v2::reserve_price::spot_price_from_reserves;
///
/// let res = spot_price_from_reserves(U256::from(100), U256::from(200), 6, 6);
///
/// assert_eq!(res, 2.0f64);
/// ```
pub fn spot_price_from_reserves(
    r0: U256,
    r1: U256,
    token_0_decimals: u32,
    token_1_decimals: u32,
) -> f64 {
    let token_correction = 10f64.powi(token_0_decimals as i32 - token_1_decimals as i32);
    (u256_to_f64(r1) / u256_to_f64(r0)) * token_correction
}

#[cfg(test)]
mod test {
    use super::*;

    use approx::assert_ulps_eq;
    use rstest::rstest;

    fn u256_str(dec_str: &str) -> U256 {
        U256::from_dec_str(dec_str).unwrap()
    }

    #[rstest]
    #[case::dai_weth(
        u256_str("6459290401503744160496018"),
        u256_str("5271291858877575385159"),
        18,
        18,
        0.0008160790940209781f64
    )]
    #[case::weth_usdt(
        u256_str("9404438958522240683671"),
        u256_str("11524076256844"),
        18,
        6,
        1225.3868952385467f64
    )]
    #[case::paxg_weth(
        u256_str("1953602660669219944829"),
        u256_str("2875413366760000758700"),
        18,
        18,
        1.4718516844029115f64
    )]
    fn test_real_world_examples(
        #[case] r0: U256,
        #[case] r1: U256,
        #[case] t0d: u32,
        #[case] t1d: u32,
        #[case] exp: f64,
    ) {
        let res = spot_price_from_reserves(r0, r1, t0d, t1d);

        assert_ulps_eq!(res, exp);
    }
}
