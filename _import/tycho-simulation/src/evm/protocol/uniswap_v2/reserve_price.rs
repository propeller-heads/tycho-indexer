use num_bigint::BigUint;
use num_traits::ToPrimitive;

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
    r0: &BigUint,
    r1: &BigUint,
    token_0_decimals: u32,
    token_1_decimals: u32,
) -> f64 {
    let token_correction = 10f64.powi(token_0_decimals as i32 - token_1_decimals as i32);
    (r1.to_f64()
        .expect("Expected reserve0 BigUint to be converted to f64") /
        r0.to_f64()
            .expect("Expected reserve1 BigUint to be converted to f64")) *
        token_correction
}

#[cfg(test)]
mod test {
    use super::*;

    use approx::assert_ulps_eq;
    use rstest::rstest;
    use std::str::FromStr;

    #[rstest]
    #[case::dai_weth(
    BigUint::from_str("6459290401503744160496018").unwrap(),
    BigUint::from_str("5271291858877575385159").unwrap(),
        18,
        18,
        0.0008160790940209781f64
    )]
    #[case::weth_usdt(
    BigUint::from_str("9404438958522240683671").unwrap(),
    BigUint::from_str("11524076256844").unwrap(),
        18,
        6,
        1225.3868952385467f64
    )]
    #[case::paxg_weth(
    BigUint::from_str("1953602660669219944829").unwrap(),
    BigUint::from_str("2875413366760000758700").unwrap(),
        18,
        18,
        1.4718516844029115f64
    )]
    fn test_real_world_examples(
        #[case] r0: BigUint,
        #[case] r1: BigUint,
        #[case] t0d: u32,
        #[case] t1d: u32,
        #[case] exp: f64,
    ) {
        let res = spot_price_from_reserves(&r0, &r1, t0d, t1d);

        assert_ulps_eq!(res, exp);
    }
}
