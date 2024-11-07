use std::ops::BitOr;

use ethers::types::{Sign, I256, U256};

use crate::{
    protocol::errors::SimulationError,
    safe_math::{safe_div_u256, safe_mul_u256},
};

pub const MIN_TICK: i32 = -887272;
pub const MAX_TICK: i32 = 887272;

// 4295128739
pub const MIN_SQRT_RATIO: U256 = U256([4295128739, 0, 0, 0]);
// 1461446703485210103287273052203988822378723970342
pub const MAX_SQRT_RATIO: U256 = U256([6743328256752651558, 17280870778742802505, 4294805859, 0]);

pub fn get_sqrt_ratio_at_tick(tick: i32) -> Result<U256, SimulationError> {
    assert!(tick.abs() <= MAX_TICK);
    let abs_tick = U256::from(tick.unsigned_abs());
    let mut ratio = if abs_tick.bit(0) {
        U256([12262481743371124737, 18445821805675392311, 0, 0])
    } else {
        U256([0, 0, 1, 0])
    };
    // This section is generated with the code below
    if abs_tick.bit(1) {
        ratio =
            (safe_mul_u256(ratio, U256([6459403834229662010, 18444899583751176498, 0, 0]))?) >> 128
    }
    if abs_tick.bit(2) {
        ratio =
            (safe_mul_u256(ratio, U256([17226890335427755468, 18443055278223354162, 0, 0]))?) >> 128
    }
    if abs_tick.bit(3) {
        ratio =
            (safe_mul_u256(ratio, U256([2032852871939366096, 18439367220385604838, 0, 0]))?) >> 128
    }
    if abs_tick.bit(4) {
        ratio =
            (safe_mul_u256(ratio, U256([14545316742740207172, 18431993317065449817, 0, 0]))?) >> 128
    }
    if abs_tick.bit(5) {
        ratio =
            (safe_mul_u256(ratio, U256([5129152022828963008, 18417254355718160513, 0, 0]))?) >> 128
    }
    if abs_tick.bit(6) {
        ratio =
            (safe_mul_u256(ratio, U256([4894419605888772193, 18387811781193591352, 0, 0]))?) >> 128
    }
    if abs_tick.bit(7) {
        ratio =
            (safe_mul_u256(ratio, U256([1280255884321894483, 18329067761203520168, 0, 0]))?) >> 128
    }
    if abs_tick.bit(8) {
        ratio =
            (safe_mul_u256(ratio, U256([15924666964335305636, 18212142134806087854, 0, 0]))?) >> 128
    }
    if abs_tick.bit(9) {
        ratio =
            (safe_mul_u256(ratio, U256([8010504389359918676, 17980523815641551639, 0, 0]))?) >> 128
    }
    if abs_tick.bit(10) {
        ratio =
            (safe_mul_u256(ratio, U256([10668036004952895731, 17526086738831147013, 0, 0]))?) >> 128
    }
    if abs_tick.bit(11) {
        ratio =
            (safe_mul_u256(ratio, U256([4878133418470705625, 16651378430235024244, 0, 0]))?) >> 128
    }
    if abs_tick.bit(12) {
        ratio =
            (safe_mul_u256(ratio, U256([9537173718739605541, 15030750278693429944, 0, 0]))?) >> 128
    }
    if abs_tick.bit(13) {
        ratio =
            (safe_mul_u256(ratio, U256([9972618978014552549, 12247334978882834399, 0, 0]))?) >> 128
    }
    if abs_tick.bit(14) {
        ratio =
            (safe_mul_u256(ratio, U256([10428997489610666743, 8131365268884726200, 0, 0]))?) >> 128
    }
    if abs_tick.bit(15) {
        ratio =
            (safe_mul_u256(ratio, U256([9305304367709015974, 3584323654723342297, 0, 0]))?) >> 128
    }
    if abs_tick.bit(16) {
        ratio =
            (safe_mul_u256(ratio, U256([14301143598189091785, 696457651847595233, 0, 0]))?) >> 128
    }
    if abs_tick.bit(17) {
        ratio = (safe_mul_u256(ratio, U256([7393154844743099908, 26294789957452057, 0, 0]))?) >> 128
    }
    if abs_tick.bit(18) {
        ratio = (safe_mul_u256(ratio, U256([2209338891292245656, 37481735321082, 0, 0]))?) >> 128
    }
    if abs_tick.bit(19) {
        ratio = (safe_mul_u256(ratio, U256([10518117631919034274, 76158723, 0, 0]))?) >> 128
    }

    if tick > 0 {
        ratio = safe_div_u256(U256::MAX, ratio)?;
    }

    let (_, rest) = ratio.div_mod(U256::one() << 32);
    Ok((ratio >> 32) + if rest == U256::zero() { U256::zero() } else { U256::one() })
}

fn most_significant_bit(x: U256) -> usize {
    assert!(x > U256::zero());
    x.bits() - 1
}

pub fn get_tick_at_sqrt_ratio(sqrt_price: U256) -> Result<i32, SimulationError> {
    assert!(sqrt_price >= MIN_SQRT_RATIO && sqrt_price < MAX_SQRT_RATIO);
    let ratio_x128 = sqrt_price << 32;
    let msb = most_significant_bit(ratio_x128);
    let mut r = if msb >= 128 { ratio_x128 >> (msb - 127) } else { ratio_x128 << (127 - msb) };
    let mut log_2: I256 = I256::from((msb as i32) - 128) << 64;

    for i in 0..14 {
        r = r.pow(U256([2, 0, 0, 0])) >> 127;
        let f = r >> 128;
        log_2 =
            log_2.bitor(I256::checked_from_sign_and_abs(Sign::Positive, f << (63 - i)).unwrap());
        r >>= f;
    }

    let log_sqrt10001 = log_2 * I256::from_raw(U256([11745905768312294533, 13863, 0, 0]));

    let tmp1 = I256::from_raw(U256([6552757943157144234, 184476617836266586, 0, 0]));

    let tick_low: I256 = (log_sqrt10001 - tmp1).asr(128);
    let tick_high: I256 = (log_sqrt10001
        + I256::from_raw(U256([4998474450511881007, 15793544031827761793, 0, 0])))
    .asr(128);

    if tick_low == tick_high {
        Ok(tick_low.as_i32())
    } else if get_sqrt_ratio_at_tick(tick_high.as_i32())? <= sqrt_price {
        Ok(tick_high.as_i32())
    } else {
        Ok(tick_low.as_i32())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestCase {
        tick: i32,
        ratio: U256,
    }

    #[test]
    fn test_most_significant_bit() {
        assert_eq!(most_significant_bit(U256::from(1)), 0);
        assert_eq!(most_significant_bit(U256::from(3)), 1);
        assert_eq!(most_significant_bit(U256::from(8)), 3);
        assert_eq!(most_significant_bit(U256::from(256)), 8);
        assert_eq!(most_significant_bit(U256::from(511)), 8);
    }

    #[test]
    fn test_get_sqrt_ratio_at_tick() {
        let cases = vec![
            TestCase {
                tick: 0,
                ratio: U256::from_dec_str("79228162514264337593543950336").unwrap(),
            },
            TestCase {
                tick: 1,
                ratio: U256::from_dec_str("79232123823359799118286999568").unwrap(),
            },
            TestCase {
                tick: -1,
                ratio: U256::from_dec_str("79224201403219477170569942574").unwrap(),
            },
            TestCase {
                tick: 42,
                ratio: U256::from_dec_str("79394708140106462983274643745").unwrap(),
            },
            TestCase {
                tick: -42,
                ratio: U256::from_dec_str("79061966249810860392253787324").unwrap(),
            },
            TestCase { tick: MIN_TICK, ratio: U256::from_dec_str("4295128739").unwrap() },
            TestCase {
                tick: MAX_TICK,
                ratio: U256::from_dec_str("1461446703485210103287273052203988822378723970342")
                    .unwrap(),
            },
        ];
        for case in cases {
            assert_eq!(get_sqrt_ratio_at_tick(case.tick).unwrap(), case.ratio);
        }
    }

    #[test]
    fn test_get_tick_at_sqrt_ratio() {
        let cases = vec![
            TestCase {
                tick: 0,
                ratio: U256::from_dec_str("79228162514264337593543950336").unwrap(),
            },
            TestCase {
                tick: 1,
                ratio: U256::from_dec_str("79232123823359799118286999568").unwrap(),
            },
            TestCase {
                tick: -1,
                ratio: U256::from_dec_str("79224201403219477170569942574").unwrap(),
            },
            TestCase {
                tick: 42,
                ratio: U256::from_dec_str("79394708140106462983274643745").unwrap(),
            },
            TestCase {
                tick: -42,
                ratio: U256::from_dec_str("79061966249810860392253787324").unwrap(),
            },
            TestCase { tick: MIN_TICK, ratio: U256::from_dec_str("4295128739").unwrap() },
            TestCase {
                tick: MAX_TICK - 1,
                ratio: U256::from_dec_str("1461446703485210103287273052203988822378723970341")
                    .unwrap(),
            },
        ];
        for case in cases {
            assert_eq!(get_tick_at_sqrt_ratio(case.ratio).unwrap(), case.tick);
        }
    }
}
