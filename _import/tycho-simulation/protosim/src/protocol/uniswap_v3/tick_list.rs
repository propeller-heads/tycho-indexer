use std::cmp;

use super::tick_math;
use ethers::types::U256;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct TickInfo {
    pub index: i32,
    pub net_liquidity: i128,
    pub sqrt_price: U256,
}

impl TickInfo {
    pub fn new(index: i32, net_liquidity: i128) -> Self {
        // Note: using this method here returns slightly different values
        //  compared to the Python implementation, likely more correct
        let sqrt_price = tick_math::get_sqrt_ratio_at_tick(index).unwrap();
        TickInfo { index, net_liquidity, sqrt_price }
    }
}

impl PartialOrd for TickInfo {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.index.partial_cmp(&other.index)
    }
}

#[derive(Debug)]
pub struct TickListError {
    pub kind: TickListErrorKind,
}

#[derive(Debug, PartialEq)]
pub enum TickListErrorKind {
    NotFound,
    BelowSmallest,
    AtOrAboveLargest,
    TicksExeeded,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TickList {
    tick_spacing: u16,
    ticks: Vec<TickInfo>,
}

impl TickList {
    pub fn from(spacing: u16, ticks: Vec<TickInfo>) -> Self {
        let tick_list = TickList { tick_spacing: spacing, ticks };
        let valid = tick_list.valid_ticks();
        if valid.is_ok() {
            tick_list
        } else {
            panic!("{}", valid.unwrap_err());
        }
    }

    // Asserts that all attributes are valid. Checks for:
    // 1. Tick spacing > 0
    // 2. Tick indexes have no rest when divided by tick spacing
    // 3. Ticks are ordered by index
    fn valid_ticks(&self) -> Result<bool, String> {
        if self.tick_spacing == 0 {
            return Err(String::from("Tick spacing is 0"))
        }

        for i in 0..self.ticks.len() {
            let t = self.ticks.get(i).unwrap();
            if t.index % self.tick_spacing as i32 != 0 {
                return Err(format!(
                    "Tick index {} not aligned with tick spacing {}",
                    t.index, self.tick_spacing,
                ))
            }
        }
        for i in 0..self.ticks.len() - 1 {
            let t = self.ticks.get(i).unwrap();
            if i != self.ticks.len() && t > self.ticks.get(i + 1).unwrap() {
                let msg = format!("Ticks are not ordered at position {}", t.index);
                return Err(msg)
            }
        }

        Ok(true)
    }

    pub fn apply_liquidity_change(&mut self, lower: i32, upper: i32, delta: i128) {
        self.upsert_tick(lower, delta);
        self.upsert_tick(upper, -delta);
    }

    fn upsert_tick(&mut self, tick: i32, delta: i128) {
        match self
            .ticks
            .binary_search_by(|t| t.index.cmp(&tick))
        {
            Ok(existing_idx) => {
                let tick = &mut self.ticks[existing_idx];
                tick.net_liquidity += delta;
                if tick.net_liquidity == 0 {
                    self.ticks.remove(existing_idx);
                }
            }
            Err(insert_idx) => {
                self.ticks
                    .insert(insert_idx, TickInfo::new(tick, delta));
            }
        }
    }

    pub fn is_below_smallest(&self, tick: i32) -> bool {
        tick < self.ticks[0].index
    }

    pub fn is_below_safe_tick(&self, tick: i32) -> bool {
        let smallest = self.ticks[0].index;
        let minimum = smallest - self.tick_spacing as i32;
        tick < minimum
    }

    pub fn is_at_or_above_largest(&self, tick: i32) -> bool {
        tick >= self.ticks[self.ticks.len() - 1].index
    }

    pub fn is_at_or_above_safe_tick(&self, tick: i32) -> bool {
        let largest = self.ticks[self.ticks.len() - 1].index;
        let maximum = largest + self.tick_spacing as i32;
        tick >= maximum
    }

    pub fn get_tick(&self, index: i32) -> Result<&TickInfo, TickListError> {
        match self
            .ticks
            .binary_search_by(|el| el.index.cmp(&index))
        {
            Ok(idx) => Ok(&self.ticks[idx]),
            Err(_) => Err(TickListError { kind: TickListErrorKind::NotFound }),
        }
    }

    pub fn next_initialized_tick(&self, index: i32, lte: bool) -> Result<&TickInfo, TickListError> {
        if lte {
            if self.is_below_smallest(index) {
                return Err(TickListError { kind: TickListErrorKind::BelowSmallest })
            }
            if self.is_at_or_above_largest(index) {
                return Ok(&self.ticks[self.ticks.len() - 1])
            }
            let tick = match self
                .ticks
                .binary_search_by(|el| el.index.cmp(&index))
            {
                Ok(idx) => &self.ticks[idx],
                Err(idx) => &self.ticks[idx - 1],
            };
            Ok(tick)
        } else {
            if self.is_at_or_above_largest(index) {
                return Err(TickListError { kind: TickListErrorKind::AtOrAboveLargest })
            }
            if self.is_below_smallest(index) {
                return Ok(&self.ticks[0])
            }
            let idx = match self
                .ticks
                .binary_search_by(|el| el.index.cmp(&index))
            {
                Ok(idx) => idx + 1,
                Err(idx) => idx,
            };
            Ok(&self.ticks[idx])
        }
    }

    pub fn next_initialized_tick_within_one_word(
        &self,
        tick: i32,
        lte: bool,
    ) -> Result<(i32, bool), TickListError> {
        let spacing = self.tick_spacing as i32;
        let compressed = div_floor(tick, spacing);

        if lte {
            let word_pos = compressed >> 8;
            let min_in_word = (word_pos << 8) * spacing;

            if self.is_below_safe_tick(tick) {
                return Err(TickListError { kind: TickListErrorKind::TicksExeeded })
            }

            if self.is_below_smallest(tick) {
                let minimum = cmp::max(self.ticks[0].index - spacing, min_in_word);
                return Ok((minimum, false))
            }

            let idx = self
                .next_initialized_tick(tick, lte)?
                .index;
            let next_tick_idx = cmp::max(idx, min_in_word);
            Ok((next_tick_idx, next_tick_idx == idx))
        } else {
            let word_pos = (compressed + 1) >> 8;
            let max_in_word = (((word_pos + 1) << 8) - 1) * spacing;

            if self.is_at_or_above_safe_tick(tick) {
                return Err(TickListError { kind: TickListErrorKind::TicksExeeded })
            }

            if self.is_at_or_above_largest(tick) {
                let maximum =
                    cmp::min(self.ticks[self.ticks.len() - 1].index + spacing, max_in_word);
                return Ok((maximum, false))
            }
            let idx = self
                .next_initialized_tick(tick, lte)?
                .index;
            let next_tick_idx = cmp::min(max_in_word, idx);
            Ok((next_tick_idx, next_tick_idx == idx))
        }
    }
}

fn div_floor(lhs: i32, rhs: i32) -> i32 {
    let d = lhs / rhs;
    let r = lhs % rhs;
    if (r > 0 && rhs < 0) || (r < 0 && rhs > 0) {
        d - 1
    } else {
        d
    }
}

#[cfg(test)]
mod tests {

    use rstest::rstest;

    use crate::protocol::uniswap_v3::tick_math;

    use super::*;

    fn create_tick_list() -> TickList {
        let tick_infos =
            vec![create_tick_info(10, 10), create_tick_info(20, -5), create_tick_info(40, -5)];

        TickList::from(10, tick_infos)
    }

    fn create_tick_info(idx: i32, liq: i128) -> TickInfo {
        TickInfo { index: idx, net_liquidity: liq, sqrt_price: U256::zero() }
    }

    #[test]
    fn test_from() {
        let tick_list = create_tick_list();
        assert_eq!(tick_list.ticks.len(), 3);
        assert_eq!(tick_list.tick_spacing, 10);
    }

    #[test]
    fn test_is_below_smallest() {
        let tick_list = create_tick_list();
        assert!(tick_list.is_below_smallest(-100));
        assert!(!tick_list.is_below_smallest(10));
    }

    #[test]
    fn test_is_at_or_above_largest() {
        let tick_list = create_tick_list();
        assert!(!tick_list.is_at_or_above_largest(10));
        assert!(tick_list.is_at_or_above_largest(200));
    }

    #[test]
    fn test_get_tick_success() {
        let tick_list = create_tick_list();
        let tick = tick_list.get_tick(10).unwrap();
        assert_eq!(tick, &tick_list.ticks[0])
    }

    #[test]
    fn test_get_tick_error() {
        let tick_list = create_tick_list();
        let err = tick_list.get_tick(-10).unwrap_err();
        assert_eq!(err.kind, TickListErrorKind::NotFound);
    }

    struct TestCaseNextInitializedTick {
        args: (i32, bool),
        exp: usize,
        id: &'static str,
    }

    #[test]
    fn test_next_initialized_tick() {
        let tick_infos = vec![
            create_tick_info(tick_math::MIN_TICK + 1, 10),
            create_tick_info(0, -5),
            create_tick_info(tick_math::MAX_TICK - 1, -5),
        ];
        let tick_list = TickList::from(1, tick_infos.clone());
        let cases = vec![
            TestCaseNextInitializedTick {
                args: (tick_math::MIN_TICK + 1, true),
                exp: 0,
                id: "low: idx = MIN + 1, lte = true",
            },
            TestCaseNextInitializedTick {
                args: (tick_math::MIN_TICK + 2, true),
                exp: 0,
                id: "low: idx = MIN + 2, lte = true",
            },
            TestCaseNextInitializedTick {
                args: (tick_math::MIN_TICK, false),
                exp: 0,
                id: "low: idx = MIN, lte = false",
            },
            TestCaseNextInitializedTick {
                args: (tick_math::MIN_TICK + 1, false),
                exp: 1,
                id: "low: = MIN + 1, lte = false",
            },
            TestCaseNextInitializedTick { args: (0, true), exp: 1, id: "mid: idx = 0, lte = true" },
            TestCaseNextInitializedTick { args: (1, true), exp: 1, id: "mid: idx = 1, lte = true" },
            TestCaseNextInitializedTick {
                args: (-1, false),
                exp: 1,
                id: "mid: idx = -1, lte = false",
            },
            TestCaseNextInitializedTick {
                args: (1, false),
                exp: 2,
                id: "mid: idx = 1, lte = false",
            },
            TestCaseNextInitializedTick {
                args: (tick_math::MAX_TICK - 1, true),
                exp: 2,
                id: "high: idx = MAX - 1, lte = true",
            },
            TestCaseNextInitializedTick {
                args: (tick_math::MAX_TICK, true),
                exp: 2,
                id: "high: idx = MAX, lte = true",
            },
            TestCaseNextInitializedTick {
                args: (tick_math::MAX_TICK - 2, false),
                exp: 2,
                id: "high: idx = MAX - 2, lte = false",
            },
            TestCaseNextInitializedTick {
                args: (tick_math::MAX_TICK - 3, false),
                exp: 2,
                id: "high: idx = MAX - 3, lte = false",
            },
        ];

        for case in cases {
            assert_eq!(
                tick_list
                    .next_initialized_tick(case.args.0, case.args.1)
                    .unwrap(),
                &tick_infos[case.exp],
                "{}",
                case.id,
            );
        }
    }

    struct TestCaseNextInitializedTickWithinWord {
        args: (i32, bool),
        exp: (i32, bool),
        id: &'static str,
    }

    #[test]
    fn test_next_initialized_tick_within_one_word() {
        let tick_infos = vec![
            create_tick_info(tick_math::MIN_TICK + 1, 10),
            create_tick_info(0, -5),
            create_tick_info(tick_math::MAX_TICK - 1, -5),
        ];
        let tick_list = TickList::from(1, tick_infos);
        let cases = vec![
            TestCaseNextInitializedTickWithinWord {
                args: (-257, true),
                exp: (-512, false),
                id: "idx=-257 lte=true",
            },
            TestCaseNextInitializedTickWithinWord {
                args: (-256, true),
                exp: (-256, false),
                id: "idx=-256 lte=true",
            },
            TestCaseNextInitializedTickWithinWord {
                args: (-1, true),
                exp: (-256, false),
                id: "idx=-1 lte=true",
            },
            TestCaseNextInitializedTickWithinWord {
                args: (0, true),
                exp: (0, true),
                id: "idx=0 lte=true",
            },
            TestCaseNextInitializedTickWithinWord {
                args: (1, true),
                exp: (0, true),
                id: "idx=1 lte=true",
            },
            TestCaseNextInitializedTickWithinWord {
                args: (255, true),
                exp: (0, true),
                id: "idx=255 lte=true",
            },
            TestCaseNextInitializedTickWithinWord {
                args: (256, true),
                exp: (256, false),
                id: "idx=256 lte=true",
            },
            TestCaseNextInitializedTickWithinWord {
                args: (257, true),
                exp: (256, false),
                id: "idx=257 lte=true",
            },
            TestCaseNextInitializedTickWithinWord {
                args: (-258, false),
                exp: (-257, false),
                id: "idx=-258 lte=false",
            },
            TestCaseNextInitializedTickWithinWord {
                args: (-257, false),
                exp: (-1, false),
                id: "idx=-257 lte=false",
            },
            TestCaseNextInitializedTickWithinWord {
                args: (-256, false),
                exp: (-1, false),
                id: "idx=-256 lte=false",
            },
            TestCaseNextInitializedTickWithinWord {
                args: (-2, false),
                exp: (-1, false),
                id: "idx=-2 lte=false",
            },
            TestCaseNextInitializedTickWithinWord {
                args: (-1, false),
                exp: (0, true),
                id: "idx=-1 lte=false",
            },
            TestCaseNextInitializedTickWithinWord {
                args: (0, false),
                exp: (255, false),
                id: "idx=0 lte=false",
            },
            TestCaseNextInitializedTickWithinWord {
                args: (1, false),
                exp: (255, false),
                id: "idx=1 lte=false",
            },
            TestCaseNextInitializedTickWithinWord {
                args: (254, false),
                exp: (255, false),
                id: "idx=254 lte=false",
            },
            TestCaseNextInitializedTickWithinWord {
                args: (255, false),
                exp: (511, false),
                id: "idx=255 lte=false",
            },
            TestCaseNextInitializedTickWithinWord {
                args: (256, false),
                exp: (511, false),
                id: "idx=256 lte=false",
            },
        ];

        for case in cases {
            assert_eq!(
                tick_list
                    .next_initialized_tick_within_one_word(case.args.0, case.args.1)
                    .unwrap(),
                case.exp,
                "{}",
                case.id,
            );
        }
    }

    #[test]
    fn test_next_initialized_tick_within_one_word_spacing() {
        let tick_infos = vec![create_tick_info(0, 5), create_tick_info(512, -5)];
        let tick_list1 = TickList::from(1, tick_infos.clone());
        let tick_list2 = TickList::from(2, tick_infos);

        assert_eq!(
            tick_list1
                .next_initialized_tick_within_one_word(0, false)
                .unwrap(),
            (255, false)
        );
        assert_eq!(
            tick_list2
                .next_initialized_tick_within_one_word(0, false)
                .unwrap(),
            (510, false)
        );
    }

    struct TestCaseNextTickError {
        args: (i32, bool),
        exp: Option<(i32, bool)>,
        err: Option<TickListErrorKind>,
        id: &'static str,
    }

    #[test]
    fn test_next_initialized_tick_within_one_word_errors() {
        let tick_infos =
            vec![create_tick_info(-5100, 10), create_tick_info(0, -5), create_tick_info(5100, -5)];
        let tick_list = TickList::from(10, tick_infos);
        let cases = vec![
            TestCaseNextTickError {
                args: (-1, true),
                exp: Some((-2560, false)),
                err: None,
                id: "lte: minimum within word",
            },
            TestCaseNextTickError {
                args: (-2561, true),
                exp: Some((-5100, true)),
                err: None,
                id: "lte: smallest initialized",
            },
            TestCaseNextTickError {
                args: (-5101, true),
                exp: Some((-5110, false)),
                err: None,
                id: "lte: last safe tick",
            },
            TestCaseNextTickError {
                args: (-5110, true),
                exp: Some((-5110, false)),
                err: None,
                id: "lte: border does not raise",
            },
            TestCaseNextTickError {
                args: (-5111, true),
                exp: None,
                err: Some(TickListErrorKind::TicksExeeded),
                id: "lte: outside safe raises",
            },
            TestCaseNextTickError {
                args: (1, false),
                exp: Some((2550, false)),
                err: None,
                id: "gt: minimum within word",
            },
            TestCaseNextTickError {
                args: (2550, false),
                exp: Some((5100, true)),
                err: None,
                id: "gt: largest initialized",
            },
            TestCaseNextTickError {
                args: (5101, false),
                exp: Some((5110, false)),
                err: None,
                id: "gt: last safe tick",
            },
            TestCaseNextTickError {
                args: (5110, false),
                exp: None,
                err: Some(TickListErrorKind::TicksExeeded),
                id: "gt: border raises",
            },
            TestCaseNextTickError {
                args: (5111, false),
                exp: None,
                err: Some(TickListErrorKind::TicksExeeded),
                id: "gt: outside safe raises",
            },
        ];

        for case in cases {
            let res = tick_list.next_initialized_tick_within_one_word(case.args.0, case.args.1);
            match case.err {
                Some(kind) => {
                    let err = res.unwrap_err();
                    assert_eq!(err.kind, kind, "{}", case.id);
                }
                None => {
                    let tup = res.unwrap();
                    assert_eq!(tup, case.exp.unwrap(), "{}", case.id);
                }
            }
        }
    }

    #[rstest]
    #[case(100)]
    #[case(-100)]
    fn test_apply_liquidity_change(#[case] delta: i128) {
        let tick_infos =
            vec![create_tick_info(-5100, 10), create_tick_info(0, -5), create_tick_info(5100, -5)];
        let mut tick_list = TickList::from(10, tick_infos);

        tick_list.apply_liquidity_change(-10, 10, delta);

        let lower = tick_list.get_tick(-10).unwrap();
        let upper = tick_list.get_tick(10).unwrap();
        assert_eq!(lower.net_liquidity, delta);
        assert_eq!(upper.net_liquidity, -delta);
    }

    #[test]
    fn test_apply_liquidity_change_add_remove() {
        let tick_infos =
            vec![create_tick_info(-5100, 10), create_tick_info(0, -5), create_tick_info(5100, -5)];
        let mut tick_list = TickList::from(10, tick_infos);

        tick_list.apply_liquidity_change(-10, 10, 100);
        tick_list.apply_liquidity_change(-10, 10, -100);

        assert!(tick_list.get_tick(-10).is_err());
        assert!(tick_list.get_tick(10).is_err());
    }
}
