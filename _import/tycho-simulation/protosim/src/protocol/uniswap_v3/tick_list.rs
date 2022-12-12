use ethers::types::U256;

// enum TickSpacing{one: 1, 100, 300, 5000}

#[derive(Copy, Clone, PartialEq)]
pub struct TickInfo {
    index: usize,
    net_liquidity: U256,
    sqrt_price: U256,
}

impl PartialOrd for TickInfo {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        return self.index.partial_cmp(&other.index);
    }
}

pub struct TickList {
    tick_spacing: usize,
    ticks: Vec<TickInfo>,
    tick_idxs: Vec<usize>,
}

impl TickList {
    pub fn new(spacing: usize) -> Self {
        return TickList {
            tick_spacing: spacing,
            ticks: Vec::with_capacity(20),
            tick_idxs: Vec::with_capacity(20),
        };
    }

    pub fn from(spacing: usize, ticks: Vec<TickInfo>) -> Self {
        let tick_idxs = ticks.iter().map(|&x| x.index).collect();
        let tick_list = TickList {
            tick_spacing: spacing,
            ticks: ticks,
            tick_idxs: tick_idxs,
        };
        let valid = tick_list.valid_ticks();
        if valid.is_ok() {
            return tick_list;
        } else {
            panic!("{}", valid.unwrap_err());
        }
    }

    // Asserts that all attributes are valid. Checks for:
    // 1. Tick spacing > 0
    // 2. Tick indexes have no rest when divided by tick spacing
    // 3. Ticks are ordered by index
    // TODO: test
    fn valid_ticks(&self) -> Result<bool, String> {
        if self.tick_spacing == 0 {
            return Err(String::from("Tick spacing is 0"));
        }

        for i in 0..self.ticks.len() {
            let t = self.ticks.get(i).unwrap();
            if t.index % self.tick_spacing != 0 {
                return Err(format!(
                    "Tick index {} not aligned with tick spacing",
                    t.index
                ));
            }
            if i != self.ticks.len() && t > self.ticks.get(i + 1).unwrap() {
                let msg = format!("Ticks are not ordered at position {}", t.index);
                return Err(msg);
            }
        }

        return Ok(true);
    }

    pub fn push(&mut self, tick: TickInfo) {
        let index_to_push = self.tick_idxs.binary_search(&tick.index);
        if index_to_push.is_ok() {
            panic!("Tick at index {} already exists!", tick.index)
        }
        
        self.ticks.insert(index_to_push.unwrap_err(), tick);
        self.tick_idxs.insert(index_to_push.unwrap_err(), tick.index);
        let valid = self.valid_ticks();
        if valid.is_err() {
            panic!("{}", valid.unwrap_err());
        }
    }

    // TODO: test
    pub fn is_below_smallest(&self, tick: usize) -> bool {
        let t = &self.ticks[tick];
        return tick < t.index;
    }

    // TODO: test
    pub fn is_below_safe_tick(&self, tick: usize) -> bool {
        let smallest = &self.ticks[0];
        let minimum = smallest.index - self.tick_spacing;
        return tick < minimum;
    }

    // def is_at_or_above_largest(self, tick: int) -> bool:
    // assert len(self.ticks), "LENGTH"
    // return tick >= self.ticks[-1].tick_idx

    // def is_at_or_above_safe_tick(self, tick: int) -> bool:
    //     largest = self.ticks[-1].tick_idx
    //     maximum = largest + self.tick_spacing
    //     return tick >= maximum
}

#[cfg(test)]
mod tests {

    use super::*;

    fn create_tick_list() -> TickList {
        let mut tick_list = TickList::new(10);
        let liquidities = [(10, 10), (20, 5), (30, 0)];
        for (ix, liq) in liquidities {
            tick_list.push(create_tick_info(ix, liq));
        }
        return tick_list;
    }

    fn create_tick_info(idx: usize, liq: u8) -> TickInfo {
        return TickInfo {
            index: idx,
            net_liquidity: U256::from(liq),
            sqrt_price: U256::zero(),
        };
    }

    #[test]
    fn test_new() {
        let tick_list = create_tick_list();
        assert_eq!(tick_list.ticks.len(), 3);
        assert_eq!(tick_list.tick_spacing, 10);
        assert_eq!(tick_list.ticks.capacity(), 20);
    }

    #[test]
    fn test_push_new_tick() {
        let mut tick_list = create_tick_list();
        tick_list.push(create_tick_info(40, 10));
        assert_eq!(tick_list.ticks.len(), 4);
    }

    #[test]
    #[should_panic]
    fn test_push_tick_duplicate_ix() {
        let mut tick_list = create_tick_list();
        tick_list.push(create_tick_info(30, 10));
    }

    #[test]
    #[should_panic]
    fn test_push_tick_invalid_ix() {
        let mut tick_list = create_tick_list();
        tick_list.push(create_tick_info(35, 10));
    }

    #[test]
    fn test_is_below_smallest() {}
}
