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
}

impl TickList {
    pub fn new(spacing: usize) -> Self {
        return TickList {
            tick_spacing: spacing,
            ticks: Vec::with_capacity(20),
        };
    }

    pub fn from(spacing: usize, ticks: Vec<TickInfo>) -> Self {
        let tick_list = TickList {
            tick_spacing: spacing,
            ticks: ticks,
        };
        if tick_list.valid_ticks() {
            return tick_list;
        } else {
            panic!()
        }
    }

    fn valid_ticks(&self) -> bool {
        if self.tick_spacing == 0 {
            return false;
        }

        for i in 0..self.ticks.len() {
            let t = self.ticks.get(i).unwrap();
            if t.index % self.tick_spacing != 0 {
                return false;
            }
            if i != self.ticks.len() && t > self.ticks.get(i + 1).unwrap() {
                return false;
            }
        }

        return true;
    }

    pub fn push(&mut self, tick: TickInfo) {
        self.ticks.push(tick);
        self.ticks.insert(tick.index, tick);
        self.ticks.sort_by_key(|t| t.index);
    }

    // TODO: which one is faster heap reference or copy to stack?
    pub fn is_below_smallest(&mut self, tick: usize) -> bool {
        let t = &self.ticks[tick];
        return tick < t.index;
    }
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
    }

    #[test]
    fn test_push_new_tick() {
        let mut tick_list = create_tick_list();
        tick_list.push(create_tick_info(40, 10));
        assert_eq!(tick_list.ticks.len(), 4);
    }

    #[test]
    fn test_push_tick_duplicate_ix() {
        let mut tick_list = create_tick_list();
        tick_list.push(create_tick_info(30, 10));
        assert_eq!(tick_list.ticks.len(), 3);
    }

    #[test]
    fn test_is_below_smallest() {}
}
