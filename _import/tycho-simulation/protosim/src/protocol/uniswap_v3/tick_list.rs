use ethers::types::U256;

#[derive(Copy, Clone)]
pub struct USV3TickInfo {
    tick_idx: usize,
    net_liquidity: U256,
    sqrt_price: U256,
}

pub struct TickList {
    tick_spacing: usize,
    ticks: Vec<USV3TickInfo>,
}

impl TickList {
    pub fn new(spacing: usize) -> Self {
        TickList {
            tick_spacing: spacing,
            ticks: Vec::with_capacity(20),
        }
    }

    pub fn push(&mut self, tick: USV3TickInfo) {
        self.ticks.push(tick);
    }

    // TODO: which one is faster heap reference or copy to stack?
    pub fn is_below_smallest(&mut self, tick: usize) -> bool {
        let t = &self.ticks[tick];
        tick < t.tick_idx
    }
}
