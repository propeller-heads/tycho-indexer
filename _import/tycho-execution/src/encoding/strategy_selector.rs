use crate::encoding::models::Solution;
use crate::encoding::strategy_encoder::{
    SequentialStrategyEncoder, SingleSwapStrategyEncoder, SlipSwapStrategyEncoder,
    StraightToPoolStrategyEncoder, StrategyEncoder,
};

pub trait StrategySelector {
    fn select_strategy(&self, solution: &Solution) -> Box<dyn StrategyEncoder>;
}

pub struct DefaultStrategySelector;

impl StrategySelector for DefaultStrategySelector {
    fn select_strategy(&self, solution: &Solution) -> Box<dyn StrategyEncoder> {
        if solution.straight_to_pool {
            Box::new(StraightToPoolStrategyEncoder {})
        } else if solution.swaps.len() == 1 {
            Box::new(SingleSwapStrategyEncoder {})
        } else if solution.swaps.iter().all(|s| s.split == 0.0) {
            Box::new(SequentialStrategyEncoder {})
        } else {
            Box::new(SlipSwapStrategyEncoder {})
        }
    }
}
