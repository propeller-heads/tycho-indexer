use crate::encoding::{
    evm::strategy_encoder::encoder::{
        SequentialStrategyEncoder, SingleSwapStrategyEncoder, SplitSwapStrategyEncoder,
        StraightToPoolStrategyEncoder,
    },
    models::Solution,
    strategy_encoder::{StrategyEncoder, StrategySelector},
};

pub struct EVMStrategySelector;

impl StrategySelector for EVMStrategySelector {
    fn select_strategy(&self, solution: &Solution) -> Box<dyn StrategyEncoder> {
        if solution.straight_to_pool {
            Box::new(StraightToPoolStrategyEncoder {})
        } else if solution.swaps.len() == 1 {
            Box::new(SingleSwapStrategyEncoder {})
        } else if solution
            .swaps
            .iter()
            .all(|s| s.split == 0.0)
        {
            Box::new(SequentialStrategyEncoder {})
        } else {
            Box::new(SplitSwapStrategyEncoder {})
        }
    }
}
