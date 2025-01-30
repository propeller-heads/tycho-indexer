use crate::encoding::{
    evm::strategy_encoder::encoder::{ExecutorStrategyEncoder, SplitSwapStrategyEncoder},
    models::Solution,
    strategy_encoder::{StrategyEncoder, StrategySelector},
};

pub struct EVMStrategySelector;

impl StrategySelector for EVMStrategySelector {
    fn select_strategy(&self, solution: &Solution) -> Box<dyn StrategyEncoder> {
        if solution.straight_to_pool {
            Box::new(ExecutorStrategyEncoder {})
        } else {
            Box::new(SplitSwapStrategyEncoder {})
        }
    }
}
