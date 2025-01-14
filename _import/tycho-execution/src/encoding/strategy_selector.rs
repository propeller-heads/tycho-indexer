use crate::encoding::models::Order;
use crate::encoding::strategy_encoder::{
    SequentialStrategyEncoder, SingleSwapStrategyEncoder, SlipSwapStrategyEncoder,
    StraightToPoolStrategyEncoder, StrategyEncoder,
};

pub trait StrategySelector {
    fn select_strategy(&self, order: &Order) -> Box<dyn StrategyEncoder>;
}

pub struct DefaultStrategySelector;

impl StrategySelector for DefaultStrategySelector {
    fn select_strategy(&self, order: &Order) -> Box<dyn StrategyEncoder> {
        if order.straight_to_pool {
            Box::new(StraightToPoolStrategyEncoder {})
        } else if order.swaps.len() == 1 {
            Box::new(SingleSwapStrategyEncoder {})
        } else if order.swaps.iter().all(|s| s.split == 0.0) {
            Box::new(SequentialStrategyEncoder {})
        } else {
            Box::new(SlipSwapStrategyEncoder {})
        }
    }
}
