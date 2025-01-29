use alloy_primitives::Address;

use crate::encoding::{errors::EncodingError, models::Solution};

#[allow(dead_code)]
pub trait StrategyEncoder {
    fn encode_strategy(&self, to_encode: Solution) -> Result<(Vec<u8>, Address), EncodingError>;
    fn selector(&self, exact_out: bool) -> &str;
}

pub trait StrategySelector {
    #[allow(dead_code)]
    fn select_strategy(&self, solution: &Solution) -> Box<dyn StrategyEncoder>;
}
