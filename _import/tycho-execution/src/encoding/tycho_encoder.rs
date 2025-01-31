use crate::encoding::{
    errors::EncodingError,
    models::{Solution, Transaction},
    strategy_encoder::StrategySelector,
};

#[allow(dead_code)]
pub trait TychoEncoder<S: StrategySelector> {
    fn encode_router_calldata(
        &self,
        solutions: Vec<Solution>,
    ) -> Result<Vec<Transaction>, EncodingError>;

    fn validate_solution(&self, solution: &Solution) -> Result<(), EncodingError>;
}
