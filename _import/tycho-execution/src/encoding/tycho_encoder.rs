use crate::encoding::{
    errors::EncodingError,
    models::{Solution, Transaction},
    strategy_encoder::StrategyEncoderRegistry,
};

pub trait TychoEncoder<S: StrategyEncoderRegistry> {
    fn encode_router_calldata(
        &self,
        solutions: Vec<Solution>,
    ) -> Result<Vec<Transaction>, EncodingError>;
}
