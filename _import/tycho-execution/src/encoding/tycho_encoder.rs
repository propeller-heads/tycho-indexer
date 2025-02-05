use crate::encoding::{
    errors::EncodingError,
    models::{Solution, Transaction},
    strategy_encoder::StrategyEncoderRegistry,
};

/// An encoder must implement this trait in order to encode a solution into a Transaction for
/// execution using a Tycho router or related contracts.
pub trait TychoEncoder<S: StrategyEncoderRegistry> {
    fn encode_router_calldata(
        &self,
        solutions: Vec<Solution>,
    ) -> Result<Vec<Transaction>, EncodingError>;
}
