use tycho_core::models::Chain;

use crate::encoding::{
    errors::EncodingError,
    evm::strategy_encoder::strategy_encoders::{
        SplitSwapStrategyEncoder, StraightToPoolStrategyEncoder,
    },
    models::Solution,
    strategy_encoder::{StrategyEncoder, StrategySelector},
};

pub struct EVMStrategySelector;

impl StrategySelector for EVMStrategySelector {
    fn select_strategy(
        &self,
        solution: &Solution,
        signer: Option<String>,
        chain: Chain,
    ) -> Result<Box<dyn StrategyEncoder>, EncodingError> {
        if solution.straight_to_pool {
            Ok(Box::new(StraightToPoolStrategyEncoder {}))
        } else {
            let signer_pk = signer.ok_or_else(|| {
                EncodingError::FatalError(
                    "Signer is required for SplitSwapStrategyEncoder".to_string(),
                )
            })?;
            Ok(Box::new(SplitSwapStrategyEncoder::new(signer_pk, chain).unwrap()))
        }
    }
}
