use alloy::signers::local::PrivateKeySigner;
use alloy_primitives::ChainId;

use crate::encoding::{
    errors::EncodingError,
    evm::strategy_encoder::encoder::{SplitSwapStrategyEncoder, StraightToPoolStrategyEncoder},
    models::Solution,
    strategy_encoder::{StrategyEncoder, StrategySelector},
};

pub struct EVMStrategySelector;

impl StrategySelector for EVMStrategySelector {
    fn select_strategy(
        &self,
        solution: &Solution,
        signer: Option<PrivateKeySigner>,
        chain_id: ChainId,
    ) -> Result<Box<dyn StrategyEncoder>, EncodingError> {
        if solution.straight_to_pool {
            Ok(Box::new(StraightToPoolStrategyEncoder {}))
        } else {
            let signer = signer.ok_or_else(|| {
                EncodingError::FatalError(
                    "Signer is required for SplitSwapStrategyEncoder".to_string(),
                )
            })?;
            Ok(Box::new(SplitSwapStrategyEncoder::new(signer, chain_id).unwrap()))
        }
    }
}
