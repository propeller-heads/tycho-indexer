use tycho_core::dto::Chain;

use crate::encoding::{
    errors::EncodingError,
    evm::{
        strategy_encoders::{ExecutorStrategyEncoder, SplitSwapStrategyEncoder},
        swap_encoder::swap_encoder_registry::SwapEncoderRegistry,
        tycho_encoder::EVMTychoEncoder,
    },
    strategy_encoder::StrategyEncoder,
};

pub struct EVMEncoderBuilder {
    strategy: Box<dyn StrategyEncoder>,
    chain: Chain,
}

impl EVMEncoderBuilder {
    pub fn new(chain: Chain, strategy: Box<dyn StrategyEncoder>) -> Self {
        EVMEncoderBuilder { chain, strategy }
    }
    pub fn tycho_router(
        chain: Chain,
        signer_pk: String,
        executors_file_path: Option<String>,
    ) -> Result<Self, EncodingError> {
        let swap_encoder_registry = SwapEncoderRegistry::new(executors_file_path, chain)?;
        let strategy =
            Box::new(SplitSwapStrategyEncoder::new(signer_pk, chain, swap_encoder_registry)?);
        Ok(EVMEncoderBuilder { chain, strategy })
    }
    pub fn direct_execution(
        chain: Chain,
        executors_file_path: Option<String>,
    ) -> Result<Self, EncodingError> {
        let swap_encoder_registry = SwapEncoderRegistry::new(executors_file_path, chain)?;
        let strategy = Box::new(ExecutorStrategyEncoder::new(swap_encoder_registry));
        Ok(EVMEncoderBuilder { chain, strategy })
    }

    pub fn build(self) -> Result<EVMTychoEncoder, EncodingError> {
        EVMTychoEncoder::new(self.chain, self.strategy)
    }
}
