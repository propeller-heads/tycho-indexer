use tycho_core::dto::Chain;

use crate::encoding::{
    errors::EncodingError,
    evm::{
        strategy_encoder::strategy_encoders::{ExecutorStrategyEncoder, SplitSwapStrategyEncoder},
        swap_encoder::swap_encoder_registry::SwapEncoderRegistry,
        tycho_encoder::EVMTychoEncoder,
    },
    strategy_encoder::StrategyEncoder,
};

pub struct EVMEncoderBuilder {
    strategy: Option<Box<dyn StrategyEncoder>>,
    chain: Option<Chain>,
}

impl Default for EVMEncoderBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl EVMEncoderBuilder {
    pub fn new() -> Self {
        EVMEncoderBuilder { chain: None, strategy: None }
    }
    pub fn chain(mut self, chain: Chain) -> Self {
        self.chain = Some(chain);
        self
    }
    pub fn strategy_encoder(mut self, strategy: Box<dyn StrategyEncoder>) -> Self {
        self.strategy = Some(strategy);
        self
    }
    pub fn tycho_router(
        self,
        swapper_pk: String,
        executors_file_path: Option<String>,
    ) -> Result<Self, EncodingError> {
        if let Some(chain) = self.chain {
            let swap_encoder_registry = SwapEncoderRegistry::new(executors_file_path, chain)?;
            let strategy =
                Box::new(SplitSwapStrategyEncoder::new(swapper_pk, chain, swap_encoder_registry)?);
            Ok(EVMEncoderBuilder { chain: Some(chain), strategy: Some(strategy) })
        } else {
            Err(EncodingError::FatalError(
                "Please set the chain before setting the strategy".to_string(),
            ))
        }
    }
    pub fn direct_execution(
        self,
        executors_file_path: Option<String>,
    ) -> Result<Self, EncodingError> {
        if let Some(chain) = self.chain {
            let swap_encoder_registry = SwapEncoderRegistry::new(executors_file_path, chain)?;
            let strategy = Box::new(ExecutorStrategyEncoder::new(swap_encoder_registry));
            Ok(EVMEncoderBuilder { chain: Some(chain), strategy: Some(strategy) })
        } else {
            Err(EncodingError::FatalError(
                "Please set the chain before setting the strategy".to_string(),
            ))
        }
    }

    pub fn build(self) -> Result<EVMTychoEncoder, EncodingError> {
        if let (Some(chain), Some(strategy)) = (self.chain, self.strategy) {
            EVMTychoEncoder::new(chain, strategy)
        } else {
            Err(EncodingError::FatalError(
                "Please set the chain and strategy before building the encoder".to_string(),
            ))
        }
    }
}
