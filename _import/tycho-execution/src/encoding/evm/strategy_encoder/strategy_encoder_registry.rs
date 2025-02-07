use std::collections::HashMap;

use crate::encoding::{
    errors::EncodingError,
    evm::{
        strategy_encoder::strategy_encoders::{ExecutorStrategyEncoder, SplitSwapStrategyEncoder},
        swap_encoder::swap_encoder_registry::SwapEncoderRegistry,
    },
    models::{Chain, Solution},
    strategy_encoder::{StrategyEncoder, StrategyEncoderRegistry},
};

/// Contains all supported strategies to encode a solution.
///
/// # Fields
/// * `strategies` - A hashmap containing the name of the strategy as a key and the strategy encoder
///   as a value.
pub struct EVMStrategyEncoderRegistry {
    strategies: HashMap<String, Box<dyn StrategyEncoder>>,
}

impl StrategyEncoderRegistry for EVMStrategyEncoderRegistry {
    fn new(
        chain: tycho_core::dto::Chain,
        executors_file_path: Option<String>,
        signer_pk: Option<String>,
    ) -> Result<Self, EncodingError> {
        let chain = Chain::from(chain);
        let swap_encoder_registry = SwapEncoderRegistry::new(executors_file_path, chain.clone())?;

        let mut strategies: HashMap<String, Box<dyn StrategyEncoder>> = HashMap::new();
        strategies.insert(
            "executor".to_string(),
            Box::new(ExecutorStrategyEncoder::new(swap_encoder_registry.clone())),
        );
        if let Some(signer) = signer_pk {
            strategies.insert(
                "split_swap".to_string(),
                Box::new(
                    SplitSwapStrategyEncoder::new(signer, chain, swap_encoder_registry).unwrap(),
                ),
            );
        }
        Ok(Self { strategies })
    }
    fn get_encoder(&self, solution: &Solution) -> Result<&Box<dyn StrategyEncoder>, EncodingError> {
        if solution.direct_execution {
            self.strategies
                .get("executor")
                .ok_or(EncodingError::FatalError("Executor strategy not found".to_string()))
        } else {
            self.strategies
                .get("split_swap")
                .ok_or(EncodingError::FatalError("Split swap strategy not found. Please pass the signer private key to the StrategySelector constructor".to_string()))
        }
    }
}

impl Clone for EVMStrategyEncoderRegistry {
    fn clone(&self) -> Self {
        Self {
            strategies: self
                .strategies
                .iter()
                .map(|(k, v)| (k.clone(), v.clone_box()))
                .collect(),
        }
    }
}
