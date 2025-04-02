use tycho_common::{models::Chain, Bytes};

use crate::encoding::{
    errors::EncodingError,
    evm::{
        strategy_encoder::strategy_encoders::{ExecutorStrategyEncoder, SplitSwapStrategyEncoder},
        swap_encoder::swap_encoder_registry::SwapEncoderRegistry,
        tycho_encoder::EVMTychoEncoder,
    },
    strategy_encoder::StrategyEncoder,
};

/// Builder pattern for constructing an `EVMTychoEncoder` with customizable options.
///
/// This struct allows setting a chain and strategy encoder before building the final encoder.
pub struct EVMEncoderBuilder {
    strategy: Option<Box<dyn StrategyEncoder>>,
    chain: Option<Chain>,
    executors_file_path: Option<String>,
    router_address: Option<Bytes>,
}

impl Default for EVMEncoderBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl EVMEncoderBuilder {
    pub fn new() -> Self {
        EVMEncoderBuilder {
            chain: None,
            strategy: None,
            executors_file_path: None,
            router_address: None,
        }
    }
    pub fn chain(mut self, chain: Chain) -> Self {
        self.chain = Some(chain);
        self
    }

    /// Sets the `executors_file_path` manually.
    /// If it's not set, the default path will be used (config/executor_addresses.json)
    pub fn executors_file_path(mut self, executors_file_path: String) -> Self {
        self.executors_file_path = Some(executors_file_path);
        self
    }

    /// Sets the `router_address` manually.
    /// If it's not set, the default router address will be used (config/router_addresses.json)
    pub fn router_address(mut self, router_address: Bytes) -> Self {
        self.router_address = Some(router_address);
        self
    }

    /// Sets the `strategy_encoder` manually.
    ///
    /// **Note**: This method should not be used in combination with `tycho_router` or
    /// `direct_execution`.
    pub fn strategy_encoder(mut self, strategy: Box<dyn StrategyEncoder>) -> Self {
        self.strategy = Some(strategy);
        self
    }

    /// Shortcut method to initialize a `SplitSwapStrategyEncoder` without any approval nor token in
    /// transfer. **Note**: Should not be used at the same time as `strategy_encoder`.
    pub fn initialize_tycho_router(self) -> Result<Self, EncodingError> {
        if let Some(chain) = self.chain {
            let swap_encoder_registry =
                SwapEncoderRegistry::new(self.executors_file_path.clone(), chain)?;
            let strategy = Box::new(SplitSwapStrategyEncoder::new(
                chain,
                swap_encoder_registry,
                None,
                self.router_address.clone(),
            )?);
            Ok(EVMEncoderBuilder {
                chain: Some(chain),
                strategy: Some(strategy),
                executors_file_path: self.executors_file_path,
                router_address: self.router_address,
            })
        } else {
            Err(EncodingError::FatalError(
                "Please set the chain before setting the tycho router".to_string(),
            ))
        }
    }

    /// Shortcut method to initialize a `SplitSwapStrategyEncoder` with Permit2 approval and token
    /// in transfer. **Note**: Should not be used at the same time as `strategy_encoder`.
    pub fn initialize_tycho_router_with_permit2(
        self,
        swapper_pk: String,
    ) -> Result<Self, EncodingError> {
        if let Some(chain) = self.chain {
            let swap_encoder_registry =
                SwapEncoderRegistry::new(self.executors_file_path.clone(), chain)?;
            let strategy = Box::new(SplitSwapStrategyEncoder::new(
                chain,
                swap_encoder_registry,
                Some(swapper_pk),
                self.router_address.clone(),
            )?);
            Ok(EVMEncoderBuilder {
                chain: Some(chain),
                strategy: Some(strategy),
                executors_file_path: self.executors_file_path,
                router_address: self.router_address,
            })
        } else {
            Err(EncodingError::FatalError(
                "Please set the chain before setting the tycho router".to_string(),
            ))
        }
    }

    /// Shortcut method to initialize an `ExecutorStrategyEncoder`.
    /// **Note**: Should not be used at the same time as `strategy_encoder`.
    pub fn initialize_direct_execution(self) -> Result<Self, EncodingError> {
        if let Some(chain) = self.chain {
            let swap_encoder_registry =
                SwapEncoderRegistry::new(self.executors_file_path.clone(), chain)?;
            let strategy = Box::new(ExecutorStrategyEncoder::new(swap_encoder_registry));
            Ok(EVMEncoderBuilder {
                chain: Some(chain),
                strategy: Some(strategy),
                executors_file_path: self.executors_file_path,
                router_address: self.router_address,
            })
        } else {
            Err(EncodingError::FatalError(
                "Please set the chain before setting the strategy".to_string(),
            ))
        }
    }

    /// Builds the `EVMTychoEncoder` instance using the configured chain and strategy.
    /// Returns an error if either the chain or strategy has not been set.
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
