use tycho_common::{models::Chain, Bytes};

use crate::encoding::{
    errors::EncodingError,
    evm::{
        strategy_encoder::strategy_encoders::SplitSwapStrategyEncoder,
        swap_encoder::swap_encoder_registry::SwapEncoderRegistry,
        tycho_encoders::{TychoExecutorEncoder, TychoRouterEncoder},
    },
    strategy_encoder::StrategyEncoder,
    tycho_encoder::TychoEncoder,
};

/// Builder pattern for constructing a `TychoRouterEncoder` with customizable options.
///
/// This struct allows setting a chain and strategy encoder before building the final encoder.
pub struct TychoRouterEncoderBuilder {
    swapper_pk: Option<String>,
    strategy: Option<Box<dyn StrategyEncoder>>,
    chain: Option<Chain>,
    executors_file_path: Option<String>,
    router_address: Option<Bytes>,
}

impl Default for TychoRouterEncoderBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl TychoRouterEncoderBuilder {
    pub fn new() -> Self {
        TychoRouterEncoderBuilder {
            swapper_pk: None,
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

    pub fn swapper_pk(mut self, swapper_pk: String) -> Self {
        self.swapper_pk = Some(swapper_pk);
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

    /// Builds the `TychoRouterEncoder` instance using the configured chain and strategy.
    /// Returns an error if either the chain or strategy has not been set.
    pub fn build(self) -> Result<Box<dyn TychoEncoder>, EncodingError> {
        if let Some(chain) = self.chain {
            let swap_encoder_registry =
                SwapEncoderRegistry::new(self.executors_file_path.clone(), chain)?;

            let strategy = Box::new(SplitSwapStrategyEncoder::new(
                chain,
                swap_encoder_registry,
                self.swapper_pk,
                self.router_address.clone(),
            )?);
            Ok(Box::new(TychoRouterEncoder::new(chain, strategy)?))
        } else {
            Err(EncodingError::FatalError(
                "Please set the chain and strategy before building the encoder".to_string(),
            ))
        }
    }
}

/// Builder pattern for constructing a `TychoExecutorEncoder` with customizable options.
pub struct TychoExecutorEncoderBuilder {
    chain: Option<Chain>,
    executors_file_path: Option<String>,
}

impl Default for TychoExecutorEncoderBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl TychoExecutorEncoderBuilder {
    pub fn new() -> Self {
        TychoExecutorEncoderBuilder { chain: None, executors_file_path: None }
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

    /// Builds the `TychoExecutorEncoder` instance using the configured chain and strategy.
    /// Returns an error if either the chain or strategy has not been set.
    pub fn build(self) -> Result<Box<dyn TychoEncoder>, EncodingError> {
        if let Some(chain) = self.chain {
            let swap_encoder_registry =
                SwapEncoderRegistry::new(self.executors_file_path.clone(), chain)?;
            Ok(Box::new(TychoExecutorEncoder::new(chain, swap_encoder_registry)?))
        } else {
            Err(EncodingError::FatalError(
                "Please set the chain and strategy before building the encoder".to_string(),
            ))
        }
    }
}
