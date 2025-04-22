use std::collections::HashMap;

use tycho_common::{models::Chain as TychoCommonChain, Bytes};

use crate::encoding::{
    errors::EncodingError,
    evm::{
        constants::DEFAULT_ROUTERS_JSON,
        swap_encoder::swap_encoder_registry::SwapEncoderRegistry,
        tycho_encoders::{TychoExecutorEncoder, TychoRouterEncoder},
    },
    models::Chain,
    tycho_encoder::TychoEncoder,
};

/// Builder pattern for constructing a `TychoRouterEncoder` with customizable options.
///
/// This struct allows setting a chain and strategy encoder before building the final encoder.
pub struct TychoRouterEncoderBuilder {
    swapper_pk: Option<String>,
    chain: Option<Chain>,
    executors_file_path: Option<String>,
    router_address: Option<Bytes>,
    token_in_already_in_router: Option<bool>,
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
            executors_file_path: None,
            router_address: None,
            token_in_already_in_router: None,
        }
    }
    pub fn chain(mut self, chain: TychoCommonChain) -> Self {
        self.chain = Some(chain.into());
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

    // Sets the `token_in_already_in_router` flag.
    // If set to true, the encoder will assume that the token in is already in the router.
    // WARNING: this is an advanced feature and should be used with caution. Make sure you have
    // checks to make sure that your tokens won't be lost. The Router is not considered safe to hold
    // tokens, so if this is not done within the same transaction you will lose your tokens.
    pub fn token_in_already_in_router(mut self, token_in_already_in_router: bool) -> Self {
        self.token_in_already_in_router = Some(token_in_already_in_router);
        self
    }

    /// Builds the `TychoRouterEncoder` instance using the configured chain.
    /// Returns an error if either the chain has not been set.
    pub fn build(self) -> Result<Box<dyn TychoEncoder>, EncodingError> {
        if let Some(chain) = self.chain {
            let tycho_router_address;
            if let Some(address) = self.router_address {
                tycho_router_address = address;
            } else {
                let default_routers: HashMap<String, Bytes> =
                    serde_json::from_str(DEFAULT_ROUTERS_JSON)?;
                tycho_router_address = default_routers
                    .get(&chain.name)
                    .ok_or(EncodingError::FatalError(
                        "No default router address found for chain".to_string(),
                    ))?
                    .to_owned();
            }

            let swap_encoder_registry =
                SwapEncoderRegistry::new(self.executors_file_path.clone(), chain.clone())?;

            Ok(Box::new(TychoRouterEncoder::new(
                chain,
                swap_encoder_registry,
                self.swapper_pk,
                tycho_router_address,
                self.token_in_already_in_router
                    .unwrap_or(false),
            )?))
        } else {
            Err(EncodingError::FatalError(
                "Please set the chain and router address before building the encoder".to_string(),
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
    pub fn chain(mut self, chain: TychoCommonChain) -> Self {
        self.chain = Some(chain.into());
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
                SwapEncoderRegistry::new(self.executors_file_path.clone(), chain.clone())?;
            Ok(Box::new(TychoExecutorEncoder::new(chain, swap_encoder_registry)?))
        } else {
            Err(EncodingError::FatalError(
                "Please set the chain and strategy before building the encoder".to_string(),
            ))
        }
    }
}
