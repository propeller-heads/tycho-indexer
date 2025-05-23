use std::collections::HashMap;

use alloy::signers::local::PrivateKeySigner;
use tycho_common::{models::Chain as TychoCommonChain, Bytes};

use crate::encoding::{
    errors::EncodingError,
    evm::{
        constants::DEFAULT_ROUTERS_JSON,
        swap_encoder::swap_encoder_registry::SwapEncoderRegistry,
        tycho_encoders::{TychoExecutorEncoder, TychoRouterEncoder},
    },
    models::{Chain, UserTransferType},
    tycho_encoder::TychoEncoder,
};

/// Builder pattern for constructing a `TychoRouterEncoder` with customizable options.
///
/// This struct allows setting a chain and strategy encoder before building the final encoder.
pub struct TychoRouterEncoderBuilder {
    chain: Option<Chain>,
    user_transfer_type: Option<UserTransferType>,
    executors_file_path: Option<String>,
    router_address: Option<Bytes>,
    signer: Option<PrivateKeySigner>,
}

impl Default for TychoRouterEncoderBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl TychoRouterEncoderBuilder {
    pub fn new() -> Self {
        TychoRouterEncoderBuilder {
            chain: None,
            executors_file_path: None,
            router_address: None,
            signer: None,
            user_transfer_type: None,
        }
    }
    pub fn chain(mut self, chain: TychoCommonChain) -> Self {
        self.chain = Some(chain.into());
        self
    }

    pub fn user_transfer_type(mut self, user_transfer_type: UserTransferType) -> Self {
        self.user_transfer_type = Some(user_transfer_type);
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

    pub fn signer(mut self, signer: PrivateKeySigner) -> Self {
        self.signer = Some(signer);
        self
    }

    /// Builds the `TychoRouterEncoder` instance using the configured chain.
    /// Returns an error if either the chain has not been set.
    pub fn build(self) -> Result<Box<dyn TychoEncoder>, EncodingError> {
        if let (Some(chain), Some(user_transfer_type)) = (self.chain, self.user_transfer_type) {
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
                tycho_router_address,
                user_transfer_type,
                self.signer,
            )?))
        } else {
            Err(EncodingError::FatalError(
                "Please set the chain and user transfer type before building the encoder"
                    .to_string(),
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
            Ok(Box::new(TychoExecutorEncoder::new(swap_encoder_registry)?))
        } else {
            Err(EncodingError::FatalError(
                "Please set the chain and strategy before building the encoder".to_string(),
            ))
        }
    }
}
