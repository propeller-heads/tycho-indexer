use std::{collections::HashMap, str::FromStr};

use alloy::{primitives::B256, signers::local::PrivateKeySigner};
use tycho_common::{models::Chain, Bytes};

use crate::encoding::{
    errors::EncodingError,
    evm::{
        constants::DEFAULT_ROUTERS_JSON,
        swap_encoder::swap_encoder_registry::SwapEncoderRegistry,
        tycho_encoders::{TychoExecutorEncoder, TychoRouterEncoder},
    },
    models::UserTransferType,
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
    swapper_pk: Option<String>,
    historical_trade: bool,
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
            swapper_pk: None,
            user_transfer_type: None,
            historical_trade: false,
        }
    }
    pub fn chain(mut self, chain: Chain) -> Self {
        self.chain = Some(chain);
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

    /// Sets the `historical_trade` manually to true.
    /// If set to true, it means that the encoded trade will be used in an historical block (as a
    /// test) and not in the current one. This is relevant for checking token approvals in some
    /// protocols (like Balancer v2).
    pub fn historical_trade(mut self) -> Self {
        self.historical_trade = true;
        self
    }

    /// Sets the `swapper_pk` for the encoder. This is used to sign permit2 objects. This is only
    /// needed if you intend to get the full calldata for the transfer. We do not recommend
    /// using this option, you should sign and create the function calldata entirely on your
    /// own.
    #[deprecated(
        note = "This is deprecated and will be removed in the future. You should sign and create the function calldata on your own."
    )]
    pub fn swapper_pk(mut self, swapper_pk: String) -> Self {
        self.swapper_pk = Some(swapper_pk);
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
                let default_routers: HashMap<Chain, Bytes> =
                    serde_json::from_str(DEFAULT_ROUTERS_JSON)?;
                tycho_router_address = default_routers
                    .get(&chain)
                    .ok_or(EncodingError::FatalError(
                        "No default router address found for chain".to_string(),
                    ))?
                    .to_owned();
            }

            let swap_encoder_registry =
                SwapEncoderRegistry::new(self.executors_file_path.clone(), chain)?;

            let signer = if let Some(pk) = self.swapper_pk {
                let pk = B256::from_str(&pk).map_err(|_| {
                    EncodingError::FatalError("Invalid swapper private key provided".to_string())
                })?;
                Some(PrivateKeySigner::from_bytes(&pk).map_err(|_| {
                    EncodingError::FatalError("Failed to create signer".to_string())
                })?)
            } else {
                None
            };

            Ok(Box::new(TychoRouterEncoder::new(
                chain,
                swap_encoder_registry,
                tycho_router_address,
                user_transfer_type,
                signer,
                self.historical_trade,
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
            Ok(Box::new(TychoExecutorEncoder::new(swap_encoder_registry)?))
        } else {
            Err(EncodingError::FatalError(
                "Please set the chain and strategy before building the encoder".to_string(),
            ))
        }
    }
}
