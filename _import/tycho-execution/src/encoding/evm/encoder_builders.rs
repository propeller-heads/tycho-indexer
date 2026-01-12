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
    swap_encoder_registry: Option<SwapEncoderRegistry>,
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
            swap_encoder_registry: None,
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

    pub fn swap_encoder_registry(mut self, swap_encoder_registry: SwapEncoderRegistry) -> Self {
        self.swap_encoder_registry = Some(swap_encoder_registry);
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
        if let (Some(chain), Some(user_transfer_type), Some(swap_encoder_registry)) =
            (self.chain, self.user_transfer_type, self.swap_encoder_registry)
        {
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
                "Please set the chain, user transfer type and swap encoder registry before building the encoder"
                    .to_string(),
            ))
        }
    }
}

/// Builder pattern for constructing a `TychoExecutorEncoder` with customizable options.
pub struct TychoExecutorEncoderBuilder {
    swap_encoder_registry: Option<SwapEncoderRegistry>,
}

impl Default for TychoExecutorEncoderBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl TychoExecutorEncoderBuilder {
    pub fn new() -> Self {
        TychoExecutorEncoderBuilder { swap_encoder_registry: None }
    }

    pub fn swap_encoder_registry(mut self, swap_encoder_registry: SwapEncoderRegistry) -> Self {
        self.swap_encoder_registry = Some(swap_encoder_registry);
        self
    }

    /// Builds the `TychoExecutorEncoder` instance using the configured chain and strategy.
    /// Returns an error if either the chain or strategy has not been set.
    pub fn build(self) -> Result<Box<dyn TychoEncoder>, EncodingError> {
        if let Some(swap_encoder_registry) = self.swap_encoder_registry {
            Ok(Box::new(TychoExecutorEncoder::new(swap_encoder_registry)?))
        } else {
            Err(EncodingError::FatalError(
                "Please set the swap encoder registry before building the encoder".to_string(),
            ))
        }
    }
}
