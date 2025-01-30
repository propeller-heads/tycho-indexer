mod builder;
mod registry;
mod swap_encoders;

use std::sync::RwLock;

use lazy_static::lazy_static;
use tycho_core::dto::Chain;

use crate::encoding::evm::swap_encoder::registry::{Config, SwapEncoderRegistry};

// TODO: init this at the higher level at some point
lazy_static! {
    pub static ref SWAP_ENCODER_REGISTRY: RwLock<SwapEncoderRegistry> = {
        let config = Config::from_file("src/encoding/config/executor_addresses.json")
            .expect("Failed to load configuration file");
        RwLock::new(SwapEncoderRegistry::new(config, Chain::Ethereum))
    };
}
