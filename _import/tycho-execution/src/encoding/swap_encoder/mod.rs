use std::sync::RwLock;

use lazy_static::lazy_static;
use tycho_core::dto::Chain;

use crate::encoding::swap_encoder::registry::{Config, SwapEncoderRegistry};

mod builder;
mod registry;
mod swap_struct_encoder;

lazy_static! {
    pub static ref SWAP_ENCODER_REGISTRY: RwLock<SwapEncoderRegistry> = {
        let config = Config::from_file("config.json").expect("Failed to load configuration file");
        RwLock::new(SwapEncoderRegistry::new(config, Chain::Ethereum))
    };
}
