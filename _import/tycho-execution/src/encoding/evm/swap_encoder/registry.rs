use std::{collections::HashMap, fs};

use serde::Deserialize;
use tycho_core::dto::Chain;

use crate::encoding::{
    errors::EncodingError, evm::swap_encoder::builder::SwapEncoderBuilder,
    swap_encoder::SwapEncoder,
};

pub struct SwapEncoderRegistry {
    encoders: HashMap<String, Box<dyn SwapEncoder>>,
}

impl SwapEncoderRegistry {
    pub fn new(config: Config, blockchain: Chain) -> Self {
        let mut encoders = HashMap::new();
        let executors = config
            .executors
            .get(&blockchain)
            .unwrap_or_else(|| panic!("No executors found for blockchain: {}", blockchain));
        for (protocol, executor_address) in executors {
            let builder = SwapEncoderBuilder::new(protocol, executor_address);
            let encoder = builder.build().unwrap_or_else(|_| {
                panic!("Failed to build swap encoder for protocol: {}", protocol)
            });
            encoders.insert(protocol.to_string(), encoder);
        }

        Self { encoders }
    }

    #[allow(clippy::borrowed_box)]
    pub fn get_encoder(&self, protocol_system: &str) -> Option<&Box<dyn SwapEncoder>> {
        self.encoders.get(protocol_system)
    }
}

#[derive(Deserialize)]
pub struct Config {
    pub executors: HashMap<Chain, HashMap<String, String>>, /* Blockchain -> {Protocol ->
                                                             * Executor address} mapping */
}

impl Config {
    pub fn from_file(path: &str) -> Result<Self, EncodingError> {
        let config_str = fs::read_to_string(path)?;
        let config: Config = serde_json::from_str(&config_str)?;
        Ok(config)
    }
}
