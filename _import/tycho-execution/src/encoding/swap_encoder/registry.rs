use crate::encoding::swap_encoder::builder::SwapEncoderBuilder;
use crate::encoding::swap_encoder::swap_encoder::SwapEncoder;
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;

pub struct SwapEncoderRegistry {
    encoders: HashMap<String, Box<dyn SwapEncoder>>,
}

impl SwapEncoderRegistry {
    pub fn new(config: Config) -> Self {
        let mut encoders = HashMap::new();

        for (protocol, executor_address) in config.executors {
            let builder = SwapEncoderBuilder::new(&protocol).executor_address(&executor_address);
            let encoder = builder.build().expect(&format!(
                "Failed to build swap encoder for protocol: {}",
                protocol
            ));
            encoders.insert(protocol, encoder);
        }

        Self { encoders }
    }

    pub fn get_encoder(&self, protocol_system: &str) -> Option<&Box<dyn SwapEncoder>> {
        self.encoders.get(protocol_system)
    }
}

#[derive(Deserialize)]
pub struct Config {
    pub executors: HashMap<String, String>, // Protocol -> Executor address mapping
}

impl Config {
    pub fn from_file(path: &str) -> Result<Self, anyhow::Error> {
        let config_str = fs::read_to_string(path)?;
        let config: Config = serde_json::from_str(&config_str)?;
        Ok(config)
    }
}
