use std::{collections::HashMap, fs};

use crate::encoding::{
    errors::EncodingError,
    evm::{constants::DEFAULT_EXECUTORS_JSON, swap_encoder::builder::SwapEncoderBuilder},
    models::Chain,
    swap_encoder::SwapEncoder,
};

/// Registry containing all supported `SwapEncoders`.
#[derive(Clone)]
pub struct SwapEncoderRegistry {
    /// A hashmap containing the protocol system as a key and the `SwapEncoder` as a value.
    encoders: HashMap<String, Box<dyn SwapEncoder>>,
}

impl SwapEncoderRegistry {
    /// Populates the registry with the `SwapEncoders` for the given blockchain by parsing the
    /// executors' addresses in the file at the given path.
    pub fn new(
        executors_file_path: Option<String>,
        blockchain: tycho_common::models::Chain,
    ) -> Result<Self, EncodingError> {
        let chain = Chain::from(blockchain);
        let config_str = if let Some(ref path) = executors_file_path {
            fs::read_to_string(path).map_err(|e| {
                EncodingError::FatalError(format!(
                    "Error reading executors file from {:?}: {}",
                    executors_file_path, e
                ))
            })?
        } else {
            DEFAULT_EXECUTORS_JSON.to_string()
        };
        let config: HashMap<String, HashMap<String, String>> = serde_json::from_str(&config_str)?;
        let mut encoders = HashMap::new();
        let executors = config
            .get(&chain.name)
            .ok_or(EncodingError::FatalError("No executors found for chain".to_string()))?;
        for (protocol, executor_address) in executors {
            let builder = SwapEncoderBuilder::new(protocol, executor_address, chain.clone());
            let encoder = builder.build()?;
            encoders.insert(protocol.to_string(), encoder);
        }

        Ok(Self { encoders })
    }

    #[allow(clippy::borrowed_box)]
    pub fn get_encoder(&self, protocol_system: &str) -> Option<&Box<dyn SwapEncoder>> {
        self.encoders.get(protocol_system)
    }
}
