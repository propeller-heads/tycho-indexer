use std::{collections::HashMap, fs};

use tycho_core::models::Chain;

use crate::encoding::{
    errors::EncodingError, evm::swap_encoder::builder::SwapEncoderBuilder,
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
    /// executors in the file at the given path.
    pub fn new(executors_file_path: &str, blockchain: Chain) -> Result<Self, EncodingError> {
        let config_str = fs::read_to_string(executors_file_path)?;
        let config: HashMap<Chain, HashMap<String, String>> = serde_json::from_str(&config_str)?;
        let mut encoders = HashMap::new();
        let executors = config
            .get(&blockchain)
            .ok_or(EncodingError::FatalError("No executors found for blockchain".to_string()))?;
        for (protocol, executor_address) in executors {
            let builder = SwapEncoderBuilder::new(protocol, executor_address);
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
