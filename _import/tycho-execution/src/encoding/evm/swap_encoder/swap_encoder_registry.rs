use std::collections::HashMap;

use tycho_common::models::Chain;

use crate::encoding::{
    errors::EncodingError,
    evm::{
        constants::{DEFAULT_EXECUTORS_JSON, PROTOCOL_SPECIFIC_CONFIG},
        swap_encoder::builder::SwapEncoderBuilder,
    },
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
    pub fn new(executors_addresses: Option<String>, chain: Chain) -> Result<Self, EncodingError> {
        let config_str = if let Some(addresses) = executors_addresses {
            addresses
        } else {
            DEFAULT_EXECUTORS_JSON.to_string()
        };
        let config: HashMap<Chain, HashMap<String, String>> = serde_json::from_str(&config_str)?;
        let executors = config
            .get(&chain)
            .ok_or(EncodingError::FatalError("No executors found for chain".to_string()))?;

        let protocol_specific_config: HashMap<Chain, HashMap<String, HashMap<String, String>>> =
            serde_json::from_str(PROTOCOL_SPECIFIC_CONFIG)?;
        let protocol_specific_config = protocol_specific_config
            .get(&chain)
            .ok_or(EncodingError::FatalError(
                "No protocol specific config found for chain".to_string(),
            ))?;
        let mut encoders = HashMap::new();
        for (protocol, executor_address) in executors {
            let builder = SwapEncoderBuilder::new(
                protocol,
                executor_address,
                chain,
                protocol_specific_config
                    .get(protocol)
                    .cloned(),
            );
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
