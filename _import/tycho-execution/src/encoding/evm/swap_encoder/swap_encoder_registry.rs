use std::{collections::HashMap, fs};

use tycho_core::dto::Chain;

use crate::encoding::{
    errors::EncodingError, evm::swap_encoder::builder::SwapEncoderBuilder,
    swap_encoder::SwapEncoder,
};

#[derive(Clone)]
pub struct SwapEncoderRegistry {
    encoders: HashMap<String, Box<dyn SwapEncoder>>,
}

impl SwapEncoderRegistry {
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

    pub fn new_direct_execution() -> Self {
        let mut encoders = HashMap::new();

        // Add default encoders with their respective executor addresses
        let default_encoders = [
            ("uniswap_v2", "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D"),
            ("vm:balancer_v2", "0xBA12222222228d8Ba445958a75a0704d566BF2C8"),
        ];

        for (protocol, executor_address) in default_encoders {
            let builder = SwapEncoderBuilder::new(protocol, executor_address);
            if let Ok(encoder) = builder.build() {
                encoders.insert(protocol.to_string(), encoder);
            }
        }

        Self { encoders }
    }

    #[allow(clippy::borrowed_box)]
    pub fn get_encoder(&self, protocol_system: &str) -> Option<&Box<dyn SwapEncoder>> {
        self.encoders.get(protocol_system)
    }
}
