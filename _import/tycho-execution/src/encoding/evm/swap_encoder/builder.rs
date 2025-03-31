use crate::encoding::{
    errors::EncodingError,
    evm::swap_encoder::swap_encoders::{
        BalancerV2SwapEncoder, UniswapV2SwapEncoder, UniswapV3SwapEncoder, UniswapV4SwapEncoder,
    },
    swap_encoder::SwapEncoder,
};

/// Builds a `SwapEncoder` for the given protocol system and executor address.
pub struct SwapEncoderBuilder {
    protocol_system: String,
    executor_address: String,
}

impl SwapEncoderBuilder {
    pub fn new(protocol_system: &str, executor_address: &str) -> Self {
        SwapEncoderBuilder {
            protocol_system: protocol_system.to_string(),
            executor_address: executor_address.to_string(),
        }
    }

    pub fn build(self) -> Result<Box<dyn SwapEncoder>, EncodingError> {
        match self.protocol_system.as_str() {
            "uniswap_v2" => Ok(Box::new(UniswapV2SwapEncoder::new(self.executor_address))),
            "sushiswap_v2" => Ok(Box::new(UniswapV2SwapEncoder::new(self.executor_address))),
            "pancakeswap_v2" => Ok(Box::new(UniswapV2SwapEncoder::new(self.executor_address))),
            "vm:balancer_v2" => Ok(Box::new(BalancerV2SwapEncoder::new(self.executor_address))),
            "uniswap_v3" => Ok(Box::new(UniswapV3SwapEncoder::new(self.executor_address))),
            "pancakeswap_v3" => Ok(Box::new(UniswapV3SwapEncoder::new(self.executor_address))),
            "uniswap_v4" => Ok(Box::new(UniswapV4SwapEncoder::new(self.executor_address))),
            _ => Err(EncodingError::FatalError(format!(
                "Unknown protocol system: {}",
                self.protocol_system
            ))),
        }
    }
}
