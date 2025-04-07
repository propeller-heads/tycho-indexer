use crate::encoding::{
    errors::EncodingError,
    evm::swap_encoder::swap_encoders::{
        BalancerV2SwapEncoder, CurveSwapEncoder, EkuboSwapEncoder, UniswapV2SwapEncoder,
        UniswapV3SwapEncoder, UniswapV4SwapEncoder,
    },
    models::Chain,
    swap_encoder::SwapEncoder,
};

/// Builds a `SwapEncoder` for the given protocol system and executor address.
pub struct SwapEncoderBuilder {
    protocol_system: String,
    executor_address: String,
    chain: Chain,
}

impl SwapEncoderBuilder {
    pub fn new(protocol_system: &str, executor_address: &str, chain: Chain) -> Self {
        SwapEncoderBuilder {
            protocol_system: protocol_system.to_string(),
            executor_address: executor_address.to_string(),
            chain,
        }
    }

    pub fn build(self) -> Result<Box<dyn SwapEncoder>, EncodingError> {
        match self.protocol_system.as_str() {
            "uniswap_v2" => {
                Ok(Box::new(UniswapV2SwapEncoder::new(self.executor_address, self.chain)?))
            }
            "sushiswap_v2" => {
                Ok(Box::new(UniswapV2SwapEncoder::new(self.executor_address, self.chain)?))
            }
            "pancakeswap_v2" => {
                Ok(Box::new(UniswapV2SwapEncoder::new(self.executor_address, self.chain)?))
            }
            "vm:balancer_v2" => {
                Ok(Box::new(BalancerV2SwapEncoder::new(self.executor_address, self.chain)?))
            }
            "uniswap_v3" => {
                Ok(Box::new(UniswapV3SwapEncoder::new(self.executor_address, self.chain)?))
            }
            "pancakeswap_v3" => {
                Ok(Box::new(UniswapV3SwapEncoder::new(self.executor_address, self.chain)?))
            }
            "uniswap_v4" => {
                Ok(Box::new(UniswapV4SwapEncoder::new(self.executor_address, self.chain)?))
            }
            "ekubo_v2" => Ok(Box::new(EkuboSwapEncoder::new(self.executor_address, self.chain)?)),
            "vm:curve" => Ok(Box::new(CurveSwapEncoder::new(self.executor_address, self.chain)?)),
            _ => Err(EncodingError::FatalError(format!(
                "Unknown protocol system: {}",
                self.protocol_system
            ))),
        }
    }
}
