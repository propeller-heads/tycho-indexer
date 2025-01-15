use crate::encoding::swap_encoder::swap_encoder::{
    BalancerV2SwapEncoder, SwapEncoder, UniswapV2SwapEncoder,
};
use alloy_primitives::Address;
use std::str::FromStr;

pub struct SwapEncoderBuilder {
    protocol_system: String,
    executor_address: Address,
}

impl SwapEncoderBuilder {
    pub fn new(protocol_system: &str, executor_address: &str) -> Self {
        SwapEncoderBuilder {
            protocol_system: protocol_system.to_string(),
            executor_address: Address::from_str(executor_address)
                .expect(&format!("Invalid address: {}", executor_address)),
        }
    }

    pub fn build(self) -> Result<Box<dyn SwapEncoder>, String> {
        match self.protocol_system.as_str() {
            "uniswap_v2" => Ok(Box::new(UniswapV2SwapEncoder::new(self.executor_address))),
            "vm:balancer_v2" => Ok(Box::new(BalancerV2SwapEncoder::new(self.executor_address))),
            _ => Err(format!("Unknown protocol system: {}", self.protocol_system)),
        }
    }
}
