use crate::encoding::swap_encoder::swap_encoder::{
    BalancerV2SwapEncoder, SwapEncoder, UniswapV2SwapEncoder,
};
use alloy_primitives::Address;
use std::str::FromStr;

pub struct SwapEncoderBuilder {
    protocol_system: String,
    executor_address: Option<Address>,
}

impl SwapEncoderBuilder {
    pub fn new(protocol_system: &str) -> Self {
        SwapEncoderBuilder {
            protocol_system: protocol_system.to_string(),
            executor_address: None,
        }
    }

    pub fn executor_address(mut self, address: &str) -> Self {
        self.executor_address =
            Some(Address::from_str(address).expect(&format!("Invalid address: {}", address)));
        self
    }

    pub fn build(self) -> Result<Box<dyn SwapEncoder>, String> {
        let executor_address = self.executor_address.ok_or_else(|| {
            format!(
                "Executor address must be provided for protocol: {}",
                self.protocol_system
            )
        })?;
        match self.protocol_system.as_str() {
            "uniswap_v2" => Ok(Box::new(UniswapV2SwapEncoder::new(executor_address))),
            "vm:balancer_v2" => Ok(Box::new(BalancerV2SwapEncoder::new(executor_address))),
            _ => Err(format!("Unknown protocol system: {}", self.protocol_system)),
        }
    }
}
