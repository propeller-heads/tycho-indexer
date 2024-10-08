use std::any::Any;

use ethers::types::U256;

use crate::protocol::state::ProtocolEvent;

#[derive(Debug, Clone)]
pub struct UniswapV2Sync {
    pub reserve0: U256,
    pub reserve1: U256,
}

impl UniswapV2Sync {
    pub fn new(r0: U256, r1: U256) -> Self {
        UniswapV2Sync { reserve0: r0, reserve1: r1 }
    }
}

impl ProtocolEvent for UniswapV2Sync {
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn clone_box(&self) -> Box<dyn ProtocolEvent> {
        Box::new(self.clone())
    }
}
