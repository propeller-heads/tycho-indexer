use ethers::types::U256;

#[derive(Debug)]
pub struct UniswapV2Sync {
    pub reserve0: U256,
    pub reserve1: U256,
}

impl UniswapV2Sync {
    pub fn new(r0: U256, r1: U256) -> Self {
        UniswapV2Sync {
            reserve0: r0,
            reserve1: r1,
        }
    }
}
