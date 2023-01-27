use ethers::types::U256;

#[derive(Debug)]
pub struct LiquidityChangeData {
    pub tick_upper: i32,
    pub tick_lower: i32,
    pub amount: i128,
}

impl LiquidityChangeData {
    pub fn new(lower: i32, upper: i32, amount: i128) -> Self {
        LiquidityChangeData {
            tick_lower: lower,
            tick_upper: upper,
            amount: amount,
        }
    }
}

#[derive(Debug)]
pub struct SwapData {
    pub sqrt_price: U256,
    pub liquidity: u128,
    pub tick: i32,
}

impl SwapData {
    pub fn new(sqrt_price: U256, liquidity: u128, tick: i32) -> Self {
        SwapData {
            sqrt_price,
            liquidity,
            tick,
        }
    }
}

#[derive(Debug)]
pub enum UniswapV3Event {
    Mint(LiquidityChangeData),
    Burn(LiquidityChangeData),
    Swap(SwapData),
}
