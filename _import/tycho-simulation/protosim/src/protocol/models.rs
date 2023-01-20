use ethers::types::U256;

#[derive(Debug)]
pub struct GetAmountOutResult {
    pub amount: U256,
    pub gas: U256,
}

impl GetAmountOutResult {
    pub fn new(amount: U256, gas: U256) -> Self {
        GetAmountOutResult { amount, gas }
    }
}
