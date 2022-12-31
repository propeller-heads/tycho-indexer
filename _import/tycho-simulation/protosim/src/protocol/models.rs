use ethers::types::{H160, U256};

use crate::models::ERC20Token;

use super::state::ProtocolState;

#[derive(Debug, Clone)]
pub struct PairProperties {
    pub address: H160,
    pub tokens: Vec<ERC20Token>,
}

#[derive(Clone)]
pub struct Pair(pub PairProperties, pub ProtocolState);

#[derive(Debug)]
pub struct GetAmountOutResult {
    pub amount: U256,
    pub gas: U256,
}

impl GetAmountOutResult {
    pub fn new(amount: U256, gas: U256) -> Self {
        GetAmountOutResult { amount, gas }
    }

    pub fn aggregate(&mut self, other: &Self) {
        self.amount = other.amount;
        self.gas += other.gas;
    }
}
