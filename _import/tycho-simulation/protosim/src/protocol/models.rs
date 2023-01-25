use ethers::types::{H160, U256};

use crate::models::ERC20Token;

use super::state::ProtocolState;

/// PairProperties struct represents the properties of a trading pair
///
/// # Fields
///
/// * `address`: H160, the address of the trading pair
/// * `tokens`: Vec<ERC20Token>, the tokens of the trading pair
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairProperties {
    pub address: H160,
    pub tokens: Vec<ERC20Token>,
}

/// Pair struct represents a trading pair with its properties and state
#[derive(Clone, Debug)]
pub struct Pair(pub PairProperties, pub ProtocolState);

/// GetAmountOutResult struct represents the result of getting the amount out of a trading pair
///
/// # Fields
///
/// * `amount`: U256, the amount of the trading pair
/// * `gas`: U256, the gas of the trading pair
#[derive(Debug)]
pub struct GetAmountOutResult {
    pub amount: U256,
    pub gas: U256,
}

impl GetAmountOutResult {
    /// Constructs a new GetAmountOutResult struct with the given amount and gas
    pub fn new(amount: U256, gas: U256) -> Self {
        GetAmountOutResult { amount, gas }
    }

    /// Aggregates the given GetAmountOutResult struct to the current one.
    /// It updates the amount with the other's amount and adds the other's gas to the current one's gas.
    pub fn aggregate(&mut self, other: &Self) {
        self.amount = other.amount;
        self.gas += other.gas;
    }
}
