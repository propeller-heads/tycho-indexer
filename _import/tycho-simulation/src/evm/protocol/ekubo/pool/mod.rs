pub mod base;
pub mod full_range;
pub mod oracle;
pub mod twamm;

use evm_ekubo_sdk::{
    math::uint::U256,
    quoting::types::{NodeKey, Tick, TokenAmount},
};

use super::state::EkuboState;
use crate::protocol::errors::{SimulationError, TransitionError};

pub struct EkuboPoolQuote {
    pub consumed_amount: i128,
    pub calculated_amount: i128,
    pub gas: u64,
    pub new_state: EkuboState,
}

#[enum_delegate::register]
pub trait EkuboPool {
    fn key(&self) -> &NodeKey;
    fn sqrt_ratio(&self) -> U256;

    fn set_sqrt_ratio(&mut self, sqrt_ratio: U256);
    fn set_liquidity(&mut self, liquidity: u128);

    fn quote(&self, token_amount: TokenAmount) -> Result<super::pool::EkuboPoolQuote, SimulationError>;
    fn get_limit(&self, token_in: U256) -> Result<u128, SimulationError>;

    fn finish_transition(&mut self) -> Result<(), TransitionError<String>>;
}
