pub mod base;
pub mod full_range;
pub mod oracle;

use evm_ekubo_sdk::{
    math::uint::U256,
    quoting::types::{NodeKey, Tick},
};

use super::state::EkuboState;
use crate::protocol::errors::{SimulationError, TransitionError};

#[enum_delegate::register]
pub trait EkuboPool {
    fn key(&self) -> &NodeKey;

    fn sqrt_ratio(&self) -> U256;

    fn set_sqrt_ratio(&mut self, sqrt_ratio: U256);
    fn set_liquidity(&mut self, liquidity: u128);
    fn set_tick(&mut self, tick: Tick) -> Result<(), String>;

    fn get_limit(&self, token_in: U256) -> Result<u128, SimulationError>;

    fn reinstantiate(&mut self) -> Result<(), TransitionError<String>>;
}

pub struct EkuboPoolQuote {
    pub consumed_amount: i128,
    pub calculated_amount: i128,
    pub gas: u64,
    pub new_state: EkuboState,
}
