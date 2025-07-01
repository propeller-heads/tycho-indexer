pub mod base;
pub mod full_range;
pub mod mev_resist;
pub mod oracle;
pub mod twamm;

use std::collections::{HashMap, HashSet};

use evm_ekubo_sdk::{
    math::uint::U256,
    quoting::types::{NodeKey, TokenAmount},
};
use tycho_common::Bytes;

use super::state::EkuboState;
use crate::protocol::errors::{SimulationError, TransitionError};

pub struct EkuboPoolQuote {
    pub consumed_amount: i128,
    pub calculated_amount: u128,
    pub gas: u64,
    pub new_state: EkuboState,
}

#[enum_delegate::register]
pub trait EkuboPool {
    fn key(&self) -> &NodeKey;
    fn sqrt_ratio(&self) -> U256;

    fn set_sqrt_ratio(&mut self, sqrt_ratio: U256);
    fn set_liquidity(&mut self, liquidity: u128);

    fn finish_transition(
        &mut self,
        updated_attributes: HashMap<String, Bytes>,
        deleted_attributes: HashSet<String>,
    ) -> Result<(), TransitionError<String>>;

    fn quote(
        &self,
        token_amount: TokenAmount,
    ) -> Result<super::pool::EkuboPoolQuote, SimulationError>;
    fn get_limit(&self, token_in: U256) -> Result<i128, SimulationError>;
}
