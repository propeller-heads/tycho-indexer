use enum_dispatch::enum_dispatch;
use ethers::types::U256;

use crate::models::ERC20Token;

use super::{
    errors::TradeSimulationError, models::GetAmountOutResult, uniswap_v2::state::UniswapV2State,
    uniswap_v3::state::UniswapV3State,
};

#[enum_dispatch]
pub trait ProtocolSim {
    fn fee(&self) -> f64;
    fn spot_price(&self, a: &ERC20Token, b: &ERC20Token) -> f64;
    fn get_amount_out(
        &self,
        amount_in: U256,
        token_a: &ERC20Token,
        token_b: &ERC20Token,
    ) -> Result<GetAmountOutResult, TradeSimulationError>;
}

#[enum_dispatch(ProtocolSim)]
pub enum ProtocolState {
    UniswapV2(UniswapV2State),
    UniswapV3(UniswapV3State),
}
