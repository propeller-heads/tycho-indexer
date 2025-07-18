use std::{any::Any, collections::HashMap};

use num_bigint::BigUint;
use tycho_common::{
    dto::ProtocolStateDelta,
    models::token::Token,
    simulation::{
        errors::{SimulationError, TransitionError},
        protocol_sim::{Balances, GetAmountOutResult, ProtocolSim},
    },
    Bytes,
};

#[derive(Debug)]
pub struct BebopState {
    pub base_token: String,
    pub quote_token: String,
    pub last_update_ts: u64,
    pub bids: Vec<(f64, f64)>,
    pub asks: Vec<(f64, f64)>,
}

impl ProtocolSim for BebopState {
    fn fee(&self) -> f64 {
        todo!()
    }

    fn spot_price(&self, _base: &Token, _quote: &Token) -> Result<f64, SimulationError> {
        todo!()
    }

    fn get_amount_out(
        &self,
        _amount_in: BigUint,
        _token_in: &Token,
        _token_out: &Token,
    ) -> Result<GetAmountOutResult, SimulationError> {
        todo!()
    }

    fn get_limits(
        &self,
        _sell_token: Bytes,
        _buy_token: Bytes,
    ) -> Result<(BigUint, BigUint), SimulationError> {
        todo!()
    }

    fn delta_transition(
        &mut self,
        _delta: ProtocolStateDelta,
        _tokens: &HashMap<Bytes, Token>,
        _balances: &Balances,
    ) -> Result<(), TransitionError<String>> {
        todo!()
    }

    fn clone_box(&self) -> Box<dyn ProtocolSim> {
        todo!()
    }

    fn as_any(&self) -> &dyn Any {
        todo!()
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        todo!()
    }

    fn eq(&self, _other: &dyn ProtocolSim) -> bool {
        todo!()
    }
}
