use std::{
    any::Any,
    sync::{Arc, RwLock},
};

use ethers::{
    prelude::BaseContract,
    types::{H160, U256},
};
use revm::{
    db::DatabaseRef,
    primitives::{Address, U256 as rU256},
};
use tycho_core::dto::ProtocolStateDelta;

use crate::{
    evm::simulation::{SimulationEngine, SimulationParameters},
    protocol::{
        errors::TransitionError,
        events::{EVMLogMeta, LogIndex},
        models::GetAmountOutResult,
        state::{ProtocolEvent, ProtocolSim},
    },
    u256_num::u256_to_f64,
};

#[allow(dead_code)]
#[derive(Debug)]
pub struct DodoPoolState<D: DatabaseRef + std::clone::Clone>
where
    D::Error: std::fmt::Debug,
{
    pool_address: H160,
    pool_abi: BaseContract,
    // TODO: Not sure how DODO handles these... so I am adding it here for no to not have to
    // query every time
    base_token: H160,
    helper_address: H160,
    helper_abi: BaseContract,
    engine: SimulationEngine<D>,
    spot_price_cache: Arc<RwLock<Option<(f64, f64)>>>,
}
impl<D: DatabaseRef + std::clone::Clone> Clone for DodoPoolState<D>
where
    D::Error: std::fmt::Debug,
{
    fn clone(&self) -> Self {
        DodoPoolState {
            pool_address: self.pool_address,
            pool_abi: self.pool_abi.clone(),
            base_token: self.base_token,
            helper_address: self.helper_address,
            helper_abi: self.helper_abi.clone(),
            engine: self.engine.clone(),
            spot_price_cache: Arc::clone(&self.spot_price_cache),
        }
    }
}

impl<D: DatabaseRef + std::clone::Clone> DodoPoolState<D>
where
    D::Error: std::fmt::Debug,
{
    #[allow(dead_code)]
    fn simulate_spot_prices(
        &self,
        base: &crate::models::ERC20Token,
        quote: &crate::models::ERC20Token,
    ) -> (f64, f64) {
        let spot_price_calldata = self
            .pool_abi
            .encode("getMidPrice", ())
            .unwrap();
        let params: SimulationParameters = SimulationParameters {
            caller: Address::ZERO,
            to: Address::from(self.pool_address.0),
            data: spot_price_calldata,
            value: U256::zero(),
            overrides: None,
            gas_limit: None,
            block_number: 0,
            timestamp: 0,
        };
        let simulation_result = self.engine.simulate(&params).unwrap();
        let spot_price_u256 = self
            .pool_abi
            .decode_output::<U256, _>("getMidPrice", simulation_result.result)
            .expect("DODO: Failed decoding spot price result!");
        (
            u256_to_f64(spot_price_u256) / 10f64.powi(quote.decimals as i32),
            10f64.powi(base.decimals as i32) / u256_to_f64(spot_price_u256),
        )
    }
}

impl<D: DatabaseRef + Send + Sync + std::fmt::Debug + 'static + std::clone::Clone> ProtocolSim
    for DodoPoolState<D>
where
    D::Error: std::fmt::Debug,
{
    /// Dodo fees
    ///
    ///  Fee rates are in slot 8 and 9 they are accessed directly.
    fn fee(&self) -> f64 {
        let lp_fee = self
            .engine
            .state
            .storage_ref(Address::from_slice(&self.pool_address.0), rU256::from(8))
            .unwrap_or_else(|_| panic!("Error while requesting data from node."));
        let maintainer_fee = self
            .engine
            .state
            .storage_ref(Address::from_slice(&self.pool_address.0), rU256::from(8))
            .unwrap_or_else(|_| panic!("Error while requesting data from node."));
        let total_fee = U256::from_little_endian((lp_fee + maintainer_fee).as_le_slice());
        u256_to_f64(total_fee) / 1e18f64
    }

    fn spot_price(
        &self,
        base: &crate::models::ERC20Token,
        quote: &crate::models::ERC20Token,
    ) -> f64 {
        let mut cache = self.spot_price_cache.write().unwrap();
        if cache.is_none() {
            let prices = self.simulate_spot_prices(base, quote);
            *cache = Some(prices);
        }
        let prices = cache.unwrap();
        if self.base_token == base.address {
            prices.0
        } else {
            prices.1
        }
    }

    /// Dodo's V1 PMM algorithm
    ///
    /// Accessed via a helper smart contract. Seems like they forgot to add the quote simulation
    ///  for both directions on V1.
    fn get_amount_out(
        &self,
        amount_in: ethers::types::U256,
        token_in: &crate::models::ERC20Token,
        _token_out: &crate::models::ERC20Token,
    ) -> Result<
        crate::protocol::models::GetAmountOutResult,
        crate::protocol::errors::TradeSimulationError,
    > {
        let calldata = if self.base_token == token_in.address {
            self.helper_abi
                .encode("querySellBaseToken", (self.pool_address, amount_in))
        } else {
            self.helper_abi
                .encode("querySellQuoteToken", (self.pool_address, amount_in))
        }
        .expect(
            "DODO: Error
     encoding calldata for get_amount_out!",
        );
        let params = SimulationParameters {
            caller: Address::ZERO,
            to: Address::from(self.helper_address.0),
            data: calldata,
            value: U256::zero(),
            overrides: None,
            gas_limit: None,
            block_number: 0,
            timestamp: 0,
        };
        let simulation_result = self.engine.simulate(&params).unwrap();
        let amount_out = self
            .pool_abi
            .decode_output::<U256, _>("querySellBaseToken", simulation_result.result)
            .expect("DODO: Failed decoding get_amount_out result!");
        Ok(GetAmountOutResult { amount: amount_out, gas: U256::from(simulation_result.gas_used) })
    }

    #[allow(unused_variables)]
    fn delta_transition(
        &mut self,
        delta: ProtocolStateDelta,
    ) -> Result<(), TransitionError<String>> {
        unimplemented!()
    }

    #[allow(unused_variables)]
    fn event_transition(
        &mut self,
        protocol_event: Box<dyn ProtocolEvent>,
        log: &EVMLogMeta,
    ) -> Result<(), TransitionError<LogIndex>> {
        unimplemented!()
    }

    fn clone_box(&self) -> Box<dyn ProtocolSim> {
        Box::new(self.clone())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    #[allow(unused_variables)]
    fn eq(&self, other: &dyn ProtocolSim) -> bool {
        unimplemented!()
    }
}
