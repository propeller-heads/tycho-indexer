use std::{borrow::BorrowMut, cell::RefCell, sync::Arc};

use ethers::{
    prelude::BaseContract,
    providers::Middleware,
    types::{H160, U256},
};
use revm::{
    primitives::{ExecutionResult, Output, B160, U256 as rU256},
    Database,
};

use crate::{
    evm_simulation::simulation::{SimulationEngine, SimulationParameters},
    protocol::{models::GetAmountOutResult, state::ProtocolSim},
    u256_num::u256_to_f64,
};

pub struct DodoPoolState<M: Middleware + Clone> {
    pool_address: H160,
    pool_abi: BaseContract,
    // TODO: Not sure how DODO handles these... so I am adding it here for no to not have to query every time
    base_token: H160,
    helper_address: H160,
    helper_abi: BaseContract,
    // TODO: it would be nicer to move all the caching behind a RefCell instead of exposing it to the user
    engine: RefCell<SimulationEngine<M>>,
    spot_price_cache: RefCell<Option<(f64, f64)>>,
}

impl<M: Middleware + Clone> DodoPoolState<M> {
    fn simulate_spot_prices(
        &self,
        base: &crate::models::ERC20Token,
        quote: &crate::models::ERC20Token,
    ) -> (f64, f64) {
        let spot_price_calldata = self.pool_abi.encode("getMidPrice", ()).unwrap();
        let params: SimulationParameters = SimulationParameters {
            caller: H160::zero(),
            to: self.pool_address,
            data: spot_price_calldata,
            value: U256::zero(),
        };
        let mut engine = self.engine.borrow_mut();
        let res = engine
            .simulate(&params)
            .expect("DODO: Spot price simulation while requesting data from node!");
        let spot_price_u256 = match res {
            ExecutionResult::Success {
                reason: _,
                gas_used: _,
                gas_refunded: _,
                logs: _,
                output,
            } => {
                if let Output::Call(data) = output {
                    self.pool_abi
                        .decode_output::<U256, _>("getMidPrice", data)
                        .expect("DODO: Failed decoding spot price result!")
                } else {
                    panic!("DODO: spot price calculation resulted in a contract creation!")
                }
            }
            _ => panic!("DODO: Spot prices: EVM execution reverted"),
        };
        (
            u256_to_f64(spot_price_u256) / 10f64.powi(quote.decimals as i32),
            10f64.powi(base.decimals as i32) / u256_to_f64(spot_price_u256),
        )
    }
}

impl<M: Middleware + Clone> ProtocolSim for DodoPoolState<M> {
    /// Dodo fees
    ///
    ///  Fee rates are in slot 8 and 9 they are accessed directly.
    fn fee(&self) -> f64 {
        let mut engine = self.engine.borrow_mut();
        let lp_fee = engine
            .state
            .storage(B160(self.pool_address.0), rU256::from(8))
            .expect("DODO: Error while requesting data from node!");
        let mantainer_fee = engine
            .state
            .storage(B160(self.pool_address.0), rU256::from(8))
            .expect("DODO: Error while requesting data from node!");
        let total_fee = U256::from_little_endian((lp_fee + mantainer_fee).as_le_slice());
        u256_to_f64(total_fee) / 1e18f64
    }

    fn spot_price(
        &self,
        base: &crate::models::ERC20Token,
        quote: &crate::models::ERC20Token,
    ) -> f64 {
        let mut cache = self.spot_price_cache.borrow_mut();
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
        token_out: &crate::models::ERC20Token,
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
        .expect("DODO: Error encoding calldata for get_amount_out!");
        let params = SimulationParameters {
            caller: H160::zero(),
            to: self.helper_address,
            data: calldata,
            value: U256::zero(),
        };
        let mut engine = self.engine.borrow_mut();
        let (amount_out, gas) = match engine
            .simulate(&params)
            .expect("DODO: get_amount_out simulation failed while requesting data from node")
        {
            ExecutionResult::Success {
                reason: _,
                gas_used,
                gas_refunded,
                logs: _,
                output,
            } => {
                if let Output::Call(data) = output {
                    (
                        self.pool_abi
                            .decode_output::<U256, _>("querySellBaseToken", data)
                            .expect("DODO: Failed decoding get_amount_out result!"),
                        gas_used - gas_refunded,
                    )
                } else {
                    panic!("DODO: get_amount_out calculation resulted in a contract creation!")
                }
            }
            _ => panic!("DODO: get_amount_out: EVM execution reverted"),
        };
        Ok(GetAmountOutResult {
            amount: amount_out,
            gas: U256::from(gas),
        })
    }
}
