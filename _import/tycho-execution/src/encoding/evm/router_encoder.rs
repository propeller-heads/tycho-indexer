use std::str::FromStr;

use num_bigint::BigUint;
use tycho_core::{models::Chain, Bytes};

use crate::encoding::{
    errors::EncodingError,
    evm::utils::encode_input,
    models::{NativeAction, Solution, Transaction},
    router_encoder::RouterEncoder,
    strategy_encoder::StrategySelector,
};

#[allow(dead_code)]
pub struct EVMRouterEncoder<S: StrategySelector> {
    strategy_selector: S,
    signer: Option<String>,
    chain: Chain,
    router_address: String,
}

#[allow(dead_code)]
impl<S: StrategySelector> EVMRouterEncoder<S> {
    pub fn new(
        strategy_selector: S,
        router_address: String,
        signer: Option<String>,
        chain: Chain,
    ) -> Result<Self, EncodingError> {
        Ok(EVMRouterEncoder { strategy_selector, signer, chain, router_address })
    }
}
impl<S: StrategySelector> RouterEncoder<S> for EVMRouterEncoder<S> {
    fn encode_router_calldata(
        &self,
        solutions: Vec<Solution>,
    ) -> Result<Vec<Transaction>, EncodingError> {
        let mut transactions: Vec<Transaction> = Vec::new();
        for solution in solutions.iter() {
            let exact_out = solution.exact_out;
            let straight_to_pool = solution.straight_to_pool;
            let router_address = solution
                .router_address
                .clone()
                .unwrap_or(Bytes::from_str(&self.router_address).map_err(|_| {
                    EncodingError::FatalError("Invalid router address".to_string())
                })?);
            let strategy = self.strategy_selector.select_strategy(
                solution,
                self.signer.clone(),
                self.chain,
            )?;
            let method_calldata = strategy.encode_strategy(solution.clone(), router_address)?;

            let contract_interaction = if straight_to_pool {
                method_calldata
            } else {
                encode_input(strategy.selector(exact_out), method_calldata)
            };

            let value = if solution.native_action.clone().unwrap() == NativeAction::Wrap {
                solution.given_amount.clone()
            } else {
                BigUint::ZERO
            };
            transactions.push(Transaction { value, data: contract_interaction });
        }
        Ok(transactions)
    }
}
