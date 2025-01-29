use std::str::FromStr;

use num_bigint::BigUint;
use tycho_core::Bytes;

use crate::encoding::{
    errors::EncodingError,
    evm::utils::encode_input,
    models::{NativeAction, Solution, Transaction},
    router_encoder::RouterEncoder,
    strategy_encoder::StrategySelector,
    user_approvals_manager::{Approval, UserApprovalsManager},
};

#[allow(dead_code)]
pub struct EVMRouterEncoder<S: StrategySelector, A: UserApprovalsManager> {
    strategy_selector: S,
    approvals_manager: A,
    router_address: String,
}

#[allow(dead_code)]
impl<S: StrategySelector, A: UserApprovalsManager> EVMRouterEncoder<S, A> {
    pub fn new(strategy_selector: S, approvals_manager: A, router_address: String) -> Self {
        EVMRouterEncoder { strategy_selector, approvals_manager, router_address }
    }
}
impl<S: StrategySelector, A: UserApprovalsManager> RouterEncoder<S, A> for EVMRouterEncoder<S, A> {
    fn encode_router_calldata(
        &self,
        solutions: Vec<Solution>,
    ) -> Result<Vec<Transaction>, EncodingError> {
        let _approvals_calldata = self.handle_approvals(&solutions)?;
        let mut transactions: Vec<Transaction> = Vec::new();
        for solution in solutions.iter() {
            let exact_out = solution.exact_out;
            let straight_to_pool = solution.straight_to_pool;

            let strategy = self
                .strategy_selector
                .select_strategy(solution);
            let (method_calldata, target_address) =
                strategy.encode_strategy((*solution).clone())?;

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
            transactions.push(Transaction {
                value,
                data: contract_interaction,
                to: target_address,
            });
        }
        Ok(transactions)
    }

    fn handle_approvals(&self, solutions: &[Solution]) -> Result<Vec<Vec<u8>>, EncodingError> {
        let mut approvals = Vec::new();
        for solution in solutions.iter() {
            approvals.push(Approval {
                token: solution.given_token.clone(),
                spender: solution
                    .router_address
                    .clone()
                    .unwrap_or(Bytes::from_str(&self.router_address).map_err(|_| {
                        EncodingError::FatalError("Invalid router address".to_string())
                    })?),
                amount: solution.given_amount.clone(),
                owner: solution.sender.clone(),
            });
        }
        self.approvals_manager
            .encode_approvals(approvals)
    }
}
