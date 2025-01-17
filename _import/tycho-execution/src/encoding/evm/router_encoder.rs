use num_bigint::BigUint;

use crate::encoding::{
    errors::EncodingError,
    evm::utils::encode_input,
    models::{NativeAction, Solution, Transaction, PROPELLER_ROUTER_ADDRESS},
    router_encoder::RouterEncoder,
    strategy_encoder::StrategySelector,
    user_approvals_manager::{Approval, UserApprovalsManager},
};

#[allow(dead_code)]
pub struct EVMRouterEncoder<S: StrategySelector, A: UserApprovalsManager> {
    strategy_selector: S,
    approvals_manager: A,
}

#[allow(dead_code)]
impl<S: StrategySelector, A: UserApprovalsManager> EVMRouterEncoder<S, A> {
    pub fn new(strategy_selector: S, approvals_manager: A) -> Self {
        EVMRouterEncoder { strategy_selector, approvals_manager }
    }
}
impl<S: StrategySelector, A: UserApprovalsManager> RouterEncoder<S, A> for EVMRouterEncoder<S, A> {
    fn encode_router_calldata(
        &self,
        solutions: Vec<Solution>,
    ) -> Result<Vec<Transaction>, EncodingError> {
        let _approvals_calldata = self.handle_approvals(&solutions)?; // TODO: where should we append this?
        let mut transactions: Vec<Transaction> = Vec::new();
        for solution in solutions.iter() {
            let exact_out = solution.exact_out;
            let straight_to_pool = solution.straight_to_pool;

            let strategy = self
                .strategy_selector
                .select_strategy(solution);
            let method_calldata = strategy.encode_strategy((*solution).clone())?;

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

    fn handle_approvals(&self, solutions: &[Solution]) -> Result<Vec<Vec<u8>>, EncodingError> {
        let mut approvals = Vec::new();
        for solution in solutions.iter() {
            approvals.push(Approval {
                token: solution.given_token.clone(),
                spender: solution
                    .router_address
                    .clone()
                    .unwrap_or(PROPELLER_ROUTER_ADDRESS.clone()),
                amount: solution.given_amount.clone(),
                owner: solution.sender.clone(),
            });
        }
        Ok(self
            .approvals_manager
            .encode_approvals(approvals))
    }
}
