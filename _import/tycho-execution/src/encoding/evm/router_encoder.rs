use alloy_sol_types::SolValue;
use anyhow::Error;
use num_bigint::BigUint;

use crate::encoding::{
    evm::utils::{encode_input, ple_encode},
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
    fn encode_router_calldata(&self, solutions: Vec<Solution>) -> Result<Transaction, Error> {
        let _approvals_calldata = self.handle_approvals(&solutions)?; // TODO: where should we append this?
        let mut calldata_list: Vec<Vec<u8>> = Vec::new();
        let encode_for_batch_execute = solutions.len() > 1;
        let mut value = BigUint::ZERO;
        for solution in solutions.iter() {
            let exact_out = solution.exact_out;
            let straight_to_pool = solution.straight_to_pool;

            let strategy = self
                .strategy_selector
                .select_strategy(solution);
            let method_calldata = strategy.encode_strategy((*solution).clone())?;

            let contract_interaction = if encode_for_batch_execute {
                let args = (strategy.action_type(exact_out) as u16, method_calldata);
                args.abi_encode()
            } else if straight_to_pool {
                method_calldata
            } else {
                encode_input(strategy.selector(exact_out), method_calldata)
            };
            calldata_list.push(contract_interaction);

            if solution.native_action.clone().unwrap() == NativeAction::Wrap {
                value += solution.given_amount.clone();
            }
        }
        let data = if encode_for_batch_execute {
            let args = (false, ple_encode(calldata_list));
            encode_input("batchExecute(bytes)", args.abi_encode())
        } else {
            calldata_list[0].clone()
        };

        Ok(Transaction { data, value })
    }

    fn handle_approvals(&self, solutions: &[Solution]) -> Result<Vec<u8>, Error> {
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
