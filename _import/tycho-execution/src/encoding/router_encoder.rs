use crate::encoding::approvals::interface::{Approval, UserApprovalsManager};
use crate::encoding::models::{Solution, PROPELLER_ROUTER_ADDRESS};
use crate::encoding::strategy_selector::StrategySelector;
use crate::encoding::utils::{encode_input, ple_encode};
use alloy_sol_types::SolValue;
use anyhow::Error;

struct RouterEncoder<S: StrategySelector, A: UserApprovalsManager> {
    strategy_selector: S,
    approvals_manager: A,
}
impl<S: StrategySelector, A: UserApprovalsManager> RouterEncoder<S, A> {
    pub fn new(strategy_selector: S, approvals_manager: A) -> Self {
        RouterEncoder {
            strategy_selector,
            approvals_manager,
        }
    }
    pub fn encode_router_calldata(&self, solutions: Vec<Solution>) -> Result<Vec<u8>, Error> {
        let approvals_calldata = self.handle_approvals(&solutions)?; // TODO: where should we append this?
        let mut calldata_list: Vec<Vec<u8>> = Vec::new();
        let encode_for_batch_execute = solutions.len() > 1;
        for solution in solutions.iter() {
            let exact_out = solution.exact_out.clone();
            let straight_to_pool = solution.straight_to_pool.clone();

            let strategy = self.strategy_selector.select_strategy(&solution);
            let method_calldata = strategy.encode_strategy((*solution).clone())?;

            let contract_interaction = if encode_for_batch_execute {
                let args = (strategy.action_type(exact_out) as u16, method_calldata);
                args.abi_encode()
            } else {
                if straight_to_pool {
                    method_calldata
                } else {
                    encode_input(strategy.selector(exact_out), method_calldata)
                }
            };
            calldata_list.push(contract_interaction);
        }
        if encode_for_batch_execute {
            let args = (false, ple_encode(calldata_list));
            Ok(encode_input("batchExecute(bytes)", args.abi_encode()))
        } else {
            Ok(calldata_list[0].clone())
        }
    }

    fn handle_approvals(&self, solutions: &Vec<Solution>) -> Result<Vec<u8>, Error> {
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
        Ok(self.approvals_manager.encode_approvals(approvals))
    }
}
