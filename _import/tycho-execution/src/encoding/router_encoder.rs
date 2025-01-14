use crate::encoding::approvals::interface::{Approval, UserApprovalsManager};
use crate::encoding::models::{Solution, PROPELLER_ROUTER_ADDRESS};
use crate::encoding::strategy_encoder::StrategyEncoder;
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
    pub fn encode_router_calldata(&self, solution: Solution) -> Result<Vec<u8>, Error> {
        let approvals_calldata = self.handle_approvals(&solution)?; // TODO: where should we append this?
        let mut calldata_list: Vec<Vec<u8>> = Vec::new();
        let encode_for_batch_execute = solution.orders.len() > 1;
        for order in solution.orders {
            let strategy = self.strategy_selector.select_strategy(&order);
            let contract_interaction = strategy.encode_strategy(order, encode_for_batch_execute)?;
            calldata_list.push(contract_interaction);
        }
        if encode_for_batch_execute {
            let args = (false, ple_encode(calldata_list));
            Ok(encode_input("batchExecute(bytes)", args.abi_encode()))
        } else {
            Ok(calldata_list[0].clone())
        }
    }

    fn handle_approvals(&self, solution: &Solution) -> Result<Vec<u8>, Error> {
        let mut approvals = Vec::new();
        for order in solution.orders.iter() {
            approvals.push(Approval {
                token: order.given_token.clone(),
                spender: order
                    .router_address
                    .clone()
                    .unwrap_or(PROPELLER_ROUTER_ADDRESS.clone()),
                amount: order.given_amount.clone(),
                owner: order.sender.clone(),
            });
        }
        Ok(self.approvals_manager.encode_approvals(approvals))
    }
}
