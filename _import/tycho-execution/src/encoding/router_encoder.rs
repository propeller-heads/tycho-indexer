use crate::encoding::models::{Solution, PROPELLER_ROUTER_ADDRESS};
use crate::encoding::permit2::{Permit2, PermitRequest};
use crate::encoding::strategy_encoder::StrategyEncoder;
use crate::encoding::strategy_selector::StrategySelector;
use crate::encoding::utils::{encode_input, ple_encode};
use alloy_sol_types::SolValue;
use anyhow::Error;

struct RouterEncoder<S: StrategySelector> {
    strategy_selector: S,
}
impl<S: StrategySelector> RouterEncoder<S> {
    pub fn new(strategy_selector: S) -> Self {
        RouterEncoder { strategy_selector }
    }
    pub fn encode_router_calldata(&self, solution: Solution) -> Result<Vec<u8>, Error> {
        let permit_calldata = self.handle_approvals(&solution)?; // TODO: where should we append this?
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
        let mut permits = Vec::new();
        for order in solution.orders.iter() {
            permits.push(PermitRequest {
                token: order.given_token.clone(),
                spender: order.sender.clone(),
                amount: order.given_amount.clone(),
                router_address: order
                    .router_address
                    .clone()
                    .unwrap_or(PROPELLER_ROUTER_ADDRESS.clone()),
            });
        }
        Ok(Permit2::new().encode_permit(permits))
    }
}
