use crate::encoding::models::{Order, Solution, PROPELLER_ROUTER_ADDRESS};
use crate::encoding::permit2::{Permit2, PermitRequest};
use crate::encoding::strategy_encoder::{
    SequentialExactInStrategyEncoder, SingleSwapStrategyEncoder, SlipSwapStrategyEncoder,
    StrategyEncoder,
};
use crate::encoding::utils::{encode_input, ple_encode};
use alloy_sol_types::SolValue;
use anyhow::Error;
use std::str::FromStr;

struct RouterEncoder {}

impl RouterEncoder {
    pub fn encode_router_calldata(&self, solution: Solution) -> Result<Vec<u8>, Error> {
        let permit_calldata = self.handle_approvals(&solution)?; // TODO: where should we append this?
        let mut calldata_list: Vec<Vec<u8>> = Vec::new();
        let encode_for_batch_execute = solution.orders.len() > 1;
        for order in solution.orders {
            let strategy = self.get_strategy(&order);
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

    fn get_strategy(&self, order: &Order) -> &dyn StrategyEncoder {
        if order.swaps.len() == 1 {
            &SingleSwapStrategyEncoder {}
        } else if order.swaps.iter().all(|s| s.split == 0.0) {
            &SequentialExactInStrategyEncoder {}
        } else {
            &SlipSwapStrategyEncoder {}
        }
    }
}
