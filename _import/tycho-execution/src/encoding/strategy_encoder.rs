use alloy_sol_types::SolValue;
use anyhow::Error;
use num_bigint::BigUint;

use crate::encoding::models::{
    ActionType, EncodingContext, NativeAction, Order, PROPELLER_ROUTER_ADDRESS,
};
use crate::encoding::swap_encoder::{get_swap_encoder, get_swap_executor_address};
use crate::encoding::utils::{biguint_to_u256, ple_encode};

pub trait StrategyEncoder {
    fn encode_strategy(&self, to_encode: Order) -> Result<Vec<u8>, Error>;

    fn action_type(&self, exact_out: bool) -> ActionType;
    fn selector(&self, exact_out: bool) -> &str;

    fn encode_protocol_header(
        &self,
        protocol_data: Vec<u8>,
        protocol_system: String,
        // Token indices, split, and token inclusion are only used for split swaps
        token_in: u16,
        token_out: u16,
        split: u16, // not sure what should be the type of this :/
    ) -> Vec<u8> {
        let executor_address = get_swap_executor_address(&protocol_system);
        let args = (executor_address, token_in, token_out, split, protocol_data);
        args.abi_encode()
    }
}

pub struct SingleSwapStrategyEncoder {}

impl StrategyEncoder for SingleSwapStrategyEncoder {
    fn encode_strategy(&self, order: Order) -> Result<Vec<u8>, Error> {
        todo!()
    }

    fn action_type(&self, exact_out: bool) -> ActionType {
        if exact_out {
            ActionType::SingleExactOut
        } else {
            ActionType::SingleExactIn
        }
    }

    fn selector(&self, exact_out: bool) -> &str {
        if exact_out {
            "singleExactOut(uint256, bytes)"
        } else {
            "singleExactIn(uint256, bytes)"
        }
    }
}

pub struct SequentialStrategyEncoder {}

impl StrategyEncoder for SequentialStrategyEncoder {
    fn encode_strategy(&self, order: Order) -> Result<Vec<u8>, Error> {
        let mut check_amount = order.check_amount.clone();
        if order.slippage.is_some() {
            let one_hundred = BigUint::from(100u32);
            let slippage_percent = BigUint::from((order.slippage.unwrap() * 100.0) as u32);
            let multiplier = &one_hundred - slippage_percent;
            check_amount = (&order.check_amount * multiplier) / one_hundred;
        }
        let mut swaps = vec![];
        for (index, swap) in order.swaps.iter().enumerate() {
            let is_last = index == order.swaps.len() - 1;
            let protocol_system = swap.component.protocol_system.clone();
            let swap_encoder = get_swap_encoder(&protocol_system);
            let router_address = if order.router_address.is_some() {
                order.router_address.clone().unwrap()
            } else {
                PROPELLER_ROUTER_ADDRESS.clone()
            };
            let receiver = if is_last {
                order.receiver.clone()
            } else {
                router_address.clone()
            };

            let encoding_context = EncodingContext {
                receiver,
                exact_out: order.exact_out,
                address_for_approvals: router_address,
            };
            let protocol_data = swap_encoder.encode_swap(swap.clone(), encoding_context)?;
            let swap_data = self.encode_protocol_header(protocol_data, protocol_system, 0, 0, 0);
            swaps.push(swap_data);
        }

        let encoded_swaps = ple_encode(swaps);

        let (mut unwrap, mut wrap) = (false, false);
        if order.native_action.is_some() {
            match order.native_action.unwrap() {
                NativeAction::Wrap => wrap = true,
                NativeAction::Unwrap => unwrap = true,
            }
        }
        let method_calldata = (
            wrap,
            unwrap,
            biguint_to_u256(&order.given_amount),
            biguint_to_u256(&check_amount),
            encoded_swaps,
        )
            .abi_encode();
        Ok(method_calldata)
    }

    fn action_type(&self, exact_out: bool) -> ActionType {
        if exact_out {
            ActionType::SequentialExactOut
        } else {
            ActionType::SequentialExactIn
        }
    }

    fn selector(&self, exact_out: bool) -> &str {
        if exact_out {
            "sequentialExactOut(uint256, uint256, bytes[])"
        } else {
            "sequentialExactIn(uint256, uint256, bytes[])"
        }
    }
}

pub struct SlipSwapStrategyEncoder {}

impl StrategyEncoder for SlipSwapStrategyEncoder {
    fn encode_strategy(&self, order: Order) -> Result<Vec<u8>, Error> {
        todo!()
    }
    fn action_type(&self, _exact_out: bool) -> ActionType {
        ActionType::SplitIn
    }

    fn selector(&self, _exact_out: bool) -> &str {
        "splitExactIn(uint256, address, uint256, bytes[])"
    }
}

/// This strategy encoder is used for orders that are sent directly to the pool.
/// Only 1 order with 1 swap is supported.
pub struct StraightToPoolStrategyEncoder {}

impl StrategyEncoder for StraightToPoolStrategyEncoder {
    fn encode_strategy(&self, order: Order) -> Result<Vec<u8>, Error> {
        if order.router_address.is_none() {
            return Err(anyhow::anyhow!(
                "Router address is required for straight to pool orders"
            ));
        }
        let swap = order.swaps.first().unwrap();
        let protocol_system = swap.component.protocol_system.clone();
        let swap_encoder = get_swap_encoder(&protocol_system);
        let router_address = order.router_address.unwrap();

        let encoding_context = EncodingContext {
            receiver: order.receiver,
            exact_out: order.exact_out,
            address_for_approvals: router_address,
        };
        let protocol_data = swap_encoder.encode_swap(swap.clone(), encoding_context)?;
        Ok(protocol_data)
    }

    fn action_type(&self, _exact_out: bool) -> ActionType {
        unimplemented!();
    }

    fn selector(&self, _exact_out: bool) -> &str {
        unimplemented!();
    }
}
