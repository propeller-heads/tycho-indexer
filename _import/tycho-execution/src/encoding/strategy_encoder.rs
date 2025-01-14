use alloy_sol_types::SolValue;
use anyhow::Error;
use num_bigint::BigUint;

use crate::encoding::models::{
    ActionType, EncodingContext, NativeAction, Order, PROPELLER_ROUTER_ADDRESS,
};
use crate::encoding::swap_encoder::{get_swap_encoder, get_swap_executor_address};
use crate::encoding::utils::{biguint_to_u256, bytes_to_address, encode_input, ple_encode};

pub trait StrategyEncoder {
    fn encode_strategy(
        &self,
        to_encode: Order,
        encode_for_batch_execute: bool,
    ) -> Result<Vec<u8>, Error>;

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
    fn encode_strategy(
        &self,
        order: Order,
        encode_for_batch_execute: bool,
    ) -> Result<Vec<u8>, Error> {
        todo!()
    }
}

pub struct SequentialExactInStrategyEncoder {}

impl StrategyEncoder for SequentialExactInStrategyEncoder {
    fn encode_strategy(
        &self,
        order: Order,
        encode_for_batch_execute: bool,
    ) -> Result<Vec<u8>, Error> {
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
                router_address,
            };
            let protocol_data = swap_encoder.encode_swap(swap.clone(), encoding_context)?;
            let swap_data = self.encode_protocol_header(protocol_data, protocol_system, 0, 0, 0);
            swaps.push(swap_data);
        }

        let selector = "sequentialExactIn(uint256, uint256, bytes[])";
        let action_type = ActionType::SequentialExactIn;

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
        if encode_for_batch_execute {
            let args = (action_type as u16, method_calldata);
            Ok(args.abi_encode())
        } else {
            Ok(encode_input(selector, method_calldata))
        }
    }
}

pub struct SlipSwapStrategyEncoder {}

impl StrategyEncoder for SlipSwapStrategyEncoder {
    fn encode_strategy(
        &self,
        order: Order,
        encode_for_batch_execute: bool,
    ) -> Result<Vec<u8>, Error> {
        todo!()
    }
}
