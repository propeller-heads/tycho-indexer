use alloy_primitives::Address;
use alloy_sol_types::SolValue;
use anyhow::Error;
use num_bigint::BigUint;
use std::cmp::min;

use crate::encoding::models::{ActionType, EncodingContext, Order};
use crate::encoding::swap_encoder::{get_swap_encoder, get_swap_executor_address};
use crate::encoding::utils::{biguint_to_u256, bytes_to_address, encode_input, ple_encode};

pub trait StrategyEncoder {
    fn encode_strategy(
        &self,
        to_encode: Order,
        router_address: Address,
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
        router_address: Address,
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
        router_address: Address,
        encode_for_batch_execute: bool,
    ) -> Result<Vec<u8>, Error> {
        let one_hundred = BigUint::from(100u32);
        let slippage_percent = BigUint::from((order.slippage * 100.0) as u32);
        let multiplier = &one_hundred - slippage_percent;
        let slippage_buy_amount = (&order.given_amount * multiplier) / one_hundred;

        let min_checked_amount = if order.min_checked_amount.is_some() {
            min(order.min_checked_amount.unwrap(), slippage_buy_amount)
        } else {
            slippage_buy_amount
        };
        let mut swaps = vec![];
        for (index, swap) in order.swaps.iter().enumerate() {
            let is_last = index == order.swaps.len() - 1;
            let protocol_system = swap.component.protocol_system.clone();
            let swap_encoder = get_swap_encoder(&protocol_system);
            let receiver = if is_last {
                bytes_to_address(&order.receiver)?
            } else {
                router_address
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
        let (selector, action_type) = if order.exact_out {
            (
                "sequentialExactOut(uint256, uint256, bytes[])",
                ActionType::SequentialExactOut,
            )
        } else {
            (
                "sequentialExactIn(uint256, uint256, bytes[])",
                ActionType::SequentialExactIn,
            )
        };
        let encoded_swaps = ple_encode(swaps);
        if encode_for_batch_execute {
            let args = (
                action_type as u16,
                biguint_to_u256(&order.given_amount),
                biguint_to_u256(&min_checked_amount),
                encoded_swaps,
            );
            Ok(args.abi_encode())
        } else {
            Ok(encode_input(
                selector,
                (
                    biguint_to_u256(&order.given_amount),
                    biguint_to_u256(&min_checked_amount),
                    encoded_swaps,
                )
                    .abi_encode(),
            ))
        }
    }
}

pub struct SlipSwapStrategyEncoder {}

impl StrategyEncoder for SlipSwapStrategyEncoder {
    fn encode_strategy(
        &self,
        order: Order,
        router_address: Address,
        encode_for_batch_execute: bool,
    ) -> Result<Vec<u8>, Error> {
        todo!()
    }
}
