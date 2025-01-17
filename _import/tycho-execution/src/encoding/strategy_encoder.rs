use std::{cmp::min, str::FromStr};

use alloy_primitives::Address;
use alloy_sol_types::SolValue;
use anyhow::Error;
use num_bigint::BigUint;
use num_traits::Zero;

use crate::encoding::{
    models::{ActionType, EncodingContext, NativeAction, Solution, PROPELLER_ROUTER_ADDRESS},
    swap_encoder::SWAP_ENCODER_REGISTRY,
    utils::{biguint_to_u256, ple_encode},
};

#[allow(dead_code)]
pub trait StrategyEncoder {
    fn encode_strategy(&self, to_encode: Solution) -> Result<Vec<u8>, Error>;

    fn action_type(&self, exact_out: bool) -> ActionType;
    fn selector(&self, exact_out: bool) -> &str;

    fn encode_protocol_header(
        &self,
        protocol_data: Vec<u8>,
        executor_address: Address,
        // Token indices, split, and token inclusion are only used for split swaps
        token_in: u16,
        token_out: u16,
        split: u16, // not sure what should be the type of this :/
    ) -> Vec<u8> {
        let args = (executor_address, token_in, token_out, split, protocol_data);
        args.abi_encode()
    }
}

pub struct SingleSwapStrategyEncoder {}

impl StrategyEncoder for SingleSwapStrategyEncoder {
    fn encode_strategy(&self, _solution: Solution) -> Result<Vec<u8>, Error> {
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
    fn encode_strategy(&self, solution: Solution) -> Result<Vec<u8>, Error> {
        let check_amount = if solution.check_amount.is_some() {
            let mut check_amount = solution.check_amount.clone().unwrap();
            if solution.slippage.is_some() {
                let one_hundred = BigUint::from(100u32);
                let slippage_percent = BigUint::from((solution.slippage.unwrap() * 100.0) as u32);
                let multiplier = &one_hundred - slippage_percent;
                let expected_amount_with_slippage =
                    (&solution.expected_amount * multiplier) / one_hundred;
                check_amount = min(check_amount, expected_amount_with_slippage);
            }
            check_amount
        } else {
            BigUint::ZERO
        };

        let mut swaps = vec![];
        for (index, swap) in solution.swaps.iter().enumerate() {
            let is_last = index == solution.swaps.len() - 1;
            let registry = SWAP_ENCODER_REGISTRY.read().unwrap();
            let swap_encoder = registry
                .get_encoder(&swap.component.protocol_system)
                .expect("Swap encoder not found");
            let router_address = if solution.router_address.is_some() {
                solution.router_address.clone().unwrap()
            } else {
                PROPELLER_ROUTER_ADDRESS.clone()
            };
            let receiver = if is_last { solution.receiver.clone() } else { router_address.clone() };

            let encoding_context = EncodingContext {
                receiver,
                exact_out: solution.exact_out,
                address_for_approvals: router_address,
            };
            let protocol_data = swap_encoder.encode_swap(swap.clone(), encoding_context)?;
            let executor_address = swap_encoder.executor_address();
            let swap_data = self.encode_protocol_header(
                protocol_data,
                Address::from_str(executor_address).expect("Couldn't convert executor address"),
                0,
                0,
                0,
            );
            swaps.push(swap_data);
        }

        let encoded_swaps = ple_encode(swaps);

        let (mut unwrap, mut wrap) = (false, false);
        if solution.native_action.is_some() {
            match solution.native_action.unwrap() {
                NativeAction::Wrap => wrap = true,
                NativeAction::Unwrap => unwrap = true,
            }
        }
        let method_calldata = (
            wrap,
            unwrap,
            biguint_to_u256(&solution.given_amount),
            !check_amount.is_zero(), /* if check_amount is zero, then we don't need to check */
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

pub struct SplitSwapStrategyEncoder {}

impl StrategyEncoder for SplitSwapStrategyEncoder {
    fn encode_strategy(&self, _solution: Solution) -> Result<Vec<u8>, Error> {
        todo!()
    }
    fn action_type(&self, _exact_out: bool) -> ActionType {
        ActionType::SplitIn
    }

    fn selector(&self, _exact_out: bool) -> &str {
        "splitExactIn(uint256, address, uint256, bytes[])"
    }
}

/// This strategy encoder is used for solutions that are sent directly to the pool.
/// Only 1 solution with 1 swap is supported.
pub struct StraightToPoolStrategyEncoder {}

impl StrategyEncoder for StraightToPoolStrategyEncoder {
    fn encode_strategy(&self, solution: Solution) -> Result<Vec<u8>, Error> {
        if solution.router_address.is_none() {
            return Err(anyhow::anyhow!(
                "Router address is required for straight to pool solutions"
            ));
        }
        let swap = solution.swaps.first().unwrap();
        let registry = SWAP_ENCODER_REGISTRY.read().unwrap();
        let swap_encoder = registry
            .get_encoder(&swap.component.protocol_system)
            .expect("Swap encoder not found");
        let router_address = solution.router_address.unwrap();

        let encoding_context = EncodingContext {
            receiver: solution.receiver,
            exact_out: solution.exact_out,
            address_for_approvals: router_address,
        };
        let protocol_data = swap_encoder.encode_swap(swap.clone(), encoding_context)?;
        // TODO: here we need to pass also the address of the executor to be used
        Ok(protocol_data)
    }

    fn action_type(&self, _exact_out: bool) -> ActionType {
        unimplemented!();
    }

    fn selector(&self, _exact_out: bool) -> &str {
        unimplemented!();
    }
}
