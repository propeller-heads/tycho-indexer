use std::str::FromStr;

use alloy_primitives::Address;
use alloy_sol_types::SolValue;

use crate::encoding::{
    errors::EncodingError,
    evm::swap_encoder::SWAP_ENCODER_REGISTRY,
    models::{EncodingContext, Solution},
    strategy_encoder::StrategyEncoder,
};

#[allow(dead_code)]
pub trait EVMStrategyEncoder: StrategyEncoder {
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

pub struct SplitSwapStrategyEncoder {}
impl EVMStrategyEncoder for SplitSwapStrategyEncoder {}
impl StrategyEncoder for SplitSwapStrategyEncoder {
    fn encode_strategy(&self, _solution: Solution) -> Result<(Vec<u8>, Address), EncodingError> {
        todo!()
    }
    fn selector(&self, _exact_out: bool) -> &str {
        "swap(uint256, address, uint256, bytes[])"
    }
}

/// This strategy encoder is used for solutions that are sent directly to the pool.
/// Only 1 solution with 1 swap is supported.
pub struct ExecutorEncoder {}
impl EVMStrategyEncoder for ExecutorEncoder {}
impl StrategyEncoder for ExecutorEncoder {
    fn encode_strategy(&self, solution: Solution) -> Result<(Vec<u8>, Address), EncodingError> {
        if solution.router_address.is_none() {
            return Err(EncodingError::InvalidInput(
                "Router address is required for straight to pool solutions".to_string(),
            ));
        }
        let swap = solution.swaps.first().unwrap();
        let registry = SWAP_ENCODER_REGISTRY
            .read()
            .map_err(|_| {
                EncodingError::FatalError("Failed to read the swap encoder registry".to_string())
            })?;
        let swap_encoder = registry
            .get_encoder(&swap.component.protocol_system)
            .ok_or_else(|| {
                EncodingError::InvalidInput(format!(
                    "Swap encoder not found for protocol: {}",
                    swap.component.protocol_system
                ))
            })?;
        let router_address = solution.router_address.unwrap();

        let encoding_context = EncodingContext {
            receiver: solution.receiver,
            exact_out: solution.exact_out,
            router_address,
        };
        let protocol_data = swap_encoder.encode_swap(swap.clone(), encoding_context)?;
        let executor_address = Address::from_str(swap_encoder.executor_address())
            .map_err(|_| EncodingError::FatalError("Invalid executor address".to_string()))?;
        Ok((protocol_data, executor_address))
    }
    fn selector(&self, _exact_out: bool) -> &str {
        "swap(uint256, bytes)"
    }
}
