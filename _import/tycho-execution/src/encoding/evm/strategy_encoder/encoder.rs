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

#[cfg(test)]
mod tests {
    use num_bigint::BigUint;
    use tycho_core::{dto::ProtocolComponent, Bytes};

    use super::*;
    use crate::encoding::models::Swap;

    #[test]
    fn test_executor_encoder() {
        let encoder = ExecutorEncoder {};

        let token_in = Bytes::from("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2");
        let token_out = Bytes::from("0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174");

        let swap = Swap {
            component: ProtocolComponent {
                id: "0x5c6ee304399dbdb9c8ef030ab642b10820db8f56000200000000000000000014"
                    .to_string(),
                protocol_system: "vm:balancer_v2".to_string(),
                ..Default::default()
            },
            token_in: token_in.clone(),
            token_out: token_out.clone(),
            split: 0.5,
        };

        let solution = Solution {
            exact_out: false,
            given_token: token_in,
            given_amount: BigUint::from(1000000000000000000u64),
            expected_amount: BigUint::from(1000000000000000000u64),
            checked_token: token_out,
            check_amount: None,
            sender: Bytes::from_str("0x0000000000000000000000000000000000000000").unwrap(),
            receiver: Bytes::from_str("0x0000000000000000000000000000000000000000").unwrap(),
            swaps: vec![swap],
            straight_to_pool: true,
            router_address: Some(
                Bytes::from_str("0x0000000000000000000000000000000000000002").unwrap(),
            ),
            slippage: None,
            native_action: None,
        };

        let (_, executor_address) = encoder
            .encode_strategy(solution)
            .unwrap();
        assert_eq!(
            executor_address,
            Address::from_str("0x543778987b293C7E8Cf0722BB2e935ba6f4068D4").unwrap()
        );
    }
}
