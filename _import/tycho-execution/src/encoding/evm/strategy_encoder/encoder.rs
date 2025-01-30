use std::cmp::min;

use alloy_primitives::{aliases::U24, map::HashSet, U256, U8};
use alloy_sol_types::SolValue;
use num_bigint::BigUint;
use tycho_core::{models::Chain, Bytes};

use crate::encoding::{
    errors::EncodingError,
    evm::{
        approvals::permit2::Permit2,
        swap_encoder::SWAP_ENCODER_REGISTRY,
        utils::{biguint_to_u256, bytes_to_address, percentage_to_uint24, ple_encode},
    },
    models::{EncodingContext, NativeAction, Solution},
    strategy_encoder::StrategyEncoder,
};

#[allow(dead_code)]
pub trait EVMStrategyEncoder: StrategyEncoder {
    fn encode_swap_header(
        &self,
        token_in: U8,
        token_out: U8,
        split: U24,
        protocol_data: Vec<u8>,
    ) -> Vec<u8> {
        let mut encoded = Vec::new();
        encoded.push(token_in.to_be_bytes_vec()[0]);
        encoded.push(token_out.to_be_bytes_vec()[0]);
        encoded.extend_from_slice(&split.to_be_bytes_vec());
        encoded.extend(protocol_data);
        encoded
    }
}

pub struct SplitSwapStrategyEncoder {
    permit2: Permit2,
}

impl SplitSwapStrategyEncoder {
    pub fn new(signer_pk: String, chain: Chain) -> Result<Self, EncodingError> {
        Ok(Self { permit2: Permit2::new(signer_pk, chain)? })
    }
}
impl EVMStrategyEncoder for SplitSwapStrategyEncoder {}
impl StrategyEncoder for SplitSwapStrategyEncoder {
    fn encode_strategy(
        &self,
        solution: Solution,
        router_address: Bytes,
    ) -> Result<Vec<u8>, EncodingError> {
        let (permit, signature) = self.permit2.get_permit(
            &router_address,
            &solution.sender,
            &solution.given_token,
            &solution.given_amount,
        )?;
        let min_amount_out = if solution.check_amount.is_some() {
            let mut min_amount_out = solution.check_amount.clone().unwrap();
            if solution.slippage.is_some() {
                let one_hundred = BigUint::from(100u32);
                let slippage_percent = BigUint::from((solution.slippage.unwrap() * 100.0) as u32);
                let multiplier = &one_hundred - slippage_percent;
                let expected_amount_with_slippage =
                    (&solution.expected_amount * multiplier) / one_hundred;
                min_amount_out = min(min_amount_out, expected_amount_with_slippage);
            }
            min_amount_out
        } else {
            BigUint::ZERO
        };

        let mut tokens: Vec<Bytes> = solution
            .swaps
            .iter()
            .flat_map(|swap| vec![swap.token_in.clone(), swap.token_out.clone()])
            .collect::<HashSet<Bytes>>()
            .into_iter()
            .collect();

        // this is only to make the test deterministic (same index for the same token for different
        // runs)
        tokens.sort();

        let mut swaps = vec![];
        for swap in solution.swaps.iter() {
            let registry = SWAP_ENCODER_REGISTRY.read().unwrap();
            let swap_encoder = registry
                .get_encoder(&swap.component.protocol_system)
                .expect("Swap encoder not found");

            let encoding_context = EncodingContext {
                receiver: router_address.clone(),
                exact_out: solution.exact_out,
                router_address: router_address.clone(),
            };
            let protocol_data = swap_encoder.encode_swap(swap.clone(), encoding_context)?;
            let swap_data = self.encode_swap_header(
                U8::from(
                    tokens
                        .iter()
                        .position(|t| *t == swap.token_in)
                        .ok_or_else(|| {
                            EncodingError::InvalidInput(
                                "Token in not found in tokens array".to_string(),
                            )
                        })?,
                ),
                U8::from(
                    tokens
                        .iter()
                        .position(|t| *t == swap.token_out)
                        .ok_or_else(|| {
                            EncodingError::InvalidInput(
                                "Token out not found in tokens array".to_string(),
                            )
                        })?,
                ),
                percentage_to_uint24(swap.split),
                protocol_data,
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
            biguint_to_u256(&solution.given_amount),
            bytes_to_address(&solution.given_token)?,
            bytes_to_address(&solution.checked_token)?,
            biguint_to_u256(&min_amount_out),
            wrap,
            unwrap,
            U256::from(tokens.len()),
            bytes_to_address(&solution.receiver)?,
            permit,
            signature.as_bytes().to_vec(),
            encoded_swaps,
        )
            .abi_encode();
        Ok(method_calldata)
    }

    fn selector(&self, _exact_out: bool) -> &str {
        "swap(uint256, address, uint256, bytes[])"
    }
}

/// This strategy encoder is used for solutions that are sent directly to the pool.
/// Only 1 solution with 1 swap is supported.
pub struct StraightToPoolStrategyEncoder {}
impl EVMStrategyEncoder for StraightToPoolStrategyEncoder {}
impl StrategyEncoder for StraightToPoolStrategyEncoder {
    fn encode_strategy(
        &self,
        solution: Solution,
        _router_address: Bytes,
    ) -> Result<Vec<u8>, EncodingError> {
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
        // TODO: here we need to pass also the address of the executor to be used
        Ok(protocol_data)
    }
    fn selector(&self, _exact_out: bool) -> &str {
        unimplemented!();
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use alloy::hex::encode;
    use tycho_core::dto::ProtocolComponent;

    use super::*;
    use crate::encoding::models::Swap;

    #[test]
    fn test_split_swap_strategy_encoder() {
        // Set up a mock private key for signing
        let private_key =
            "4c0883a69102937d6231471b5dbb6204fe512961708279feb1be6ae5538da033".to_string();

        let weth = Bytes::from_str("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2").unwrap();
        let dai = Bytes::from_str("0x6b175474e89094c44da98b954eedeac495271d0f").unwrap();

        let swap = Swap {
            component: ProtocolComponent {
                id: "0x88e6A0c2dDD26FEEb64F039a2c41296FcB3f5640".to_string(),
                protocol_system: "uniswap_v2".to_string(),
                ..Default::default()
            },
            token_in: weth.clone(),
            token_out: dai.clone(),
            split: 0f64,
        };

        let encoder = SplitSwapStrategyEncoder::new(private_key, Chain::Ethereum).unwrap();
        let solution = Solution {
            exact_out: false,
            given_token: weth,
            given_amount: BigUint::from_str("1_000000000000000000").unwrap(),
            checked_token: dai,
            expected_amount: BigUint::from_str("3_000_000000000000000000").unwrap(),
            check_amount: None,
            sender: Bytes::from_str("0x2c6A3cd97c6283b95Ac8C5A4459eBB0d5Fd404F4").unwrap(),
            receiver: Bytes::from_str("0x2c6A3cd97c6283b95Ac8C5A4459eBB0d5Fd404F4").unwrap(),
            swaps: vec![swap],
            ..Default::default()
        };
        let router_address = Bytes::from_str("0x2c6A3cd97c6283b95Ac8C5A4459eBB0d5Fd404F4").unwrap();

        let calldata = encoder
            .encode_strategy(solution, router_address)
            .unwrap();

        let expected_input = String::from(concat!(
            "0000000000000000000000000000000000000000000000000000000000000020", // offset
            "0000000000000000000000000000000000000000000000000de0b6b3a7640000", // amount out
            "000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2", // token in
            "0000000000000000000000006b175474e89094c44da98b954eedeac495271d0f", // token out
            "0000000000000000000000000000000000000000000000000000000000000000", // min amount out
            "0000000000000000000000000000000000000000000000000000000000000000", // wrap
            "0000000000000000000000000000000000000000000000000000000000000000", // unwrap
            "0000000000000000000000000000000000000000000000000000000000000002", // tokens length
            "0000000000000000000000002c6a3cd97c6283b95ac8c5a4459ebb0d5fd404f4", // receiver
        ));
        // after this there is the permit and because of the deadlines (that depend on block time)
        // it's hard to assert
        // "000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2", // token in
        // "0000000000000000000000000000000000000000000000000de0b6b3a7640000", // amount in
        // "0000000000000000000000000000000000000000000000000000000067c205fe", // expiration
        // "0000000000000000000000000000000000000000000000000000000000000000", // nonce
        // "0000000000000000000000002c6a3cd97c6283b95ac8c5a4459ebb0d5fd404f4", // spender
        // "00000000000000000000000000000000000000000000000000000000679a8006", // deadline
        //  offsets???
        // "0000000000000000000000000000000000000000000000000000000000000200",
        // "0000000000000000000000000000000000000000000000000000000000000280",
        // "0000000000000000000000000000000000000000000000000000000000000041",
        //  signature
        // "fc5bac4e27cd5d71c85d232d8c6b31ea924d2e0031091ff9a39579d9e49c214328ea34876961d9200af691373c71a174e166793d02241c76adb93c5f87fe0f381c",

        let expected_swaps = String::from(concat!(
            // ple encode adds aaalll of this :/ is it correct?
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000120000",
            "0000000000000000000000000000000000000000000000000000000000020000",
            "0000000000000000000000000000000000000000000000000000000000060000",
            "000000000000000000000000000000000000000000000000000000000005b000",
            "0000000000000000000000000000000000000000000000000000000000080000",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "000000000000000000000000000000000000000000000000000000000005b",
            // Swap header
            "01",     // token in index
            "00",     // token out index
            "000000", // split
            // Swap data
            "5c2f5a71f67c01775180adc06909288b4c329308", // executor address
            "bd0625ab",                                 // selector
            "c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2", // token in
            "88e6a0c2ddd26feeb64f039a2c41296fcb3f5640", // component id
            "2c6a3cd97c6283b95ac8c5a4459ebb0d5fd404f4", // receiver
            "00",                                       // zero2one
            "00",                                       // exact out
            "0000000000",                               // padding
        ));
        let hex_calldata = encode(&calldata);
        assert_eq!(hex_calldata[..576], expected_input);
        assert_eq!(hex_calldata[1283..], expected_swaps);
    }
}
