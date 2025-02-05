use std::{
    cmp::max,
    collections::{HashMap, HashSet, VecDeque},
    str::FromStr,
};

use alloy_primitives::{aliases::U24, FixedBytes, U256, U8};
use alloy_sol_types::SolValue;
use num_bigint::BigUint;
use tycho_core::{dto::Chain, keccak256, Bytes};

use crate::encoding::{
    errors::EncodingError,
    evm::{
        approvals::permit2::Permit2,
        constants::{NATIVE_ADDRESS, WETH_ADDRESS},
        swap_encoder::swap_encoder_registry::SwapEncoderRegistry,
        utils::{biguint_to_u256, bytes_to_address, encode_input, percentage_to_uint24},
    },
    models::{EncodingContext, NativeAction, Solution, Swap},
    strategy_encoder::StrategyEncoder,
    swap_encoder::SwapEncoder,
};

pub trait EVMStrategyEncoder: StrategyEncoder {
    fn encode_swap_header(
        &self,
        token_in: U8,
        token_out: U8,
        split: U24,
        executor_address: Bytes,
        executor_selector: FixedBytes<4>,
        protocol_data: Vec<u8>,
    ) -> Vec<u8> {
        let mut encoded = Vec::new();
        encoded.push(token_in.to_be_bytes_vec()[0]);
        encoded.push(token_out.to_be_bytes_vec()[0]);
        encoded.extend_from_slice(&split.to_be_bytes_vec());
        encoded.extend(executor_address.to_vec());
        encoded.extend(executor_selector);
        encoded.extend(protocol_data);
        encoded
    }
    fn encode_executor_selector(&self, selector: &str) -> FixedBytes<4> {
        let hash = keccak256(selector.as_bytes());
        FixedBytes::<4>::from([hash[0], hash[1], hash[2], hash[3]])
    }

    fn ple_encode(&self, action_data_array: Vec<Vec<u8>>) -> Vec<u8> {
        let mut encoded_action_data: Vec<u8> = Vec::new();

        for action_data in action_data_array {
            let args = (encoded_action_data, action_data.len() as u16, action_data);
            encoded_action_data = args.abi_encode_packed();
        }

        encoded_action_data
    }
}

pub struct SplitSwapStrategyEncoder {
    swap_encoder_registry: SwapEncoderRegistry,
    permit2: Permit2,
    selector: String,
}

impl SplitSwapStrategyEncoder {
    pub fn new(
        signer_pk: String,
        chain: Chain,
        swap_encoder_registry: SwapEncoderRegistry,
    ) -> Result<Self, EncodingError> {
        let selector = "swap(uint256,address,address,uint256,bool,bool,uint256,address,((address,uint160,uint48,uint48),address,uint256),bytes,bytes)".to_string();
        Ok(Self { permit2: Permit2::new(signer_pk, chain)?, selector, swap_encoder_registry })
    }

    fn validate_split_percentages(&self, swaps: &[Swap]) -> Result<(), EncodingError> {
        let mut swaps_by_token: HashMap<Bytes, Vec<&Swap>> = HashMap::new();
        for swap in swaps {
            if swap.split >= 1.0 {
                return Err(EncodingError::InvalidInput(format!(
                    "Split percentage must be less than 1 (100%), got {}",
                    swap.split
                )));
            }
            swaps_by_token
                .entry(swap.token_in.clone())
                .or_default()
                .push(swap);
        }

        for (token, token_swaps) in swaps_by_token {
            // Single swaps don't need remainder handling
            if token_swaps.len() == 1 {
                if token_swaps[0].split != 0.0 {
                    return Err(EncodingError::InvalidInput(format!(
                        "Single swap must have 0% split for token {:?}",
                        token
                    )));
                }
                continue;
            }

            let mut found_zero_split = false;
            let mut total_percentage = 0.0;
            for (i, swap) in token_swaps.iter().enumerate() {
                match (swap.split == 0.0, i == token_swaps.len() - 1) {
                    (true, false) => {
                        return Err(EncodingError::InvalidInput(format!(
                            "The 0% split for token {:?} must be the last swap",
                            token
                        )))
                    }
                    (true, true) => found_zero_split = true,
                    (false, _) => {
                        if swap.split <= 0.0 {
                            return Err(EncodingError::InvalidInput(format!(
                                "Non-remainder splits must be >0% for token {:?}",
                                token
                            )));
                        }
                        total_percentage += swap.split;
                    }
                }
            }

            if !found_zero_split {
                return Err(EncodingError::InvalidInput(format!(
                    "Token {:?} must have exactly one 0% split for remainder handling",
                    token
                )));
            }

            // Total must be <100% to leave room for remainder
            if total_percentage >= 1.0 {
                return Err(EncodingError::InvalidInput(format!(
                    "Total of non-remainder splits for token {:?} must be <100%, got {}%",
                    token,
                    total_percentage * 100.0
                )));
            }
        }

        Ok(())
    }

    fn validate_swap_path(
        &self,
        swaps: &[Swap],
        given_token: &Bytes,
        checked_token: &Bytes,
        native_action: &Option<NativeAction>,
    ) -> Result<(), EncodingError> {
        // Convert ETH to WETH only if there's a corresponding wrap/unwrap action
        let given_token = if *given_token == *NATIVE_ADDRESS {
            match native_action {
                Some(NativeAction::Wrap) => &WETH_ADDRESS,
                _ => given_token,
            }
        } else {
            given_token
        };

        let checked_token = if *checked_token == *NATIVE_ADDRESS {
            match native_action {
                Some(NativeAction::Unwrap) => &WETH_ADDRESS,
                _ => checked_token,
            }
        } else {
            checked_token
        };

        // Build directed graph of token flows
        let mut graph: HashMap<&Bytes, HashSet<&Bytes>> = HashMap::new();
        for swap in swaps {
            graph
                .entry(&swap.token_in)
                .or_default()
                .insert(&swap.token_out);
        }

        // BFS from validation_given
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(given_token);

        while let Some(token) = queue.pop_front() {
            if !visited.insert(token) {
                continue;
            }

            // Early success check
            if token == checked_token && visited.len() == graph.len() + 1 {
                return Ok(());
            }

            if let Some(next_tokens) = graph.get(token) {
                for &next_token in next_tokens {
                    if !visited.contains(next_token) {
                        queue.push_back(next_token);
                    }
                }
            }
        }

        // If we get here, either checked_token wasn't reached or not all tokens were visited
        if !visited.contains(checked_token) {
            Err(EncodingError::InvalidInput(
                "Checked token is not reachable through swap path".to_string(),
            ))
        } else {
            Err(EncodingError::InvalidInput(
                "Some tokens are not connected to the main path".to_string(),
            ))
        }
    }
}
impl EVMStrategyEncoder for SplitSwapStrategyEncoder {}
impl StrategyEncoder for SplitSwapStrategyEncoder {
    fn encode_strategy(
        &self,
        solution: Solution,
        router_address: Bytes,
    ) -> Result<(Vec<u8>, Bytes), EncodingError> {
        self.validate_split_percentages(&solution.swaps)?;
        self.validate_swap_path(
            &solution.swaps,
            &solution.given_token,
            &solution.checked_token,
            &solution.native_action,
        )?;
        let (permit, signature) = self.permit2.get_permit(
            &router_address,
            &solution.sender,
            &solution.given_token,
            &solution.given_amount,
        )?;
        let mut min_amount_out = solution
            .check_amount
            .unwrap_or(BigUint::ZERO);

        if let (Some(expected_amount), Some(slippage)) =
            (solution.expected_amount.as_ref(), solution.slippage)
        {
            let one_hundred = BigUint::from(100u32);
            let slippage_percent = BigUint::from((slippage * 100.0) as u32);
            let multiplier = &one_hundred - slippage_percent;
            let expected_amount_with_slippage = (expected_amount * &multiplier) / &one_hundred;
            min_amount_out = max(min_amount_out, expected_amount_with_slippage);
        }
        // The tokens array is composed of the given token, the checked token and all the
        // intermediary tokens in between. The contract expects the tokens to be in this order.
        let solution_tokens: HashSet<Bytes> =
            vec![solution.given_token.clone(), solution.checked_token.clone()]
                .into_iter()
                .collect();

        let intermediary_tokens: HashSet<Bytes> = solution
            .swaps
            .iter()
            .flat_map(|swap| vec![swap.token_in.clone(), swap.token_out.clone()])
            .collect();
        let mut intermediary_tokens: Vec<Bytes> = intermediary_tokens
            .difference(&solution_tokens)
            .cloned()
            .collect();
        // this is only to make the test deterministic (same index for the same token for different
        // runs)
        intermediary_tokens.sort();

        let (mut unwrap, mut wrap) = (false, false);
        if let Some(action) = solution.native_action.clone() {
            match action {
                NativeAction::Wrap => wrap = true,
                NativeAction::Unwrap => unwrap = true,
            }
        }

        let mut tokens = Vec::with_capacity(2 + intermediary_tokens.len());
        if wrap {
            tokens.push(WETH_ADDRESS.clone());
        } else {
            tokens.push(solution.given_token.clone());
        }
        tokens.extend(intermediary_tokens);

        if unwrap {
            tokens.push(WETH_ADDRESS.clone());
        } else {
            tokens.push(solution.checked_token.clone());
        }

        let mut swaps = vec![];
        for swap in solution.swaps.iter() {
            let swap_encoder = self
                .get_swap_encoder(&swap.component.protocol_system)
                .ok_or_else(|| {
                    EncodingError::InvalidInput(format!(
                        "Swap encoder not found for protocol: {}",
                        swap.component.protocol_system
                    ))
                })?;

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
                                "In token not found in tokens array".to_string(),
                            )
                        })?,
                ),
                U8::from(
                    tokens
                        .iter()
                        .position(|t| *t == swap.token_out)
                        .ok_or_else(|| {
                            EncodingError::InvalidInput(
                                "Out token not found in tokens array".to_string(),
                            )
                        })?,
                ),
                percentage_to_uint24(swap.split),
                Bytes::from_str(swap_encoder.executor_address()).map_err(|_| {
                    EncodingError::FatalError("Invalid executor address".to_string())
                })?,
                self.encode_executor_selector(swap_encoder.executor_selector()),
                protocol_data,
            );
            swaps.push(swap_data);
        }

        let encoded_swaps = self.ple_encode(swaps);
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

        let contract_interaction = encode_input(&self.selector, method_calldata);
        Ok((contract_interaction, router_address))
    }

    fn get_swap_encoder(&self, protocol_system: &str) -> Option<&Box<dyn SwapEncoder>> {
        self.swap_encoder_registry
            .get_encoder(protocol_system)
    }
}

/// This strategy encoder is used for solutions that are sent directly to the pool.
/// Only 1 solution with 1 swap is supported.
pub struct ExecutorStrategyEncoder {
    swap_encoder_registry: SwapEncoderRegistry,
}

impl ExecutorStrategyEncoder {
    pub fn new(swap_encoder_registry: SwapEncoderRegistry) -> Self {
        Self { swap_encoder_registry }
    }
}
impl EVMStrategyEncoder for ExecutorStrategyEncoder {}
impl StrategyEncoder for ExecutorStrategyEncoder {
    fn encode_strategy(
        &self,
        solution: Solution,
        _router_address: Bytes,
    ) -> Result<(Vec<u8>, Bytes), EncodingError> {
        let router_address = solution.router_address.ok_or_else(|| {
            EncodingError::InvalidInput(
                "Router address is required for straight to pool solutions".to_string(),
            )
        })?;

        let swap = solution
            .swaps
            .first()
            .ok_or_else(|| EncodingError::InvalidInput("No swaps found in solution".to_string()))?;

        let swap_encoder = self
            .get_swap_encoder(&swap.component.protocol_system)
            .ok_or_else(|| {
                EncodingError::InvalidInput(format!(
                    "Swap encoder not found for protocol: {}",
                    swap.component.protocol_system
                ))
            })?;

        let encoding_context = EncodingContext {
            receiver: solution.receiver,
            exact_out: solution.exact_out,
            router_address,
        };
        let protocol_data = swap_encoder.encode_swap(swap.clone(), encoding_context)?;

        let executor_address = Bytes::from_str(swap_encoder.executor_address())
            .map_err(|_| EncodingError::FatalError("Invalid executor address".to_string()))?;
        Ok((protocol_data, executor_address))
    }
    fn get_swap_encoder(&self, protocol_system: &str) -> Option<&Box<dyn SwapEncoder>> {
        self.swap_encoder_registry
            .get_encoder(protocol_system)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use alloy::hex::encode;
    use num_bigint::BigUint;
    use rstest::rstest;
    use tycho_core::{dto::ProtocolComponent, Bytes};

    use super::*;
    use crate::encoding::{
        evm::constants::{NATIVE_ADDRESS, WETH_ADDRESS},
        models::Swap,
    };

    fn get_swap_encoder_registry() -> SwapEncoderRegistry {
        SwapEncoderRegistry::new("src/encoding/config/executor_addresses.json", Chain::Ethereum)
            .unwrap()
    }

    #[test]
    fn test_executor_strategy_encode() {
        let swap_encoder_registry = get_swap_encoder_registry();
        let encoder = ExecutorStrategyEncoder::new(swap_encoder_registry);

        let token_in = Bytes::from("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2");
        let token_out = Bytes::from("0x6b175474e89094c44da98b954eedeac495271d0f");

        let swap = Swap {
            component: ProtocolComponent {
                id: "0xA478c2975Ab1Ea89e8196811F51A7B7Ade33eB11".to_string(),
                protocol_system: "uniswap_v2".to_string(),
                ..Default::default()
            },
            token_in: token_in.clone(),
            token_out: token_out.clone(),
            split: 0f64,
        };

        let solution = Solution {
            exact_out: false,
            given_token: token_in,
            given_amount: BigUint::from(1000000000000000000u64),
            expected_amount: Some(BigUint::from(1000000000000000000u64)),
            checked_token: token_out,
            check_amount: None,
            sender: Bytes::from_str("0x0000000000000000000000000000000000000000").unwrap(),
            // The receiver was generated with `makeAddr("bob") using forge`
            receiver: Bytes::from_str("0x1d96f2f6bef1202e4ce1ff6dad0c2cb002861d3e").unwrap(),
            swaps: vec![swap],
            direct_execution: true,
            router_address: Some(Bytes::zero(20)),
            slippage: None,
            native_action: None,
        };

        let (protocol_data, executor_address) = encoder
            .encode_strategy(solution, Bytes::zero(20))
            .unwrap();
        let hex_protocol_data = encode(&protocol_data);
        assert_eq!(
            executor_address,
            Bytes::from_str("0x5c2f5a71f67c01775180adc06909288b4c329308").unwrap()
        );
        assert_eq!(
            hex_protocol_data,
            String::from(concat!(
                // in token
                "c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
                // component id
                "a478c2975ab1ea89e8196811f51a7b7ade33eb11",
                // receiver
                "1d96f2f6bef1202e4ce1ff6dad0c2cb002861d3e",
                // zero for one
                "00",
            ))
        );
    }

    #[rstest]
    #[case::no_check_no_slippage(
        None,
        None,
        None,
        U256::from_str("0").unwrap(),
    )]
    #[case::with_check_no_slippage(
        None,
        None,
    Some(BigUint::from_str("3_000_000000000000000000").unwrap()),
        U256::from_str("3_000_000000000000000000").unwrap(),
    )]
    #[case::no_check_with_slippage(
        Some(BigUint::from_str("3_000_000000000000000000").unwrap()),
        Some(0.01f64),
        None,
        U256::from_str("2_970_000000000000000000").unwrap(),
    )]
    #[case::with_check_and_slippage(
        Some(BigUint::from_str("3_000_000000000000000000").unwrap()),
        Some(0.01f64),
        Some(BigUint::from_str("2_999_000000000000000000").unwrap()),
        U256::from_str("2_999_000000000000000000").unwrap(),
    )]
    fn test_split_swap_strategy_encoder_simple_route(
        #[case] expected_amount: Option<BigUint>,
        #[case] slippage: Option<f64>,
        #[case] check_amount: Option<BigUint>,
        #[case] expected_min_amount: U256,
    ) {
        // Performs a single swap from WETH to DAI on a USV2 pool

        // Set up a mock private key for signing
        let private_key =
            "0x123456789abcdef123456789abcdef123456789abcdef123456789abcdef1234".to_string();

        let weth = Bytes::from_str("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2").unwrap();
        let dai = Bytes::from_str("0x6b175474e89094c44da98b954eedeac495271d0f").unwrap();

        let swap = Swap {
            component: ProtocolComponent {
                id: "0xA478c2975Ab1Ea89e8196811F51A7B7Ade33eB11".to_string(),
                protocol_system: "uniswap_v2".to_string(),
                ..Default::default()
            },
            token_in: weth.clone(),
            token_out: dai.clone(),
            split: 0f64,
        };
        let swap_encoder_registry = get_swap_encoder_registry();
        let encoder =
            SplitSwapStrategyEncoder::new(private_key, Chain::Ethereum, swap_encoder_registry)
                .unwrap();
        let solution = Solution {
            exact_out: false,
            given_token: weth,
            given_amount: BigUint::from_str("1_000000000000000000").unwrap(),
            checked_token: dai,
            expected_amount,
            slippage,
            check_amount,
            sender: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
            receiver: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
            swaps: vec![swap],
            ..Default::default()
        };
        let router_address = Bytes::from_str("0x3Ede3eCa2a72B3aeCC820E955B36f38437D01395").unwrap();

        let (calldata, _) = encoder
            .encode_strategy(solution, router_address)
            .unwrap();
        let expected_min_amount_encoded = hex::encode(U256::abi_encode(&expected_min_amount));
        let expected_input = [
            "4860f9ed",                                                             // Function selector
            "0000000000000000000000000000000000000000000000000de0b6b3a7640000",      // amount out
            "000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",      // token in
            "0000000000000000000000006b175474e89094c44da98b954eedeac495271d0f",      // token out
            &expected_min_amount_encoded,                                            // min amount out
            "0000000000000000000000000000000000000000000000000000000000000000",      // wrap
            "0000000000000000000000000000000000000000000000000000000000000000",      // unwrap
            "0000000000000000000000000000000000000000000000000000000000000002",      // tokens length
            "000000000000000000000000cd09f75e2bf2a4d11f3ab23f1389fcc1621c0cc2",      // receiver
        ]
            .join("");

        // after this there is the permit and because of the deadlines (that depend on block time)
        // it's hard to assert
        // "000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2", // token in
        // "0000000000000000000000000000000000000000000000000de0b6b3a7640000", // amount in
        // "0000000000000000000000000000000000000000000000000000000067c205fe", // expiration
        // "0000000000000000000000000000000000000000000000000000000000000000", // nonce
        // "0000000000000000000000002c6a3cd97c6283b95ac8c5a4459ebb0d5fd404f4", // spender
        // "00000000000000000000000000000000000000000000000000000000679a8006", // deadline
        // offset of signature (from start of call data to beginning of length indication)
        // "0000000000000000000000000000000000000000000000000000000000000200",
        // offset of ple encoded swaps (from start of call data to beginning of length indication)
        // "0000000000000000000000000000000000000000000000000000000000000280",
        // length of signature without padding
        // "0000000000000000000000000000000000000000000000000000000000000041",
        // signature + padding
        // "a031b63a01ef5d25975663e5d6c420ef498e3a5968b593cdf846c6729a788186",
        // "1ddaf79c51453cd501d321ee541d13593e3a266be44103eefdf6e76a032d2870",
        // "1b00000000000000000000000000000000000000000000000000000000000000"

        let expected_swaps = String::from(concat!(
            // length of ple encoded swaps without padding
            "000000000000000000000000000000000000000000000000000000000000005c",
            // ple encoded swaps
            "005a",
            // Swap header
            "00",     // token in index
            "01",     // token out index
            "000000", // split
            // Swap data
            "5c2f5a71f67c01775180adc06909288b4c329308", // executor address
            "bd0625ab",                                 // selector
            "c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2", // token in
            "a478c2975ab1ea89e8196811f51a7b7ade33eb11", // component id
            "3ede3eca2a72b3aecc820e955b36f38437d01395", // receiver
            "00",                                       // zero2one
            "00",                                       // exact out
            "000000",                                   // padding
        ));
        let hex_calldata = encode(&calldata);

        assert_eq!(hex_calldata[..520], expected_input);
        assert_eq!(hex_calldata[1288..], expected_swaps);
    }

    #[test]
    fn test_split_swap_strategy_encoder_simple_route_wrap() {
        // Performs a single swap from WETH to DAI on a USV2 pool, wrapping ETH
        // Note: This test does not assert anything. It is only used to obtain integration test
        // data for our router solidity test.

        // Set up a mock private key for signing
        let private_key =
            "0x123456789abcdef123456789abcdef123456789abcdef123456789abcdef1234".to_string();

        let dai = Bytes::from_str("0x6b175474e89094c44da98b954eedeac495271d0f").unwrap();

        let swap = Swap {
            component: ProtocolComponent {
                id: "0xA478c2975Ab1Ea89e8196811F51A7B7Ade33eB11".to_string(),
                protocol_system: "uniswap_v2".to_string(),
                ..Default::default()
            },
            token_in: WETH_ADDRESS.clone(),
            token_out: dai.clone(),
            split: 0f64,
        };
        let swap_encoder_registry = get_swap_encoder_registry();
        let encoder =
            SplitSwapStrategyEncoder::new(private_key, Chain::Ethereum, swap_encoder_registry)
                .unwrap();
        let solution = Solution {
            exact_out: false,
            given_token: NATIVE_ADDRESS.clone(),
            given_amount: BigUint::from_str("1_000000000000000000").unwrap(),
            checked_token: dai,
            expected_amount: Some(BigUint::from_str("3_000_000000000000000000").unwrap()),
            check_amount: None,
            sender: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
            receiver: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
            swaps: vec![swap],
            native_action: Some(NativeAction::Wrap),
            ..Default::default()
        };
        let router_address = Bytes::from_str("0x3Ede3eCa2a72B3aeCC820E955B36f38437D01395").unwrap();

        let (calldata, _) = encoder
            .encode_strategy(solution, router_address)
            .unwrap();

        let hex_calldata = encode(&calldata);
        println!("{}", hex_calldata);
    }

    #[test]
    fn test_split_swap_strategy_encoder_simple_route_unwrap() {
        // Performs a single swap from DAI to WETH on a USV2 pool, unwrapping ETH at the end
        // Note: This test does not assert anything. It is only used to obtain integration test
        // data for our router solidity test.

        // Set up a mock private key for signing
        let private_key =
            "0x123456789abcdef123456789abcdef123456789abcdef123456789abcdef1234".to_string();

        let dai = Bytes::from_str("0x6b175474e89094c44da98b954eedeac495271d0f").unwrap();

        let swap = Swap {
            component: ProtocolComponent {
                id: "0xA478c2975Ab1Ea89e8196811F51A7B7Ade33eB11".to_string(),
                protocol_system: "uniswap_v2".to_string(),
                ..Default::default()
            },
            token_in: dai.clone(),
            token_out: WETH_ADDRESS.clone(),
            split: 0f64,
        };
        let swap_encoder_registry = get_swap_encoder_registry();
        let encoder =
            SplitSwapStrategyEncoder::new(private_key, Chain::Ethereum, swap_encoder_registry)
                .unwrap();
        let solution = Solution {
            exact_out: false,
            given_token: dai,
            given_amount: BigUint::from_str("3_000_000000000000000000").unwrap(),
            checked_token: NATIVE_ADDRESS.clone(),
            expected_amount: Some(BigUint::from_str("1_000000000000000000").unwrap()),
            check_amount: None,
            sender: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
            receiver: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
            swaps: vec![swap],
            native_action: Some(NativeAction::Unwrap),
            ..Default::default()
        };
        let router_address = Bytes::from_str("0x3Ede3eCa2a72B3aeCC820E955B36f38437D01395").unwrap();

        let (calldata, _) = encoder
            .encode_strategy(solution, router_address)
            .unwrap();

        let hex_calldata = encode(&calldata);
        println!("{}", hex_calldata);
    }

    #[test]
    fn test_split_swap_strategy_encoder_complex_route() {
        // Note: This test does not assert anything. It is only used to obtain integration test
        // data for our router solidity test.
        //
        // Performs a split swap from WETH to USDC though WBTC and DAI using USV2 pools
        //
        //         ┌──(USV2)──> WBTC ───(USV2)──> USDC
        //   WETH ─┤
        //         └──(USV2)──> DAI  ───(USV2)──> USDC
        //

        // Set up a mock private key for signing
        let private_key =
            "0x123456789abcdef123456789abcdef123456789abcdef123456789abcdef1234".to_string();

        let weth = Bytes::from_str("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2").unwrap();
        let dai = Bytes::from_str("0x6b175474e89094c44da98b954eedeac495271d0f").unwrap();
        let wbtc = Bytes::from_str("0x2260fac5e5542a773aa44fbcfedf7c193bc2c599").unwrap();
        let usdc = Bytes::from_str("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48").unwrap();

        let swap_weth_dai = Swap {
            component: ProtocolComponent {
                id: "0xA478c2975Ab1Ea89e8196811F51A7B7Ade33eB11".to_string(),
                protocol_system: "uniswap_v2".to_string(),
                ..Default::default()
            },
            token_in: weth.clone(),
            token_out: dai.clone(),
            split: 0.5f64,
        };
        let swap_weth_wbtc = Swap {
            component: ProtocolComponent {
                id: "0xBb2b8038a1640196FbE3e38816F3e67Cba72D940".to_string(),
                protocol_system: "uniswap_v2".to_string(),
                ..Default::default()
            },
            token_in: weth.clone(),
            token_out: wbtc.clone(),
            // This represents the remaining 50%, but to avoid any rounding errors we set this to
            // 0 to signify "the remainder of the WETH value". It should still be very close to 50%
            split: 0f64,
        };
        let swap_dai_usdc = Swap {
            component: ProtocolComponent {
                id: "0xAE461cA67B15dc8dc81CE7615e0320dA1A9aB8D5".to_string(),
                protocol_system: "uniswap_v2".to_string(),
                ..Default::default()
            },
            token_in: dai.clone(),
            token_out: usdc.clone(),
            split: 0f64,
        };
        let swap_wbtc_usdc = Swap {
            component: ProtocolComponent {
                id: "0x004375Dff511095CC5A197A54140a24eFEF3A416".to_string(),
                protocol_system: "uniswap_v2".to_string(),
                ..Default::default()
            },
            token_in: wbtc.clone(),
            token_out: usdc.clone(),
            split: 0f64,
        };
        let swap_encoder_registry = get_swap_encoder_registry();
        let encoder =
            SplitSwapStrategyEncoder::new(private_key, Chain::Ethereum, swap_encoder_registry)
                .unwrap();
        let solution = Solution {
            exact_out: false,
            given_token: weth,
            given_amount: BigUint::from_str("1_000000000000000000").unwrap(),
            checked_token: usdc,
            expected_amount: Some(BigUint::from_str("3_000_000000").unwrap()),
            check_amount: None,
            sender: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
            receiver: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
            swaps: vec![swap_weth_dai, swap_weth_wbtc, swap_dai_usdc, swap_wbtc_usdc],
            ..Default::default()
        };
        let router_address = Bytes::from_str("0x3Ede3eCa2a72B3aeCC820E955B36f38437D01395").unwrap();

        let (calldata, _) = encoder
            .encode_strategy(solution, router_address)
            .unwrap();

        let _hex_calldata = encode(&calldata);
        println!("{}", _hex_calldata);
    }

    fn get_mock_split_swap_strategy_encoder() -> SplitSwapStrategyEncoder {
        let private_key =
            "0x123456789abcdef123456789abcdef123456789abcdef123456789abcdef1234".to_string();
        let swap_encoder_registry = get_swap_encoder_registry();
        SplitSwapStrategyEncoder::new(private_key, Chain::Ethereum, swap_encoder_registry).unwrap()
    }

    #[test]
    fn test_validate_path_single_swap() {
        let encoder = get_mock_split_swap_strategy_encoder();
        let weth = Bytes::from_str("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2").unwrap();
        let dai = Bytes::from_str("0x6b175474e89094c44da98b954eedeac495271d0f").unwrap();
        let swaps = vec![Swap {
            component: ProtocolComponent {
                id: "0xA478c2975Ab1Ea89e8196811F51A7B7Ade33eB11".to_string(),
                protocol_system: "uniswap_v2".to_string(),
                ..Default::default()
            },
            token_in: weth.clone(),
            token_out: dai.clone(),
            split: 0f64,
        }];
        let result = encoder.validate_swap_path(&swaps, &weth, &dai, &None);
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn test_validate_path_multiple_swaps() {
        let encoder = get_mock_split_swap_strategy_encoder();
        let weth = Bytes::from_str("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2").unwrap();
        let dai = Bytes::from_str("0x6b175474e89094c44da98b954eedeac495271d0f").unwrap();
        let usdc = Bytes::from_str("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48").unwrap();
        let swaps = vec![
            Swap {
                component: ProtocolComponent {
                    id: "0xA478c2975Ab1Ea89e8196811F51A7B7Ade33eB11".to_string(),
                    protocol_system: "uniswap_v2".to_string(),
                    ..Default::default()
                },
                token_in: weth.clone(),
                token_out: dai.clone(),
                split: 0.5f64,
            },
            Swap {
                component: ProtocolComponent {
                    id: "0xA478c2975Ab1Ea89e8196811F51A7B7Ade33eB11".to_string(),
                    protocol_system: "uniswap_v2".to_string(),
                    ..Default::default()
                },
                token_in: dai.clone(),
                token_out: usdc.clone(),
                split: 0f64,
            },
        ];
        let result = encoder.validate_swap_path(&swaps, &weth, &usdc, &None);
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn test_validate_path_disconnected() {
        let encoder = get_mock_split_swap_strategy_encoder();
        let weth = Bytes::from_str("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2").unwrap();
        let dai = Bytes::from_str("0x6b175474e89094c44da98b954eedeac495271d0f").unwrap();
        let usdc = Bytes::from_str("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48").unwrap();
        let wbtc = Bytes::from_str("0x2260fac5e5542a773aa44fbcfedf7c193bc2c599").unwrap();

        let disconnected_swaps = vec![
            Swap {
                component: ProtocolComponent {
                    id: "pool1".to_string(),
                    protocol_system: "uniswap_v2".to_string(),
                    ..Default::default()
                },
                token_in: weth.clone(),
                token_out: dai.clone(),
                split: 0.5,
            },
            // This swap is disconnected from the WETH->DAI path
            Swap {
                component: ProtocolComponent {
                    id: "pool2".to_string(),
                    protocol_system: "uniswap_v2".to_string(),
                    ..Default::default()
                },
                token_in: wbtc.clone(),
                token_out: usdc.clone(),
                split: 0.0,
            },
        ];
        let result = encoder.validate_swap_path(&disconnected_swaps, &weth, &usdc, &None);
        assert!(matches!(
            result,
            Err(EncodingError::InvalidInput(msg)) if msg.contains("not reachable through swap path")
        ));
    }

    #[test]
    fn test_validate_path_unreachable_checked_token() {
        let encoder = get_mock_split_swap_strategy_encoder();
        let weth = Bytes::from_str("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2").unwrap();
        let dai = Bytes::from_str("0x6b175474e89094c44da98b954eedeac495271d0f").unwrap();
        let usdc = Bytes::from_str("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48").unwrap();

        let unreachable_swaps = vec![Swap {
            component: ProtocolComponent {
                id: "pool1".to_string(),
                protocol_system: "uniswap_v2".to_string(),
                ..Default::default()
            },
            token_in: weth.clone(),
            token_out: dai.clone(),
            split: 1.0,
        }];
        let result = encoder.validate_swap_path(&unreachable_swaps, &weth, &usdc, &None);
        assert!(matches!(
            result,
            Err(EncodingError::InvalidInput(msg)) if msg.contains("not reachable through swap path")
        ));
    }

    #[test]
    fn test_validate_path_empty_swaps() {
        let encoder = get_mock_split_swap_strategy_encoder();
        let weth = Bytes::from_str("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2").unwrap();
        let usdc = Bytes::from_str("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48").unwrap();

        let empty_swaps: Vec<Swap> = vec![];
        let result = encoder.validate_swap_path(&empty_swaps, &weth, &usdc, &None);
        assert!(matches!(
            result,
            Err(EncodingError::InvalidInput(msg)) if msg.contains("not reachable through swap path")
        ));
    }

    #[test]
    fn test_validate_swap_single() {
        let encoder = get_mock_split_swap_strategy_encoder();
        let weth = Bytes::from_str("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2").unwrap();
        let dai = Bytes::from_str("0x6b175474e89094c44da98b954eedeac495271d0f").unwrap();
        let swaps = vec![Swap {
            component: ProtocolComponent {
                id: "0xA478c2975Ab1Ea89e8196811F51A7B7Ade33eB11".to_string(),
                protocol_system: "uniswap_v2".to_string(),
                ..Default::default()
            },
            token_in: weth.clone(),
            token_out: dai.clone(),
            split: 0f64,
        }];
        let result = encoder.validate_split_percentages(&swaps);
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn test_validate_swaps_multiple() {
        let weth = Bytes::from_str("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2").unwrap();
        let dai = Bytes::from_str("0x6b175474e89094c44da98b954eedeac495271d0f").unwrap();

        // Valid case: Multiple swaps with proper splits (50%, 30%, remainder)
        let valid_swaps = vec![
            Swap {
                component: ProtocolComponent {
                    id: "pool1".to_string(),
                    protocol_system: "uniswap_v2".to_string(),
                    ..Default::default()
                },
                token_in: weth.clone(),
                token_out: dai.clone(),
                split: 0.5,
            },
            Swap {
                component: ProtocolComponent {
                    id: "pool2".to_string(),
                    protocol_system: "uniswap_v2".to_string(),
                    ..Default::default()
                },
                token_in: weth.clone(),
                token_out: dai.clone(),
                split: 0.3,
            },
            Swap {
                component: ProtocolComponent {
                    id: "pool3".to_string(),
                    protocol_system: "uniswap_v2".to_string(),
                    ..Default::default()
                },
                token_in: weth.clone(),
                token_out: dai.clone(),
                split: 0.0, // Remainder (20%)
            },
        ];
        let encoder = get_mock_split_swap_strategy_encoder();
        assert!(encoder
            .validate_split_percentages(&valid_swaps)
            .is_ok());
    }

    #[test]
    fn test_validate_swaps_no_remainder_split() {
        let weth = Bytes::from_str("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2").unwrap();
        let dai = Bytes::from_str("0x6b175474e89094c44da98b954eedeac495271d0f").unwrap();

        let invalid_total_swaps = vec![
            Swap {
                component: ProtocolComponent {
                    id: "pool1".to_string(),
                    protocol_system: "uniswap_v2".to_string(),
                    ..Default::default()
                },
                token_in: weth.clone(),
                token_out: dai.clone(),
                split: 0.7,
            },
            Swap {
                component: ProtocolComponent {
                    id: "pool2".to_string(),
                    protocol_system: "uniswap_v2".to_string(),
                    ..Default::default()
                },
                token_in: weth.clone(),
                token_out: dai.clone(),
                split: 0.3,
            },
        ];
        let encoder = get_mock_split_swap_strategy_encoder();
        assert!(matches!(
            encoder.validate_split_percentages(&invalid_total_swaps),
            Err(EncodingError::InvalidInput(msg)) if msg.contains("must have exactly one 0% split")
        ));
    }

    #[test]
    fn test_validate_swaps_zero_split_not_at_end() {
        let weth = Bytes::from_str("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2").unwrap();
        let dai = Bytes::from_str("0x6b175474e89094c44da98b954eedeac495271d0f").unwrap();

        let invalid_zero_position_swaps = vec![
            Swap {
                component: ProtocolComponent {
                    id: "pool1".to_string(),
                    protocol_system: "uniswap_v2".to_string(),
                    ..Default::default()
                },
                token_in: weth.clone(),
                token_out: dai.clone(),
                split: 0.0,
            },
            Swap {
                component: ProtocolComponent {
                    id: "pool2".to_string(),
                    protocol_system: "uniswap_v2".to_string(),
                    ..Default::default()
                },
                token_in: weth.clone(),
                token_out: dai.clone(),
                split: 0.5,
            },
        ];
        let encoder = get_mock_split_swap_strategy_encoder();
        assert!(matches!(
            encoder.validate_split_percentages(&invalid_zero_position_swaps),
            Err(EncodingError::InvalidInput(msg)) if msg.contains("must be the last swap")
        ));
    }

    #[test]
    fn test_validate_swaps_splits_exceed_hundred_percent() {
        let weth = Bytes::from_str("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2").unwrap();
        let dai = Bytes::from_str("0x6b175474e89094c44da98b954eedeac495271d0f").unwrap();

        let invalid_overflow_swaps = vec![
            Swap {
                component: ProtocolComponent {
                    id: "pool1".to_string(),
                    protocol_system: "uniswap_v2".to_string(),
                    ..Default::default()
                },
                token_in: weth.clone(),
                token_out: dai.clone(),
                split: 0.6,
            },
            Swap {
                component: ProtocolComponent {
                    id: "pool2".to_string(),
                    protocol_system: "uniswap_v2".to_string(),
                    ..Default::default()
                },
                token_in: weth.clone(),
                token_out: dai.clone(),
                split: 0.5,
            },
            Swap {
                component: ProtocolComponent {
                    id: "pool3".to_string(),
                    protocol_system: "uniswap_v2".to_string(),
                    ..Default::default()
                },
                token_in: weth.clone(),
                token_out: dai.clone(),
                split: 0.0,
            },
        ];
        let encoder = get_mock_split_swap_strategy_encoder();
        assert!(matches!(
            encoder.validate_split_percentages(&invalid_overflow_swaps),
            Err(EncodingError::InvalidInput(msg)) if msg.contains("must be <100%")
        ));
    }

    #[test]
    fn test_validate_path_wrap_eth_given_token() {
        let encoder = get_mock_split_swap_strategy_encoder();

        let eth = Bytes::from_str("0x0000000000000000000000000000000000000000").unwrap();
        let usdc = Bytes::from_str("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48").unwrap();
        let weth = Bytes::from_str("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2").unwrap();

        let swaps = vec![Swap {
            component: ProtocolComponent {
                id: "pool1".to_string(),
                protocol_system: "uniswap_v2".to_string(),
                ..Default::default()
            },
            token_in: weth.clone(),
            token_out: usdc.clone(),
            split: 0f64,
        }];

        let result = encoder.validate_swap_path(&swaps, &eth, &usdc, &Some(NativeAction::Wrap));
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn test_validate_token_path_connectivity_wrap_eth_checked_token() {
        let encoder = get_mock_split_swap_strategy_encoder();

        let eth = Bytes::from_str("0x0000000000000000000000000000000000000000").unwrap();
        let usdc = Bytes::from_str("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48").unwrap();
        let weth = Bytes::from_str("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2").unwrap();

        let swaps = vec![Swap {
            component: ProtocolComponent {
                id: "pool1".to_string(),
                protocol_system: "uniswap_v2".to_string(),
                ..Default::default()
            },
            token_in: usdc.clone(),
            token_out: weth.clone(),
            split: 0f64,
        }];

        let result = encoder.validate_swap_path(&swaps, &usdc, &eth, &Some(NativeAction::Unwrap));
        assert_eq!(result, Ok(()));
    }
}
