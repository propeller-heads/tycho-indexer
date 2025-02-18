use std::{
    collections::{HashMap, HashSet, VecDeque},
    str::FromStr,
};

use alloy_primitives::{aliases::U24, FixedBytes, U256, U8};
use alloy_sol_types::SolValue;
use tycho_core::{keccak256, Bytes};

use crate::encoding::{
    errors::EncodingError,
    evm::{
        approvals::permit2::Permit2,
        constants::GROUPABLE_PROTOCOLS,
        swap_encoder::swap_encoder_registry::SwapEncoderRegistry,
        utils::{
            biguint_to_u256, bytes_to_address, encode_input, get_min_amount_for_solution,
            get_token_position, percentage_to_uint24,
        },
    },
    models::{Chain, EncodingContext, NativeAction, Solution, Swap},
    strategy_encoder::StrategyEncoder,
    swap_encoder::SwapEncoder,
};

/// Encodes a solution using a specific strategy for execution on the EVM-compatible network.
pub trait EVMStrategyEncoder: StrategyEncoder {
    /// Encodes information necessary for performing a single swap against a given executor for
    /// a protocol.
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

    /// Encodes a selector string into its 4-byte representation.
    fn encode_executor_selector(&self, selector: &str) -> FixedBytes<4> {
        let hash = keccak256(selector.as_bytes());
        FixedBytes::<4>::from([hash[0], hash[1], hash[2], hash[3]])
    }

    /// Uses prefix-length encoding to efficient encode action data.
    ///
    /// Prefix-length encoding is a data encoding method where the beginning of a data segment
    /// (the "prefix") contains information about the length of the following data.
    fn ple_encode(&self, action_data_array: Vec<Vec<u8>>) -> Vec<u8> {
        let mut encoded_action_data: Vec<u8> = Vec::new();

        for action_data in action_data_array {
            let args = (encoded_action_data, action_data.len() as u16, action_data);
            encoded_action_data = args.abi_encode_packed();
        }

        encoded_action_data
    }
}

/// Represents a group of swaps that can be encoded into a single swap execution for gas
/// optimization.
///
/// # Fields
/// * `input_token`: Bytes, the input token of the first swap
/// * `output_token`: Bytes, the output token of the final swap
/// * `protocol_system`: String, the protocol system of the swaps
/// * `swaps`: Vec<Swap>, the sequence of swaps to be executed as a group
/// * `split`: f64, the split percentage of the first swap in the group
#[derive(Clone, PartialEq, Debug)]
pub struct SwapGroup {
    input_token: Bytes,
    output_token: Bytes,
    protocol_system: String,
    swaps: Vec<Swap>,
    split: f64,
}

/// Represents the encoder for a swap strategy which supports single, sequential and split swaps.
///
/// # Fields
/// * `swap_encoder_registry`: SwapEncoderRegistry, containing all possible swap encoders
/// * `permit2`: Permit2, responsible for managing permit2 operations and providing necessary
///   signatures and permit2 objects for calling the router
/// * `selector`: String, the selector for the swap function in the router contract
#[derive(Clone)]
pub struct SplitSwapStrategyEncoder {
    swap_encoder_registry: SwapEncoderRegistry,
    permit2: Permit2,
    selector: String,
    native_address: Bytes,
    wrapped_address: Bytes,
    split_swap_validator: SplitSwapValidator,
}

/// Validates whether a sequence of split swaps represents a valid solution.
#[derive(Clone)]
pub struct SplitSwapValidator;

impl SplitSwapValidator {
    /// Raises an error if the split percentages are invalid.
    ///
    /// Split percentages are considered valid if all the following conditions are met:
    /// * Each split amount is < 1 (100%)
    /// * There is exactly one 0% split for each token, and it's the last swap specified, signifying
    ///   to the router to send the remainder of the token to the designated protocol
    /// * The sum of all non-remainder splits for each token is < 1 (100%)
    /// * There are no negative split amounts
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
                        if swap.split < 0.0 {
                            return Err(EncodingError::InvalidInput(format!(
                                "All splits must be >= 0% for token {:?}",
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

    /// Raises an error if swaps do not represent a valid path from the given token to the checked
    /// token.
    ///
    /// A path is considered valid if all the following conditions are met:
    /// * The checked token is reachable from the given token through the swap path
    /// * There are no tokens which are unconnected from the main path
    ///
    /// If the given token is the native token and the native action is WRAP, it will be converted
    /// to the wrapped token before validating the swap path. The same principle applies for the
    /// checked token and the UNWRAP action.
    fn validate_swap_path(
        &self,
        swaps: &[Swap],
        given_token: &Bytes,
        checked_token: &Bytes,
        native_action: &Option<NativeAction>,
        native_address: &Bytes,
        wrapped_address: &Bytes,
    ) -> Result<(), EncodingError> {
        // Convert ETH to WETH only if there's a corresponding wrap/unwrap action
        let given_token = if *given_token == *native_address {
            match native_action {
                Some(NativeAction::Wrap) => wrapped_address,
                _ => given_token,
            }
        } else {
            given_token
        };

        let checked_token = if *checked_token == *native_address {
            match native_action {
                Some(NativeAction::Unwrap) => wrapped_address,
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

impl SplitSwapStrategyEncoder {
    pub fn new(
        signer_pk: String,
        chain: Chain,
        swap_encoder_registry: SwapEncoderRegistry,
    ) -> Result<Self, EncodingError> {
        let selector = "swap(uint256,address,address,uint256,bool,bool,uint256,address,((address,uint160,uint48,uint48),address,uint256),bytes,bytes)".to_string();
        Ok(Self {
            permit2: Permit2::new(signer_pk, chain.clone())?,
            selector,
            swap_encoder_registry,
            native_address: chain.native_token()?,
            wrapped_address: chain.wrapped_token()?,
            split_swap_validator: SplitSwapValidator,
        })
    }

    /// Group consecutive swaps which can be encoded into one swap execution for gas optimization.
    ///
    /// An example where this applies is the case of USV4, which uses a PoolManager contract
    /// to save token transfers on consecutive swaps.
    fn group_swaps(&self, swaps: Vec<Swap>) -> Vec<SwapGroup> {
        let mut grouped_swaps: Vec<SwapGroup> = Vec::new();
        let mut current_group: Option<SwapGroup> = None;
        let mut last_swap_protocol = "".to_string();
        let mut groupable_protocol;
        let mut last_swap_out_token = Bytes::default();
        for swap in swaps {
            let current_swap_protocol = swap.component.protocol_system.clone();
            groupable_protocol = GROUPABLE_PROTOCOLS.contains(&current_swap_protocol.as_str());

            // Split 0 can also mean that the swap is the remaining part of a branch of splits,
            // so we need to check the last swap's out token as well
            let no_split = swap.split == 0.0 && swap.token_in == last_swap_out_token;

            if current_swap_protocol == last_swap_protocol && groupable_protocol && no_split {
                // Second or later groupable pool in a sequence of groupable pools. Merge to the
                // current group.
                if let Some(group) = current_group.as_mut() {
                    group.swaps.push(swap.clone());
                    // Update the output token of the current group.
                    group.output_token = swap.token_out.clone();
                }
            } else {
                // Not second or later USV4 pool. Push the current group (if it exists) and then
                // create a new group.
                if let Some(group) = current_group.as_mut() {
                    grouped_swaps.push(group.clone());
                }
                current_group = Some(SwapGroup {
                    input_token: swap.token_in.clone(),
                    output_token: swap.token_out.clone(),
                    protocol_system: current_swap_protocol.clone(),
                    swaps: vec![swap.clone()],
                    split: swap.split,
                });
            }
            last_swap_protocol = current_swap_protocol;
            last_swap_out_token = swap.token_out.clone();
        }
        if let Some(group) = current_group.as_mut() {
            grouped_swaps.push(group.clone());
        }
        grouped_swaps
    }
}
impl EVMStrategyEncoder for SplitSwapStrategyEncoder {}

impl StrategyEncoder for SplitSwapStrategyEncoder {
    fn encode_strategy(
        &self,
        solution: Solution,
    ) -> Result<(Vec<u8>, Bytes, Option<String>), EncodingError> {
        self.split_swap_validator
            .validate_split_percentages(&solution.swaps)?;
        self.split_swap_validator
            .validate_swap_path(
                &solution.swaps,
                &solution.given_token,
                &solution.checked_token,
                &solution.native_action,
                &self.native_address,
                &self.wrapped_address,
            )?;
        let (permit, signature) = self.permit2.get_permit(
            &solution.router_address,
            &solution.sender,
            &solution.given_token,
            &solution.given_amount,
        )?;
        let min_amount_out = get_min_amount_for_solution(solution.clone());

        // The tokens array is composed of the given token, the checked token and all the
        // intermediary tokens in between. The contract expects the tokens to be in this order.
        let solution_tokens: HashSet<Bytes> =
            vec![solution.given_token.clone(), solution.checked_token.clone()]
                .into_iter()
                .collect();

        let grouped_swaps = self.group_swaps(solution.swaps);

        let intermediary_tokens: HashSet<Bytes> = grouped_swaps
            .iter()
            .flat_map(|grouped_swap| {
                vec![grouped_swap.input_token.clone(), grouped_swap.output_token.clone()]
            })
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
            tokens.push(self.wrapped_address.clone());
        } else {
            tokens.push(solution.given_token.clone());
        }
        tokens.extend(intermediary_tokens);

        if unwrap {
            tokens.push(self.wrapped_address.clone());
        } else {
            tokens.push(solution.checked_token.clone());
        }

        let mut swaps = vec![];
        for grouped_swap in grouped_swaps.iter() {
            let swap_encoder = self
                .get_swap_encoder(&grouped_swap.protocol_system)
                .ok_or_else(|| {
                    EncodingError::InvalidInput(format!(
                        "Swap encoder not found for protocol: {}",
                        grouped_swap.protocol_system
                    ))
                })?;

            let encoding_context = EncodingContext {
                receiver: solution.router_address.clone(),
                exact_out: solution.exact_out,
                router_address: solution.router_address.clone(),
            };
            let mut grouped_protocol_data: Vec<Vec<u8>> = vec![];
            for swap in grouped_swap.swaps.iter() {
                let protocol_data =
                    swap_encoder.encode_swap(swap.clone(), encoding_context.clone())?;
                grouped_protocol_data.push(protocol_data);
            }

            let swap_data = self.encode_swap_header(
                get_token_position(tokens.clone(), grouped_swap.input_token.clone())?,
                get_token_position(tokens.clone(), grouped_swap.output_token.clone())?,
                percentage_to_uint24(grouped_swap.split),
                Bytes::from_str(swap_encoder.executor_address()).map_err(|_| {
                    EncodingError::FatalError("Invalid executor address".to_string())
                })?,
                self.encode_executor_selector(swap_encoder.executor_selector()),
                grouped_protocol_data.abi_encode_packed(),
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
        Ok((contract_interaction, solution.router_address, None))
    }

    fn get_swap_encoder(&self, protocol_system: &str) -> Option<&Box<dyn SwapEncoder>> {
        self.swap_encoder_registry
            .get_encoder(protocol_system)
    }

    fn clone_box(&self) -> Box<dyn StrategyEncoder> {
        Box::new(self.clone())
    }
}

/// This strategy encoder is used for solutions that are sent directly to the executor, bypassing
/// the router. Only one solution with one swap is supported.
///
/// # Fields
/// * `swap_encoder_registry`: SwapEncoderRegistry, containing all possible swap encoders
#[derive(Clone)]
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
    ) -> Result<(Vec<u8>, Bytes, Option<String>), EncodingError> {
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
            router_address: solution.router_address,
        };
        let protocol_data = swap_encoder.encode_swap(swap.clone(), encoding_context)?;

        let executor_address = Bytes::from_str(swap_encoder.executor_address())
            .map_err(|_| EncodingError::FatalError("Invalid executor address".to_string()))?;
        Ok((
            protocol_data,
            executor_address,
            Some(
                swap_encoder
                    .executor_selector()
                    .to_string(),
            ),
        ))
    }

    fn get_swap_encoder(&self, protocol_system: &str) -> Option<&Box<dyn SwapEncoder>> {
        self.swap_encoder_registry
            .get_encoder(protocol_system)
    }

    fn clone_box(&self) -> Box<dyn StrategyEncoder> {
        Box::new(self.clone())
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use alloy::hex::encode;
    use alloy_primitives::hex;
    use num_bigint::BigUint;
    use rstest::rstest;
    use tycho_core::{
        dto::{Chain as TychoCoreChain, ProtocolComponent},
        Bytes,
    };

    use super::*;
    use crate::encoding::models::Swap;

    fn eth_chain() -> Chain {
        TychoCoreChain::Ethereum.into()
    }

    fn eth() -> Bytes {
        Bytes::from(hex!("0000000000000000000000000000000000000000").to_vec())
    }

    fn weth() -> Bytes {
        Bytes::from(hex!("c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2").to_vec())
    }

    fn get_swap_encoder_registry() -> SwapEncoderRegistry {
        let eth_chain = eth_chain();
        SwapEncoderRegistry::new(None, eth_chain).unwrap()
    }

    #[test]
    fn test_executor_strategy_encode() {
        let swap_encoder_registry = get_swap_encoder_registry();
        let encoder = ExecutorStrategyEncoder::new(swap_encoder_registry);

        let token_in = weth();
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
            checked_amount: None,
            sender: Bytes::from_str("0x0000000000000000000000000000000000000000").unwrap(),
            // The receiver was generated with `makeAddr("bob") using forge`
            receiver: Bytes::from_str("0x1d96f2f6bef1202e4ce1ff6dad0c2cb002861d3e").unwrap(),
            swaps: vec![swap],
            direct_execution: true,
            router_address: Bytes::from_str("0x3Ede3eCa2a72B3aeCC820E955B36f38437D01395").unwrap(),
            slippage: None,
            native_action: None,
        };

        let (protocol_data, executor_address, selector) = encoder
            .encode_strategy(solution)
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
        assert_eq!(selector, Some("swap(uint256,bytes)".to_string()));
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
        #[case] checked_amount: Option<BigUint>,
        #[case] expected_min_amount: U256,
    ) {
        // Performs a single swap from WETH to DAI on a USV2 pool, with no grouping optimizations.

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
            SplitSwapStrategyEncoder::new(private_key, eth_chain(), swap_encoder_registry).unwrap();
        let solution = Solution {
            exact_out: false,
            given_token: weth,
            given_amount: BigUint::from_str("1_000000000000000000").unwrap(),
            checked_token: dai,
            expected_amount,
            slippage,
            checked_amount,
            sender: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
            receiver: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
            router_address: Bytes::from_str("0x3Ede3eCa2a72B3aeCC820E955B36f38437D01395").unwrap(),
            swaps: vec![swap],
            ..Default::default()
        };

        let (calldata, _, _) = encoder
            .encode_strategy(solution)
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
            token_in: weth(),
            token_out: dai.clone(),
            split: 0f64,
        };
        let swap_encoder_registry = get_swap_encoder_registry();
        let encoder =
            SplitSwapStrategyEncoder::new(private_key, eth_chain(), swap_encoder_registry).unwrap();
        let solution = Solution {
            exact_out: false,
            given_token: eth(),
            given_amount: BigUint::from_str("1_000000000000000000").unwrap(),
            checked_token: dai,
            expected_amount: Some(BigUint::from_str("3_000_000000000000000000").unwrap()),
            checked_amount: None,
            sender: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
            receiver: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
            router_address: Bytes::from_str("0x3Ede3eCa2a72B3aeCC820E955B36f38437D01395").unwrap(),
            swaps: vec![swap],
            native_action: Some(NativeAction::Wrap),
            ..Default::default()
        };

        let (calldata, _, _) = encoder
            .encode_strategy(solution)
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
            token_out: weth(),
            split: 0f64,
        };
        let swap_encoder_registry = get_swap_encoder_registry();
        let encoder =
            SplitSwapStrategyEncoder::new(private_key, eth_chain(), swap_encoder_registry).unwrap();
        let solution = Solution {
            exact_out: false,
            given_token: dai,
            given_amount: BigUint::from_str("3_000_000000000000000000").unwrap(),
            checked_token: eth(),
            expected_amount: Some(BigUint::from_str("1_000000000000000000").unwrap()),
            checked_amount: None,
            sender: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
            receiver: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
            router_address: Bytes::from_str("0x3Ede3eCa2a72B3aeCC820E955B36f38437D01395").unwrap(),
            swaps: vec![swap],
            native_action: Some(NativeAction::Unwrap),
            ..Default::default()
        };

        let (calldata, _, _) = encoder
            .encode_strategy(solution)
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

        let weth = weth();
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
            SplitSwapStrategyEncoder::new(private_key, eth_chain(), swap_encoder_registry).unwrap();
        let solution = Solution {
            exact_out: false,
            given_token: weth,
            given_amount: BigUint::from_str("1_000000000000000000").unwrap(),
            checked_token: usdc,
            expected_amount: Some(BigUint::from_str("3_000_000000").unwrap()),
            checked_amount: None,
            sender: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
            receiver: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
            router_address: Bytes::from_str("0x3Ede3eCa2a72B3aeCC820E955B36f38437D01395").unwrap(),
            swaps: vec![swap_weth_dai, swap_weth_wbtc, swap_dai_usdc, swap_wbtc_usdc],
            ..Default::default()
        };

        let (calldata, _, _) = encoder
            .encode_strategy(solution)
            .unwrap();

        let _hex_calldata = encode(&calldata);
        println!("{}", _hex_calldata);
    }

    #[test]
    fn test_group_swaps_simple() {
        // The first and second swaps can be grouped since there is no split, and they are
        // both USV4.
        //
        //   WETH ──(USV4)──> WBTC ───(USV4)──> USDC ───(USV2)──> DAI
        //
        // Set up a mock private key for signing
        let private_key =
            "0x123456789abcdef123456789abcdef123456789abcdef123456789abcdef1234".to_string();

        let weth = weth();
        let wbtc = Bytes::from_str("0x2260fac5e5542a773aa44fbcfedf7c193bc2c599").unwrap();
        let usdc = Bytes::from_str("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48").unwrap();
        let dai = Bytes::from_str("0x6b175474e89094c44da98b954eedeac495271d0f").unwrap();

        let swap_weth_wbtc = Swap {
            component: ProtocolComponent {
                protocol_system: "uniswap_v4".to_string(),
                ..Default::default()
            },
            token_in: weth.clone(),
            token_out: wbtc.clone(),
            // This represents the remaining 50%, but to avoid any rounding errors we set this to
            // 0 to signify "the remainder of the WETH value". It should still be very close to 50%
            split: 0f64,
        };
        let swap_wbtc_usdc = Swap {
            component: ProtocolComponent {
                protocol_system: "uniswap_v4".to_string(),
                ..Default::default()
            },
            token_in: wbtc.clone(),
            token_out: usdc.clone(),
            split: 0f64,
        };
        let swap_usdc_dai = Swap {
            component: ProtocolComponent {
                protocol_system: "uniswap_v2".to_string(),
                ..Default::default()
            },
            token_in: usdc.clone(),
            token_out: dai.clone(),
            split: 0f64,
        };
        let swap_encoder_registry = get_swap_encoder_registry();
        let encoder =
            SplitSwapStrategyEncoder::new(private_key, eth_chain(), swap_encoder_registry).unwrap();

        let grouped_swaps = encoder.group_swaps(vec![
            swap_weth_wbtc.clone(),
            swap_wbtc_usdc.clone(),
            swap_usdc_dai.clone(),
        ]);

        assert_eq!(
            grouped_swaps,
            vec![
                SwapGroup {
                    swaps: vec![swap_weth_wbtc, swap_wbtc_usdc],
                    input_token: weth,
                    output_token: usdc.clone(),
                    protocol_system: "uniswap_v4".to_string(),
                    split: 0f64,
                },
                SwapGroup {
                    swaps: vec![swap_usdc_dai],
                    input_token: usdc,
                    output_token: dai,
                    protocol_system: "uniswap_v2".to_string(),
                    split: 0f64,
                }
            ]
        );
    }

    #[test]
    fn test_group_swaps_complex_split() {
        // There is a split in the solution, but it's possible to combine two of the USV4 splits.
        // The WETH -> USDC swap cannot get grouped with anything, but the WETH -> DAI and
        // DAI -> USDC swaps can be grouped.
        //
        //                            ┌──(USV4)──> USDC
        //   WBTC ──> (USV4)──> WETH ─┤
        //                            └──(USV4)──> DAI ───(USV4)──> USDC
        let private_key =
            "0x123456789abcdef123456789abcdef123456789abcdef123456789abcdef1234".to_string();

        let weth = weth();
        let wbtc = Bytes::from_str("0x2260fac5e5542a773aa44fbcfedf7c193bc2c599").unwrap();
        let usdc = Bytes::from_str("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48").unwrap();
        let dai = Bytes::from_str("0x6b175474e89094c44da98b954eedeac495271d0f").unwrap();

        let swap_wbtc_weth = Swap {
            component: ProtocolComponent {
                protocol_system: "uniswap_v4".to_string(),
                ..Default::default()
            },
            token_in: wbtc.clone(),
            token_out: weth.clone(),
            split: 0f64,
        };
        let swap_weth_usdc = Swap {
            component: ProtocolComponent {
                protocol_system: "uniswap_v4".to_string(),
                ..Default::default()
            },
            token_in: weth.clone(),
            token_out: usdc.clone(),
            split: 0.5f64,
        };
        let swap_weth_dai = Swap {
            component: ProtocolComponent {
                protocol_system: "uniswap_v4".to_string(),
                ..Default::default()
            },
            token_in: weth.clone(),
            token_out: dai.clone(),
            // This represents the remaining 50%, but to avoid any rounding errors we set this to
            // 0 to signify "the remainder of the WETH value". It should still be very close to 50%
            split: 0f64,
        };
        let swap_dai_usdc = Swap {
            component: ProtocolComponent {
                protocol_system: "uniswap_v4".to_string(),
                ..Default::default()
            },
            token_in: dai.clone(),
            token_out: usdc.clone(),
            split: 0f64,
        };
        let swap_encoder_registry = get_swap_encoder_registry();
        let encoder =
            SplitSwapStrategyEncoder::new(private_key, eth_chain(), swap_encoder_registry).unwrap();

        let grouped_swaps = encoder.group_swaps(vec![
            swap_wbtc_weth.clone(),
            swap_weth_usdc.clone(),
            swap_weth_dai.clone(),
            swap_dai_usdc.clone(),
        ]);

        assert_eq!(
            grouped_swaps,
            vec![
                SwapGroup {
                    swaps: vec![swap_wbtc_weth],
                    input_token: wbtc.clone(),
                    output_token: weth.clone(),
                    protocol_system: "uniswap_v4".to_string(),
                    split: 0f64,
                },
                SwapGroup {
                    swaps: vec![swap_weth_usdc],
                    input_token: weth.clone(),
                    output_token: usdc.clone(),
                    protocol_system: "uniswap_v4".to_string(),
                    split: 0.5f64,
                },
                SwapGroup {
                    swaps: vec![swap_weth_dai, swap_dai_usdc],
                    input_token: weth,
                    output_token: usdc,
                    protocol_system: "uniswap_v4".to_string(),
                    split: 0f64,
                }
            ]
        );
    }

    #[test]
    fn test_group_swaps_complex_split_multi_protocol() {
        // There is a split in the solution, but it's possible to group the USV4 splits with each
        // other and the Balancer V3 swaps with each other.
        //
        //         ┌──(BalancerV3)──> WBTC ──(BalancerV3)──> USDC
        //   WETH ─┤
        //         └──(USV4)──> DAI ───(USV4)──> USDC
        let private_key =
            "0x123456789abcdef123456789abcdef123456789abcdef123456789abcdef1234".to_string();

        let weth = weth();
        let wbtc = Bytes::from_str("0x2260fac5e5542a773aa44fbcfedf7c193bc2c599").unwrap();
        let usdc = Bytes::from_str("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48").unwrap();
        let dai = Bytes::from_str("0x6b175474e89094c44da98b954eedeac495271d0f").unwrap();

        let swap_weth_wbtc = Swap {
            component: ProtocolComponent {
                protocol_system: "balancer_v3".to_string(),
                ..Default::default()
            },
            token_in: weth.clone(),
            token_out: wbtc.clone(),
            split: 0.5f64,
        };
        let swap_wbtc_usdc = Swap {
            component: ProtocolComponent {
                protocol_system: "balancer_v3".to_string(),
                ..Default::default()
            },
            token_in: wbtc.clone(),
            token_out: usdc.clone(),
            split: 0f64,
        };
        let swap_weth_dai = Swap {
            component: ProtocolComponent {
                protocol_system: "uniswap_v4".to_string(),
                ..Default::default()
            },
            token_in: weth.clone(),
            token_out: dai.clone(),
            // This represents the remaining 50%, but to avoid any rounding errors we set this to
            // 0 to signify "the remainder of the WETH value". It should still be very close to 50%
            split: 0f64,
        };
        let swap_dai_usdc = Swap {
            component: ProtocolComponent {
                protocol_system: "uniswap_v4".to_string(),
                ..Default::default()
            },
            token_in: dai.clone(),
            token_out: usdc.clone(),
            split: 0f64,
        };
        let swap_encoder_registry = get_swap_encoder_registry();
        let encoder =
            SplitSwapStrategyEncoder::new(private_key, eth_chain(), swap_encoder_registry).unwrap();

        let grouped_swaps = encoder.group_swaps(vec![
            swap_weth_wbtc.clone(),
            swap_wbtc_usdc.clone(),
            swap_weth_dai.clone(),
            swap_dai_usdc.clone(),
        ]);

        assert_eq!(
            grouped_swaps,
            vec![
                SwapGroup {
                    swaps: vec![swap_weth_wbtc, swap_wbtc_usdc],
                    input_token: weth.clone(),
                    output_token: usdc.clone(),
                    protocol_system: "balancer_v3".to_string(),
                    split: 0.5f64,
                },
                SwapGroup {
                    swaps: vec![swap_weth_dai, swap_dai_usdc],
                    input_token: weth,
                    output_token: usdc,
                    protocol_system: "uniswap_v4".to_string(),
                    split: 0f64,
                }
            ]
        );
    }

    #[test]
    fn test_split_encoding_strategy_usv4() {
        // Performs a split swap from WETH to USDC though WBTC using two consecutive USV4 pools
        //
        //   WETH ──(USV4)──> WBTC ───(USV4)──> USDC
        //

        // Set up a mock private key for signing
        let private_key =
            "0x123456789abcdef123456789abcdef123456789abcdef123456789abcdef1234".to_string();

        let weth = weth();
        let wbtc = Bytes::from_str("0x2260fac5e5542a773aa44fbcfedf7c193bc2c599").unwrap();
        let usdc = Bytes::from_str("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48").unwrap();

        let swap_weth_wbtc = Swap {
            component: ProtocolComponent {
                id: "0xBb2b8038a1640196FbE3e38816F3e67Cba72D940".to_string(),
                protocol_system: "uniswap_v4".to_string(),
                ..Default::default()
            },
            token_in: weth.clone(),
            token_out: wbtc.clone(),
            // This represents the remaining 50%, but to avoid any rounding errors we set this to
            // 0 to signify "the remainder of the WETH value". It should still be very close to 50%
            split: 0f64,
        };
        let swap_wbtc_usdc = Swap {
            component: ProtocolComponent {
                id: "0xAE461cA67B15dc8dc81CE7615e0320dA1A9aB8D5".to_string(),
                protocol_system: "uniswap_v4".to_string(),
                ..Default::default()
            },
            token_in: wbtc.clone(),
            token_out: usdc.clone(),
            split: 0f64,
        };
        let swap_encoder_registry = get_swap_encoder_registry();
        let encoder =
            SplitSwapStrategyEncoder::new(private_key, eth_chain(), swap_encoder_registry).unwrap();
        let solution = Solution {
            exact_out: false,
            given_token: weth,
            given_amount: BigUint::from_str("1_000000000000000000").unwrap(),
            checked_token: usdc,
            expected_amount: Some(BigUint::from_str("3_000_000000").unwrap()),
            checked_amount: None,
            slippage: None,
            sender: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
            receiver: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
            router_address: Bytes::from_str("0x3Ede3eCa2a72B3aeCC820E955B36f38437D01395").unwrap(),
            swaps: vec![swap_weth_wbtc, swap_wbtc_usdc],
            ..Default::default()
        };

        let (calldata, _, _) = encoder
            .encode_strategy(solution)
            .unwrap();

        let expected_input = [
            "4860f9ed",                                                              // Function selector
            "0000000000000000000000000000000000000000000000000de0b6b3a7640000",      // amount out
            "000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",      // token in
            "000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",      // token out
            "0000000000000000000000000000000000000000000000000000000000000000",      // min amount out
            "0000000000000000000000000000000000000000000000000000000000000000",      // wrap
            "0000000000000000000000000000000000000000000000000000000000000000",      // unwrap
            // tokens length (not including intermediary tokens of USV4-optimized swaps)
            "0000000000000000000000000000000000000000000000000000000000000002",
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
            "0000000000000000000000000000000000000000000000000000000000000099",
            // ple encoded swaps
            "0097",   // Swap length
            "00",     // token in index
            "01",     // token out index
            "000000", // split
            // Swap data header
            "5c2f5a71f67c01775180adc06909288b4c329308", // executor address
            "bd0625ab",                                 // selector
            // First swap protocol data
            "c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2", // token in
            "bb2b8038a1640196fbe3e38816f3e67cba72d940", // component id
            "3ede3eca2a72b3aecc820e955b36f38437d01395", // receiver
            "00",                                       // zero2one
            // Second swap protocol data
            "2260fac5e5542a773aa44fbcfedf7c193bc2c599", // token in
            "ae461ca67b15dc8dc81ce7615e0320da1a9ab8d5", // component id
            "3ede3eca2a72b3aecc820e955b36f38437d01395", // receiver
            "01",                                       // zero2one
            "00000000000000",                           // padding
        ));
        let hex_calldata = encode(&calldata);

        assert_eq!(hex_calldata[..520], expected_input);
        assert_eq!(hex_calldata[1288..], expected_swaps);
    }

    #[test]
    fn test_validate_path_single_swap() {
        let validator = SplitSwapValidator;
        let eth = Bytes::from_str("0x0000000000000000000000000000000000000000").unwrap();
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
        let result = validator.validate_swap_path(&swaps, &weth, &dai, &None, &eth, &weth);
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn test_validate_path_multiple_swaps() {
        let validator = SplitSwapValidator;
        let eth = Bytes::from_str("0x0000000000000000000000000000000000000000").unwrap();
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
        let result = validator.validate_swap_path(&swaps, &weth, &usdc, &None, &eth, &weth);
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn test_validate_path_disconnected() {
        let validator = SplitSwapValidator;
        let eth = Bytes::from_str("0x0000000000000000000000000000000000000000").unwrap();
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
        let result =
            validator.validate_swap_path(&disconnected_swaps, &weth, &usdc, &None, &eth, &weth);
        assert!(matches!(
            result,
            Err(EncodingError::InvalidInput(msg)) if msg.contains("not reachable through swap path")
        ));
    }

    #[test]
    fn test_validate_path_unreachable_checked_token() {
        let validator = SplitSwapValidator;
        let eth = Bytes::from_str("0x0000000000000000000000000000000000000000").unwrap();
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
        let result =
            validator.validate_swap_path(&unreachable_swaps, &weth, &usdc, &None, &eth, &weth);
        assert!(matches!(
            result,
            Err(EncodingError::InvalidInput(msg)) if msg.contains("not reachable through swap path")
        ));
    }

    #[test]
    fn test_validate_path_empty_swaps() {
        let validator = SplitSwapValidator;
        let eth = Bytes::from_str("0x0000000000000000000000000000000000000000").unwrap();
        let weth = Bytes::from_str("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2").unwrap();
        let usdc = Bytes::from_str("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48").unwrap();

        let empty_swaps: Vec<Swap> = vec![];
        let result = validator.validate_swap_path(&empty_swaps, &weth, &usdc, &None, &eth, &weth);
        assert!(matches!(
            result,
            Err(EncodingError::InvalidInput(msg)) if msg.contains("not reachable through swap path")
        ));
    }

    #[test]
    fn test_validate_swap_single() {
        let validator = SplitSwapValidator;
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
        let result = validator.validate_split_percentages(&swaps);
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn test_validate_swaps_multiple() {
        let validator = SplitSwapValidator;
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
        assert!(validator
            .validate_split_percentages(&valid_swaps)
            .is_ok());
    }

    #[test]
    fn test_validate_swaps_no_remainder_split() {
        let validator = SplitSwapValidator;
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
        assert!(matches!(
            validator.validate_split_percentages(&invalid_total_swaps),
            Err(EncodingError::InvalidInput(msg)) if msg.contains("must have exactly one 0% split")
        ));
    }

    #[test]
    fn test_validate_swaps_zero_split_not_at_end() {
        let validator = SplitSwapValidator;
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
        assert!(matches!(
            validator.validate_split_percentages(&invalid_zero_position_swaps),
            Err(EncodingError::InvalidInput(msg)) if msg.contains("must be the last swap")
        ));
    }

    #[test]
    fn test_validate_swaps_splits_exceed_hundred_percent() {
        let validator = SplitSwapValidator;
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
        assert!(matches!(
            validator.validate_split_percentages(&invalid_overflow_swaps),
            Err(EncodingError::InvalidInput(msg)) if msg.contains("must be <100%")
        ));
    }

    #[test]
    fn test_validate_path_wrap_eth_given_token() {
        let validator = SplitSwapValidator;
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

        let result = validator.validate_swap_path(
            &swaps,
            &eth,
            &usdc,
            &Some(NativeAction::Wrap),
            &eth,
            &weth,
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn test_validate_token_path_connectivity_wrap_eth_checked_token() {
        let validator = SplitSwapValidator;
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

        let result = validator.validate_swap_path(
            &swaps,
            &usdc,
            &eth,
            &Some(NativeAction::Unwrap),
            &eth,
            &weth,
        );
        assert_eq!(result, Ok(()));
    }
}
