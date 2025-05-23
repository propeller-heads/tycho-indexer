use std::{collections::HashSet, str::FromStr};

use alloy_primitives::{aliases::U24, U8};
use tycho_common::Bytes;

use crate::encoding::{
    errors::EncodingError,
    evm::{
        group_swaps::group_swaps,
        strategy_encoder::{
            strategy_validators::{SequentialSwapValidator, SplitSwapValidator, SwapValidator},
            transfer_optimizations::TransferOptimization,
        },
        swap_encoder::swap_encoder_registry::SwapEncoderRegistry,
        utils::{get_token_position, percentage_to_uint24, ple_encode},
    },
    models::{Chain, EncodedSolution, EncodingContext, NativeAction, Solution},
    strategy_encoder::StrategyEncoder,
    swap_encoder::SwapEncoder,
};

/// Represents the encoder for a swap strategy which supports single swaps.
///
/// # Fields
/// * `swap_encoder_registry`: SwapEncoderRegistry, containing all possible swap encoders
/// * `selector`: String, the selector for the swap function in the router contract
/// * `router_address`: Address of the router to be used to execute swaps
/// * `transfer_optimization`: TransferOptimization, responsible for optimizing the token transfers
#[derive(Clone)]
pub struct SingleSwapStrategyEncoder {
    swap_encoder_registry: SwapEncoderRegistry,
    selector: String,
    router_address: Bytes,
    transfer_optimization: TransferOptimization,
}

impl SingleSwapStrategyEncoder {
    pub fn new(
        chain: Chain,
        swap_encoder_registry: SwapEncoderRegistry,
        permit_2_active: bool,
        router_address: Bytes,
        token_in_already_in_router: bool,
    ) -> Result<Self, EncodingError> {
        let selector = if permit_2_active {
            "singleSwapPermit2(uint256,address,address,uint256,bool,bool,address,((address,uint160,uint48,uint48),address,uint256),bytes,bytes)"
        } else {
            "singleSwap(uint256,address,address,uint256,bool,bool,address,bool,bytes)"
        }.to_string();

        Ok(Self {
            selector,
            swap_encoder_registry,
            router_address: router_address.clone(),
            transfer_optimization: TransferOptimization::new(
                chain.native_token()?,
                chain.wrapped_token()?,
                token_in_already_in_router,
                router_address,
            ),
        })
    }

    /// Encodes information necessary for performing a single hop against a given executor for
    /// a protocol.
    fn encode_swap_header(&self, executor_address: Bytes, protocol_data: Vec<u8>) -> Vec<u8> {
        let mut encoded = Vec::new();
        encoded.extend(executor_address.to_vec());
        encoded.extend(protocol_data);
        encoded
    }
}

impl StrategyEncoder for SingleSwapStrategyEncoder {
    fn encode_strategy(&self, solution: Solution) -> Result<EncodedSolution, EncodingError> {
        let grouped_swaps = group_swaps(solution.clone().swaps);
        let number_of_groups = grouped_swaps.len();
        if number_of_groups != 1 {
            return Err(EncodingError::InvalidInput(format!(
                "Executor strategy only supports exactly one swap for non-groupable protocols. Found {number_of_groups}",
            )))
        }

        let grouped_swap = grouped_swaps
            .first()
            .ok_or_else(|| EncodingError::FatalError("Swap grouping failed".to_string()))?;

        if grouped_swap.split != 0f64 {
            return Err(EncodingError::InvalidInput(
                "Splits not supported for single swaps.".to_string(),
            ))
        }

        let (mut unwrap, mut wrap) = (false, false);
        if let Some(action) = solution.native_action.clone() {
            match action {
                NativeAction::Wrap => wrap = true,
                NativeAction::Unwrap => unwrap = true,
            }
        }
        let protocol = grouped_swap.protocol_system.clone();
        let swap_encoder = self
            .get_swap_encoder(&protocol)
            .ok_or_else(|| {
                EncodingError::InvalidInput(format!(
                    "Swap encoder not found for protocol: {protocol}"
                ))
            })?;

        let swap_receiver =
            if !unwrap { solution.receiver.clone() } else { self.router_address.clone() };

        let transfer = self
            .transfer_optimization
            .get_transfers(grouped_swap.clone(), solution.given_token.clone(), wrap, false);
        let encoding_context = EncodingContext {
            receiver: swap_receiver.clone(),
            exact_out: solution.exact_out,
            router_address: Some(self.router_address.clone()),
            group_token_in: grouped_swap.token_in.clone(),
            group_token_out: grouped_swap.token_out.clone(),
            transfer_type: transfer,
        };

        let mut grouped_protocol_data: Vec<u8> = vec![];
        for swap in grouped_swap.swaps.iter() {
            let protocol_data = swap_encoder.encode_swap(swap.clone(), encoding_context.clone())?;
            grouped_protocol_data.extend(protocol_data);
        }

        let swap_data = self.encode_swap_header(
            Bytes::from_str(swap_encoder.executor_address())
                .map_err(|_| EncodingError::FatalError("Invalid executor address".to_string()))?,
            grouped_protocol_data,
        );
        Ok(EncodedSolution {
            selector: self.selector.clone(),
            interacting_with: self.router_address.clone(),
            swaps: swap_data,
            permit: None,
            signature: None,
            n_tokens: 0,
        })
    }

    fn get_swap_encoder(&self, protocol_system: &str) -> Option<&Box<dyn SwapEncoder>> {
        self.swap_encoder_registry
            .get_encoder(protocol_system)
    }

    fn clone_box(&self) -> Box<dyn StrategyEncoder> {
        Box::new(self.clone())
    }
}

/// Represents the encoder for a swap strategy which supports sequential swaps.
///
/// # Fields
/// * `swap_encoder_registry`: SwapEncoderRegistry, containing all possible swap encoders
/// * `selector`: String, the selector for the swap function in the router contract
/// * `native_address`: Address of the chain's native token
/// * `wrapped_address`: Address of the chain's wrapped token
/// * `router_address`: Address of the router to be used to execute swaps
/// * `sequential_swap_validator`: SequentialSwapValidator, responsible for checking validity of
///   sequential swap solutions
/// * `transfer_optimization`: TransferOptimization, responsible for optimizing the token transfers
#[derive(Clone)]
pub struct SequentialSwapStrategyEncoder {
    swap_encoder_registry: SwapEncoderRegistry,
    selector: String,
    router_address: Bytes,
    native_address: Bytes,
    wrapped_address: Bytes,
    sequential_swap_validator: SequentialSwapValidator,
    transfer_optimization: TransferOptimization,
}

impl SequentialSwapStrategyEncoder {
    pub fn new(
        chain: Chain,
        swap_encoder_registry: SwapEncoderRegistry,
        permit_2_active: bool,
        router_address: Bytes,
        token_in_already_in_router: bool,
    ) -> Result<Self, EncodingError> {
        let selector = if permit_2_active {
            "sequentialSwapPermit2(uint256,address,address,uint256,bool,bool,address,((address,uint160,uint48,uint48),address,uint256),bytes,bytes)"
        } else {
            "sequentialSwap(uint256,address,address,uint256,bool,bool,address,bool,bytes)"

        }.to_string();
        Ok(Self {
            selector,
            swap_encoder_registry,
            router_address: router_address.clone(),
            native_address: chain.native_token()?,
            wrapped_address: chain.wrapped_token()?,
            sequential_swap_validator: SequentialSwapValidator,
            transfer_optimization: TransferOptimization::new(
                chain.native_token()?,
                chain.wrapped_token()?,
                token_in_already_in_router,
                router_address,
            ),
        })
    }

    /// Encodes information necessary for performing a single hop against a given executor for
    /// a protocol.
    fn encode_swap_header(&self, executor_address: Bytes, protocol_data: Vec<u8>) -> Vec<u8> {
        let mut encoded = Vec::new();
        encoded.extend(executor_address.to_vec());
        encoded.extend(protocol_data);
        encoded
    }
}

impl StrategyEncoder for SequentialSwapStrategyEncoder {
    fn encode_strategy(&self, solution: Solution) -> Result<EncodedSolution, EncodingError> {
        self.sequential_swap_validator
            .validate_swap_path(
                &solution.swaps,
                &solution.given_token,
                &solution.checked_token,
                &solution.native_action,
                &self.native_address,
                &self.wrapped_address,
            )?;

        let grouped_swaps = group_swaps(solution.swaps);

        let mut wrap = false;
        if let Some(action) = solution.native_action.clone() {
            if action == NativeAction::Wrap {
                wrap = true
            }
        }

        let mut swaps = vec![];
        let mut next_in_between_swap_optimization_allowed = true;
        for (i, grouped_swap) in grouped_swaps.iter().enumerate() {
            let protocol = grouped_swap.protocol_system.clone();
            let swap_encoder = self
                .get_swap_encoder(&protocol)
                .ok_or_else(|| {
                    EncodingError::InvalidInput(format!(
                        "Swap encoder not found for protocol: {protocol}",
                    ))
                })?;

            let in_between_swap_optimization_allowed = next_in_between_swap_optimization_allowed;
            let next_swap = grouped_swaps.get(i + 1);
            let (swap_receiver, next_swap_optimization) = self
                .transfer_optimization
                .get_receiver(solution.receiver.clone(), next_swap)?;
            next_in_between_swap_optimization_allowed = next_swap_optimization;

            let transfer = self
                .transfer_optimization
                .get_transfers(
                    grouped_swap.clone(),
                    solution.given_token.clone(),
                    wrap,
                    in_between_swap_optimization_allowed,
                );
            let encoding_context = EncodingContext {
                receiver: swap_receiver.clone(),
                exact_out: solution.exact_out,
                router_address: Some(self.router_address.clone()),
                group_token_in: grouped_swap.token_in.clone(),
                group_token_out: grouped_swap.token_out.clone(),
                transfer_type: transfer,
            };

            let mut grouped_protocol_data: Vec<u8> = vec![];
            for swap in grouped_swap.swaps.iter() {
                let protocol_data =
                    swap_encoder.encode_swap(swap.clone(), encoding_context.clone())?;
                grouped_protocol_data.extend(protocol_data);
            }

            let swap_data = self.encode_swap_header(
                Bytes::from_str(swap_encoder.executor_address()).map_err(|_| {
                    EncodingError::FatalError("Invalid executor address".to_string())
                })?,
                grouped_protocol_data,
            );
            swaps.push(swap_data);
        }

        let encoded_swaps = ple_encode(swaps);
        Ok(EncodedSolution {
            interacting_with: self.router_address.clone(),
            selector: self.selector.clone(),
            swaps: encoded_swaps,
            permit: None,
            signature: None,
            n_tokens: 0,
        })
    }

    fn get_swap_encoder(&self, protocol_system: &str) -> Option<&Box<dyn SwapEncoder>> {
        self.swap_encoder_registry
            .get_encoder(protocol_system)
    }

    fn clone_box(&self) -> Box<dyn StrategyEncoder> {
        Box::new(self.clone())
    }
}

/// Represents the encoder for a swap strategy which supports split swaps.
///
/// # Fields
/// * `swap_encoder_registry`: SwapEncoderRegistry, containing all possible swap encoders
/// * `selector`: String, the selector for the swap function in the router contract
/// * `native_address`: Address of the chain's native token
/// * `wrapped_address`: Address of the chain's wrapped token
/// * `split_swap_validator`: SplitSwapValidator, responsible for checking validity of split swap
///   solutions
/// * `router_address`: Address of the router to be used to execute swaps
/// * `transfer_optimization`: TransferOptimization, responsible for optimizing the token transfers
#[derive(Clone)]
pub struct SplitSwapStrategyEncoder {
    swap_encoder_registry: SwapEncoderRegistry,
    selector: String,
    native_address: Bytes,
    wrapped_address: Bytes,
    split_swap_validator: SplitSwapValidator,
    router_address: Bytes,
    transfer_optimization: TransferOptimization,
}

impl SplitSwapStrategyEncoder {
    pub fn new(
        chain: Chain,
        swap_encoder_registry: SwapEncoderRegistry,
        permit_2_active: bool,
        router_address: Bytes,
        token_in_already_in_router: bool,
    ) -> Result<Self, EncodingError> {
        let selector = if permit_2_active{
           "splitSwapPermit2(uint256,address,address,uint256,bool,bool,uint256,address,((address,uint160,uint48,uint48),address,uint256),bytes,bytes)"
        } else {
                "splitSwap(uint256,address,address,uint256,bool,bool,uint256,address,bool,bytes)"
        }.to_string();
        Ok(Self {
            selector,
            swap_encoder_registry,
            native_address: chain.native_token()?,
            wrapped_address: chain.wrapped_token()?,
            split_swap_validator: SplitSwapValidator,
            router_address: router_address.clone(),
            transfer_optimization: TransferOptimization::new(
                chain.native_token()?,
                chain.wrapped_token()?,
                token_in_already_in_router,
                router_address,
            ),
        })
    }

    /// Encodes information necessary for performing a single hop against a given executor for
    /// a protocol as part of a split swap solution.
    fn encode_swap_header(
        &self,
        token_in: U8,
        token_out: U8,
        split: U24,
        executor_address: Bytes,
        protocol_data: Vec<u8>,
    ) -> Vec<u8> {
        let mut encoded = Vec::new();
        encoded.push(token_in.to_be_bytes_vec()[0]);
        encoded.push(token_out.to_be_bytes_vec()[0]);
        encoded.extend_from_slice(&split.to_be_bytes_vec());
        encoded.extend(executor_address.to_vec());
        encoded.extend(protocol_data);
        encoded
    }
}

impl StrategyEncoder for SplitSwapStrategyEncoder {
    fn encode_strategy(&self, solution: Solution) -> Result<EncodedSolution, EncodingError> {
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

        // The tokens array is composed of the given token, the checked token and all the
        // intermediary tokens in between. The contract expects the tokens to be in this order.
        let solution_tokens: HashSet<Bytes> =
            vec![solution.given_token.clone(), solution.checked_token.clone()]
                .into_iter()
                .collect();

        let grouped_swaps = group_swaps(solution.swaps);

        let intermediary_tokens: HashSet<Bytes> = grouped_swaps
            .iter()
            .flat_map(|grouped_swap| {
                vec![grouped_swap.token_in.clone(), grouped_swap.token_out.clone()]
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
            let protocol = grouped_swap.protocol_system.clone();
            let swap_encoder = self
                .get_swap_encoder(&protocol)
                .ok_or_else(|| {
                    EncodingError::InvalidInput(format!(
                        "Swap encoder not found for protocol: {protocol}",
                    ))
                })?;

            let swap_receiver = if !unwrap && grouped_swap.token_out == solution.checked_token {
                solution.receiver.clone()
            } else {
                self.router_address.clone()
            };
            let transfer = self
                .transfer_optimization
                .get_transfers(grouped_swap.clone(), solution.given_token.clone(), wrap, false);
            let encoding_context = EncodingContext {
                receiver: swap_receiver.clone(),
                exact_out: solution.exact_out,
                router_address: Some(self.router_address.clone()),
                group_token_in: grouped_swap.token_in.clone(),
                group_token_out: grouped_swap.token_out.clone(),
                transfer_type: transfer,
            };

            let mut grouped_protocol_data: Vec<u8> = vec![];
            for swap in grouped_swap.swaps.iter() {
                let protocol_data =
                    swap_encoder.encode_swap(swap.clone(), encoding_context.clone())?;
                grouped_protocol_data.extend(protocol_data);
            }

            let swap_data = self.encode_swap_header(
                get_token_position(tokens.clone(), grouped_swap.token_in.clone())?,
                get_token_position(tokens.clone(), grouped_swap.token_out.clone())?,
                percentage_to_uint24(grouped_swap.split),
                Bytes::from_str(swap_encoder.executor_address()).map_err(|_| {
                    EncodingError::FatalError("Invalid executor address".to_string())
                })?,
                grouped_protocol_data,
            );
            swaps.push(swap_data);
        }

        let encoded_swaps = ple_encode(swaps);
        let tokens_len = if solution.given_token == solution.checked_token {
            tokens.len() - 1
        } else {
            tokens.len()
        };
        Ok(EncodedSolution {
            interacting_with: self.router_address.clone(),
            selector: self.selector.clone(),
            swaps: encoded_swaps,
            permit: None,
            signature: None,
            n_tokens: tokens_len,
        })
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
    use std::{collections::HashMap, str::FromStr};

    use alloy::hex::encode;
    use alloy_primitives::{hex, Address, PrimitiveSignature as Signature, U256};
    use num_bigint::{BigInt, BigUint};
    use tycho_common::{
        models::{protocol::ProtocolComponent, Chain as TychoCommonChain},
        Bytes,
    };

    use super::*;
    use crate::encoding::{
        evm::{
            approvals::permit2::Permit2, encoding_utils::encode_tycho_router_call,
            utils::write_calldata_to_file,
        },
        models::{PermitSingle, Swap},
    };

    fn eth_chain() -> Chain {
        TychoCommonChain::Ethereum.into()
    }

    fn eth() -> Bytes {
        Bytes::from(hex!("0000000000000000000000000000000000000000").to_vec())
    }

    fn weth() -> Bytes {
        Bytes::from(hex!("c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2").to_vec())
    }

    fn get_swap_encoder_registry() -> SwapEncoderRegistry {
        let eth_chain = eth_chain();
        SwapEncoderRegistry::new(Some("config/test_executor_addresses.json".to_string()), eth_chain)
            .unwrap()
    }

    fn router_address() -> Bytes {
        Bytes::from_str("0x3Ede3eCa2a72B3aeCC820E955B36f38437D01395").unwrap()
    }

    fn get_permit(
        chain: Chain,
        router_address: Bytes,
        solution: &Solution,
    ) -> (PermitSingle, Signature) {
        // Set up a mock private key for signing (Alice's pk in our contract tests)
        let private_key =
            "0x123456789abcdef123456789abcdef123456789abcdef123456789abcdef1234".to_string();

        let permit2 = Permit2::new(private_key, chain.clone()).unwrap();
        permit2
            .get_permit(
                &router_address,
                &solution.sender,
                &solution.given_token,
                &solution.given_amount,
            )
            .unwrap()
    }

    mod single {
        use alloy_sol_types::SolValue;

        use super::*;
        use crate::encoding::evm::utils::biguint_to_u256;
        #[test]
        fn test_single_swap_strategy_encoder() {
            // Performs a single swap from WETH to DAI on a USV2 pool, with no grouping
            // optimizations.
            let checked_amount = BigUint::from_str("2018817438608734439720").unwrap();
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
            let encoder = SingleSwapStrategyEncoder::new(
                eth_chain(),
                swap_encoder_registry,
                true,
                router_address(),
                false,
            )
            .unwrap();
            let solution = Solution {
                exact_out: false,
                given_token: weth,
                given_amount: BigUint::from_str("1_000000000000000000").unwrap(),
                checked_token: dai,
                checked_amount: checked_amount.clone(),
                sender: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
                receiver: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
                swaps: vec![swap],
                ..Default::default()
            };

            let mut encoded_solution = encoder
                .encode_strategy(solution.clone())
                .unwrap();
            let (permit, signature) = get_permit(eth_chain(), router_address(), &solution);
            encoded_solution.permit = Some(permit);
            encoded_solution.signature = Some(signature.as_bytes().to_vec());

            let calldata = encode_tycho_router_call(encoded_solution, &solution, false, eth())
                .unwrap()
                .data;
            let expected_min_amount_encoded =
                hex::encode(U256::abi_encode(&biguint_to_u256(&checked_amount)));
            let expected_input = [
                "30ace1b1",                                                             // Function selector
                "0000000000000000000000000000000000000000000000000de0b6b3a7640000",      // amount in
                "000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",      // token in
                "0000000000000000000000006b175474e89094c44da98b954eedeac495271d0f",      // token out
                &expected_min_amount_encoded,                                            // min amount out
                "0000000000000000000000000000000000000000000000000000000000000000",      // wrap
                "0000000000000000000000000000000000000000000000000000000000000000",      // unwrap
                "000000000000000000000000cd09f75e2bf2a4d11f3ab23f1389fcc1621c0cc2",      // receiver
            ]
                .join("");

            // after this there is the permit and because of the deadlines (that depend on block
            // time) it's hard to assert

            let expected_swap = String::from(concat!(
                // length of encoded swap without padding
                "0000000000000000000000000000000000000000000000000000000000000052",
                // Swap data
                "5615deb798bb3e4dfa0139dfa1b3d433cc23b72f", // executor address
                "c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2", // token in
                "a478c2975ab1ea89e8196811f51a7b7ade33eb11", // component id
                "cd09f75e2bf2a4d11f3ab23f1389fcc1621c0cc2", // receiver
                "00",                                       // zero2one
                "00",                                       // transfer type TransferFrom
                "0000000000000000000000000000",             // padding
            ));
            let hex_calldata = encode(&calldata);

            assert_eq!(hex_calldata[..456], expected_input);
            assert_eq!(hex_calldata[1224..], expected_swap);
            write_calldata_to_file("test_single_swap_strategy_encoder", &hex_calldata.to_string());
        }

        #[test]
        fn test_single_swap_strategy_encoder_no_permit2() {
            // Performs a single swap from WETH to DAI on a USV2 pool, without permit2 and no
            // grouping optimizations.

            let weth = Bytes::from_str("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2").unwrap();
            let dai = Bytes::from_str("0x6b175474e89094c44da98b954eedeac495271d0f").unwrap();

            let checked_amount = BigUint::from_str("1_640_000000000000000000").unwrap();
            let expected_min_amount = U256::from_str("1_640_000000000000000000").unwrap();

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
            let encoder = SingleSwapStrategyEncoder::new(
                eth_chain(),
                swap_encoder_registry,
                false,
                router_address(),
                false,
            )
            .unwrap();
            let solution = Solution {
                exact_out: false,
                given_token: weth,
                given_amount: BigUint::from_str("1_000000000000000000").unwrap(),
                checked_token: dai,
                checked_amount,
                sender: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
                receiver: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
                swaps: vec![swap],
                ..Default::default()
            };

            let encoded_solution = encoder
                .encode_strategy(solution.clone())
                .unwrap();
            let calldata = encode_tycho_router_call(encoded_solution, &solution, false, eth())
                .unwrap()
                .data;
            let expected_min_amount_encoded = hex::encode(U256::abi_encode(&expected_min_amount));
            let expected_input = [
                "5c4b639c",                                                           // Function selector
                "0000000000000000000000000000000000000000000000000de0b6b3a7640000",   // amount in
                "000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",   // token in
                "0000000000000000000000006b175474e89094c44da98b954eedeac495271d0f",   // token out
                &expected_min_amount_encoded,                                         // min amount out
                "0000000000000000000000000000000000000000000000000000000000000000",   // wrap
                "0000000000000000000000000000000000000000000000000000000000000000",   // unwrap
                "000000000000000000000000cd09f75e2bf2a4d11f3ab23f1389fcc1621c0cc2",   // receiver
                "0000000000000000000000000000000000000000000000000000000000000001",   // transfer from needed
                "0000000000000000000000000000000000000000000000000000000000000120",   // offset of swap bytes
                "0000000000000000000000000000000000000000000000000000000000000052",   // length of swap bytes without padding

                // Swap data
                "5615deb798bb3e4dfa0139dfa1b3d433cc23b72f", // executor address
                "c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2", // token in
                "a478c2975ab1ea89e8196811f51a7b7ade33eb11", // component id
                "cd09f75e2bf2a4d11f3ab23f1389fcc1621c0cc2", // receiver
                "00",                                       // zero2one
                "00",                                       // transfer type TransferFrom
                "0000000000000000000000000000",             // padding
            ]
                .join("");

            let hex_calldata = encode(&calldata);

            assert_eq!(hex_calldata, expected_input);
            write_calldata_to_file(
                "test_single_swap_strategy_encoder_no_permit2",
                hex_calldata.as_str(),
            );
        }

        #[test]
        fn test_single_swap_strategy_encoder_no_transfer_in() {
            // Performs a single swap from WETH to DAI on a USV2 pool assuming that the tokens are
            // already in the router

            let weth = Bytes::from_str("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2").unwrap();
            let dai = Bytes::from_str("0x6b175474e89094c44da98b954eedeac495271d0f").unwrap();

            let checked_amount = BigUint::from_str("1_640_000000000000000000").unwrap();
            let expected_min_amount = U256::from_str("1_640_000000000000000000").unwrap();

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
            let encoder = SingleSwapStrategyEncoder::new(
                eth_chain(),
                swap_encoder_registry,
                false,
                router_address(),
                true,
            )
            .unwrap();
            let solution = Solution {
                exact_out: false,
                given_token: weth,
                given_amount: BigUint::from_str("1_000000000000000000").unwrap(),
                checked_token: dai,
                checked_amount,
                sender: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
                receiver: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
                swaps: vec![swap],
                ..Default::default()
            };

            let encoded_solution = encoder
                .encode_strategy(solution.clone())
                .unwrap();
            let calldata = encode_tycho_router_call(encoded_solution, &solution, true, eth())
                .unwrap()
                .data;
            let expected_min_amount_encoded = hex::encode(U256::abi_encode(&expected_min_amount));
            let expected_input = [
                "5c4b639c",                                                           // Function selector
                "0000000000000000000000000000000000000000000000000de0b6b3a7640000",   // amount in
                "000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",   // token in
                "0000000000000000000000006b175474e89094c44da98b954eedeac495271d0f",   // token out
                &expected_min_amount_encoded,                                         // min amount out
                "0000000000000000000000000000000000000000000000000000000000000000",   // wrap
                "0000000000000000000000000000000000000000000000000000000000000000",   // unwrap
                "000000000000000000000000cd09f75e2bf2a4d11f3ab23f1389fcc1621c0cc2",   // receiver
                "0000000000000000000000000000000000000000000000000000000000000000",   // transfer from not needed
                "0000000000000000000000000000000000000000000000000000000000000120",   // offset of swap bytes
                "0000000000000000000000000000000000000000000000000000000000000052",   // length of swap bytes without padding

                // Swap data
                "5615deb798bb3e4dfa0139dfa1b3d433cc23b72f", // executor address
                "c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2", // token in
                "a478c2975ab1ea89e8196811f51a7b7ade33eb11", // component id
                "cd09f75e2bf2a4d11f3ab23f1389fcc1621c0cc2", // receiver
                "00",                                       // zero2one
                "01",                                       // transfer type Transfer
                "0000000000000000000000000000",             // padding
            ]
                .join("");

            let hex_calldata = encode(&calldata);

            assert_eq!(hex_calldata, expected_input);
            write_calldata_to_file(
                "test_single_swap_strategy_encoder_no_transfer_in",
                hex_calldata.as_str(),
            );
        }

        #[test]
        fn test_single_swap_strategy_encoder_wrap() {
            // Performs a single swap from WETH to DAI on a USV2 pool, wrapping ETH
            // Note: This test does not assert anything. It is only used to obtain integration test
            // data for our router solidity test.

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
            let encoder = SingleSwapStrategyEncoder::new(
                eth_chain(),
                swap_encoder_registry,
                true,
                router_address(),
                false,
            )
            .unwrap();
            let solution = Solution {
                exact_out: false,
                given_token: eth(),
                given_amount: BigUint::from_str("1_000000000000000000").unwrap(),
                checked_token: dai,
                checked_amount: BigUint::from_str("1659881924818443699787").unwrap(),
                sender: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
                receiver: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
                swaps: vec![swap],
                native_action: Some(NativeAction::Wrap),
            };

            let mut encoded_solution = encoder
                .encode_strategy(solution.clone())
                .unwrap();

            let (permit, signature) = get_permit(eth_chain(), router_address(), &solution);
            encoded_solution.permit = Some(permit);
            encoded_solution.signature = Some(signature.as_bytes().to_vec());

            let calldata = encode_tycho_router_call(encoded_solution, &solution, false, eth())
                .unwrap()
                .data;
            let hex_calldata = encode(&calldata);
            write_calldata_to_file("test_single_swap_strategy_encoder_wrap", hex_calldata.as_str());
        }

        #[test]
        fn test_single_swap_strategy_encoder_unwrap() {
            // Performs a single swap from DAI to WETH on a USV2 pool, unwrapping ETH at the end
            // Note: This test does not assert anything. It is only used to obtain integration test
            // data for our router solidity test.

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
            let encoder = SingleSwapStrategyEncoder::new(
                eth_chain(),
                swap_encoder_registry,
                true,
                Bytes::from("0x3Ede3eCa2a72B3aeCC820E955B36f38437D01395"),
                false,
            )
            .unwrap();
            let solution = Solution {
                exact_out: false,
                given_token: dai,
                given_amount: BigUint::from_str("3_000_000000000000000000").unwrap(),
                checked_token: eth(),
                checked_amount: BigUint::from_str("1_000000000000000000").unwrap(),
                sender: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
                receiver: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
                swaps: vec![swap],
                native_action: Some(NativeAction::Unwrap),
            };

            let mut encoded_solution = encoder
                .encode_strategy(solution.clone())
                .unwrap();

            let (permit, signature) = get_permit(eth_chain(), router_address(), &solution);
            encoded_solution.permit = Some(permit);
            encoded_solution.signature = Some(signature.as_bytes().to_vec());

            let calldata = encode_tycho_router_call(encoded_solution, &solution, false, eth())
                .unwrap()
                .data;

            let hex_calldata = encode(&calldata);
            write_calldata_to_file(
                "test_single_swap_strategy_encoder_unwrap",
                hex_calldata.as_str(),
            );
        }
    }

    mod sequential {
        use super::*;

        #[test]
        fn test_sequential_swap_strategy_encoder() {
            // Note: This test does not assert anything. It is only used to obtain integration test
            // data for our router solidity test.
            //
            // Performs a sequential swap from WETH to USDC though WBTC using USV2 pools
            //
            //   WETH ───(USV2)──> WBTC ───(USV2)──> USDC

            let weth = weth();
            let wbtc = Bytes::from_str("0x2260fac5e5542a773aa44fbcfedf7c193bc2c599").unwrap();
            let usdc = Bytes::from_str("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48").unwrap();

            let swap_weth_wbtc = Swap {
                component: ProtocolComponent {
                    id: "0xBb2b8038a1640196FbE3e38816F3e67Cba72D940".to_string(),
                    protocol_system: "uniswap_v2".to_string(),
                    ..Default::default()
                },
                token_in: weth.clone(),
                token_out: wbtc.clone(),
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
            let encoder = SequentialSwapStrategyEncoder::new(
                eth_chain(),
                swap_encoder_registry,
                true,
                router_address(),
                false,
            )
            .unwrap();
            let solution = Solution {
                exact_out: false,
                given_token: weth,
                given_amount: BigUint::from_str("1_000000000000000000").unwrap(),
                checked_token: usdc,
                checked_amount: BigUint::from_str("26173932").unwrap(),
                sender: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
                receiver: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
                swaps: vec![swap_weth_wbtc, swap_wbtc_usdc],
                ..Default::default()
            };

            let mut encoded_solution = encoder
                .encode_strategy(solution.clone())
                .unwrap();
            let (permit, signature) = get_permit(eth_chain(), router_address(), &solution);
            encoded_solution.permit = Some(permit);
            encoded_solution.signature = Some(signature.as_bytes().to_vec());

            let calldata = encode_tycho_router_call(encoded_solution, &solution, false, eth())
                .unwrap()
                .data;

            let hex_calldata = encode(&calldata);
            write_calldata_to_file("test_sequential_swap_strategy_encoder", hex_calldata.as_str());
        }

        #[test]
        fn test_sequential_swap_strategy_encoder_no_permit2() {
            // Performs a sequential swap from WETH to USDC though WBTC using USV2 pools
            //
            //   WETH ───(USV2)──> WBTC ───(USV2)──> USDC

            let weth = weth();
            let wbtc = Bytes::from_str("0x2260fac5e5542a773aa44fbcfedf7c193bc2c599").unwrap();
            let usdc = Bytes::from_str("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48").unwrap();

            let swap_weth_wbtc = Swap {
                component: ProtocolComponent {
                    id: "0xBb2b8038a1640196FbE3e38816F3e67Cba72D940".to_string(),
                    protocol_system: "uniswap_v2".to_string(),
                    ..Default::default()
                },
                token_in: weth.clone(),
                token_out: wbtc.clone(),
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
            let encoder = SequentialSwapStrategyEncoder::new(
                eth_chain(),
                swap_encoder_registry,
                false,
                router_address(),
                false,
            )
            .unwrap();
            let solution = Solution {
                exact_out: false,
                given_token: weth,
                given_amount: BigUint::from_str("1_000000000000000000").unwrap(),
                checked_token: usdc,
                checked_amount: BigUint::from_str("26173932").unwrap(),
                sender: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
                receiver: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
                swaps: vec![swap_weth_wbtc, swap_wbtc_usdc],
                ..Default::default()
            };

            let encoded_solution = encoder
                .encode_strategy(solution.clone())
                .unwrap();

            let calldata = encode_tycho_router_call(encoded_solution, &solution, false, eth())
                .unwrap()
                .data;

            let hex_calldata = encode(&calldata);

            let expected = String::from(concat!(
                "e21dd0d3",                                                         /* function selector */
                "0000000000000000000000000000000000000000000000000de0b6b3a7640000", // amount in
                "000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2", // token in
                "000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", // token ou
                "00000000000000000000000000000000000000000000000000000000018f61ec", /* min amount out */
                "0000000000000000000000000000000000000000000000000000000000000000", // wrap
                "0000000000000000000000000000000000000000000000000000000000000000", // unwrap
                "000000000000000000000000cd09f75e2bf2a4d11f3ab23f1389fcc1621c0cc2", // receiver
                "0000000000000000000000000000000000000000000000000000000000000001", /* transfer from needed */
                "0000000000000000000000000000000000000000000000000000000000000120", /* length ple
                                                                                     * encode */
                "00000000000000000000000000000000000000000000000000000000000000a8",
                // swap 1
                "0052",                                     // swap length
                "5615deb798bb3e4dfa0139dfa1b3d433cc23b72f", // executor address
                "c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2", // token in
                "bb2b8038a1640196fbe3e38816f3e67cba72d940", // component id
                "004375dff511095cc5a197a54140a24efef3a416", // receiver (next pool)
                "00",                                       // zero to one
                "00",                                       // transfer type TransferFrom
                // swap 2
                "0052",                                             // swap length
                "5615deb798bb3e4dfa0139dfa1b3d433cc23b72f",         // executor address
                "2260fac5e5542a773aa44fbcfedf7c193bc2c599",         // token in
                "004375dff511095cc5a197a54140a24efef3a416",         // component id
                "cd09f75e2bf2a4d11f3ab23f1389fcc1621c0cc2",         // receiver (final user)
                "01",                                               // zero to one
                "02",                                               // transfer type None
                "000000000000000000000000000000000000000000000000", // padding
            ));

            assert_eq!(hex_calldata, expected);
            write_calldata_to_file(
                "test_sequential_swap_strategy_encoder_no_permit2",
                hex_calldata.as_str(),
            );
        }

        #[test]
        fn test_sequential_strategy_cyclic_swap() {
            // This test has start and end tokens that are the same
            // The flow is:
            // USDC -> WETH -> USDC  using two pools

            let weth = Bytes::from_str("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2").unwrap();
            let usdc = Bytes::from_str("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48").unwrap();

            // Create two Uniswap V3 pools for the cyclic swap
            // USDC -> WETH (Pool 1)
            let swap_usdc_weth = Swap {
                component: ProtocolComponent {
                    id: "0x88e6A0c2dDD26FEEb64F039a2c41296FcB3f5640".to_string(), /* USDC-WETH USV3
                                                                                   * Pool 1 */
                    protocol_system: "uniswap_v3".to_string(),
                    static_attributes: {
                        let mut attrs = HashMap::new();
                        attrs.insert(
                            "fee".to_string(),
                            Bytes::from(BigInt::from(500).to_signed_bytes_be()),
                        );
                        attrs
                    },
                    ..Default::default()
                },
                token_in: usdc.clone(),
                token_out: weth.clone(),
                split: 0f64,
            };

            // WETH -> USDC (Pool 2)
            let swap_weth_usdc = Swap {
                component: ProtocolComponent {
                    id: "0x8ad599c3A0ff1De082011EFDDc58f1908eb6e6D8".to_string(), /* USDC-WETH USV3
                                                                                   * Pool 2 */
                    protocol_system: "uniswap_v3".to_string(),
                    static_attributes: {
                        let mut attrs = HashMap::new();
                        attrs.insert(
                            "fee".to_string(),
                            Bytes::from(BigInt::from(3000).to_signed_bytes_be()),
                        );
                        attrs
                    },
                    ..Default::default()
                },
                token_in: weth.clone(),
                token_out: usdc.clone(),
                split: 0f64,
            };

            let swap_encoder_registry = get_swap_encoder_registry();
            let encoder = SequentialSwapStrategyEncoder::new(
                eth_chain(),
                swap_encoder_registry,
                true,
                Bytes::from("0x3Ede3eCa2a72B3aeCC820E955B36f38437D01395"),
                false,
            )
            .unwrap();

            let solution = Solution {
                exact_out: false,
                given_token: usdc.clone(),
                given_amount: BigUint::from_str("100000000").unwrap(), // 100 USDC (6 decimals)
                checked_token: usdc.clone(),
                checked_amount: BigUint::from_str("99389294").unwrap(), /* Expected output
                                                                         * from test */
                swaps: vec![swap_usdc_weth, swap_weth_usdc],
                sender: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
                receiver: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
                ..Default::default()
            };

            let mut encoded_solution = encoder
                .encode_strategy(solution.clone())
                .unwrap();
            let (permit, signature) = get_permit(eth_chain(), router_address(), &solution);
            encoded_solution.permit = Some(permit);
            encoded_solution.signature = Some(signature.as_bytes().to_vec());

            let calldata = encode_tycho_router_call(encoded_solution, &solution, false, eth())
                .unwrap()
                .data;
            let hex_calldata = hex::encode(&calldata);
            let expected_input = [
                "51bcc7b6",                                                         // selector
                "0000000000000000000000000000000000000000000000000000000005f5e100", // given amount
                "000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", // given token
                "000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", // checked token
                "0000000000000000000000000000000000000000000000000000000005ec8f6e", // min amount out
                "0000000000000000000000000000000000000000000000000000000000000000", // wrap action
                "0000000000000000000000000000000000000000000000000000000000000000", // unwrap action
                "000000000000000000000000cd09f75e2bf2a4d11f3ab23f1389fcc1621c0cc2", // receiver
            ]
                .join("");

            let expected_swaps = [
                "00000000000000000000000000000000000000000000000000000000000000d6",  // length of ple encoded swaps without padding
                "0069",  // ple encoded swaps
                "2e234dae75c793f67a35089c9d99245e1c58470b", // executor address
                "a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", // token in
                "c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2", // token out
                "0001f4",                                   // pool fee
                "3ede3eca2a72b3aecc820e955b36f38437d01395", // receiver
                "88e6a0c2ddd26feeb64f039a2c41296fcb3f5640", // component id
                "01",                                       // zero2one
                "00",                                       // transfer type TransferFrom
                "0069",                                     // ple encoded swaps
                "2e234dae75c793f67a35089c9d99245e1c58470b", // executor address
                "c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2", // token in
                "a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", // token out
                "000bb8",                                   // pool fee
                "cd09f75e2bf2a4d11f3ab23f1389fcc1621c0cc2", // receiver
                "8ad599c3a0ff1de082011efddc58f1908eb6e6d8", // component id
                "00",                                       // zero2one
                "01",                                       // transfer type Transfer
                "00000000000000000000",                     // padding
            ]
                .join("");

            assert_eq!(hex_calldata[..456], expected_input);
            assert_eq!(hex_calldata[1224..], expected_swaps);
            write_calldata_to_file("test_sequential_strategy_cyclic_swap", hex_calldata.as_str());
        }

        mod optimized_transfers {
            // In this module we test the ability to chain swaps or not. Different protocols are
            // tested. The encoded data is used for solidity tests as well
            use super::*;

            #[test]
            fn test_uniswap_v3_uniswap_v2() {
                // Note: This test does not assert anything. It is only used to obtain integration
                // test data for our router solidity test.
                //
                // Performs a sequential swap from WETH to USDC though WBTC using USV3 and USV2
                // pools
                //
                //   WETH ───(USV3)──> WBTC ───(USV2)──> USDC

                let weth = weth();
                let wbtc = Bytes::from_str("0x2260fac5e5542a773aa44fbcfedf7c193bc2c599").unwrap();
                let usdc = Bytes::from_str("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48").unwrap();

                let swap_weth_wbtc = Swap {
                    component: ProtocolComponent {
                        id: "0xCBCdF9626bC03E24f779434178A73a0B4bad62eD".to_string(),
                        protocol_system: "uniswap_v3".to_string(),
                        static_attributes: {
                            let mut attrs = HashMap::new();
                            attrs.insert(
                                "fee".to_string(),
                                Bytes::from(BigInt::from(3000).to_signed_bytes_be()),
                            );
                            attrs
                        },
                        ..Default::default()
                    },
                    token_in: weth.clone(),
                    token_out: wbtc.clone(),
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
                let encoder = SequentialSwapStrategyEncoder::new(
                    eth_chain(),
                    swap_encoder_registry,
                    false,
                    router_address(),
                    false,
                )
                .unwrap();
                let solution = Solution {
                    exact_out: false,
                    given_token: weth,
                    given_amount: BigUint::from_str("1_000000000000000000").unwrap(),
                    checked_token: usdc,
                    checked_amount: BigUint::from_str("26173932").unwrap(),
                    sender: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
                    receiver: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2")
                        .unwrap(),
                    swaps: vec![swap_weth_wbtc, swap_wbtc_usdc],
                    ..Default::default()
                };

                let encoded_solution = encoder
                    .encode_strategy(solution.clone())
                    .unwrap();

                let calldata = encode_tycho_router_call(encoded_solution, &solution, false, eth())
                    .unwrap()
                    .data;

                let hex_calldata = encode(&calldata);
                write_calldata_to_file("test_uniswap_v3_uniswap_v2", hex_calldata.as_str());
            }

            #[test]
            fn test_uniswap_v3_uniswap_v3() {
                // Note: This test does not assert anything. It is only used to obtain integration
                // test data for our router solidity test.
                //
                // Performs a sequential swap from WETH to USDC though WBTC using USV3 pools
                // There is no optimization between the two USV3 pools, this is currently not
                // supported.
                //
                //   WETH ───(USV3)──> WBTC ───(USV3)──> USDC

                let weth = weth();
                let wbtc = Bytes::from_str("0x2260fac5e5542a773aa44fbcfedf7c193bc2c599").unwrap();
                let usdc = Bytes::from_str("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48").unwrap();

                let swap_weth_wbtc = Swap {
                    component: ProtocolComponent {
                        id: "0xCBCdF9626bC03E24f779434178A73a0B4bad62eD".to_string(),
                        protocol_system: "uniswap_v3".to_string(),
                        static_attributes: {
                            let mut attrs = HashMap::new();
                            attrs.insert(
                                "fee".to_string(),
                                Bytes::from(BigInt::from(3000).to_signed_bytes_be()),
                            );
                            attrs
                        },
                        ..Default::default()
                    },
                    token_in: weth.clone(),
                    token_out: wbtc.clone(),
                    split: 0f64,
                };
                let swap_wbtc_usdc = Swap {
                    component: ProtocolComponent {
                        id: "0x99ac8cA7087fA4A2A1FB6357269965A2014ABc35".to_string(),
                        protocol_system: "uniswap_v3".to_string(),
                        static_attributes: {
                            let mut attrs = HashMap::new();
                            attrs.insert(
                                "fee".to_string(),
                                Bytes::from(BigInt::from(3000).to_signed_bytes_be()),
                            );
                            attrs
                        },
                        ..Default::default()
                    },
                    token_in: wbtc.clone(),
                    token_out: usdc.clone(),
                    split: 0f64,
                };
                let swap_encoder_registry = get_swap_encoder_registry();
                let encoder = SequentialSwapStrategyEncoder::new(
                    eth_chain(),
                    swap_encoder_registry,
                    false,
                    router_address(),
                    false,
                )
                .unwrap();
                let solution = Solution {
                    exact_out: false,
                    given_token: weth,
                    given_amount: BigUint::from_str("1_000000000000000000").unwrap(),
                    checked_token: usdc,
                    checked_amount: BigUint::from_str("26173932").unwrap(),
                    sender: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
                    receiver: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2")
                        .unwrap(),
                    swaps: vec![swap_weth_wbtc, swap_wbtc_usdc],
                    ..Default::default()
                };

                let encoded_solution = encoder
                    .encode_strategy(solution.clone())
                    .unwrap();

                let calldata = encode_tycho_router_call(encoded_solution, &solution, false, eth())
                    .unwrap()
                    .data;

                let hex_calldata = encode(&calldata);
                write_calldata_to_file("test_uniswap_v3_uniswap_v3", hex_calldata.as_str());
            }

            #[test]
            fn test_uniswap_v3_curve() {
                // Note: This test does not assert anything. It is only used to obtain integration
                // test data for our router solidity test.
                //
                // Performs a sequential swap from WETH to USDT though WBTC using USV3 and curve
                // pools
                //
                //   WETH ───(USV3)──> WBTC ───(curve)──> USDT

                let weth = weth();
                let wbtc = Bytes::from_str("0x2260fac5e5542a773aa44fbcfedf7c193bc2c599").unwrap();
                let usdt = Bytes::from_str("0xdAC17F958D2ee523a2206206994597C13D831ec7").unwrap();

                let swap_weth_wbtc = Swap {
                    component: ProtocolComponent {
                        id: "0xCBCdF9626bC03E24f779434178A73a0B4bad62eD".to_string(),
                        protocol_system: "uniswap_v3".to_string(),
                        static_attributes: {
                            let mut attrs = HashMap::new();
                            attrs.insert(
                                "fee".to_string(),
                                Bytes::from(BigInt::from(3000).to_signed_bytes_be()),
                            );
                            attrs
                        },
                        ..Default::default()
                    },
                    token_in: weth.clone(),
                    token_out: wbtc.clone(),
                    split: 0f64,
                };

                let swap_wbtc_usdt = Swap {
                    component: ProtocolComponent {
                        id: String::from("0xD51a44d3FaE010294C616388b506AcdA1bfAAE46"),
                        protocol_system: String::from("vm:curve"),
                        static_attributes: {
                            let mut attrs: HashMap<String, Bytes> = HashMap::new();
                            attrs.insert(
                                "factory".into(),
                                Bytes::from(
                                    "0x0000000000000000000000000000000000000000"
                                        .as_bytes()
                                        .to_vec(),
                                ),
                            );
                            attrs.insert(
                                "coins".into(),
                                Bytes::from_str("0x5b22307864616331376639353864326565353233613232303632303639393435393763313364383331656337222c22307832323630666163356535353432613737336161343466626366656466376331393362633263353939222c22307863303261616133396232323366653864306130653563346632376561643930383363373536636332225d")
                                    .unwrap(),
                            );
                            attrs
                        },
                        ..Default::default()
                    },
                    token_in: wbtc.clone(),
                    token_out: usdt.clone(),
                    split: 0f64,
                };
                let swap_encoder_registry = get_swap_encoder_registry();
                let encoder = SequentialSwapStrategyEncoder::new(
                    eth_chain(),
                    swap_encoder_registry,
                    false,
                    router_address(),
                    false,
                )
                .unwrap();
                let solution = Solution {
                    exact_out: false,
                    given_token: weth,
                    given_amount: BigUint::from_str("1_000000000000000000").unwrap(),
                    checked_token: usdt,
                    checked_amount: BigUint::from_str("26173932").unwrap(),
                    sender: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
                    receiver: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2")
                        .unwrap(),
                    swaps: vec![swap_weth_wbtc, swap_wbtc_usdt],
                    ..Default::default()
                };

                let encoded_solution = encoder
                    .encode_strategy(solution.clone())
                    .unwrap();

                let calldata = encode_tycho_router_call(encoded_solution, &solution, false, eth())
                    .unwrap()
                    .data;

                let hex_calldata = encode(&calldata);
                write_calldata_to_file("test_uniswap_v3_curve", hex_calldata.as_str());
            }

            #[test]
            fn test_balancer_v2_uniswap_v2() {
                // Note: This test does not assert anything. It is only used to obtain integration
                // test data for our router solidity test.
                //
                // Performs a sequential swap from WETH to USDC though WBTC using balancer and USV2
                // pools
                //
                //   WETH ───(balancer)──> WBTC ───(USV2)──> USDC

                let weth = weth();
                let wbtc = Bytes::from_str("0x2260fac5e5542a773aa44fbcfedf7c193bc2c599").unwrap();
                let usdc = Bytes::from_str("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48").unwrap();

                let swap_weth_wbtc = Swap {
                    component: ProtocolComponent {
                        id: "0xa6f548df93de924d73be7d25dc02554c6bd66db500020000000000000000000e"
                            .to_string(),
                        protocol_system: "vm:balancer_v2".to_string(),
                        ..Default::default()
                    },
                    token_in: weth.clone(),
                    token_out: wbtc.clone(),
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
                let encoder = SequentialSwapStrategyEncoder::new(
                    eth_chain(),
                    swap_encoder_registry,
                    false,
                    router_address(),
                    false,
                )
                .unwrap();
                let solution = Solution {
                    exact_out: false,
                    given_token: weth,
                    given_amount: BigUint::from_str("1_000000000000000000").unwrap(),
                    checked_token: usdc,
                    checked_amount: BigUint::from_str("26173932").unwrap(),
                    sender: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
                    receiver: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2")
                        .unwrap(),
                    swaps: vec![swap_weth_wbtc, swap_wbtc_usdc],
                    ..Default::default()
                };

                let encoded_solution = encoder
                    .encode_strategy(solution.clone())
                    .unwrap();

                let calldata = encode_tycho_router_call(encoded_solution, &solution, false, eth())
                    .unwrap()
                    .data;

                let hex_calldata = encode(&calldata);
                write_calldata_to_file("test_balancer_v2_uniswap_v2", hex_calldata.as_str());
            }

            #[test]
            fn test_multi_protocol() {
                // Note: This test does not assert anything. It is only used to obtain integration
                // test data for our router solidity test.
                //
                // Performs the following swap:
                //
                //   DAI ─(USV2)-> WETH ─(bal)─> WBTC ─(curve)─> USDT ─(ekubo)─> USDC ─(USV4)─> ETH

                let weth = weth();
                let eth = eth();
                let wbtc = Bytes::from_str("0x2260fac5e5542a773aa44fbcfedf7c193bc2c599").unwrap();
                let usdc = Bytes::from_str("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48").unwrap();
                let usdt = Bytes::from_str("0xdAC17F958D2ee523a2206206994597C13D831ec7").unwrap();
                let dai = Bytes::from_str("0x6B175474E89094C44Da98b954EedeAC495271d0F").unwrap();

                let usv2_swap_dai_weth = Swap {
                    component: ProtocolComponent {
                        id: "0xA478c2975Ab1Ea89e8196811F51A7B7Ade33eB11".to_string(),
                        protocol_system: "uniswap_v2".to_string(),
                        ..Default::default()
                    },
                    token_in: dai.clone(),
                    token_out: weth.clone(),
                    split: 0f64,
                };

                let balancer_swap_weth_wbtc = Swap {
                    component: ProtocolComponent {
                        id: "0xa6f548df93de924d73be7d25dc02554c6bd66db500020000000000000000000e"
                            .to_string(),
                        protocol_system: "vm:balancer_v2".to_string(),
                        ..Default::default()
                    },
                    token_in: weth.clone(),
                    token_out: wbtc.clone(),
                    split: 0f64,
                };

                let curve_swap_wbtc_usdt = Swap {
                    component: ProtocolComponent {
                        id: String::from("0xD51a44d3FaE010294C616388b506AcdA1bfAAE46"),
                        protocol_system: String::from("vm:curve"),
                        static_attributes: {
                            let mut attrs: HashMap<String, Bytes> = HashMap::new();
                            attrs.insert(
                                "factory".into(),
                                Bytes::from(
                                    "0x0000000000000000000000000000000000000000"
                                        .as_bytes()
                                        .to_vec(),
                                ),
                            );
                            attrs.insert(
                                "coins".into(),
                                Bytes::from_str("0x5b22307864616331376639353864326565353233613232303632303639393435393763313364383331656337222c22307832323630666163356535353432613737336161343466626366656466376331393362633263353939222c22307863303261616133396232323366653864306130653563346632376561643930383363373536636332225d")
                                    .unwrap(),
                            );
                            attrs
                        },
                        ..Default::default()
                    },
                    token_in: wbtc.clone(),
                    token_out: usdt.clone(),
                    split: 0f64,
                };

                // Ekubo

                let component = ProtocolComponent {
                    // All Ekubo swaps go through the core contract - not necessary to specify pool
                    // id for test
                    protocol_system: "ekubo_v2".to_string(),
                    // 0.0025% fee & 0.005% base pool
                    static_attributes: HashMap::from([
                        ("fee".to_string(), Bytes::from(461168601842738_u64)),
                        ("tick_spacing".to_string(), Bytes::from(50_u32)),
                        ("extension".to_string(), Bytes::zero(20)),
                    ]),
                    ..Default::default()
                };
                let ekubo_swap_usdt_usdc = Swap {
                    component,
                    token_in: usdt.clone(),
                    token_out: usdc.clone(),
                    split: 0f64,
                };

                // USV4
                // Fee and tick spacing information for this test is obtained by querying the
                // USV4 Position Manager contract: 0xbd216513d74c8cf14cf4747e6aaa6420ff64ee9e
                // Using the poolKeys function with the first 25 bytes of the pool id
                let pool_fee_usdc_eth = Bytes::from(BigInt::from(3000).to_signed_bytes_be());
                let tick_spacing_usdc_eth = Bytes::from(BigInt::from(60).to_signed_bytes_be());
                let mut static_attributes_usdc_eth: HashMap<String, Bytes> = HashMap::new();
                static_attributes_usdc_eth.insert("key_lp_fee".into(), pool_fee_usdc_eth);
                static_attributes_usdc_eth.insert("tick_spacing".into(), tick_spacing_usdc_eth);

                let usv4_swap_usdc_eth = Swap {
                    component: ProtocolComponent {
                        id: "0xdce6394339af00981949f5f3baf27e3610c76326a700af57e4b3e3ae4977f78d"
                            .to_string(),
                        protocol_system: "uniswap_v4".to_string(),
                        static_attributes: static_attributes_usdc_eth,
                        ..Default::default()
                    },
                    token_in: usdc.clone(),
                    token_out: eth.clone(),
                    split: 0f64,
                };

                // Put all components together
                let swap_encoder_registry = get_swap_encoder_registry();
                let encoder = SequentialSwapStrategyEncoder::new(
                    eth_chain(),
                    swap_encoder_registry,
                    true,
                    router_address(),
                    false,
                )
                .unwrap();
                let solution = Solution {
                    exact_out: false,
                    given_token: dai,
                    given_amount: BigUint::from_str("1500_000000000000000000").unwrap(),
                    checked_token: eth.clone(),
                    checked_amount: BigUint::from_str("732214216964381330").unwrap(),
                    sender: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
                    receiver: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2")
                        .unwrap(),
                    swaps: vec![
                        usv2_swap_dai_weth,
                        balancer_swap_weth_wbtc,
                        curve_swap_wbtc_usdt,
                        ekubo_swap_usdt_usdc,
                        usv4_swap_usdc_eth,
                    ],
                    ..Default::default()
                };

                let mut encoded_solution = encoder
                    .encode_strategy(solution.clone())
                    .unwrap();
                let (permit, signature) = get_permit(eth_chain(), router_address(), &solution);
                encoded_solution.permit = Some(permit);
                encoded_solution.signature = Some(signature.as_bytes().to_vec());

                let calldata = encode_tycho_router_call(encoded_solution, &solution, false, eth)
                    .unwrap()
                    .data;

                let hex_calldata = encode(&calldata);
                write_calldata_to_file("test_multi_protocol", hex_calldata.as_str());
            }
        }
    }

    mod split {
        use super::*;

        #[test]
        fn test_split_swap_strategy_encoder() {
            // Note: This test does not assert anything. It is only used to obtain integration test
            // data for our router solidity test.
            //
            // Performs a split swap from WETH to USDC though WBTC and DAI using USV2 pools
            //
            //         ┌──(USV2)──> WBTC ───(USV2)──> USDC
            //   WETH ─┤
            //         └──(USV2)──> DAI  ───(USV2)──> USDC
            //

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
                // This represents the remaining 50%, but to avoid any rounding errors we set this
                // to 0 to signify "the remainder of the WETH value". It should
                // still be very close to 50%
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
            let encoder = SplitSwapStrategyEncoder::new(
                eth_chain(),
                swap_encoder_registry,
                true,
                Bytes::from("0x3Ede3eCa2a72B3aeCC820E955B36f38437D01395"),
                false,
            )
            .unwrap();
            let solution = Solution {
                exact_out: false,
                given_token: weth,
                given_amount: BigUint::from_str("1_000000000000000000").unwrap(),
                checked_token: usdc,
                checked_amount: BigUint::from_str("26173932").unwrap(),
                sender: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
                receiver: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
                swaps: vec![swap_weth_dai, swap_weth_wbtc, swap_dai_usdc, swap_wbtc_usdc],
                ..Default::default()
            };

            let mut encoded_solution = encoder
                .encode_strategy(solution.clone())
                .unwrap();
            let (permit, signature) = get_permit(eth_chain(), router_address(), &solution);
            encoded_solution.permit = Some(permit);
            encoded_solution.signature = Some(signature.as_bytes().to_vec());

            let calldata = encode_tycho_router_call(encoded_solution, &solution, false, eth())
                .unwrap()
                .data;

            let hex_calldata = encode(&calldata);
            write_calldata_to_file("test_split_swap_strategy_encoder", hex_calldata.as_str());
        }

        #[test]
        fn test_split_input_cyclic_swap() {
            // This test has start and end tokens that are the same
            // The flow is:
            //            ┌─ (USV3, 60% split) ──> WETH ─┐
            //            │                              │
            // USDC ──────┤                              ├──(USV2)──> USDC
            //            │                              │
            //            └─ (USV3, 40% split) ──> WETH ─┘

            let weth = Bytes::from_str("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2").unwrap();
            let usdc = Bytes::from_str("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48").unwrap();

            // USDC -> WETH (Pool 1) - 60% of input
            let swap_usdc_weth_pool1 = Swap {
                component: ProtocolComponent {
                    id: "0x88e6A0c2dDD26FEEb64F039a2c41296FcB3f5640".to_string(), /* USDC-WETH USV3
                                                                                   * Pool 1 */
                    protocol_system: "uniswap_v3".to_string(),
                    static_attributes: {
                        let mut attrs = HashMap::new();
                        attrs.insert(
                            "fee".to_string(),
                            Bytes::from(BigInt::from(500).to_signed_bytes_be()),
                        );
                        attrs
                    },
                    ..Default::default()
                },
                token_in: usdc.clone(),
                token_out: weth.clone(),
                split: 0.6f64, // 60% of input
            };

            // USDC -> WETH (Pool 2) - 40% of input (remaining)
            let swap_usdc_weth_pool2 = Swap {
                component: ProtocolComponent {
                    id: "0x8ad599c3A0ff1De082011EFDDc58f1908eb6e6D8".to_string(), /* USDC-WETH USV3
                                                                                   * Pool 2 */
                    protocol_system: "uniswap_v3".to_string(),
                    static_attributes: {
                        let mut attrs = HashMap::new();
                        attrs.insert(
                            "fee".to_string(),
                            Bytes::from(BigInt::from(3000).to_signed_bytes_be()),
                        );
                        attrs
                    },
                    ..Default::default()
                },
                token_in: usdc.clone(),
                token_out: weth.clone(),
                split: 0f64, // Remaining 40%
            };

            // WETH -> USDC (Pool 2)
            let swap_weth_usdc_pool2 = Swap {
                component: ProtocolComponent {
                    id: "0xB4e16d0168e52d35CaCD2c6185b44281Ec28C9Dc".to_string(), /* USDC-WETH USV2
                                                                                   * Pool 2 */
                    protocol_system: "uniswap_v2".to_string(),
                    static_attributes: {
                        let mut attrs = HashMap::new();
                        attrs.insert(
                            "fee".to_string(),
                            Bytes::from(BigInt::from(3000).to_signed_bytes_be()),
                        );
                        attrs
                    },
                    ..Default::default()
                },
                token_in: weth.clone(),
                token_out: usdc.clone(),
                split: 0.0f64,
            };

            let swap_encoder_registry = get_swap_encoder_registry();
            let encoder = SplitSwapStrategyEncoder::new(
                eth_chain(),
                swap_encoder_registry,
                true,
                Bytes::from("0x3Ede3eCa2a72B3aeCC820E955B36f38437D01395"),
                false,
            )
            .unwrap();

            let solution = Solution {
                exact_out: false,
                given_token: usdc.clone(),
                given_amount: BigUint::from_str("100000000").unwrap(), // 100 USDC (6 decimals)
                checked_token: usdc.clone(),
                checked_amount: BigUint::from_str("99574171").unwrap(), /* Expected output
                                                                         * from
                                                                         * test */
                sender: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
                receiver: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
                swaps: vec![swap_usdc_weth_pool1, swap_usdc_weth_pool2, swap_weth_usdc_pool2],
                ..Default::default()
            };

            let mut encoded_solution = encoder
                .encode_strategy(solution.clone())
                .unwrap();
            let (permit, signature) = get_permit(eth_chain(), router_address(), &solution);
            encoded_solution.permit = Some(permit);
            encoded_solution.signature = Some(signature.as_bytes().to_vec());

            let calldata = encode_tycho_router_call(encoded_solution, &solution, false, eth())
                .unwrap()
                .data;

            let hex_calldata = hex::encode(&calldata);
            let expected_input = [
                "7c553846",                                                         // selector
                "0000000000000000000000000000000000000000000000000000000005f5e100", // given amount
                "000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", // given token
                "000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", // checked token
                "0000000000000000000000000000000000000000000000000000000005ef619b", // min amount out
                "0000000000000000000000000000000000000000000000000000000000000000", // wrap action
                "0000000000000000000000000000000000000000000000000000000000000000", // unwrap action
                "0000000000000000000000000000000000000000000000000000000000000002", // tokens length
                "000000000000000000000000cd09f75e2bf2a4d11f3ab23f1389fcc1621c0cc2", // receiver
            ]
                .join("");
            let expected_swaps = [
                "0000000000000000000000000000000000000000000000000000000000000139", // length of ple encoded swaps without padding
                "006e", // ple encoded swaps
                "00", // token in index
                "01", // token out index
                "999999", // split
                "2e234dae75c793f67a35089c9d99245e1c58470b", // executor address
                "a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", // token in
                "c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2", // token out
                "0001f4", // pool fee
                "3ede3eca2a72b3aecc820e955b36f38437d01395", // receiver
                "88e6a0c2ddd26feeb64f039a2c41296fcb3f5640", // component id
                "01", // zero2one
                "00", // transfer type TransferFrom
                "006e", // ple encoded swaps
                "00", // token in index
                "01", // token out index
                "000000", // split
                "2e234dae75c793f67a35089c9d99245e1c58470b", // executor address
                "a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", // token in
                "c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2", // token out
                "000bb8", // pool fee
                "3ede3eca2a72b3aecc820e955b36f38437d01395", // receiver
                "8ad599c3a0ff1de082011efddc58f1908eb6e6d8", // component id
                "01", // zero2one
                "00", // transfer type TransferFrom
                "0057", // ple encoded swaps
                "01", // token in index
                "00", // token out index
                "000000", // split
                "5615deb798bb3e4dfa0139dfa1b3d433cc23b72f", // executor address,
                "c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2", // token in
                "b4e16d0168e52d35cacd2c6185b44281ec28c9dc", // component id,
                "cd09f75e2bf2a4d11f3ab23f1389fcc1621c0cc2", // receiver
                "00", // zero2one
                "01", // transfer type Transfer
                "00000000000000" // padding
            ]
                .join("");
            assert_eq!(hex_calldata[..520], expected_input);
            assert_eq!(hex_calldata[1288..], expected_swaps);
            write_calldata_to_file("test_split_input_cyclic_swap", hex_calldata.as_str());
        }

        #[test]
        fn test_split_output_cyclic_swap() {
            // This test has start and end tokens that are the same
            // The flow is:
            //                        ┌─── (USV3, 60% split) ───┐
            //                        │                         │
            // USDC ──(USV2) ── WETH──|                         ├─> USDC
            //                        │                         │
            //                        └─── (USV3, 40% split) ───┘

            let weth = Bytes::from_str("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2").unwrap();
            let usdc = Bytes::from_str("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48").unwrap();

            let swap_usdc_weth_v2 = Swap {
                component: ProtocolComponent {
                    id: "0xB4e16d0168e52d35CaCD2c6185b44281Ec28C9Dc".to_string(), // USDC-WETH USV2
                    protocol_system: "uniswap_v2".to_string(),
                    static_attributes: {
                        let mut attrs = HashMap::new();
                        attrs.insert(
                            "fee".to_string(),
                            Bytes::from(BigInt::from(500).to_signed_bytes_be()),
                        );
                        attrs
                    },
                    ..Default::default()
                },
                token_in: usdc.clone(),
                token_out: weth.clone(),
                split: 0.0f64,
            };

            let swap_weth_usdc_v3_pool1 = Swap {
                component: ProtocolComponent {
                    id: "0x88e6A0c2dDD26FEEb64F039a2c41296FcB3f5640".to_string(), /* USDC-WETH USV3
                                                                                   * Pool 1 */
                    protocol_system: "uniswap_v3".to_string(),
                    static_attributes: {
                        let mut attrs = HashMap::new();
                        attrs.insert(
                            "fee".to_string(),
                            Bytes::from(BigInt::from(500).to_signed_bytes_be()),
                        );
                        attrs
                    },
                    ..Default::default()
                },
                token_in: weth.clone(),
                token_out: usdc.clone(),
                split: 0.6f64,
            };

            let swap_weth_usdc_v3_pool2 = Swap {
                component: ProtocolComponent {
                    id: "0x8ad599c3A0ff1De082011EFDDc58f1908eb6e6D8".to_string(), /* USDC-WETH USV3
                                                                                   * Pool 2 */
                    protocol_system: "uniswap_v3".to_string(),
                    static_attributes: {
                        let mut attrs = HashMap::new();
                        attrs.insert(
                            "fee".to_string(),
                            Bytes::from(BigInt::from(3000).to_signed_bytes_be()),
                        );
                        attrs
                    },
                    ..Default::default()
                },
                token_in: weth.clone(),
                token_out: usdc.clone(),
                split: 0.0f64,
            };

            let swap_encoder_registry = get_swap_encoder_registry();
            let encoder = SplitSwapStrategyEncoder::new(
                eth_chain(),
                swap_encoder_registry,
                true,
                Bytes::from("0x3Ede3eCa2a72B3aeCC820E955B36f38437D01395"),
                false,
            )
            .unwrap();

            let solution = Solution {
                exact_out: false,
                given_token: usdc.clone(),
                given_amount: BigUint::from_str("100000000").unwrap(), // 100 USDC (6 decimals)
                checked_token: usdc.clone(),
                checked_amount: BigUint::from_str("99025908").unwrap(), /* Expected output
                                                                         * from
                                                                         * test */
                sender: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
                receiver: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
                swaps: vec![swap_usdc_weth_v2, swap_weth_usdc_v3_pool1, swap_weth_usdc_v3_pool2],
                ..Default::default()
            };

            let mut encoded_solution = encoder
                .encode_strategy(solution.clone())
                .unwrap();
            let (permit, signature) = get_permit(eth_chain(), router_address(), &solution);
            encoded_solution.permit = Some(permit);
            encoded_solution.signature = Some(signature.as_bytes().to_vec());

            let calldata = encode_tycho_router_call(encoded_solution, &solution, false, eth())
                .unwrap()
                .data;

            let hex_calldata = hex::encode(&calldata);
            let expected_input = [
                "7c553846",                                                         // selector
                "0000000000000000000000000000000000000000000000000000000005f5e100", // given amount
                "000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", // given token
                "000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", // checked token
                "0000000000000000000000000000000000000000000000000000000005e703f4", // min amount out
                "0000000000000000000000000000000000000000000000000000000000000000", // wrap action
                "0000000000000000000000000000000000000000000000000000000000000000", // unwrap action
                "0000000000000000000000000000000000000000000000000000000000000002", // tokens length
                "000000000000000000000000cd09f75e2bf2a4d11f3ab23f1389fcc1621c0cc2", // receiver
            ]
                .join("");

            let expected_swaps = [
                "0000000000000000000000000000000000000000000000000000000000000139", // length of ple encoded swaps without padding
                "0057", // ple encoded swaps
                "00", // token in index
                "01", // token out index
                "000000", // split
                "5615deb798bb3e4dfa0139dfa1b3d433cc23b72f", // executor address
                "a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", // token in
                "b4e16d0168e52d35cacd2c6185b44281ec28c9dc", // component id
                "3ede3eca2a72b3aecc820e955b36f38437d01395", // receiver
                "01", // zero2one
                "00", // transfer type TransferFrom
                "006e", // ple encoded swaps
                "01", // token in index
                "00", // token out index
                "999999", // split
                "2e234dae75c793f67a35089c9d99245e1c58470b", // executor address
                "c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2", // token in
                "a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", // token out
                "0001f4", // pool fee
                "cd09f75e2bf2a4d11f3ab23f1389fcc1621c0cc2", // receiver
                "88e6a0c2ddd26feeb64f039a2c41296fcb3f5640", // component id
                "00", // zero2one
                "01", // transfer type Transfer
                "006e", // ple encoded swaps
                "01", // token in index
                "00", // token out index
                "000000", // split
                "2e234dae75c793f67a35089c9d99245e1c58470b", // executor address
                "c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2", // token in
                "a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", // token out
                "000bb8", // pool fee
                "cd09f75e2bf2a4d11f3ab23f1389fcc1621c0cc2", // receiver
                "8ad599c3a0ff1de082011efddc58f1908eb6e6d8", // component id
                "00", // zero2one
                "01", // transfer type Transfer
                "00000000000000" // padding
            ]
                .join("");

            assert_eq!(hex_calldata[..520], expected_input);
            assert_eq!(hex_calldata[1288..], expected_swaps);
            write_calldata_to_file("test_split_output_cyclic_swap", hex_calldata.as_str());
        }
    }

    mod protocol_integration {
        // in this module we test protocol specific logic by creating the calldata that then is
        // used in the solidity tests
        use super::*;

        #[test]
        fn test_single_encoding_strategy_ekubo() {
            //   ETH ──(EKUBO)──> USDC

            let token_in = Bytes::from(Address::ZERO.as_slice());
            let token_out = Bytes::from("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"); // USDC

            let static_attributes = HashMap::from([
                ("fee".to_string(), Bytes::from(0_u64)),
                ("tick_spacing".to_string(), Bytes::from(0_u32)),
                (
                    "extension".to_string(),
                    Bytes::from("0x51d02a5948496a67827242eabc5725531342527c"),
                ), /* Oracle */
            ]);

            let component = ProtocolComponent {
                // All Ekubo swaps go through the core contract - not necessary to specify pool id
                // for test
                protocol_system: "ekubo_v2".to_string(),
                static_attributes,
                ..Default::default()
            };

            let swap = Swap {
                component,
                token_in: token_in.clone(),
                token_out: token_out.clone(),
                split: 0f64,
            };

            let swap_encoder_registry = get_swap_encoder_registry();
            let encoder = SingleSwapStrategyEncoder::new(
                eth_chain(),
                swap_encoder_registry,
                false,
                Bytes::from_str("0xA4AD4f68d0b91CFD19687c881e50f3A00242828c").unwrap(),
                false,
            )
            .unwrap();

            let solution = Solution {
                exact_out: false,
                given_token: token_in,
                given_amount: BigUint::from_str("1_000000000000000000").unwrap(),
                checked_token: token_out,
                checked_amount: BigUint::from_str("1000").unwrap(),
                // Alice
                sender: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
                receiver: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
                swaps: vec![swap],
                ..Default::default()
            };

            let encoded_solution = encoder
                .encode_strategy(solution.clone())
                .unwrap();

            let calldata = encode_tycho_router_call(encoded_solution, &solution, false, eth())
                .unwrap()
                .data;
            let hex_calldata = encode(&calldata);
            write_calldata_to_file("test_single_encoding_strategy_ekubo", hex_calldata.as_str());
        }

        #[test]
        fn test_single_encoding_strategy_maverick() {
            // GHO -> (maverick) -> USDC
            let maverick_pool = ProtocolComponent {
                id: String::from("0x14Cf6D2Fe3E1B326114b07d22A6F6bb59e346c67"),
                protocol_system: String::from("vm:maverick_v2"),
                ..Default::default()
            };
            let token_in = Bytes::from("0x40D16FC0246aD3160Ccc09B8D0D3A2cD28aE6C2f");
            let token_out = Bytes::from("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48");
            let swap = Swap {
                component: maverick_pool,
                token_in: token_in.clone(),
                token_out: token_out.clone(),
                split: 0f64,
            };

            let swap_encoder_registry = get_swap_encoder_registry();
            let encoder = SingleSwapStrategyEncoder::new(
                eth_chain(),
                swap_encoder_registry,
                false,
                Bytes::from_str("0xA4AD4f68d0b91CFD19687c881e50f3A00242828c").unwrap(),
                false,
            )
            .unwrap();

            let solution = Solution {
                exact_out: false,
                given_token: token_in,
                given_amount: BigUint::from_str("1_000000000000000000").unwrap(),
                checked_token: token_out,
                checked_amount: BigUint::from_str("1000").unwrap(),
                // Alice
                sender: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
                receiver: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
                swaps: vec![swap],
                ..Default::default()
            };

            let encoded_solution = encoder
                .encode_strategy(solution.clone())
                .unwrap();

            let calldata = encode_tycho_router_call(encoded_solution, &solution, false, eth())
                .unwrap()
                .data;
            let hex_calldata = encode(&calldata);
            write_calldata_to_file("test_single_encoding_strategy_maverick", hex_calldata.as_str());
        }

        #[test]
        fn test_single_encoding_strategy_usv4_eth_in() {
            // Performs a single swap from ETH to PEPE using a USV4 pool
            // Note: This test does not assert anything. It is only used to obtain integration test
            // data for our router solidity test.
            //
            //   ETH ───(USV4)──> PEPE
            //
            let eth = eth();
            let pepe = Bytes::from_str("0x6982508145454Ce325dDbE47a25d4ec3d2311933").unwrap();

            let pool_fee_eth_pepe = Bytes::from(BigInt::from(25000).to_signed_bytes_be());
            let tick_spacing_eth_pepe = Bytes::from(BigInt::from(500).to_signed_bytes_be());
            let mut static_attributes_eth_pepe: HashMap<String, Bytes> = HashMap::new();
            static_attributes_eth_pepe.insert("key_lp_fee".into(), pool_fee_eth_pepe);
            static_attributes_eth_pepe.insert("tick_spacing".into(), tick_spacing_eth_pepe);

            let swap_eth_pepe = Swap {
                component: ProtocolComponent {
                    id: "0xecd73ecbf77219f21f129c8836d5d686bbc27d264742ddad620500e3e548e2c9"
                        .to_string(),
                    protocol_system: "uniswap_v4".to_string(),
                    static_attributes: static_attributes_eth_pepe,
                    ..Default::default()
                },
                token_in: eth.clone(),
                token_out: pepe.clone(),
                split: 0f64,
            };
            let swap_encoder_registry = get_swap_encoder_registry();
            let encoder = SingleSwapStrategyEncoder::new(
                eth_chain(),
                swap_encoder_registry,
                true,
                Bytes::from("0x3Ede3eCa2a72B3aeCC820E955B36f38437D01395"),
                false,
            )
            .unwrap();

            let solution = Solution {
                exact_out: false,
                given_token: eth.clone(),
                given_amount: BigUint::from_str("1_000000000000000000").unwrap(),
                checked_token: pepe,
                checked_amount: BigUint::from_str("152373460199848577067005852").unwrap(),
                sender: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
                receiver: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
                swaps: vec![swap_eth_pepe],
                ..Default::default()
            };

            let mut encoded_solution = encoder
                .encode_strategy(solution.clone())
                .unwrap();
            let (permit, signature) = get_permit(eth_chain(), router_address(), &solution);
            encoded_solution.permit = Some(permit);
            encoded_solution.signature = Some(signature.as_bytes().to_vec());

            let calldata = encode_tycho_router_call(encoded_solution, &solution, false, eth)
                .unwrap()
                .data;
            let hex_calldata = encode(&calldata);

            write_calldata_to_file(
                "test_single_encoding_strategy_usv4_eth_in",
                hex_calldata.as_str(),
            );
        }

        #[test]
        fn test_single_encoding_strategy_usv4_eth_out() {
            // Performs a single swap from USDC to ETH using a USV4 pool
            // Note: This test does not assert anything. It is only used to obtain integration test
            // data for our router solidity test.
            //
            //   USDC ───(USV4)──> ETH
            //
            let eth = eth();
            let usdc = Bytes::from_str("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48").unwrap();

            // Fee and tick spacing information for this test is obtained by querying the
            // USV4 Position Manager contract: 0xbd216513d74c8cf14cf4747e6aaa6420ff64ee9e
            // Using the poolKeys function with the first 25 bytes of the pool id
            let pool_fee_usdc_eth = Bytes::from(BigInt::from(3000).to_signed_bytes_be());
            let tick_spacing_usdc_eth = Bytes::from(BigInt::from(60).to_signed_bytes_be());
            let mut static_attributes_usdc_eth: HashMap<String, Bytes> = HashMap::new();
            static_attributes_usdc_eth.insert("key_lp_fee".into(), pool_fee_usdc_eth);
            static_attributes_usdc_eth.insert("tick_spacing".into(), tick_spacing_usdc_eth);

            let swap_usdc_eth = Swap {
                component: ProtocolComponent {
                    id: "0xdce6394339af00981949f5f3baf27e3610c76326a700af57e4b3e3ae4977f78d"
                        .to_string(),
                    protocol_system: "uniswap_v4".to_string(),
                    static_attributes: static_attributes_usdc_eth,
                    ..Default::default()
                },
                token_in: usdc.clone(),
                token_out: eth.clone(),
                split: 0f64,
            };

            let swap_encoder_registry = get_swap_encoder_registry();
            let encoder = SplitSwapStrategyEncoder::new(
                eth_chain(),
                swap_encoder_registry,
                true,
                Bytes::from("0x3Ede3eCa2a72B3aeCC820E955B36f38437D01395"),
                false,
            )
            .unwrap();

            let solution = Solution {
                exact_out: false,
                given_token: usdc,
                given_amount: BigUint::from_str("3000_000000").unwrap(),
                checked_token: eth.clone(),
                checked_amount: BigUint::from_str("1117254495486192350").unwrap(),
                sender: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
                receiver: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
                swaps: vec![swap_usdc_eth],
                ..Default::default()
            };

            let mut encoded_solution = encoder
                .encode_strategy(solution.clone())
                .unwrap();
            let (permit, signature) = get_permit(eth_chain(), router_address(), &solution);
            encoded_solution.permit = Some(permit);
            encoded_solution.signature = Some(signature.as_bytes().to_vec());

            let calldata = encode_tycho_router_call(encoded_solution, &solution, false, eth)
                .unwrap()
                .data;

            let hex_calldata = encode(&calldata);
            write_calldata_to_file(
                "test_single_encoding_strategy_usv4_eth_out",
                hex_calldata.as_str(),
            );
        }

        #[test]
        fn test_single_encoding_strategy_usv4_grouped_swap() {
            // Performs a sequential swap from USDC to PEPE though ETH using two consecutive USV4
            // pools
            //
            //   USDC ──(USV4)──> ETH ───(USV4)──> PEPE
            //

            let eth = eth();
            let usdc = Bytes::from_str("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48").unwrap();
            let pepe = Bytes::from_str("0x6982508145454Ce325dDbE47a25d4ec3d2311933").unwrap();

            // Fee and tick spacing information for this test is obtained by querying the
            // USV4 Position Manager contract: 0xbd216513d74c8cf14cf4747e6aaa6420ff64ee9e
            // Using the poolKeys function with the first 25 bytes of the pool id
            let pool_fee_usdc_eth = Bytes::from(BigInt::from(3000).to_signed_bytes_be());
            let tick_spacing_usdc_eth = Bytes::from(BigInt::from(60).to_signed_bytes_be());
            let mut static_attributes_usdc_eth: HashMap<String, Bytes> = HashMap::new();
            static_attributes_usdc_eth.insert("key_lp_fee".into(), pool_fee_usdc_eth);
            static_attributes_usdc_eth.insert("tick_spacing".into(), tick_spacing_usdc_eth);

            let pool_fee_eth_pepe = Bytes::from(BigInt::from(25000).to_signed_bytes_be());
            let tick_spacing_eth_pepe = Bytes::from(BigInt::from(500).to_signed_bytes_be());
            let mut static_attributes_eth_pepe: HashMap<String, Bytes> = HashMap::new();
            static_attributes_eth_pepe.insert("key_lp_fee".into(), pool_fee_eth_pepe);
            static_attributes_eth_pepe.insert("tick_spacing".into(), tick_spacing_eth_pepe);

            let swap_usdc_eth = Swap {
                component: ProtocolComponent {
                    id: "0xdce6394339af00981949f5f3baf27e3610c76326a700af57e4b3e3ae4977f78d"
                        .to_string(),
                    protocol_system: "uniswap_v4".to_string(),
                    static_attributes: static_attributes_usdc_eth,
                    ..Default::default()
                },
                token_in: usdc.clone(),
                token_out: eth.clone(),
                split: 0f64,
            };

            let swap_eth_pepe = Swap {
                component: ProtocolComponent {
                    id: "0xecd73ecbf77219f21f129c8836d5d686bbc27d264742ddad620500e3e548e2c9"
                        .to_string(),
                    protocol_system: "uniswap_v4".to_string(),
                    static_attributes: static_attributes_eth_pepe,
                    ..Default::default()
                },
                token_in: eth.clone(),
                token_out: pepe.clone(),
                split: 0f64,
            };
            let swap_encoder_registry = get_swap_encoder_registry();
            let encoder = SingleSwapStrategyEncoder::new(
                eth_chain(),
                swap_encoder_registry,
                true,
                Bytes::from("0x3Ede3eCa2a72B3aeCC820E955B36f38437D01395"),
                false,
            )
            .unwrap();
            let solution = Solution {
                exact_out: false,
                given_token: usdc,
                given_amount: BigUint::from_str("1000_000000").unwrap(),
                checked_token: pepe,
                checked_amount: BigUint::from_str("97191013220606467325121599").unwrap(),
                sender: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
                receiver: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
                swaps: vec![swap_usdc_eth, swap_eth_pepe],
                ..Default::default()
            };

            let mut encoded_solution = encoder
                .encode_strategy(solution.clone())
                .unwrap();
            let (permit, signature) = get_permit(eth_chain(), router_address(), &solution);
            encoded_solution.permit = Some(permit);
            encoded_solution.signature = Some(signature.as_bytes().to_vec());

            let calldata = encode_tycho_router_call(encoded_solution, &solution, false, eth)
                .unwrap()
                .data;

            let expected_input = [
                "30ace1b1",                                                              // Function selector (single swap)
                "000000000000000000000000000000000000000000000000000000003b9aca00",      // amount in
                "000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",      // token in
                "0000000000000000000000006982508145454ce325ddbe47a25d4ec3d2311933",      // token out
                "0000000000000000000000000000000000000000005064ff624d54346285543f",      // min amount out
                "0000000000000000000000000000000000000000000000000000000000000000",      // wrap
                "0000000000000000000000000000000000000000000000000000000000000000",      // unwrap
                "000000000000000000000000cd09f75e2bf2a4d11f3ab23f1389fcc1621c0cc2",      // receiver
            ]
                .join("");

            // after this there is the permit and because of the deadlines (that depend on block
            // time) it's hard to assert

            let expected_swaps = String::from(concat!(
                // length of ple encoded swaps without padding
                "0000000000000000000000000000000000000000000000000000000000000086",
                // Swap data header
                "f62849f9a0b5bf2913b396098f7c7019b51a820a", // executor address
                // Protocol data
                "a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", // group token in
                "6982508145454ce325ddbe47a25d4ec3d2311933", // group token in
                "00",                                       // zero2one
                "00",                                       // transfer type TransferFrom
                "cd09f75e2bf2a4d11f3ab23f1389fcc1621c0cc2", // receiver
                // First pool params
                "0000000000000000000000000000000000000000", // intermediary token (ETH)
                "000bb8",                                   // fee
                "00003c",                                   // tick spacing
                // Second pool params
                "6982508145454ce325ddbe47a25d4ec3d2311933", // intermediary token (PEPE)
                "0061a8",                                   // fee
                "0001f4",                                   // tick spacing
                "0000000000000000000000000000000000000000000000000000"  // padding
            ));

            let hex_calldata = encode(&calldata);

            assert_eq!(hex_calldata[..456], expected_input);
            assert_eq!(hex_calldata[1224..], expected_swaps);
            write_calldata_to_file(
                "test_single_encoding_strategy_usv4_grouped_swap",
                hex_calldata.as_str(),
            );
        }

        #[test]
        fn test_single_encoding_strategy_curve() {
            //   UWU ──(curve 2 crypto pool)──> WETH

            let token_in = Bytes::from("0x55C08ca52497e2f1534B59E2917BF524D4765257"); // UWU
            let token_out = Bytes::from("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"); // WETH

            let static_attributes = HashMap::from([(
                "factory".to_string(),
                Bytes::from(
                    "0x98ee851a00abee0d95d08cf4ca2bdce32aeaaf7f"
                        .as_bytes()
                        .to_vec(),
                )),
                ("coins".to_string(), Bytes::from_str("0x5b22307863303261616133396232323366653864306130653563346632376561643930383363373536636332222c22307835356330386361353234393765326631353334623539653239313762663532346434373635323537225d").unwrap()),
            ]);

            let component = ProtocolComponent {
                id: String::from("0x77146B0a1d08B6844376dF6d9da99bA7F1b19e71"),
                protocol_system: String::from("vm:curve"),
                static_attributes,
                ..Default::default()
            };

            let swap = Swap {
                component,
                token_in: token_in.clone(),
                token_out: token_out.clone(),
                split: 0f64,
            };

            let swap_encoder_registry = get_swap_encoder_registry();
            let encoder = SingleSwapStrategyEncoder::new(
                eth_chain(),
                swap_encoder_registry,
                false,
                router_address(),
                false,
            )
            .unwrap();

            let solution = Solution {
                exact_out: false,
                given_token: token_in,
                given_amount: BigUint::from_str("1_000000000000000000").unwrap(),
                checked_token: token_out,
                checked_amount: BigUint::from_str("1").unwrap(),
                // Alice
                sender: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
                receiver: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
                swaps: vec![swap],
                ..Default::default()
            };

            let encoded_solution = encoder
                .encode_strategy(solution.clone())
                .unwrap();

            let calldata = encode_tycho_router_call(encoded_solution, &solution, false, eth())
                .unwrap()
                .data;

            let hex_calldata = encode(&calldata);
            write_calldata_to_file("test_single_encoding_strategy_curve", hex_calldata.as_str());
        }

        #[test]
        fn test_single_encoding_strategy_curve_st_eth() {
            //   ETH ──(curve stETH pool)──> STETH

            let token_in = Bytes::from("0x0000000000000000000000000000000000000000"); // ETH
            let token_out = Bytes::from("0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84"); // STETH

            let static_attributes = HashMap::from([(
                "factory".to_string(),
                Bytes::from(
                    "0x0000000000000000000000000000000000000000"
                        .as_bytes()
                        .to_vec(),
                ),
            ),
                ("coins".to_string(), Bytes::from_str("0x5b22307865656565656565656565656565656565656565656565656565656565656565656565656565656565222c22307861653761623936353230646533613138653565313131623565616162303935333132643766653834225d").unwrap()),]);

            let component = ProtocolComponent {
                id: String::from("0xDC24316b9AE028F1497c275EB9192a3Ea0f67022"),
                protocol_system: String::from("vm:curve"),
                static_attributes,
                ..Default::default()
            };

            let swap = Swap {
                component,
                token_in: token_in.clone(),
                token_out: token_out.clone(),
                split: 0f64,
            };

            let swap_encoder_registry = get_swap_encoder_registry();
            let encoder = SingleSwapStrategyEncoder::new(
                eth_chain(),
                swap_encoder_registry,
                false,
                router_address(),
                false,
            )
            .unwrap();

            let solution = Solution {
                exact_out: false,
                given_token: token_in,
                given_amount: BigUint::from_str("1_000000000000000000").unwrap(),
                checked_token: token_out,
                checked_amount: BigUint::from_str("1").unwrap(),
                // Alice
                sender: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
                receiver: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
                swaps: vec![swap],
                ..Default::default()
            };

            let encoded_solution = encoder
                .encode_strategy(solution.clone())
                .unwrap();
            let calldata = encode_tycho_router_call(encoded_solution, &solution, false, eth())
                .unwrap()
                .data;

            let hex_calldata = encode(&calldata);
            write_calldata_to_file(
                "test_single_encoding_strategy_curve_st_eth",
                hex_calldata.as_str(),
            );
        }
    }
}
