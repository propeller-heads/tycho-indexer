use std::{collections::HashSet, str::FromStr};

use alloy::primitives::{aliases::U24, U8};
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
    models::{Chain, EncodedSolution, EncodingContext, NativeAction, Solution, UserTransferType},
    strategy_encoder::StrategyEncoder,
    swap_encoder::SwapEncoder,
};

/// Represents the encoder for a swap strategy which supports single swaps.
///
/// # Fields
/// * `swap_encoder_registry`: SwapEncoderRegistry, containing all possible swap encoders
/// * `function_signature`: String, the signature for the swap function in the router contract
/// * `router_address`: Address of the router to be used to execute swaps
/// * `transfer_optimization`: TransferOptimization, responsible for optimizing the token transfers
#[derive(Clone)]
pub struct SingleSwapStrategyEncoder {
    swap_encoder_registry: SwapEncoderRegistry,
    function_signature: String,
    router_address: Bytes,
    transfer_optimization: TransferOptimization,
}

impl SingleSwapStrategyEncoder {
    pub fn new(
        chain: Chain,
        swap_encoder_registry: SwapEncoderRegistry,
        user_transfer_type: UserTransferType,
        router_address: Bytes,
    ) -> Result<Self, EncodingError> {
        let function_signature = if user_transfer_type == UserTransferType::TransferFromPermit2 {
            "singleSwapPermit2(uint256,address,address,uint256,bool,bool,address,((address,uint160,uint48,uint48),address,uint256),bytes,bytes)"
        } else {
            "singleSwap(uint256,address,address,uint256,bool,bool,address,bool,bytes)"
        }.to_string();

        Ok(Self {
            function_signature,
            swap_encoder_registry,
            router_address: router_address.clone(),
            transfer_optimization: TransferOptimization::new(
                chain.native_token()?,
                chain.wrapped_token()?,
                user_transfer_type,
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
    fn encode_strategy(&self, solution: &Solution) -> Result<EncodedSolution, EncodingError> {
        let grouped_swaps = group_swaps(&solution.swaps);
        let number_of_groups = grouped_swaps.len();
        if number_of_groups != 1 {
            return Err(EncodingError::InvalidInput(format!(
                "Single strategy only supports exactly one swap for non-groupable protocols. Found {number_of_groups}",
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
        if let Some(action) = &solution.native_action {
            match *action {
                NativeAction::Wrap => wrap = true,
                NativeAction::Unwrap => unwrap = true,
            }
        }
        let protocol = &grouped_swap.protocol_system;
        let swap_encoder = self
            .get_swap_encoder(protocol)
            .ok_or_else(|| {
                EncodingError::InvalidInput(format!(
                    "Swap encoder not found for protocol: {protocol}"
                ))
            })?;

        let swap_receiver =
            if !unwrap { solution.receiver.clone() } else { self.router_address.clone() };

        let transfer = self
            .transfer_optimization
            .get_transfers(grouped_swap, &solution.given_token, wrap, false);
        let encoding_context = EncodingContext {
            receiver: swap_receiver,
            exact_out: solution.exact_out,
            router_address: Some(self.router_address.clone()),
            group_token_in: grouped_swap.token_in.clone(),
            group_token_out: grouped_swap.token_out.clone(),
            transfer_type: transfer,
        };

        let mut grouped_protocol_data: Vec<Vec<u8>> = vec![];
        let mut initial_protocol_data: Vec<u8> = vec![];
        for swap in grouped_swap.swaps.iter() {
            let protocol_data = swap_encoder.encode_swap(swap, &encoding_context)?;
            if encoding_context.group_token_in == swap.token_in {
                initial_protocol_data = protocol_data;
            } else {
                grouped_protocol_data.push(protocol_data);
            }
        }

        if !grouped_protocol_data.is_empty() {
            initial_protocol_data.extend(ple_encode(grouped_protocol_data));
        }

        let swap_data = self.encode_swap_header(
            Bytes::from_str(swap_encoder.executor_address())
                .map_err(|_| EncodingError::FatalError("Invalid executor address".to_string()))?,
            initial_protocol_data,
        );
        Ok(EncodedSolution {
            function_signature: self.function_signature.clone(),
            interacting_with: self.router_address.clone(),
            swaps: swap_data,
            permit: None,
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
/// * `function_signature`: String, the signature for the swap function in the router contract
/// * `native_address`: Address of the chain's native token
/// * `wrapped_address`: Address of the chain's wrapped token
/// * `router_address`: Address of the router to be used to execute swaps
/// * `sequential_swap_validator`: SequentialSwapValidator, responsible for checking validity of
///   sequential swap solutions
/// * `transfer_optimization`: TransferOptimization, responsible for optimizing the token transfers
#[derive(Clone)]
pub struct SequentialSwapStrategyEncoder {
    swap_encoder_registry: SwapEncoderRegistry,
    function_signature: String,
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
        user_transfer_type: UserTransferType,
        router_address: Bytes,
    ) -> Result<Self, EncodingError> {
        let function_signature = if user_transfer_type == UserTransferType::TransferFromPermit2 {
            "sequentialSwapPermit2(uint256,address,address,uint256,bool,bool,address,((address,uint160,uint48,uint48),address,uint256),bytes,bytes)"
        } else {
            "sequentialSwap(uint256,address,address,uint256,bool,bool,address,bool,bytes)"

        }.to_string();
        Ok(Self {
            function_signature,
            swap_encoder_registry,
            router_address: router_address.clone(),
            native_address: chain.native_token()?,
            wrapped_address: chain.wrapped_token()?,
            sequential_swap_validator: SequentialSwapValidator,
            transfer_optimization: TransferOptimization::new(
                chain.native_token()?,
                chain.wrapped_token()?,
                user_transfer_type,
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
    fn encode_strategy(&self, solution: &Solution) -> Result<EncodedSolution, EncodingError> {
        self.sequential_swap_validator
            .validate_swap_path(
                &solution.swaps,
                &solution.given_token,
                &solution.checked_token,
                &solution.native_action,
                &self.native_address,
                &self.wrapped_address,
            )?;

        let grouped_swaps = group_swaps(&solution.swaps);

        let mut wrap = false;
        if let Some(action) = &solution.native_action {
            if action == &NativeAction::Wrap {
                wrap = true
            }
        }

        let mut swaps = vec![];
        let mut next_in_between_swap_optimization_allowed = true;
        for (i, grouped_swap) in grouped_swaps.iter().enumerate() {
            let protocol = &grouped_swap.protocol_system;
            let swap_encoder = self
                .get_swap_encoder(protocol)
                .ok_or_else(|| {
                    EncodingError::InvalidInput(format!(
                        "Swap encoder not found for protocol: {protocol}",
                    ))
                })?;

            let in_between_swap_optimization_allowed = next_in_between_swap_optimization_allowed;
            let next_swap = grouped_swaps.get(i + 1);
            let (swap_receiver, next_swap_optimization) = self
                .transfer_optimization
                .get_receiver(&solution.receiver, next_swap)?;
            next_in_between_swap_optimization_allowed = next_swap_optimization;

            let transfer = self
                .transfer_optimization
                .get_transfers(
                    grouped_swap,
                    &solution.given_token,
                    wrap,
                    in_between_swap_optimization_allowed,
                );
            let encoding_context = EncodingContext {
                receiver: swap_receiver,
                exact_out: solution.exact_out,
                router_address: Some(self.router_address.clone()),
                group_token_in: grouped_swap.token_in.clone(),
                group_token_out: grouped_swap.token_out.clone(),
                transfer_type: transfer,
            };

            let mut grouped_protocol_data: Vec<Vec<u8>> = vec![];
            let mut initial_protocol_data: Vec<u8> = vec![];
            for swap in grouped_swap.swaps.iter() {
                let protocol_data = swap_encoder.encode_swap(swap, &encoding_context)?;
                if encoding_context.group_token_in == swap.token_in {
                    initial_protocol_data = protocol_data;
                } else {
                    grouped_protocol_data.push(protocol_data);
                }
            }

            if !grouped_protocol_data.is_empty() {
                initial_protocol_data.extend(ple_encode(grouped_protocol_data));
            }

            let swap_data = self.encode_swap_header(
                Bytes::from_str(swap_encoder.executor_address()).map_err(|_| {
                    EncodingError::FatalError("Invalid executor address".to_string())
                })?,
                initial_protocol_data,
            );
            swaps.push(swap_data);
        }

        let encoded_swaps = ple_encode(swaps);
        Ok(EncodedSolution {
            interacting_with: self.router_address.clone(),
            function_signature: self.function_signature.clone(),
            swaps: encoded_swaps,
            permit: None,
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
/// * `function_signature`: String, the signature for the swap function in the router contract
/// * `native_address`: Address of the chain's native token
/// * `wrapped_address`: Address of the chain's wrapped token
/// * `split_swap_validator`: SplitSwapValidator, responsible for checking validity of split swap
///   solutions
/// * `router_address`: Address of the router to be used to execute swaps
/// * `transfer_optimization`: TransferOptimization, responsible for optimizing the token transfers
#[derive(Clone)]
pub struct SplitSwapStrategyEncoder {
    swap_encoder_registry: SwapEncoderRegistry,
    function_signature: String,
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
        user_transfer_type: UserTransferType,
        router_address: Bytes,
    ) -> Result<Self, EncodingError> {
        let function_signature = if user_transfer_type == UserTransferType::TransferFromPermit2 {
           "splitSwapPermit2(uint256,address,address,uint256,bool,bool,uint256,address,((address,uint160,uint48,uint48),address,uint256),bytes,bytes)"
        } else {
                "splitSwap(uint256,address,address,uint256,bool,bool,uint256,address,bool,bytes)"
        }.to_string();
        Ok(Self {
            function_signature,
            swap_encoder_registry,
            native_address: chain.native_token()?,
            wrapped_address: chain.wrapped_token()?,
            split_swap_validator: SplitSwapValidator,
            router_address: router_address.clone(),
            transfer_optimization: TransferOptimization::new(
                chain.native_token()?,
                chain.wrapped_token()?,
                user_transfer_type,
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
    fn encode_strategy(&self, solution: &Solution) -> Result<EncodedSolution, EncodingError> {
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
        let solution_tokens: HashSet<&Bytes> = vec![&solution.given_token, &solution.checked_token]
            .into_iter()
            .collect();

        let grouped_swaps = group_swaps(&solution.swaps);

        let intermediary_tokens: HashSet<&Bytes> = grouped_swaps
            .iter()
            .flat_map(|grouped_swap| vec![&grouped_swap.token_in, &grouped_swap.token_out])
            .collect();
        let mut intermediary_tokens: Vec<&Bytes> = intermediary_tokens
            .difference(&solution_tokens)
            .cloned()
            .collect();
        // this is only to make the test deterministic (same index for the same token for different
        // runs)
        intermediary_tokens.sort();

        let (mut unwrap, mut wrap) = (false, false);
        if let Some(action) = &solution.native_action {
            match *action {
                NativeAction::Wrap => wrap = true,
                NativeAction::Unwrap => unwrap = true,
            }
        }

        let mut tokens = Vec::with_capacity(2 + intermediary_tokens.len());
        if wrap {
            tokens.push(&self.wrapped_address);
        } else {
            tokens.push(&solution.given_token);
        }
        tokens.extend(intermediary_tokens);

        if unwrap {
            tokens.push(&self.wrapped_address);
        } else {
            tokens.push(&solution.checked_token);
        }

        let mut swaps = vec![];
        for grouped_swap in grouped_swaps.iter() {
            let protocol = &grouped_swap.protocol_system;
            let swap_encoder = self
                .get_swap_encoder(protocol)
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
                .get_transfers(grouped_swap, &solution.given_token, wrap, false);
            let encoding_context = EncodingContext {
                receiver: swap_receiver,
                exact_out: solution.exact_out,
                router_address: Some(self.router_address.clone()),
                group_token_in: grouped_swap.token_in.clone(),
                group_token_out: grouped_swap.token_out.clone(),
                transfer_type: transfer,
            };

            let mut grouped_protocol_data: Vec<Vec<u8>> = vec![];
            let mut initial_protocol_data: Vec<u8> = vec![];
            for swap in grouped_swap.swaps.iter() {
                let protocol_data = swap_encoder.encode_swap(swap, &encoding_context)?;
                if encoding_context.group_token_in == swap.token_in {
                    initial_protocol_data = protocol_data;
                } else {
                    grouped_protocol_data.push(protocol_data);
                }
            }

            if !grouped_protocol_data.is_empty() {
                initial_protocol_data.extend(ple_encode(grouped_protocol_data));
            }

            let swap_data = self.encode_swap_header(
                get_token_position(&tokens, &grouped_swap.token_in)?,
                get_token_position(&tokens, &grouped_swap.token_out)?,
                percentage_to_uint24(grouped_swap.split),
                Bytes::from_str(swap_encoder.executor_address()).map_err(|_| {
                    EncodingError::FatalError("Invalid executor address".to_string())
                })?,
                initial_protocol_data,
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
            function_signature: self.function_signature.clone(),
            swaps: encoded_swaps,
            permit: None,
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

    use alloy::{hex::encode, primitives::hex};
    use num_bigint::{BigInt, BigUint};
    use tycho_common::{
        models::{protocol::ProtocolComponent, Chain as TychoCommonChain},
        Bytes,
    };

    use super::*;
    use crate::encoding::models::Swap;

    fn eth_chain() -> Chain {
        TychoCommonChain::Ethereum.into()
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

    mod single {

        use super::*;
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
                user_data: None,
            };
            let swap_encoder_registry = get_swap_encoder_registry();
            let encoder = SingleSwapStrategyEncoder::new(
                eth_chain(),
                swap_encoder_registry,
                UserTransferType::TransferFromPermit2,
                router_address(),
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

            let encoded_solution = encoder
                .encode_strategy(&solution)
                .unwrap();

            let expected_swap = String::from(concat!(
                // Swap data
                "5615deb798bb3e4dfa0139dfa1b3d433cc23b72f", // executor address
                "c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2", // token in
                "a478c2975ab1ea89e8196811f51a7b7ade33eb11", // component id
                "cd09f75e2bf2a4d11f3ab23f1389fcc1621c0cc2", // receiver
                "00",                                       // zero2one
                "00",                                       // transfer type TransferFrom
            ));
            let hex_calldata = encode(&encoded_solution.swaps);

            assert_eq!(hex_calldata, expected_swap);
            assert_eq!(encoded_solution.function_signature, "singleSwapPermit2(uint256,address,address,uint256,bool,bool,address,((address,uint160,uint48,uint48),address,uint256),bytes,bytes)".to_string());
            assert_eq!(encoded_solution.interacting_with, router_address());
        }

        #[test]
        fn test_single_swap_strategy_encoder_no_transfer_in() {
            // Performs a single swap from WETH to DAI on a USV2 pool assuming that the tokens are
            // already in the router

            let weth = Bytes::from_str("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2").unwrap();
            let dai = Bytes::from_str("0x6b175474e89094c44da98b954eedeac495271d0f").unwrap();

            let checked_amount = BigUint::from_str("1_640_000000000000000000").unwrap();

            let swap = Swap {
                component: ProtocolComponent {
                    id: "0xA478c2975Ab1Ea89e8196811F51A7B7Ade33eB11".to_string(),
                    protocol_system: "uniswap_v2".to_string(),
                    ..Default::default()
                },
                token_in: weth.clone(),
                token_out: dai.clone(),
                split: 0f64,
                user_data: None,
            };
            let swap_encoder_registry = get_swap_encoder_registry();
            let encoder = SingleSwapStrategyEncoder::new(
                eth_chain(),
                swap_encoder_registry,
                UserTransferType::None,
                router_address(),
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
                .encode_strategy(&solution)
                .unwrap();

            let expected_input = [
                // Swap data
                "5615deb798bb3e4dfa0139dfa1b3d433cc23b72f", // executor address
                "c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2", // token in
                "a478c2975ab1ea89e8196811f51a7b7ade33eb11", // component id
                "cd09f75e2bf2a4d11f3ab23f1389fcc1621c0cc2", // receiver
                "00",                                       // zero2one
                "01",                                       // transfer type Transfer
            ]
            .join("");

            let hex_calldata = encode(&encoded_solution.swaps);

            assert_eq!(hex_calldata, expected_input);
            assert_eq!(
                encoded_solution.function_signature,
                "singleSwap(uint256,address,address,uint256,bool,bool,address,bool,bytes)"
                    .to_string()
            );
            assert_eq!(encoded_solution.interacting_with, router_address());
        }
    }

    mod sequential {
        use super::*;

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
                user_data: None,
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
                user_data: None,
            };
            let swap_encoder_registry = get_swap_encoder_registry();
            let encoder = SequentialSwapStrategyEncoder::new(
                eth_chain(),
                swap_encoder_registry,
                UserTransferType::TransferFrom,
                router_address(),
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
                .encode_strategy(&solution)
                .unwrap();

            let hex_calldata = encode(&encoded_solution.swaps);

            let expected = String::from(concat!(
                // swap 1
                "0052",                                     // swap length
                "5615deb798bb3e4dfa0139dfa1b3d433cc23b72f", // executor address
                "c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2", // token in
                "bb2b8038a1640196fbe3e38816f3e67cba72d940", // component id
                "004375dff511095cc5a197a54140a24efef3a416", // receiver (next pool)
                "00",                                       // zero to one
                "00",                                       // transfer type TransferFrom
                // swap 2
                "0052",                                     // swap length
                "5615deb798bb3e4dfa0139dfa1b3d433cc23b72f", // executor address
                "2260fac5e5542a773aa44fbcfedf7c193bc2c599", // token in
                "004375dff511095cc5a197a54140a24efef3a416", // component id
                "cd09f75e2bf2a4d11f3ab23f1389fcc1621c0cc2", // receiver (final user)
                "01",                                       // zero to one
                "02",                                       // transfer type None
            ));

            assert_eq!(hex_calldata, expected);
            assert_eq!(
                encoded_solution.function_signature,
                "sequentialSwap(uint256,address,address,uint256,bool,bool,address,bool,bytes)"
                    .to_string()
            );
            assert_eq!(encoded_solution.interacting_with, router_address());
        }
    }

    mod split {
        use super::*;

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
                user_data: None,
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
                split: 0f64,
                user_data: None, // Remaining 40%
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
                user_data: None,
            };

            let swap_encoder_registry = get_swap_encoder_registry();
            let encoder = SplitSwapStrategyEncoder::new(
                eth_chain(),
                swap_encoder_registry,
                UserTransferType::TransferFromPermit2,
                Bytes::from("0x3Ede3eCa2a72B3aeCC820E955B36f38437D01395"),
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

            let encoded_solution = encoder
                .encode_strategy(&solution)
                .unwrap();

            let hex_calldata = hex::encode(&encoded_solution.swaps);

            let expected_swaps = [
                "006e",                                     // ple encoded swaps
                "00",                                       // token in index
                "01",                                       // token out index
                "999999",                                   // split
                "2e234dae75c793f67a35089c9d99245e1c58470b", // executor address
                "a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", // token in
                "c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2", // token out
                "0001f4",                                   // pool fee
                "3ede3eca2a72b3aecc820e955b36f38437d01395", // receiver
                "88e6a0c2ddd26feeb64f039a2c41296fcb3f5640", // component id
                "01",                                       // zero2one
                "00",                                       // transfer type TransferFrom
                "006e",                                     // ple encoded swaps
                "00",                                       // token in index
                "01",                                       // token out index
                "000000",                                   // split
                "2e234dae75c793f67a35089c9d99245e1c58470b", // executor address
                "a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", // token in
                "c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2", // token out
                "000bb8",                                   // pool fee
                "3ede3eca2a72b3aecc820e955b36f38437d01395", // receiver
                "8ad599c3a0ff1de082011efddc58f1908eb6e6d8", // component id
                "01",                                       // zero2one
                "00",                                       // transfer type TransferFrom
                "0057",                                     // ple encoded swaps
                "01",                                       // token in index
                "00",                                       // token out index
                "000000",                                   // split
                "5615deb798bb3e4dfa0139dfa1b3d433cc23b72f", // executor address,
                "c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2", // token in
                "b4e16d0168e52d35cacd2c6185b44281ec28c9dc", // component id,
                "cd09f75e2bf2a4d11f3ab23f1389fcc1621c0cc2", // receiver
                "00",                                       // zero2one
                "01",                                       // transfer type Transfer
            ]
            .join("");
            assert_eq!(hex_calldata, expected_swaps);
            assert_eq!(
                encoded_solution.function_signature,
                "splitSwapPermit2(uint256,address,address,uint256,bool,bool,uint256,address,((address,uint160,uint48,uint48),address,uint256),bytes,bytes)"
                    .to_string()
            );
            assert_eq!(encoded_solution.interacting_with, router_address());
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
                user_data: None,
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
                user_data: None,
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
                user_data: None,
            };

            let swap_encoder_registry = get_swap_encoder_registry();
            let encoder = SplitSwapStrategyEncoder::new(
                eth_chain(),
                swap_encoder_registry,
                UserTransferType::TransferFrom,
                Bytes::from("0x3Ede3eCa2a72B3aeCC820E955B36f38437D01395"),
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

            let encoded_solution = encoder
                .encode_strategy(&solution)
                .unwrap();

            let hex_calldata = hex::encode(&encoded_solution.swaps);

            let expected_swaps = [
                "0057",                                     // ple encoded swaps
                "00",                                       // token in index
                "01",                                       // token out index
                "000000",                                   // split
                "5615deb798bb3e4dfa0139dfa1b3d433cc23b72f", // executor address
                "a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", // token in
                "b4e16d0168e52d35cacd2c6185b44281ec28c9dc", // component id
                "3ede3eca2a72b3aecc820e955b36f38437d01395", // receiver
                "01",                                       // zero2one
                "00",                                       // transfer type TransferFrom
                "006e",                                     // ple encoded swaps
                "01",                                       // token in index
                "00",                                       // token out index
                "999999",                                   // split
                "2e234dae75c793f67a35089c9d99245e1c58470b", // executor address
                "c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2", // token in
                "a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", // token out
                "0001f4",                                   // pool fee
                "cd09f75e2bf2a4d11f3ab23f1389fcc1621c0cc2", // receiver
                "88e6a0c2ddd26feeb64f039a2c41296fcb3f5640", // component id
                "00",                                       // zero2one
                "01",                                       // transfer type Transfer
                "006e",                                     // ple encoded swaps
                "01",                                       // token in index
                "00",                                       // token out index
                "000000",                                   // split
                "2e234dae75c793f67a35089c9d99245e1c58470b", // executor address
                "c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2", // token in
                "a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", // token out
                "000bb8",                                   // pool fee
                "cd09f75e2bf2a4d11f3ab23f1389fcc1621c0cc2", // receiver
                "8ad599c3a0ff1de082011efddc58f1908eb6e6d8", // component id
                "00",                                       // zero2one
                "01",                                       // transfer type Transfer
            ]
            .join("");

            assert_eq!(hex_calldata, expected_swaps);
            assert_eq!(
                encoded_solution.function_signature,
                "splitSwap(uint256,address,address,uint256,bool,bool,uint256,address,bool,bytes)"
                    .to_string()
            );
            assert_eq!(encoded_solution.interacting_with, router_address());
        }
    }
}
