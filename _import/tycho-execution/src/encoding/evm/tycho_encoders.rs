use std::{collections::HashSet, str::FromStr};

use alloy::signers::local::PrivateKeySigner;
use tycho_common::{models::Chain, Bytes};

use crate::encoding::{
    errors::EncodingError,
    evm::{
        approvals::permit2::Permit2,
        constants::{GROUPABLE_PROTOCOLS, IN_TRANSFER_REQUIRED_PROTOCOLS},
        encoding_utils::encode_tycho_router_call,
        group_swaps::group_swaps,
        strategy_encoder::strategy_encoders::{
            SequentialSwapStrategyEncoder, SingleSwapStrategyEncoder, SplitSwapStrategyEncoder,
        },
        swap_encoder::swap_encoder_registry::SwapEncoderRegistry,
    },
    models::{
        EncodedSolution, EncodingContext, NativeAction, Solution, Transaction, TransferType,
        UserTransferType,
    },
    strategy_encoder::StrategyEncoder,
    tycho_encoder::TychoEncoder,
};

/// Encodes solutions to be used by the TychoRouter.
///
/// # Fields
/// * `chain`: Chain to be used
/// * `single_swap_strategy`: Encoder for single swaps
/// * `sequential_swap_strategy`: Encoder for sequential swaps
/// * `split_swap_strategy`: Encoder for split swaps
/// * `router_address`: Address of the Tycho router contract
/// * `user_transfer_type`: Type of user transfer
/// * `permit2`: Optional Permit2 instance for permit transfers
/// * `signer`: Optional signer (used only for permit2 and full calldata encoding)
#[derive(Clone)]
pub struct TychoRouterEncoder {
    chain: Chain,
    single_swap_strategy: SingleSwapStrategyEncoder,
    sequential_swap_strategy: SequentialSwapStrategyEncoder,
    split_swap_strategy: SplitSwapStrategyEncoder,
    router_address: Bytes,
    user_transfer_type: UserTransferType,
    permit2: Option<Permit2>,
    signer: Option<PrivateKeySigner>,
}

impl TychoRouterEncoder {
    pub fn new(
        chain: Chain,
        swap_encoder_registry: SwapEncoderRegistry,
        router_address: Bytes,
        user_transfer_type: UserTransferType,
        signer: Option<PrivateKeySigner>,
    ) -> Result<Self, EncodingError> {
        let permit2 = if user_transfer_type == UserTransferType::TransferFromPermit2 {
            Some(Permit2::new()?)
        } else {
            None
        };
        Ok(TychoRouterEncoder {
            single_swap_strategy: SingleSwapStrategyEncoder::new(
                chain,
                swap_encoder_registry.clone(),
                user_transfer_type.clone(),
                router_address.clone(),
            )?,
            sequential_swap_strategy: SequentialSwapStrategyEncoder::new(
                chain,
                swap_encoder_registry.clone(),
                user_transfer_type.clone(),
                router_address.clone(),
            )?,
            split_swap_strategy: SplitSwapStrategyEncoder::new(
                chain,
                swap_encoder_registry,
                user_transfer_type.clone(),
                router_address.clone(),
            )?,
            router_address,
            permit2,
            signer,
            chain,
            user_transfer_type,
        })
    }

    fn encode_solution(&self, solution: &Solution) -> Result<EncodedSolution, EncodingError> {
        self.validate_solution(solution)?;
        let protocols: HashSet<String> = solution
            .swaps
            .iter()
            .map(|swap| swap.component.protocol_system.clone())
            .collect();

        let mut encoded_solution = if (solution.swaps.len() == 1) ||
            ((protocols.len() == 1 &&
                protocols
                    .iter()
                    .any(|p| GROUPABLE_PROTOCOLS.contains(&p.as_str()))) &&
                solution
                    .swaps
                    .iter()
                    .all(|swap| swap.split == 0.0))
        {
            self.single_swap_strategy
                .encode_strategy(solution)?
        } else if solution
            .swaps
            .iter()
            .all(|swap| swap.split == 0.0)
        {
            self.sequential_swap_strategy
                .encode_strategy(solution)?
        } else {
            self.split_swap_strategy
                .encode_strategy(solution)?
        };

        if let Some(permit2) = &self.permit2 {
            let permit = permit2.get_permit(
                &self.router_address,
                &solution.sender,
                &solution.given_token,
                &solution.given_amount,
            )?;
            encoded_solution.permit = Some(permit);
        }
        Ok(encoded_solution)
    }
}

impl TychoEncoder for TychoRouterEncoder {
    fn encode_solutions(
        &self,
        solutions: Vec<Solution>,
    ) -> Result<Vec<EncodedSolution>, EncodingError> {
        let mut result: Vec<EncodedSolution> = Vec::new();
        for solution in solutions.iter() {
            let encoded_solution = self.encode_solution(solution)?;
            result.push(encoded_solution);
        }
        Ok(result)
    }

    fn encode_full_calldata(
        &self,
        solutions: Vec<Solution>,
    ) -> Result<Vec<Transaction>, EncodingError> {
        let mut transactions: Vec<Transaction> = Vec::new();
        for solution in solutions.iter() {
            let encoded_solution = self.encode_solution(solution)?;

            let transaction = encode_tycho_router_call(
                self.chain.id(),
                encoded_solution,
                solution,
                &self.user_transfer_type,
                &self.chain.native_token().address,
                self.signer.clone(),
            )?;

            transactions.push(transaction);
        }
        Ok(transactions)
    }

    /// Raises an `EncodingError` if the solution is not considered valid.
    ///
    /// A solution is considered valid if all the following conditions are met:
    /// * The solution is not exact out.
    /// * The solution has at least one swap.
    /// * If the solution is wrapping, the given token is the chain's native token and the first
    ///   swap's input is the chain's wrapped token.
    /// * If the solution is unwrapping, the checked token is the chain's native token and the last
    ///   swap's output is the chain's wrapped token.
    /// * The token cannot appear more than once in the solution unless it is the first and last
    ///   token (i.e. a true cyclical swap).
    fn validate_solution(&self, solution: &Solution) -> Result<(), EncodingError> {
        if solution.exact_out {
            return Err(EncodingError::FatalError(
                "Currently only exact input solutions are supported".to_string(),
            ));
        }
        if solution.swaps.is_empty() {
            return Err(EncodingError::FatalError("No swaps found in solution".to_string()));
        }
        let native_address = self.chain.native_token().address;
        let wrapped_address = self
            .chain
            .wrapped_native_token()
            .address;
        if let Some(native_action) = &solution.native_action {
            if native_action == &NativeAction::Wrap {
                if solution.given_token != native_address {
                    return Err(EncodingError::FatalError(
                        "Native token must be the input token in order to wrap".to_string(),
                    ));
                }
                if let Some(first_swap) = solution.swaps.first() {
                    if first_swap.token_in != wrapped_address {
                        return Err(EncodingError::FatalError(
                            "Wrapped token must be the first swap's input in order to wrap"
                                .to_string(),
                        ));
                    }
                }
            } else if native_action == &NativeAction::Unwrap {
                if solution.checked_token != native_address {
                    return Err(EncodingError::FatalError(
                        "Native token must be the output token in order to unwrap".to_string(),
                    ));
                }
                if let Some(last_swap) = solution.swaps.last() {
                    if last_swap.token_out != wrapped_address {
                        return Err(EncodingError::FatalError(
                            "Wrapped token must be the last swap's output in order to unwrap"
                                .to_string(),
                        ));
                    }
                }
            }
        }

        let mut solution_tokens = vec![];
        let mut split_tokens_already_considered = HashSet::new();
        for (i, swap) in solution.swaps.iter().enumerate() {
            // so we don't count the split tokens more than once
            if swap.split != 0.0 {
                if !split_tokens_already_considered.contains(&swap.token_in) {
                    solution_tokens.push(&swap.token_in);
                    split_tokens_already_considered.insert(&swap.token_in);
                }
            } else {
                // it might be the last swap of the split or a regular swap
                if !split_tokens_already_considered.contains(&swap.token_in) {
                    solution_tokens.push(&swap.token_in);
                }
            }
            if i == solution.swaps.len() - 1 {
                solution_tokens.push(&swap.token_out);
            }
        }

        if solution_tokens.len() !=
            solution_tokens
                .iter()
                .cloned()
                .collect::<HashSet<&Bytes>>()
                .len()
        {
            if let Some(last_swap) = solution.swaps.last() {
                if solution.swaps[0].token_in != last_swap.token_out {
                    return Err(EncodingError::FatalError(
                        "Cyclical swaps are only allowed if they are the first and last token of a solution".to_string(),
                    ));
                } else {
                    // it is a valid cyclical swap
                    // we don't support any wrapping or unwrapping in this case
                    if let Some(_native_action) = &solution.native_action {
                        return Err(EncodingError::FatalError(
                            "Wrapping/Unwrapping is not available in cyclical swaps".to_string(),
                        ));
                    }
                }
            }
        }
        Ok(())
    }
}

/// Represents an encoder for one swap to be executed directly against an Executor.
///
/// This is useful when you want to bypass the Tycho Router, use your own Router contract and
/// just need the calldata for a particular swap.
///
/// # Fields
/// * `swap_encoder_registry`: Registry of swap encoders
#[derive(Clone)]
pub struct TychoExecutorEncoder {
    swap_encoder_registry: SwapEncoderRegistry,
}

impl TychoExecutorEncoder {
    pub fn new(swap_encoder_registry: SwapEncoderRegistry) -> Result<Self, EncodingError> {
        Ok(TychoExecutorEncoder { swap_encoder_registry })
    }

    fn encode_executor_calldata(
        &self,
        solution: &Solution,
    ) -> Result<EncodedSolution, EncodingError> {
        let grouped_swaps = group_swaps(&solution.swaps);
        let number_of_groups = grouped_swaps.len();
        if number_of_groups > 1 {
            return Err(EncodingError::InvalidInput(format!(
                "Tycho executor encoder only supports one swap. Found {number_of_groups}"
            )))
        }

        let grouped_swap = grouped_swaps
            .first()
            .ok_or_else(|| EncodingError::FatalError("Swap grouping failed".to_string()))?;

        let swap_encoder = self
            .swap_encoder_registry
            .get_encoder(&grouped_swap.protocol_system)
            .ok_or_else(|| {
                EncodingError::InvalidInput(format!(
                    "Swap encoder not found for protocol: {}",
                    grouped_swap.protocol_system
                ))
            })?;

        let mut grouped_protocol_data: Vec<u8> = vec![];
        for swap in grouped_swap.swaps.iter() {
            let transfer = if IN_TRANSFER_REQUIRED_PROTOCOLS
                .contains(&swap.component.protocol_system.as_str())
            {
                TransferType::Transfer
            } else {
                TransferType::None
            };
            let encoding_context = EncodingContext {
                receiver: solution.receiver.clone(),
                exact_out: solution.exact_out,
                router_address: None,
                group_token_in: grouped_swap.token_in.clone(),
                group_token_out: grouped_swap.token_out.clone(),
                transfer_type: transfer,
            };
            let protocol_data = swap_encoder.encode_swap(swap, &encoding_context)?;
            grouped_protocol_data.extend(protocol_data);
        }

        let executor_address = Bytes::from_str(swap_encoder.executor_address())
            .map_err(|_| EncodingError::FatalError("Invalid executor address".to_string()))?;

        Ok(EncodedSolution {
            swaps: grouped_protocol_data,
            interacting_with: executor_address,
            permit: None,
            function_signature: "".to_string(),
            n_tokens: 0,
        })
    }
}

impl TychoEncoder for TychoExecutorEncoder {
    fn encode_solutions(
        &self,
        solutions: Vec<Solution>,
    ) -> Result<Vec<EncodedSolution>, EncodingError> {
        let solution = solutions
            .first()
            .ok_or(EncodingError::FatalError("No solutions found".to_string()))?;
        self.validate_solution(solution)?;

        let encoded_solution = self.encode_executor_calldata(solution)?;

        Ok(vec![encoded_solution])
    }

    fn encode_full_calldata(
        &self,
        _solutions: Vec<Solution>,
    ) -> Result<Vec<Transaction>, EncodingError> {
        Err(EncodingError::NotImplementedError(
            "Full calldata encoding is not supported for TychoExecutorEncoder".to_string(),
        ))
    }

    /// Raises an `EncodingError` if the solution is not considered valid.
    ///
    /// A solution is considered valid if all the following conditions are met:
    /// * The solution is not exact out.
    fn validate_solution(&self, solution: &Solution) -> Result<(), EncodingError> {
        if solution.exact_out {
            return Err(EncodingError::FatalError(
                "Currently only exact input solutions are supported".to_string(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, str::FromStr};

    use num_bigint::{BigInt, BigUint};
    use tycho_common::models::{protocol::ProtocolComponent, Chain};

    use super::*;
    use crate::encoding::models::{Swap, SwapBuilder};

    fn dai() -> Bytes {
        Bytes::from_str("0x6b175474e89094c44da98b954eedeac495271d0f").unwrap()
    }

    fn eth() -> Bytes {
        Bytes::from_str("0x0000000000000000000000000000000000000000").unwrap()
    }

    fn weth() -> Bytes {
        Bytes::from_str("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2").unwrap()
    }

    fn usdc() -> Bytes {
        Bytes::from_str("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48").unwrap()
    }

    fn wbtc() -> Bytes {
        Bytes::from_str("0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599").unwrap()
    }

    fn pepe() -> Bytes {
        Bytes::from_str("0x6982508145454Ce325dDbE47a25d4ec3d2311933").unwrap()
    }

    // Fee and tick spacing information for this test is obtained by querying the
    // USV4 Position Manager contract: 0xbd216513d74c8cf14cf4747e6aaa6420ff64ee9e
    // Using the poolKeys function with the first 25 bytes of the pool id
    fn swap_usdc_eth_univ4() -> Swap<'static> {
        let pool_fee_usdc_eth = Bytes::from(BigInt::from(3000).to_signed_bytes_be());
        let tick_spacing_usdc_eth = Bytes::from(BigInt::from(60).to_signed_bytes_be());
        let mut static_attributes_usdc_eth: HashMap<String, Bytes> = HashMap::new();
        static_attributes_usdc_eth.insert("key_lp_fee".into(), pool_fee_usdc_eth);
        static_attributes_usdc_eth.insert("tick_spacing".into(), tick_spacing_usdc_eth);
        SwapBuilder::new(
            ProtocolComponent {
                id: "0xdce6394339af00981949f5f3baf27e3610c76326a700af57e4b3e3ae4977f78d"
                    .to_string(),
                protocol_system: "uniswap_v4".to_string(),
                static_attributes: static_attributes_usdc_eth,
                ..Default::default()
            },
            usdc().clone(),
            eth().clone(),
        )
        .build()
    }

    fn swap_eth_pepe_univ4() -> Swap<'static> {
        let pool_fee_eth_pepe = Bytes::from(BigInt::from(25000).to_signed_bytes_be());
        let tick_spacing_eth_pepe = Bytes::from(BigInt::from(500).to_signed_bytes_be());
        let mut static_attributes_eth_pepe: HashMap<String, Bytes> = HashMap::new();
        static_attributes_eth_pepe.insert("key_lp_fee".into(), pool_fee_eth_pepe);
        static_attributes_eth_pepe.insert("tick_spacing".into(), tick_spacing_eth_pepe);
        SwapBuilder::new(
            ProtocolComponent {
                id: "0xecd73ecbf77219f21f129c8836d5d686bbc27d264742ddad620500e3e548e2c9"
                    .to_string(),
                protocol_system: "uniswap_v4".to_string(),
                static_attributes: static_attributes_eth_pepe,
                ..Default::default()
            },
            eth().clone(),
            pepe().clone(),
        )
        .build()
    }

    fn router_address() -> Bytes {
        Bytes::from_str("0x3Ede3eCa2a72B3aeCC820E955B36f38437D01395").unwrap()
    }

    fn eth_chain() -> Chain {
        Chain::Ethereum
    }

    fn get_swap_encoder_registry() -> SwapEncoderRegistry {
        SwapEncoderRegistry::new(
            Some("config/test_executor_addresses.json".to_string()),
            eth_chain(),
        )
        .unwrap()
    }

    fn get_tycho_router_encoder(user_transfer_type: UserTransferType) -> TychoRouterEncoder {
        TychoRouterEncoder::new(
            eth_chain(),
            get_swap_encoder_registry(),
            router_address(),
            user_transfer_type,
            None,
        )
        .unwrap()
    }

    mod router_encoder {
        use super::*;

        #[test]
        #[allow(deprecated)]
        fn test_encode_router_calldata_single_swap() {
            let encoder = get_tycho_router_encoder(UserTransferType::TransferFrom);
            let eth_amount_in = BigUint::from(1000u32);
            let swap = SwapBuilder::new(
                ProtocolComponent {
                    id: "0xA478c2975Ab1Ea89e8196811F51A7B7Ade33eB11".to_string(),
                    protocol_system: "uniswap_v2".to_string(),
                    ..Default::default()
                },
                weth().clone(),
                dai().clone(),
            )
            .build();

            let solution = Solution {
                exact_out: false,
                given_amount: eth_amount_in.clone(),
                given_token: eth(),
                checked_token: dai(),
                swaps: vec![swap],
                receiver: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
                native_action: Some(NativeAction::Wrap),
                ..Default::default()
            };

            let transactions = encoder.encode_full_calldata(vec![solution]);
            assert!(transactions.is_ok());
            let transactions = transactions.unwrap();
            assert_eq!(transactions.len(), 1);
            assert_eq!(transactions[0].value, eth_amount_in);
            assert_eq!(
                transactions[0].to,
                Bytes::from_str("0x3ede3eca2a72b3aecc820e955b36f38437d01395").unwrap()
            );
            // single swap selector
            assert_eq!(&hex::encode(transactions[0].clone().data)[..8], "5c4b639c");
        }

        #[test]
        #[allow(deprecated)]
        fn test_encode_router_calldata_single_swap_group() {
            let encoder = get_tycho_router_encoder(UserTransferType::TransferFrom);
            let solution = Solution {
                exact_out: false,
                given_token: usdc(),
                given_amount: BigUint::from_str("1000_000000").unwrap(),
                checked_token: pepe(),
                checked_amount: BigUint::from_str("105_152_000000000000000000").unwrap(),
                sender: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
                receiver: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
                swaps: vec![swap_usdc_eth_univ4(), swap_eth_pepe_univ4()],
                ..Default::default()
            };

            let transactions = encoder.encode_full_calldata(vec![solution]);
            assert!(transactions.is_ok());
            let transactions = transactions.unwrap();
            assert_eq!(transactions.len(), 1);
            // single swap selector
            assert_eq!(&hex::encode(transactions[0].clone().data)[..8], "5c4b639c");
        }

        #[test]
        #[allow(deprecated)]
        fn test_encode_router_calldata_sequential_swap() {
            let encoder = get_tycho_router_encoder(UserTransferType::TransferFrom);
            let eth_amount_in = BigUint::from(1000u32);
            let swap_weth_dai = SwapBuilder::new(
                ProtocolComponent {
                    id: "0xA478c2975Ab1Ea89e8196811F51A7B7Ade33eB11".to_string(),
                    protocol_system: "uniswap_v2".to_string(),
                    ..Default::default()
                },
                weth().clone(),
                dai().clone(),
            )
            .build();

            let swap_dai_usdc = SwapBuilder::new(
                ProtocolComponent {
                    id: "0xA478c2975Ab1Ea89e8196811F51A7B7Ade33eB11".to_string(),
                    protocol_system: "uniswap_v2".to_string(),
                    ..Default::default()
                },
                dai().clone(),
                usdc().clone(),
            )
            .build();

            let solution = Solution {
                exact_out: false,
                given_amount: eth_amount_in.clone(),
                given_token: eth(),
                checked_token: usdc(),
                swaps: vec![swap_weth_dai, swap_dai_usdc],
                receiver: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
                native_action: Some(NativeAction::Wrap),
                checked_amount: BigUint::from(1000u32),
                ..Default::default()
            };

            let transactions = encoder.encode_full_calldata(vec![solution]);
            assert!(transactions.is_ok());
            let transactions = transactions.unwrap();
            assert_eq!(transactions.len(), 1);
            assert_eq!(transactions[0].value, eth_amount_in);
            // sequential swap selector
            assert_eq!(&hex::encode(transactions[0].clone().data)[..8], "e21dd0d3");
        }

        #[test]
        fn test_encode_router_calldata_split_swap_group() {
            let encoder = get_tycho_router_encoder(UserTransferType::TransferFrom);
            let mut swap_usdc_eth = swap_usdc_eth_univ4();
            swap_usdc_eth.split = 0.5; // Set split to 50%
            let solution = Solution {
                exact_out: false,
                given_token: usdc(),
                given_amount: BigUint::from_str("1000_000000").unwrap(),
                checked_token: eth(),
                checked_amount: BigUint::from_str("105_152_000000000000000000").unwrap(),
                sender: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
                receiver: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
                swaps: vec![swap_usdc_eth, swap_usdc_eth_univ4()],
                ..Default::default()
            };

            let encoded_solution_res = encoder.encode_solution(&solution);
            assert!(encoded_solution_res.is_ok());

            let encoded_solution = encoded_solution_res.unwrap();
            assert!(encoded_solution
                .function_signature
                .contains("splitSwap"));
        }

        #[test]
        fn test_validate_fails_for_exact_out() {
            let encoder = get_tycho_router_encoder(UserTransferType::TransferFrom);
            let solution = Solution {
                exact_out: true, // This should cause an error
                ..Default::default()
            };
            let result = encoder.validate_solution(&solution);

            assert!(result.is_err());
            assert_eq!(
                result.err().unwrap(),
                EncodingError::FatalError(
                    "Currently only exact input solutions are supported".to_string()
                )
            );
        }

        #[test]
        fn test_validate_passes_for_wrap() {
            let encoder = get_tycho_router_encoder(UserTransferType::TransferFrom);
            let swap = SwapBuilder::new(
                ProtocolComponent {
                    id: "0xA478c2975Ab1Ea89e8196811F51A7B7Ade33eB11".to_string(),
                    protocol_system: "uniswap_v2".to_string(),
                    ..Default::default()
                },
                weth().clone(),
                dai().clone(),
            )
            .build();

            let solution = Solution {
                exact_out: false,
                given_token: eth(),
                checked_token: dai(),
                swaps: vec![swap],
                native_action: Some(NativeAction::Wrap),
                ..Default::default()
            };

            let result = encoder.validate_solution(&solution);

            assert!(result.is_ok());
        }

        #[test]
        fn test_validate_fails_for_wrap_wrong_input() {
            let encoder = get_tycho_router_encoder(UserTransferType::TransferFrom);
            let swap = SwapBuilder::new(
                ProtocolComponent {
                    id: "0xA478c2975Ab1Ea89e8196811F51A7B7Ade33eB11".to_string(),
                    protocol_system: "uniswap_v2".to_string(),
                    ..Default::default()
                },
                weth().clone(),
                dai().clone(),
            )
            .build();

            let solution = Solution {
                exact_out: false,
                given_token: weth(),
                swaps: vec![swap],
                native_action: Some(NativeAction::Wrap),
                ..Default::default()
            };

            let result = encoder.validate_solution(&solution);

            assert!(result.is_err());
            assert_eq!(
                result.err().unwrap(),
                EncodingError::FatalError(
                    "Native token must be the input token in order to wrap".to_string()
                )
            );
        }

        #[test]
        fn test_validate_fails_for_wrap_wrong_first_swap() {
            let encoder = get_tycho_router_encoder(UserTransferType::TransferFrom);
            let swap = SwapBuilder::new(
                ProtocolComponent {
                    id: "0xA478c2975Ab1Ea89e8196811F51A7B7Ade33eB11".to_string(),
                    protocol_system: "uniswap_v2".to_string(),
                    ..Default::default()
                },
                eth().clone(),
                dai().clone(),
            )
            .build();

            let solution = Solution {
                exact_out: false,
                given_token: eth(),
                swaps: vec![swap],
                native_action: Some(NativeAction::Wrap),
                ..Default::default()
            };

            let result = encoder.validate_solution(&solution);

            assert!(result.is_err());
            assert_eq!(
                result.err().unwrap(),
                EncodingError::FatalError(
                    "Wrapped token must be the first swap's input in order to wrap".to_string()
                )
            );
        }

        #[test]
        fn test_validate_fails_no_swaps() {
            let encoder = get_tycho_router_encoder(UserTransferType::TransferFrom);
            let solution = Solution {
                exact_out: false,
                given_token: eth(),
                swaps: vec![],
                native_action: Some(NativeAction::Wrap),
                ..Default::default()
            };

            let result = encoder.validate_solution(&solution);

            assert!(result.is_err());
            assert_eq!(
                result.err().unwrap(),
                EncodingError::FatalError("No swaps found in solution".to_string())
            );
        }

        #[test]
        fn test_validate_passes_for_unwrap() {
            let encoder = get_tycho_router_encoder(UserTransferType::TransferFrom);
            let swap = SwapBuilder::new(
                ProtocolComponent {
                    id: "0xA478c2975Ab1Ea89e8196811F51A7B7Ade33eB11".to_string(),
                    protocol_system: "uniswap_v2".to_string(),
                    ..Default::default()
                },
                dai().clone(),
                weth().clone(),
            )
            .build();

            let solution = Solution {
                exact_out: false,
                checked_token: eth(),
                swaps: vec![swap],
                native_action: Some(NativeAction::Unwrap),
                ..Default::default()
            };

            let result = encoder.validate_solution(&solution);

            assert!(result.is_ok());
        }

        #[test]
        fn test_validate_fails_for_unwrap_wrong_output() {
            let encoder = get_tycho_router_encoder(UserTransferType::TransferFrom);
            let swap = SwapBuilder::new(
                ProtocolComponent {
                    id: "0xA478c2975Ab1Ea89e8196811F51A7B7Ade33eB11".to_string(),
                    protocol_system: "uniswap_v2".to_string(),
                    ..Default::default()
                },
                dai().clone(),
                weth().clone(),
            )
            .build();

            let solution = Solution {
                exact_out: false,
                given_token: dai(),
                checked_token: weth(),
                swaps: vec![swap],
                native_action: Some(NativeAction::Unwrap),
                ..Default::default()
            };

            let result = encoder.validate_solution(&solution);

            assert!(result.is_err());
            assert_eq!(
                result.err().unwrap(),
                EncodingError::FatalError(
                    "Native token must be the output token in order to unwrap".to_string()
                )
            );
        }

        #[test]
        fn test_validate_fails_for_unwrap_wrong_last_swap() {
            let encoder = get_tycho_router_encoder(UserTransferType::TransferFrom);
            let swap = SwapBuilder::new(
                ProtocolComponent {
                    id: "0xA478c2975Ab1Ea89e8196811F51A7B7Ade33eB11".to_string(),
                    protocol_system: "uniswap_v2".to_string(),
                    ..Default::default()
                },
                dai().clone(),
                eth().clone(),
            )
            .build();

            let solution = Solution {
                exact_out: false,
                checked_token: eth(),
                swaps: vec![swap],
                native_action: Some(NativeAction::Unwrap),
                ..Default::default()
            };

            let result = encoder.validate_solution(&solution);

            assert!(result.is_err());
            assert_eq!(
                result.err().unwrap(),
                EncodingError::FatalError(
                    "Wrapped token must be the last swap's output in order to unwrap".to_string()
                )
            );
        }

        #[test]
        fn test_validate_cyclical_swap() {
            // This validation passes because the cyclical swap is the first and last token
            //      50% ->  WETH
            // DAI -              -> DAI
            //      50% -> WETH
            // (some of the pool addresses in this test are fake)
            let encoder = get_tycho_router_encoder(UserTransferType::TransferFrom);
            let swaps = vec![
                SwapBuilder::new(
                    ProtocolComponent {
                        id: "0xA478c2975Ab1Ea89e8196811F51A7B7Ade33eB11".to_string(),
                        protocol_system: "uniswap_v2".to_string(),
                        ..Default::default()
                    },
                    dai().clone(),
                    weth().clone(),
                )
                .build(),
                SwapBuilder::new(
                    ProtocolComponent {
                        id: "0x0000000000000000000000000000000000000000".to_string(),
                        protocol_system: "uniswap_v2".to_string(),
                        ..Default::default()
                    },
                    dai().clone(),
                    weth().clone(),
                )
                .build(),
                SwapBuilder::new(
                    ProtocolComponent {
                        id: "0x0000000000000000000000000000000000000000".to_string(),
                        protocol_system: "uniswap_v2".to_string(),
                        ..Default::default()
                    },
                    weth().clone(),
                    dai().clone(),
                )
                .build(),
            ];

            let solution = Solution {
                exact_out: false,
                given_token: dai(),
                checked_token: dai(),
                swaps,
                ..Default::default()
            };

            let result = encoder.validate_solution(&solution);

            assert!(result.is_ok());
        }

        #[test]
        fn test_validate_cyclical_swap_fail() {
            // This test should fail because the cyclical swap is not the first and last token
            // DAI -> WETH -> USDC -> DAI -> WBTC
            // (some of the pool addresses in this test are fake)
            let encoder = get_tycho_router_encoder(UserTransferType::TransferFrom);
            let swaps = vec![
                SwapBuilder::new(
                    ProtocolComponent {
                        id: "0xA478c2975Ab1Ea89e8196811F51A7B7Ade33eB11".to_string(),
                        protocol_system: "uniswap_v2".to_string(),
                        ..Default::default()
                    },
                    dai().clone(),
                    weth().clone(),
                )
                .build(),
                SwapBuilder::new(
                    ProtocolComponent {
                        id: "0xB4e16d0168e52d35CaCD2c6185b44281Ec28C9Dc".to_string(),
                        protocol_system: "uniswap_v2".to_string(),
                        ..Default::default()
                    },
                    weth().clone(),
                    usdc().clone(),
                )
                .build(),
                SwapBuilder::new(
                    ProtocolComponent {
                        id: "0x0000000000000000000000000000000000000000".to_string(),
                        protocol_system: "uniswap_v2".to_string(),
                        ..Default::default()
                    },
                    usdc().clone(),
                    dai().clone(),
                )
                .build(),
                SwapBuilder::new(
                    ProtocolComponent {
                        id: "0x0000000000000000000000000000000000000000".to_string(),
                        protocol_system: "uniswap_v2".to_string(),
                        ..Default::default()
                    },
                    dai().clone(),
                    wbtc().clone(),
                )
                .build(),
            ];

            let solution = Solution {
                exact_out: false,
                given_token: dai(),
                checked_token: wbtc(),
                swaps,
                ..Default::default()
            };

            let result = encoder.validate_solution(&solution);

            assert!(result.is_err());
            assert_eq!(
            result.err().unwrap(),
            EncodingError::FatalError(
                "Cyclical swaps are only allowed if they are the first and last token of a solution".to_string()
            )
        );
        }
        #[test]
        fn test_validate_cyclical_swap_split_output() {
            // This validation passes because it is a valid cyclical swap
            //             -> WETH
            // WETH -> DAI
            //             -> WETH
            // (some of the pool addresses in this test are fake)
            let encoder = get_tycho_router_encoder(UserTransferType::TransferFrom);
            let swaps = vec![
                SwapBuilder::new(
                    ProtocolComponent {
                        id: "0xA478c2975Ab1Ea89e8196811F51A7B7Ade33eB11".to_string(),
                        protocol_system: "uniswap_v2".to_string(),
                        ..Default::default()
                    },
                    weth(),
                    dai(),
                )
                .build(),
                SwapBuilder::new(
                    ProtocolComponent {
                        id: "0x0000000000000000000000000000000000000000".to_string(),
                        protocol_system: "uniswap_v2".to_string(),
                        ..Default::default()
                    },
                    dai(),
                    weth(),
                )
                .split(0.5)
                .build(),
                SwapBuilder::new(
                    ProtocolComponent {
                        id: "0x0000000000000000000000000000000000000000".to_string(),
                        protocol_system: "uniswap_v2".to_string(),
                        ..Default::default()
                    },
                    dai(),
                    weth(),
                )
                .build(),
            ];

            let solution = Solution {
                exact_out: false,
                given_token: weth(),
                checked_token: weth(),
                swaps,
                ..Default::default()
            };

            let result = encoder.validate_solution(&solution);

            assert!(result.is_ok());
        }

        #[test]
        fn test_validate_cyclical_swap_native_action_fail() {
            // This validation fails because there is a native action with a valid cyclical swap
            // ETH -> WETH -> DAI -> WETH
            // (some of the pool addresses in this test are fake)
            let encoder = get_tycho_router_encoder(UserTransferType::TransferFrom);
            let swaps = vec![
                SwapBuilder::new(
                    ProtocolComponent {
                        id: "0xA478c2975Ab1Ea89e8196811F51A7B7Ade33eB11".to_string(),
                        protocol_system: "uniswap_v2".to_string(),
                        ..Default::default()
                    },
                    weth(),
                    dai(),
                )
                .build(),
                SwapBuilder::new(
                    ProtocolComponent {
                        id: "0xA478c2975Ab1Ea89e8196811F51A7B7Ade33eB11".to_string(),
                        protocol_system: "uniswap_v2".to_string(),
                        ..Default::default()
                    },
                    dai(),
                    weth(),
                )
                .build(),
            ];

            let solution = Solution {
                exact_out: false,
                given_token: eth(),
                checked_token: weth(),
                swaps,
                native_action: Some(NativeAction::Wrap),
                ..Default::default()
            };

            let result = encoder.validate_solution(&solution);

            assert!(result.is_err());
            assert_eq!(
                result.err().unwrap(),
                EncodingError::FatalError(
                    "Wrapping/Unwrapping is not available in cyclical swaps"
                        .to_string()
                        .to_string()
                )
            );
        }
    }

    mod executor_encoder {
        use std::str::FromStr;

        use alloy::hex::encode;
        use num_bigint::BigUint;
        use tycho_common::{models::protocol::ProtocolComponent, Bytes};

        use super::*;
        use crate::encoding::models::Solution;

        #[test]
        fn test_executor_encoder_encode() {
            let swap_encoder_registry = get_swap_encoder_registry();
            let encoder = TychoExecutorEncoder::new(swap_encoder_registry).unwrap();

            let token_in = weth();
            let token_out = dai();

            let swap = SwapBuilder::new(
                ProtocolComponent {
                    id: "0xA478c2975Ab1Ea89e8196811F51A7B7Ade33eB11".to_string(),
                    protocol_system: "uniswap_v2".to_string(),
                    ..Default::default()
                },
                token_in.clone(),
                token_out.clone(),
            )
            .build();

            let solution = Solution {
                exact_out: false,
                given_token: token_in,
                given_amount: BigUint::from(1000000000000000000u64),
                checked_token: token_out,
                checked_amount: BigUint::from(1000000000000000000u64),
                sender: Bytes::from_str("0x0000000000000000000000000000000000000000").unwrap(),
                // The receiver was generated with `makeAddr("bob") using forge`
                receiver: Bytes::from_str("0x1d96f2f6bef1202e4ce1ff6dad0c2cb002861d3e").unwrap(),
                swaps: vec![swap],
                native_action: None,
            };

            let encoded_solutions = encoder
                .encode_solutions(vec![solution])
                .unwrap();
            let encoded = encoded_solutions
                .first()
                .expect("Expected at least one encoded solution");
            let hex_protocol_data = encode(&encoded.swaps);
            assert_eq!(
                encoded.interacting_with,
                Bytes::from_str("0x5615deb798bb3e4dfa0139dfa1b3d433cc23b72f").unwrap()
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
                    // transfer true
                    "01",
                ))
            );
        }

        #[test]
        fn test_executor_encoder_too_many_swaps() {
            let swap_encoder_registry = get_swap_encoder_registry();
            let encoder = TychoExecutorEncoder::new(swap_encoder_registry).unwrap();

            let token_in = weth();
            let token_out = dai();

            let swap = SwapBuilder::new(
                ProtocolComponent {
                    id: "0xA478c2975Ab1Ea89e8196811F51A7B7Ade33eB11".to_string(),
                    protocol_system: "uniswap_v2".to_string(),
                    ..Default::default()
                },
                token_in.clone(),
                token_out.clone(),
            )
            .build();

            let solution = Solution {
                exact_out: false,
                given_token: token_in,
                given_amount: BigUint::from(1000000000000000000u64),
                checked_token: token_out,
                checked_amount: BigUint::from(1000000000000000000u64),
                sender: Bytes::from_str("0x0000000000000000000000000000000000000000").unwrap(),
                receiver: Bytes::from_str("0x1d96f2f6bef1202e4ce1ff6dad0c2cb002861d3e").unwrap(),
                swaps: vec![swap.clone(), swap],
                native_action: None,
            };

            let result = encoder.encode_solutions(vec![solution]);
            assert!(result.is_err());
        }

        #[test]
        fn test_executor_encoder_grouped_swaps() {
            let swap_encoder_registry = get_swap_encoder_registry();
            let encoder = TychoExecutorEncoder::new(swap_encoder_registry).unwrap();

            let usdc = usdc();
            let pepe = pepe();

            let solution = Solution {
                exact_out: false,
                given_token: usdc,
                given_amount: BigUint::from_str("1000_000000").unwrap(),
                checked_token: pepe,
                checked_amount: BigUint::from(1000000000000000000u64),
                sender: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
                receiver: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
                swaps: vec![swap_usdc_eth_univ4(), swap_eth_pepe_univ4()],
                ..Default::default()
            };

            let encoded_solutions = encoder
                .encode_solutions(vec![solution])
                .unwrap();
            let encoded_solution = encoded_solutions
                .first()
                .expect("Expected at least one encoded solution");
            let hex_protocol_data = encode(&encoded_solution.swaps);
            assert_eq!(
                encoded_solution.interacting_with,
                Bytes::from_str("0xf62849f9a0b5bf2913b396098f7c7019b51a820a").unwrap()
            );
            assert_eq!(
                hex_protocol_data,
                String::from(concat!(
                    // group in token
                    "a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
                    // group out token
                    "6982508145454ce325ddbe47a25d4ec3d2311933",
                    // zero for one
                    "00",
                    // transfer type Transfer
                    "01",
                    // receiver
                    "cd09f75e2bf2a4d11f3ab23f1389fcc1621c0cc2",
                    // first pool intermediary token (ETH)
                    "0000000000000000000000000000000000000000",
                    // fee
                    "000bb8",
                    // tick spacing
                    "00003c",
                    // second pool intermediary token (PEPE)
                    "6982508145454ce325ddbe47a25d4ec3d2311933",
                    // fee
                    "0061a8",
                    // tick spacing
                    "0001f4"
                ))
            );
        }
    }
}
