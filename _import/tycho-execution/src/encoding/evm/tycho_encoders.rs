use std::collections::HashSet;

use alloy::signers::local::PrivateKeySigner;
use tycho_common::{
    models::{protocol::ProtocolComponent, Chain},
    Bytes,
};

use crate::encoding::{
    errors::EncodingError,
    evm::{
        approvals::permit2::Permit2,
        constants::GROUPABLE_PROTOCOLS,
        encoding_utils::encode_tycho_router_call,
        group_swaps::group_swaps,
        strategy_encoder::strategy_encoders::{
            SequentialSwapStrategyEncoder, SingleSwapStrategyEncoder, SplitSwapStrategyEncoder,
        },
        swap_encoder::swap_encoder_registry::SwapEncoderRegistry,
        utils::ple_encode,
    },
    models::{EncodedSolution, EncodingContext, Solution, Swap, Transaction, UserTransferType},
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
/// * `permit2`: Optional Permit2 instance for permit transfers
/// * `signer`: Optional signer (used only for permit2 and full calldata encoding)
#[derive(Clone)]
pub struct TychoRouterEncoder {
    chain: Chain,
    single_swap_strategy: SingleSwapStrategyEncoder,
    sequential_swap_strategy: SequentialSwapStrategyEncoder,
    split_swap_strategy: SplitSwapStrategyEncoder,
    router_address: Bytes,
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
                swap_encoder_registry.clone(),
                user_transfer_type.clone(),
                router_address.clone(),
            )?,
            sequential_swap_strategy: SequentialSwapStrategyEncoder::new(
                swap_encoder_registry.clone(),
                user_transfer_type.clone(),
                router_address.clone(),
            )?,
            split_swap_strategy: SplitSwapStrategyEncoder::new(
                swap_encoder_registry,
                user_transfer_type,
                router_address.clone(),
            )?,
            router_address,
            permit2,
            signer,
            chain,
        })
    }

    fn encode_solution(&self, solution: &Solution) -> Result<EncodedSolution, EncodingError> {
        self.validate_solution(solution)?;
        let solution = self.add_missing_eth_wrapping_unwrapping_swaps(solution, &self.chain);

        let protocols: HashSet<String> = solution
            .swaps
            .iter()
            .map(|swap| swap.component().protocol_system.clone())
            .collect();

        let mut encoded_solution = if (solution.swaps.len() == 1) ||
            ((protocols.len() == 1 &&
                protocols
                    .iter()
                    .any(|p| GROUPABLE_PROTOCOLS.contains(&p.as_str()))) &&
                solution
                    .swaps
                    .iter()
                    .all(|swap| swap.get_split() == 0.0))
        {
            self.single_swap_strategy
                .encode_strategy(&solution)?
        } else if solution
            .swaps
            .iter()
            .all(|swap| swap.get_split() == 0.0)
        {
            self.sequential_swap_strategy
                .encode_strategy(&solution)?
        } else {
            self.split_swap_strategy
                .encode_strategy(&solution)?
        };

        if let Some(permit2) = &self.permit2 {
            let permit = permit2.get_permit(
                &self.router_address,
                &solution.sender,
                &solution.token_in,
                &solution.amount_in,
            )?;
            encoded_solution.permit = Some(permit);
        }
        Ok(encoded_solution)
    }

    fn add_missing_eth_wrapping_unwrapping_swaps(
        &self,
        solution: &Solution,
        chain: &Chain,
    ) -> Solution {
        let eth_address = &chain.native_token().address;
        let weth_address = &chain.wrapped_native_token().address;

        let wrapping_swap = Swap::new(
            ProtocolComponent { protocol_system: "weth".to_string(), ..Default::default() },
            eth_address.clone(),
            weth_address.clone(),
        );

        let unwrapping_swap = Swap::new(
            ProtocolComponent { protocol_system: "weth".to_string(), ..Default::default() },
            weth_address.clone(),
            eth_address.clone(),
        );

        let wrapping_bridge = |a: &Bytes, b: &Bytes| -> Option<Swap> {
            if a == weth_address && b == eth_address {
                Some(unwrapping_swap.clone())
            } else if a == eth_address && b == weth_address {
                Some(wrapping_swap.clone())
            } else {
                None
            }
        };

        let mut solution_with_added_wraps_unwraps: Vec<Swap> =
            Vec::with_capacity(solution.swaps.len());

        if let Some(s) = wrapping_bridge(&solution.token_in, solution.swaps[0].token_in()) {
            solution_with_added_wraps_unwraps.push(s);
        }

        for i in 0..solution.swaps.len() {
            solution_with_added_wraps_unwraps.push(solution.swaps[i].clone());
            if i + 1 < solution.swaps.len() {
                let token_out = solution.swaps[i].token_out();
                let token_in = solution.swaps[i + 1].token_in();
                if let Some(s) = wrapping_bridge(token_out, token_in) {
                    solution_with_added_wraps_unwraps.push(s);
                }
            }
        }

        if let Some(last_swap) = solution.swaps.last() {
            if let Some(s) = wrapping_bridge(last_swap.token_out(), &solution.token_out) {
                solution_with_added_wraps_unwraps.push(s);
            }
        }

        Solution { swaps: solution_with_added_wraps_unwraps, ..solution.clone() }
    }
}

impl TychoEncoder for TychoRouterEncoder {
    fn encode_solutions(
        &self,
        mut solutions: Vec<Solution>,
    ) -> Result<Vec<EncodedSolution>, EncodingError> {
        let mut result: Vec<EncodedSolution> = Vec::new();
        for solution in solutions.iter_mut() {
            let encoded_solution = self.encode_solution(solution)?;
            result.push(encoded_solution);
        }
        Ok(result)
    }

    fn encode_full_calldata(
        &self,
        mut solutions: Vec<Solution>,
    ) -> Result<Vec<Transaction>, EncodingError> {
        let mut transactions: Vec<Transaction> = Vec::new();
        for solution in solutions.iter_mut() {
            let encoded_solution = self.encode_solution(solution)?;

            let transaction = encode_tycho_router_call(
                self.chain.id(),
                encoded_solution,
                solution,
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

        let mut solution_tokens = vec![];
        let mut split_tokens_already_considered = HashSet::new();
        for (i, swap) in solution.swaps.iter().enumerate() {
            // so we don't count the split tokens more than once
            if swap.get_split() != 0.0 {
                if !split_tokens_already_considered.contains(swap.token_in()) {
                    solution_tokens.push(swap.token_in());
                    split_tokens_already_considered.insert(swap.token_in());
                }
            } else {
                // it might be the last swap of the split or a regular swap
                if !split_tokens_already_considered.contains(swap.token_in()) {
                    solution_tokens.push(swap.token_in());
                }
            }
            if i == solution.swaps.len() - 1 {
                solution_tokens.push(swap.token_out());
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
                if *solution.swaps[0].token_in() != *last_swap.token_out() {
                    return Err(EncodingError::FatalError(
                        "Cyclical swaps are only allowed if they are the first and last token of a solution".to_string(),
                    ));
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

        let encoding_context = EncodingContext {
            exact_out: solution.exact_out,
            router_address: None,
            group_token_in: grouped_swap.token_in.clone(),
            group_token_out: grouped_swap.token_out.clone(),
        };
        let mut grouped_protocol_data: Vec<Vec<u8>> = vec![];
        let mut initial_protocol_data: Vec<u8> = vec![];
        for swap in grouped_swap.swaps.iter() {
            let protocol_data = swap_encoder.encode_swap(swap, &encoding_context)?;
            if encoding_context.group_token_in == *swap.token_in() {
                initial_protocol_data = protocol_data;
            } else {
                grouped_protocol_data.push(protocol_data);
            }
        }

        if !grouped_protocol_data.is_empty() {
            initial_protocol_data.extend(ple_encode(grouped_protocol_data));
        }

        Ok(EncodedSolution {
            swaps: initial_protocol_data,
            interacting_with: swap_encoder.executor_address().clone(),
            permit: None,
            function_signature: "".to_string(),
            n_tokens: 0,
        })
    }
}

impl TychoEncoder for TychoExecutorEncoder {
    fn encode_solutions(
        &self,
        mut solutions: Vec<Solution>,
    ) -> Result<Vec<EncodedSolution>, EncodingError> {
        let solution = solutions
            .first_mut()
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
    use std::{collections::HashMap, fs, str::FromStr};

    use num_bigint::{BigInt, BigUint};
    use tycho_common::models::{protocol::ProtocolComponent, Chain};

    use super::*;
    use crate::encoding::models::Swap;

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
    fn swap_usdc_eth_univ4() -> Swap {
        let pool_fee_usdc_eth = Bytes::from(BigInt::from(3000).to_signed_bytes_be());
        let tick_spacing_usdc_eth = Bytes::from(BigInt::from(60).to_signed_bytes_be());
        let mut static_attributes_usdc_eth: HashMap<String, Bytes> = HashMap::new();
        static_attributes_usdc_eth.insert("key_lp_fee".into(), pool_fee_usdc_eth);
        static_attributes_usdc_eth.insert("tick_spacing".into(), tick_spacing_usdc_eth);
        Swap::new(
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
    }

    fn swap_eth_pepe_univ4() -> Swap {
        let pool_fee_eth_pepe = Bytes::from(BigInt::from(25000).to_signed_bytes_be());
        let tick_spacing_eth_pepe = Bytes::from(BigInt::from(500).to_signed_bytes_be());
        let mut static_attributes_eth_pepe: HashMap<String, Bytes> = HashMap::new();
        static_attributes_eth_pepe.insert("key_lp_fee".into(), pool_fee_eth_pepe);
        static_attributes_eth_pepe.insert("tick_spacing".into(), tick_spacing_eth_pepe);
        Swap::new(
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
    }

    fn router_address() -> Bytes {
        Bytes::from_str("0x6bc529DC7B81A031828dDCE2BC419d01FF268C66").unwrap()
    }

    fn eth_chain() -> Chain {
        Chain::Ethereum
    }

    fn get_swap_encoder_registry() -> SwapEncoderRegistry {
        let executors_addresses =
            fs::read_to_string("config/test_executor_addresses.json").unwrap();
        SwapEncoderRegistry::new(eth_chain())
            .add_default_encoders(Some(executors_addresses))
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
            let weth_amount_in = BigUint::from(1000u32);
            let swap = Swap::new(
                ProtocolComponent {
                    id: "0xA478c2975Ab1Ea89e8196811F51A7B7Ade33eB11".to_string(),
                    protocol_system: "uniswap_v2".to_string(),
                    ..Default::default()
                },
                weth().clone(),
                dai().clone(),
            );

            let solution = Solution {
                exact_out: false,
                amount_in: weth_amount_in.clone(),
                token_in: weth(),
                token_out: dai(),
                swaps: vec![swap],
                receiver: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
                ..Default::default()
            };

            let transactions = encoder.encode_full_calldata(vec![solution]);
            assert!(transactions.is_ok());
            let transactions = transactions.unwrap();
            assert_eq!(transactions.len(), 1);
            assert_eq!(transactions[0].value, BigUint::ZERO);
            assert_eq!(
                transactions[0].to,
                Bytes::from_str("0x6bc529DC7B81A031828dDCE2BC419d01FF268C66").unwrap()
            );
            // single swap selector
            assert_eq!(&hex::encode(transactions[0].clone().data)[..8], "d51d2a96");
        }

        #[test]
        #[allow(deprecated)]
        fn test_encode_router_calldata_single_swap_group() {
            let encoder = get_tycho_router_encoder(UserTransferType::TransferFrom);
            let solution = Solution {
                exact_out: false,
                token_in: usdc(),
                amount_in: BigUint::from_str("1000_000000").unwrap(),
                token_out: pepe(),
                min_amount_out: BigUint::from_str("105_152_000000000000000000").unwrap(),
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
            assert_eq!(&hex::encode(transactions[0].clone().data)[..8], "d51d2a96");
        }

        #[test]
        #[allow(deprecated)]
        fn test_encode_router_calldata_sequential_swap() {
            let encoder = get_tycho_router_encoder(UserTransferType::TransferFrom);
            let weth_amount_in = BigUint::from(1000u32);
            let swap_weth_dai = Swap::new(
                ProtocolComponent {
                    id: "0xA478c2975Ab1Ea89e8196811F51A7B7Ade33eB11".to_string(),
                    protocol_system: "uniswap_v2".to_string(),
                    ..Default::default()
                },
                weth().clone(),
                dai().clone(),
            );

            let swap_dai_usdc = Swap::new(
                ProtocolComponent {
                    id: "0xA478c2975Ab1Ea89e8196811F51A7B7Ade33eB11".to_string(),
                    protocol_system: "uniswap_v2".to_string(),
                    ..Default::default()
                },
                dai().clone(),
                usdc().clone(),
            );

            let solution = Solution {
                exact_out: false,
                amount_in: weth_amount_in.clone(),
                token_in: weth(),
                token_out: usdc(),
                swaps: vec![swap_weth_dai, swap_dai_usdc],
                receiver: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
                min_amount_out: BigUint::from(1000u32),
                ..Default::default()
            };

            let transactions = encoder.encode_full_calldata(vec![solution]);
            assert!(transactions.is_ok());
            let transactions = transactions.unwrap();
            assert_eq!(transactions.len(), 1);
            assert_eq!(transactions[0].value, BigUint::ZERO);
            // sequential swap selector
            assert_eq!(&hex::encode(transactions[0].clone().data)[..8], "f0b6a46d");
        }

        #[test]
        fn test_encode_router_calldata_split_swap_group() {
            let encoder = get_tycho_router_encoder(UserTransferType::TransferFrom);
            let mut swap_usdc_eth = swap_usdc_eth_univ4();
            swap_usdc_eth = swap_usdc_eth.split(0.5); // Set split to 50%
            let solution = Solution {
                exact_out: false,
                token_in: usdc(),
                amount_in: BigUint::from_str("1000_000000").unwrap(),
                token_out: eth(),
                min_amount_out: BigUint::from_str("105_152_000000000000000000").unwrap(),
                sender: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
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
        fn test_add_missing_wrapped_eth_swap_in_the_middle() {
            // before adding swap: DAI -> USDC -> ETH (no swap) WETH -> DAI
            // after adding swap:  DAI -> USDC -> ETH -> WETH -> DAI

            let encoder = get_tycho_router_encoder(UserTransferType::TransferFrom);

            let swap_dai_usdc = Swap::new(
                ProtocolComponent {
                    id: "0xA478c2975Ab1Ea89e8196811F51A7B7Ade33eB11".to_string(),
                    protocol_system: "uniswap_v2".to_string(),
                    ..Default::default()
                },
                dai().clone(),
                usdc().clone(),
            );

            let swap_weth_dai = Swap::new(
                ProtocolComponent {
                    id: "0xA478c2975Ab1Ea89e8196811F51A7B7Ade33eB11".to_string(),
                    protocol_system: "uniswap_v2".to_string(),
                    ..Default::default()
                },
                weth().clone(),
                dai().clone(),
            );

            let solution = Solution {
                exact_out: false,
                token_in: dai(),
                amount_in: BigUint::from_str("1000_000000").unwrap(),
                token_out: dai(),
                min_amount_out: BigUint::from_str("105_152_000000000000000000").unwrap(),
                sender: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
                swaps: vec![swap_dai_usdc, swap_usdc_eth_univ4(), swap_weth_dai],
                ..Default::default()
            };

            let solution =
                encoder.add_missing_eth_wrapping_unwrapping_swaps(&solution, &encoder.chain);
            assert_eq!(solution.swaps.len(), 4);
            assert_eq!(solution.swaps[2].token_in(), &eth());
            assert_eq!(solution.swaps[2].token_out(), &weth());
            assert_eq!(
                solution.swaps[2]
                    .component()
                    .protocol_system,
                "weth"
            );
        }

        #[test]
        fn test_add_missing_wrapped_eth_swap_in_the_beginning() {
            // before adding swap: ETH is the solution token_in, WETH -> DAI
            // after adding swap:  ETH -> WETH -> DAI

            let encoder = get_tycho_router_encoder(UserTransferType::TransferFrom);

            let swap_weth_dai = Swap::new(
                ProtocolComponent {
                    id: "0xA478c2975Ab1Ea89e8196811F51A7B7Ade33eB11".to_string(),
                    protocol_system: "uniswap_v2".to_string(),
                    ..Default::default()
                },
                weth().clone(),
                dai().clone(),
            );

            let solution = Solution {
                exact_out: false,
                token_in: eth(),
                amount_in: BigUint::from_str("1000_000000").unwrap(),
                token_out: dai(),
                min_amount_out: BigUint::from_str("105_152_000000000000000000").unwrap(),
                sender: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
                swaps: vec![swap_weth_dai],
                ..Default::default()
            };

            let solution =
                encoder.add_missing_eth_wrapping_unwrapping_swaps(&solution, &encoder.chain);
            assert_eq!(solution.swaps.len(), 2);
            assert_eq!(solution.swaps[0].token_in(), &eth());
            assert_eq!(solution.swaps[0].token_out(), &weth());
            assert_eq!(
                solution.swaps[0]
                    .component()
                    .protocol_system,
                "weth"
            );
        }

        #[test]
        fn test_add_missing_wrapped_eth_swap_in_the_end() {
            // before adding swap: USDC -> ETH, WETH is the solution token_out
            // after adding swap:  USDC -> ETH -> WETH

            let encoder = get_tycho_router_encoder(UserTransferType::TransferFrom);
            let solution = Solution {
                exact_out: false,
                token_in: usdc(),
                amount_in: BigUint::from_str("1000_000000").unwrap(),
                token_out: weth(),
                min_amount_out: BigUint::from_str("105_152_000000000000000000").unwrap(),
                sender: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
                swaps: vec![swap_usdc_eth_univ4()],
                ..Default::default()
            };

            let solution =
                encoder.add_missing_eth_wrapping_unwrapping_swaps(&solution, &encoder.chain);
            assert_eq!(solution.swaps.len(), 2);
            assert_eq!(
                solution
                    .swaps
                    .last()
                    .unwrap()
                    .token_in(),
                &eth()
            );
            assert_eq!(
                solution
                    .swaps
                    .last()
                    .unwrap()
                    .token_out(),
                &weth()
            );
            assert_eq!(
                solution
                    .swaps
                    .last()
                    .unwrap()
                    .component()
                    .protocol_system,
                "weth"
            );
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
        fn test_validate_fails_no_swaps() {
            let encoder = get_tycho_router_encoder(UserTransferType::TransferFrom);
            let solution =
                Solution { exact_out: false, token_in: eth(), swaps: vec![], ..Default::default() };

            let result = encoder.validate_solution(&solution);

            assert!(result.is_err());
            assert_eq!(
                result.err().unwrap(),
                EncodingError::FatalError("No swaps found in solution".to_string())
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
                Swap::new(
                    ProtocolComponent {
                        id: "0xA478c2975Ab1Ea89e8196811F51A7B7Ade33eB11".to_string(),
                        protocol_system: "uniswap_v2".to_string(),
                        ..Default::default()
                    },
                    dai().clone(),
                    weth().clone(),
                ),
                Swap::new(
                    ProtocolComponent {
                        id: "0x0000000000000000000000000000000000000000".to_string(),
                        protocol_system: "uniswap_v2".to_string(),
                        ..Default::default()
                    },
                    dai().clone(),
                    weth().clone(),
                ),
                Swap::new(
                    ProtocolComponent {
                        id: "0x0000000000000000000000000000000000000000".to_string(),
                        protocol_system: "uniswap_v2".to_string(),
                        ..Default::default()
                    },
                    weth().clone(),
                    dai().clone(),
                ),
            ];

            let solution = Solution {
                exact_out: false,
                token_in: dai(),
                token_out: dai(),
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
                Swap::new(
                    ProtocolComponent {
                        id: "0xA478c2975Ab1Ea89e8196811F51A7B7Ade33eB11".to_string(),
                        protocol_system: "uniswap_v2".to_string(),
                        ..Default::default()
                    },
                    dai().clone(),
                    weth().clone(),
                ),
                Swap::new(
                    ProtocolComponent {
                        id: "0xB4e16d0168e52d35CaCD2c6185b44281Ec28C9Dc".to_string(),
                        protocol_system: "uniswap_v2".to_string(),
                        ..Default::default()
                    },
                    weth().clone(),
                    usdc().clone(),
                ),
                Swap::new(
                    ProtocolComponent {
                        id: "0x0000000000000000000000000000000000000000".to_string(),
                        protocol_system: "uniswap_v2".to_string(),
                        ..Default::default()
                    },
                    usdc().clone(),
                    dai().clone(),
                ),
                Swap::new(
                    ProtocolComponent {
                        id: "0x0000000000000000000000000000000000000000".to_string(),
                        protocol_system: "uniswap_v2".to_string(),
                        ..Default::default()
                    },
                    dai().clone(),
                    wbtc().clone(),
                ),
            ];

            let solution = Solution {
                exact_out: false,
                token_in: dai(),
                token_out: wbtc(),
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
                Swap::new(
                    ProtocolComponent {
                        id: "0xA478c2975Ab1Ea89e8196811F51A7B7Ade33eB11".to_string(),
                        protocol_system: "uniswap_v2".to_string(),
                        ..Default::default()
                    },
                    weth(),
                    dai(),
                ),
                Swap::new(
                    ProtocolComponent {
                        id: "0x0000000000000000000000000000000000000000".to_string(),
                        protocol_system: "uniswap_v2".to_string(),
                        ..Default::default()
                    },
                    dai(),
                    weth(),
                )
                .split(0.5),
                Swap::new(
                    ProtocolComponent {
                        id: "0x0000000000000000000000000000000000000000".to_string(),
                        protocol_system: "uniswap_v2".to_string(),
                        ..Default::default()
                    },
                    dai(),
                    weth(),
                ),
            ];

            let solution = Solution {
                exact_out: false,
                token_in: weth(),
                token_out: weth(),
                swaps,
                ..Default::default()
            };

            let result = encoder.validate_solution(&solution);

            assert!(result.is_ok());
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

            let swap = Swap::new(
                ProtocolComponent {
                    id: "0xA478c2975Ab1Ea89e8196811F51A7B7Ade33eB11".to_string(),
                    protocol_system: "uniswap_v2".to_string(),
                    ..Default::default()
                },
                token_in.clone(),
                token_out.clone(),
            );

            let solution = Solution {
                exact_out: false,
                token_in,
                amount_in: BigUint::from(1000000000000000000u64),
                token_out,
                min_amount_out: BigUint::from(1000000000000000000u64),
                sender: Bytes::from_str("0x0000000000000000000000000000000000000000").unwrap(),
                swaps: vec![swap],
                ..Default::default()
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
                    // component id (pool address)
                    "a478c2975ab1ea89e8196811f51a7b7ade33eb11",
                    // tokenIn (WETH)
                    "c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
                    // tokenOut (DAI)
                    "6b175474e89094c44da98b954eedeac495271d0f",
                ))
            );
        }

        #[test]
        fn test_executor_encoder_too_many_swaps() {
            let swap_encoder_registry = get_swap_encoder_registry();
            let encoder = TychoExecutorEncoder::new(swap_encoder_registry).unwrap();

            let token_in = weth();
            let token_out = dai();

            let swap = Swap::new(
                ProtocolComponent {
                    id: "0xA478c2975Ab1Ea89e8196811F51A7B7Ade33eB11".to_string(),
                    protocol_system: "uniswap_v2".to_string(),
                    ..Default::default()
                },
                token_in.clone(),
                token_out.clone(),
            );

            let solution = Solution {
                exact_out: false,
                token_in,
                amount_in: BigUint::from(1000000000000000000u64),
                token_out,
                min_amount_out: BigUint::from(1000000000000000000u64),
                sender: Bytes::from_str("0x0000000000000000000000000000000000000000").unwrap(),
                swaps: vec![swap.clone(), swap],
                ..Default::default()
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
                token_in: usdc,
                amount_in: BigUint::from_str("1000_000000").unwrap(),
                token_out: pepe,
                min_amount_out: BigUint::from(1000000000000000000u64),
                sender: Bytes::from_str("0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2").unwrap(),
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
                    // first pool intermediary token (ETH)
                    "0000000000000000000000000000000000000000",
                    // fee
                    "000bb8",
                    // tick spacing
                    "00003c",
                    // hook address (not set, so zero)
                    "0000000000000000000000000000000000000000",
                    // hook data length (0)
                    "0000",
                    // ple encoding
                    "0030",
                    // second pool intermediary token (PEPE)
                    "6982508145454ce325ddbe47a25d4ec3d2311933",
                    // fee
                    "0061a8",
                    // tick spacing
                    "0001f4",
                    // hook address (not set, so zero)
                    "0000000000000000000000000000000000000000",
                    // hook data length (0)
                    "0000",
                ))
            );
        }
    }
}
