use std::collections::HashSet;

use num_bigint::BigUint;
use tycho_common::Bytes;

use crate::encoding::{
    errors::EncodingError,
    models::{Chain, NativeAction, Solution, Transaction},
    strategy_encoder::StrategyEncoder,
    tycho_encoder::TychoEncoder,
};

/// Represents an encoder for a swap using any strategy supported by the strategy registry.
///
/// # Fields
/// * `strategy_encoder`: Strategy encoder to follow for encoding the solution
/// * `native_address`: Address of the chain's native token
/// * `wrapped_address`: Address of the chain's wrapped native token
pub struct EVMTychoEncoder {
    strategy_encoder: Box<dyn StrategyEncoder>,
    native_address: Bytes,
    wrapped_address: Bytes,
}

impl Clone for EVMTychoEncoder {
    fn clone(&self) -> Self {
        Self {
            strategy_encoder: self.strategy_encoder.clone_box(),
            native_address: self.native_address.clone(),
            wrapped_address: self.wrapped_address.clone(),
        }
    }
}

impl EVMTychoEncoder {
    pub fn new(
        chain: tycho_common::models::Chain,
        strategy_encoder: Box<dyn StrategyEncoder>,
    ) -> Result<Self, EncodingError> {
        let chain: Chain = Chain::from(chain);
        let native_address = chain.native_token()?;
        let wrapped_address = chain.wrapped_token()?;
        Ok(EVMTychoEncoder { strategy_encoder, native_address, wrapped_address })
    }
}

impl EVMTychoEncoder {
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
        if let Some(native_action) = solution.clone().native_action {
            if native_action == NativeAction::Wrap {
                if solution.given_token != self.native_address {
                    return Err(EncodingError::FatalError(
                        "Native token must be the input token in order to wrap".to_string(),
                    ));
                }
                if let Some(first_swap) = solution.swaps.first() {
                    if first_swap.token_in != self.wrapped_address {
                        return Err(EncodingError::FatalError(
                            "Wrapped token must be the first swap's input in order to wrap"
                                .to_string(),
                        ));
                    }
                }
            } else if native_action == NativeAction::Unwrap {
                if solution.checked_token != self.native_address {
                    return Err(EncodingError::FatalError(
                        "Native token must be the output token in order to unwrap".to_string(),
                    ));
                }
                if let Some(last_swap) = solution.swaps.last() {
                    if last_swap.token_out != self.wrapped_address {
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
                    solution_tokens.push(swap.token_in.clone());
                    split_tokens_already_considered.insert(swap.token_in.clone());
                }
            } else {
                // it might be the last swap of the split or a regular swap
                if !split_tokens_already_considered.contains(&swap.token_in) {
                    solution_tokens.push(swap.token_in.clone());
                }
            }
            if i == solution.swaps.len() - 1 {
                solution_tokens.push(swap.token_out.clone());
            }
        }

        if solution_tokens.len() !=
            solution_tokens
                .iter()
                .cloned()
                .collect::<HashSet<Bytes>>()
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
                    if let Some(_native_action) = solution.clone().native_action {
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

impl TychoEncoder for EVMTychoEncoder {
    fn encode_router_calldata(
        &self,
        solutions: Vec<Solution>,
    ) -> Result<Vec<Transaction>, EncodingError> {
        let mut transactions: Vec<Transaction> = Vec::new();
        for solution in solutions.iter() {
            self.validate_solution(solution)?;

            let (contract_interaction, target_address) = self
                .strategy_encoder
                .encode_strategy(solution.clone())?;

            let value = if solution.given_token == self.native_address {
                solution.given_amount.clone()
            } else {
                BigUint::ZERO
            };

            transactions.push(Transaction {
                value,
                data: contract_interaction,
                to: target_address,
            });
        }
        Ok(transactions)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use tycho_common::models::{protocol::ProtocolComponent, Chain as TychoCoreChain};

    use super::*;
    use crate::encoding::{
        models::Swap, strategy_encoder::StrategyEncoder, swap_encoder::SwapEncoder,
    };

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

    #[derive(Clone)]
    struct MockStrategy;

    impl StrategyEncoder for MockStrategy {
        fn encode_strategy(&self, _solution: Solution) -> Result<(Vec<u8>, Bytes), EncodingError> {
            Ok((
                Bytes::from_str("0x1234")
                    .unwrap()
                    .to_vec(),
                Bytes::from_str("0xabcd").unwrap(),
            ))
        }

        fn get_swap_encoder(&self, _protocol_system: &str) -> Option<&Box<dyn SwapEncoder>> {
            None
        }
        fn clone_box(&self) -> Box<dyn StrategyEncoder> {
            Box::new(self.clone())
        }
    }

    fn get_mocked_tycho_encoder() -> EVMTychoEncoder {
        let strategy_encoder = Box::new(MockStrategy {});
        EVMTychoEncoder::new(TychoCoreChain::Ethereum, strategy_encoder).unwrap()
    }

    #[test]
    fn test_encode_router_calldata() {
        let encoder = get_mocked_tycho_encoder();
        let eth_amount_in = BigUint::from(1000u32);
        let swap = Swap {
            component: ProtocolComponent {
                id: "0xA478c2975Ab1Ea89e8196811F51A7B7Ade33eB11".to_string(),
                protocol_system: "uniswap_v2".to_string(),
                ..Default::default()
            },
            token_in: weth(),
            token_out: dai(),
            split: 0f64,
        };

        let solution = Solution {
            exact_out: false,
            given_amount: eth_amount_in.clone(),
            given_token: eth(),
            swaps: vec![swap],
            native_action: Some(NativeAction::Wrap),
            ..Default::default()
        };

        let transactions = encoder.encode_router_calldata(vec![solution]);

        assert!(transactions.is_ok());
        let transactions = transactions.unwrap();
        assert_eq!(transactions.len(), 1);
        assert_eq!(transactions[0].value, eth_amount_in);
        assert_eq!(transactions[0].data, Bytes::from_str("0x1234").unwrap());
        assert_eq!(transactions[0].to, Bytes::from_str("0xabcd").unwrap());
    }

    #[test]
    fn test_validate_fails_for_exact_out() {
        let encoder = get_mocked_tycho_encoder();
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
        let encoder = get_mocked_tycho_encoder();
        let swap = Swap {
            component: ProtocolComponent {
                id: "0xA478c2975Ab1Ea89e8196811F51A7B7Ade33eB11".to_string(),
                protocol_system: "uniswap_v2".to_string(),
                ..Default::default()
            },
            token_in: weth(),
            token_out: dai(),
            split: 0f64,
        };

        let solution = Solution {
            exact_out: false,
            given_token: eth(),
            checked_token: dai(),
            checked_amount: None,
            swaps: vec![swap],
            native_action: Some(NativeAction::Wrap),
            ..Default::default()
        };

        let result = encoder.validate_solution(&solution);

        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_fails_for_wrap_wrong_input() {
        let encoder = get_mocked_tycho_encoder();
        let swap = Swap {
            component: ProtocolComponent {
                id: "0xA478c2975Ab1Ea89e8196811F51A7B7Ade33eB11".to_string(),
                protocol_system: "uniswap_v2".to_string(),
                ..Default::default()
            },
            token_in: weth(),
            token_out: dai(),
            split: 0f64,
        };

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
        let encoder = get_mocked_tycho_encoder();
        let swap = Swap {
            component: ProtocolComponent {
                id: "0xA478c2975Ab1Ea89e8196811F51A7B7Ade33eB11".to_string(),
                protocol_system: "uniswap_v2".to_string(),
                ..Default::default()
            },
            token_in: eth(),
            token_out: dai(),
            split: 0f64,
        };

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
        let encoder = get_mocked_tycho_encoder();
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
        let encoder = get_mocked_tycho_encoder();
        let swap = Swap {
            component: ProtocolComponent {
                id: "0xA478c2975Ab1Ea89e8196811F51A7B7Ade33eB11".to_string(),
                protocol_system: "uniswap_v2".to_string(),
                ..Default::default()
            },
            token_in: dai(),
            token_out: weth(),
            split: 0f64,
        };

        let solution = Solution {
            exact_out: false,
            checked_token: eth(),
            checked_amount: None,
            swaps: vec![swap],
            native_action: Some(NativeAction::Unwrap),
            ..Default::default()
        };

        let result = encoder.validate_solution(&solution);

        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_fails_for_unwrap_wrong_output() {
        let encoder = get_mocked_tycho_encoder();
        let swap = Swap {
            component: ProtocolComponent {
                id: "0xA478c2975Ab1Ea89e8196811F51A7B7Ade33eB11".to_string(),
                protocol_system: "uniswap_v2".to_string(),
                ..Default::default()
            },
            token_in: dai(),
            token_out: weth(),
            split: 0f64,
        };

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
        let encoder = get_mocked_tycho_encoder();
        let swap = Swap {
            component: ProtocolComponent {
                id: "0xA478c2975Ab1Ea89e8196811F51A7B7Ade33eB11".to_string(),
                protocol_system: "uniswap_v2".to_string(),
                ..Default::default()
            },
            token_in: dai(),
            token_out: eth(),
            split: 0f64,
        };

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
        let encoder = get_mocked_tycho_encoder();
        let swaps = vec![
            Swap {
                component: ProtocolComponent {
                    id: "0xA478c2975Ab1Ea89e8196811F51A7B7Ade33eB11".to_string(),
                    protocol_system: "uniswap_v2".to_string(),
                    ..Default::default()
                },
                token_in: dai(),
                token_out: weth(),
                split: 0.5f64,
            },
            Swap {
                component: ProtocolComponent {
                    id: "0x0000000000000000000000000000000000000000".to_string(),
                    protocol_system: "uniswap_v2".to_string(),
                    ..Default::default()
                },
                token_in: dai(),
                token_out: weth(),
                split: 0f64,
            },
            Swap {
                component: ProtocolComponent {
                    id: "0x0000000000000000000000000000000000000000".to_string(),
                    protocol_system: "uniswap_v2".to_string(),
                    ..Default::default()
                },
                token_in: weth(),
                token_out: dai(),
                split: 0f64,
            },
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
        let encoder = get_mocked_tycho_encoder();
        let swaps = vec![
            Swap {
                component: ProtocolComponent {
                    id: "0xA478c2975Ab1Ea89e8196811F51A7B7Ade33eB11".to_string(),
                    protocol_system: "uniswap_v2".to_string(),
                    ..Default::default()
                },
                token_in: dai(),
                token_out: weth(),
                split: 0f64,
            },
            Swap {
                component: ProtocolComponent {
                    id: "0xB4e16d0168e52d35CaCD2c6185b44281Ec28C9Dc".to_string(),
                    protocol_system: "uniswap_v2".to_string(),
                    ..Default::default()
                },
                token_in: weth(),
                token_out: usdc(),
                split: 0f64,
            },
            Swap {
                component: ProtocolComponent {
                    id: "0x0000000000000000000000000000000000000000".to_string(),
                    protocol_system: "uniswap_v2".to_string(),
                    ..Default::default()
                },
                token_in: usdc(),
                token_out: dai(),
                split: 0f64,
            },
            Swap {
                component: ProtocolComponent {
                    id: "0x0000000000000000000000000000000000000000".to_string(),
                    protocol_system: "uniswap_v2".to_string(),
                    ..Default::default()
                },
                token_in: dai(),
                token_out: wbtc(),
                split: 0f64,
            },
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
        let encoder = get_mocked_tycho_encoder();
        let swaps = vec![
            Swap {
                component: ProtocolComponent {
                    id: "0xA478c2975Ab1Ea89e8196811F51A7B7Ade33eB11".to_string(),
                    protocol_system: "uniswap_v2".to_string(),
                    ..Default::default()
                },
                token_in: weth(),
                token_out: dai(),
                split: 0f64,
            },
            Swap {
                component: ProtocolComponent {
                    id: "0x0000000000000000000000000000000000000000".to_string(),
                    protocol_system: "uniswap_v2".to_string(),
                    ..Default::default()
                },
                token_in: dai(),
                token_out: weth(),
                split: 0.5f64,
            },
            Swap {
                component: ProtocolComponent {
                    id: "0x0000000000000000000000000000000000000000".to_string(),
                    protocol_system: "uniswap_v2".to_string(),
                    ..Default::default()
                },
                token_in: dai(),
                token_out: weth(),
                split: 0f64,
            },
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
        let encoder = get_mocked_tycho_encoder();
        let swaps = vec![
            Swap {
                component: ProtocolComponent {
                    id: "0xA478c2975Ab1Ea89e8196811F51A7B7Ade33eB11".to_string(),
                    protocol_system: "uniswap_v2".to_string(),
                    ..Default::default()
                },
                token_in: weth(),
                token_out: dai(),
                split: 0f64,
            },
            Swap {
                component: ProtocolComponent {
                    id: "0x0000000000000000000000000000000000000000".to_string(),
                    protocol_system: "uniswap_v2".to_string(),
                    ..Default::default()
                },
                token_in: dai(),
                token_out: weth(),
                split: 0f64,
            },
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
