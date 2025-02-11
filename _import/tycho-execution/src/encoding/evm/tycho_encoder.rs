use num_bigint::BigUint;
use tycho_core::Bytes;

use crate::encoding::{
    errors::EncodingError,
    models::{Chain, NativeAction, Solution, Transaction},
    strategy_encoder::StrategyEncoderRegistry,
    tycho_encoder::TychoEncoder,
};

/// Represents an encoder for a swap using any strategy supported by the strategy registry.
///
/// # Fields
/// * `strategy_registry`: S, the strategy registry to use to select the best strategy to encode a
///   solution, based on its supported strategies and the solution attributes.
/// * `native_address`: Address of the chain's native token
/// * `wrapped_address`: Address of the chain's wrapped native token
#[derive(Clone)]
pub struct EVMTychoEncoder<S: StrategyEncoderRegistry> {
    strategy_registry: S,
    native_address: Bytes,
    wrapped_address: Bytes,
}

impl<S: StrategyEncoderRegistry> EVMTychoEncoder<S> {
    pub fn new(strategy_registry: S, chain: tycho_core::dto::Chain) -> Result<Self, EncodingError> {
        let chain: Chain = Chain::from(chain);
        if chain.name != *"ethereum" {
            return Err(EncodingError::InvalidInput(
                "Currently only Ethereum is supported".to_string(),
            ));
        }
        Ok(EVMTychoEncoder {
            strategy_registry,
            native_address: chain.native_token()?,
            wrapped_address: chain.wrapped_token()?,
        })
    }
}

impl<S: StrategyEncoderRegistry> EVMTychoEncoder<S> {
    /// Raises an `EncodingError` if the solution is not considered valid.
    ///
    /// A solution is considered valid if all the following conditions are met:
    /// * The solution is not exact out.
    /// * The solution has at least one swap.
    /// * If the solution is wrapping, the given token is the chain's native token and the first
    ///   swap's input is the chain's wrapped token.
    /// * If the solution is unwrapping, the checked token is the chain's native token and the last
    ///   swap's output is the chain's wrapped token.
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
        Ok(())
    }
}

impl<S: StrategyEncoderRegistry> TychoEncoder<S> for EVMTychoEncoder<S> {
    fn encode_router_calldata(
        &self,
        solutions: Vec<Solution>,
    ) -> Result<Vec<Transaction>, EncodingError> {
        let mut transactions: Vec<Transaction> = Vec::new();
        for solution in solutions.iter() {
            self.validate_solution(solution)?;

            let strategy = self
                .strategy_registry
                .get_encoder(solution)?;
            let (contract_interaction, target_address, selector) =
                strategy.encode_strategy(solution.clone())?;

            let value = match solution.native_action.as_ref() {
                Some(NativeAction::Wrap) => solution.given_amount.clone(),
                _ => BigUint::ZERO,
            };

            transactions.push(Transaction {
                value,
                data: contract_interaction,
                to: target_address,
                selector,
            });
        }
        Ok(transactions)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use tycho_core::dto::{Chain as TychoCoreChain, ProtocolComponent};

    use super::*;
    use crate::encoding::{
        models::Swap, strategy_encoder::StrategyEncoder, swap_encoder::SwapEncoder,
    };

    struct MockStrategyRegistry {
        strategy: Box<dyn StrategyEncoder>,
    }

    fn dai() -> Bytes {
        Bytes::from_str("0x6b175474e89094c44da98b954eedeac495271d0f").unwrap()
    }

    fn eth() -> Bytes {
        Bytes::from_str("0x0000000000000000000000000000000000000000").unwrap()
    }

    fn weth() -> Bytes {
        Bytes::from_str("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2").unwrap()
    }

    impl StrategyEncoderRegistry for MockStrategyRegistry {
        fn new(
            _chain: tycho_core::dto::Chain,
            _executors_file_path: Option<String>,
            _signer_pk: Option<String>,
        ) -> Result<MockStrategyRegistry, EncodingError> {
            Ok(Self { strategy: Box::new(MockStrategy) })
        }

        fn get_encoder(
            &self,
            _solution: &Solution,
        ) -> Result<&Box<dyn StrategyEncoder>, EncodingError> {
            Ok(&self.strategy)
        }
    }

    #[derive(Clone)]
    struct MockStrategy;

    impl StrategyEncoder for MockStrategy {
        fn encode_strategy(
            &self,
            _solution: Solution,
        ) -> Result<(Vec<u8>, Bytes, Option<String>), EncodingError> {
            Ok((
                Bytes::from_str("0x1234")
                    .unwrap()
                    .to_vec(),
                Bytes::from_str("0xabcd").unwrap(),
                None,
            ))
        }

        fn get_swap_encoder(&self, _protocol_system: &str) -> Option<&Box<dyn SwapEncoder>> {
            None
        }
        fn clone_box(&self) -> Box<dyn StrategyEncoder> {
            Box::new(self.clone())
        }
    }

    fn get_mocked_tycho_encoder() -> EVMTychoEncoder<MockStrategyRegistry> {
        let strategy_registry =
            MockStrategyRegistry::new(TychoCoreChain::Ethereum, None, None).unwrap();
        EVMTychoEncoder::new(strategy_registry, TychoCoreChain::Ethereum).unwrap()
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
            router_address: Bytes::from_str("0x1234567890abcdef1234567890abcdef12345678").unwrap(),
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
}
