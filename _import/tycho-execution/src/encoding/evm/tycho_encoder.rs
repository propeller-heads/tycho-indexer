use std::str::FromStr;

use num_bigint::BigUint;
use tycho_core::{models::Chain, Bytes};

use crate::encoding::{
    errors::EncodingError,
    models::{NativeAction, Solution, Transaction},
    strategy_encoder::StrategySelector,
    tycho_encoder::TychoEncoder,
};

#[allow(dead_code)]
pub struct EVMTychoEncoder<S: StrategySelector> {
    strategy_selector: S,
    signer: Option<String>,
    chain: Chain,
    router_address: Bytes,
}

#[allow(dead_code)]
impl<S: StrategySelector> EVMTychoEncoder<S> {
    pub fn new(
        strategy_selector: S,
        router_address: String,
        signer: Option<String>,
        chain: Chain,
    ) -> Result<Self, EncodingError> {
        let router_address = Bytes::from_str(&router_address)
            .map_err(|_| EncodingError::FatalError("Invalid router address".to_string()))?;
        Ok(EVMTychoEncoder { strategy_selector, signer, chain, router_address })
    }
}
impl<S: StrategySelector> TychoEncoder<S> for EVMTychoEncoder<S> {
    fn encode_router_calldata(
        &self,
        solutions: Vec<Solution>,
    ) -> Result<Vec<Transaction>, EncodingError> {
        let mut transactions: Vec<Transaction> = Vec::new();
        for solution in solutions.iter() {
            if solution.exact_out {
                return Err(EncodingError::FatalError(
                    "Currently only exact input solutions are supported".to_string(),
                ));
            }

            let router_address = solution
                .router_address
                .clone()
                .unwrap_or(self.router_address.clone());

            let strategy = self.strategy_selector.select_strategy(
                solution,
                self.signer.clone(),
                self.chain,
            )?;
            let (contract_interaction, target_address) =
                strategy.encode_strategy(solution.clone(), router_address)?;

            let value = match solution.native_action.as_ref() {
                Some(NativeAction::Wrap) => solution.given_amount.clone(),
                _ => BigUint::ZERO,
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
    use super::*;
    use crate::encoding::strategy_encoder::StrategyEncoder;

    struct MockStrategySelector;

    impl StrategySelector for MockStrategySelector {
        fn select_strategy(
            &self,
            _solution: &Solution,
            _signer: Option<String>,
            _chain: Chain,
        ) -> Result<Box<dyn StrategyEncoder>, EncodingError> {
            Ok(Box::new(MockStrategy))
        }
    }

    struct MockStrategy;

    impl StrategyEncoder for MockStrategy {
        fn encode_strategy(
            &self,
            _solution: Solution,
            _router_address: Bytes,
        ) -> Result<(Vec<u8>, Bytes), EncodingError> {
            Ok((
                Bytes::from_str("0x1234")
                    .unwrap()
                    .to_vec(),
                Bytes::from_str("0xabcd").unwrap(),
            ))
        }
    }

    fn get_mocker_tycho_encoder() -> EVMTychoEncoder<MockStrategySelector> {
        let strategy_selector = MockStrategySelector;
        EVMTychoEncoder::new(
            strategy_selector,
            "0x1234567890abcdef1234567890abcdef12345678".to_string(),
            Some("0xabcdef".to_string()),
            Chain::Ethereum,
        )
        .unwrap()
    }

    #[test]
    fn test_encode_router_calldata() {
        let encoder = get_mocker_tycho_encoder();

        let eth_amount_in = BigUint::from(1000u32);
        let solution = Solution {
            exact_out: false,
            given_amount: eth_amount_in.clone(),
            router_address: None,
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
    fn test_encode_router_calldata_fails_for_exact_out() {
        let encoder = get_mocker_tycho_encoder();

        let solution = Solution {
            exact_out: true, // This should cause an error
            ..Default::default()
        };

        let result = encoder.encode_router_calldata(vec![solution]);

        assert!(result.is_err());
        assert_eq!(
            result.err().unwrap(),
            EncodingError::FatalError(
                "Currently only exact input solutions are supported".to_string()
            )
        );
    }
}
