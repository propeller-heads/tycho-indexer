use std::{any::Any, collections::HashMap};

use async_trait::async_trait;
use num_bigint::BigUint;
use num_traits::{FromPrimitive, ToPrimitive};
use tycho_common::{
    dto::ProtocolStateDelta,
    models::{protocol::GetAmountOutParams, token::Token},
    simulation::{
        errors::{SimulationError, TransitionError},
        indicatively_priced::{IndicativelyPriced, SignedQuote},
        protocol_sim::{Balances, GetAmountOutResult, ProtocolSim},
    },
    Bytes,
};

use crate::rfq::{
    client::RFQClient,
    protocols::hashflow::{client::HashflowClient, models::HashflowMarketMakerLevels},
};

#[derive(Debug, Clone)]
pub struct HashflowState {
    pub base_token: Token,
    pub quote_token: Token,
    pub levels: HashflowMarketMakerLevels,
    pub client: HashflowClient,
}

impl HashflowState {
    #![allow(dead_code)] // TODO remove this
    pub fn new(
        base_token: Token,
        quote_token: Token,
        levels: HashflowMarketMakerLevels,
        client: HashflowClient,
    ) -> Self {
        Self { base_token, quote_token, levels, client }
    }
}

impl ProtocolSim for HashflowState {
    fn fee(&self) -> f64 {
        todo!()
    }

    fn spot_price(&self, _base: &Token, _quote: &Token) -> Result<f64, SimulationError> {
        todo!()
    }

    fn get_amount_out(
        &self,
        amount_in: BigUint,
        token_in: &Token,
        token_out: &Token,
    ) -> Result<GetAmountOutResult, SimulationError> {
        // The current levels are only valid for the base/quote pair.
        if !(token_in == &self.base_token && token_out == &self.quote_token) {
            return Err(SimulationError::InvalidInput(
                format!("Invalid token addresses: {}, {}", token_in.address, token_out.address),
                None,
            ));
        }
        if self.levels.levels.is_empty() {
            return Err(SimulationError::RecoverableError("No liquidity".into()));
        }

        let amount_in = amount_in.to_f64().ok_or_else(|| {
            SimulationError::RecoverableError("Can't convert amount in to f64".into())
        })? / 10f64.powi(token_in.decimals as i32);

        // First level represents the minimum amount that can be traded
        let min_amount = self.levels.levels[0].quantity;
        if amount_in < min_amount {
            return Err(SimulationError::RecoverableError(format!(
                "Amount below minimum. Input amount: {amount_in}, min amount: {min_amount}"
            )));
        }

        // Calculate amount out using the existing price level logic
        let (amount_out, remaining_amount_in) = self
            .levels
            .get_amount_out_from_levels(amount_in);

        let res = GetAmountOutResult {
            amount: BigUint::from_f64(amount_out * 10f64.powi(token_out.decimals as i32))
                .ok_or_else(|| {
                    SimulationError::RecoverableError("Can't convert amount out to BigUInt".into())
                })?,
            gas: BigUint::from(134_000u64), // Rough gas estimation
            new_state: self.clone_box(),    // The state doesn't change after a swap
        };

        if remaining_amount_in > 0.0 {
            return Err(SimulationError::InvalidInput(
                format!("Pool has not enough liquidity to support complete swap. Input amount: {amount_in}, consumed amount: {}", amount_in-remaining_amount_in),
                Some(res)));
        }

        Ok(res)
    }

    fn get_limits(
        &self,
        _sell_token: Bytes,
        _buy_token: Bytes,
    ) -> Result<(BigUint, BigUint), SimulationError> {
        todo!()
    }

    fn delta_transition(
        &mut self,
        _delta: ProtocolStateDelta,
        _tokens: &HashMap<Bytes, Token>,
        _balances: &Balances,
    ) -> Result<(), TransitionError<String>> {
        todo!()
    }

    fn clone_box(&self) -> Box<dyn ProtocolSim> {
        Box::new(self.clone())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn eq(&self, other: &dyn ProtocolSim) -> bool {
        if let Some(other_state) = other
            .as_any()
            .downcast_ref::<HashflowState>()
        {
            self.base_token == other_state.base_token &&
                self.quote_token == other_state.quote_token &&
                self.levels == other_state.levels
        } else {
            false
        }
    }
}

#[async_trait]
impl IndicativelyPriced for HashflowState {
    async fn request_signed_quote(
        &self,
        params: GetAmountOutParams,
    ) -> Result<SignedQuote, SimulationError> {
        Ok(self
            .client
            .request_binding_quote(&params)
            .await?)
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, str::FromStr};

    use tycho_common::models::Chain;

    use super::*;
    use crate::rfq::protocols::hashflow::models::{HashflowPair, HashflowPriceLevel};

    fn wbtc() -> Token {
        Token::new(
            &hex::decode("2260fac5e5542a773aa44fbcfedf7c193bc2c599")
                .unwrap()
                .into(),
            "WBTC",
            8,
            0,
            &[Some(10_000)],
            Chain::Ethereum,
            100,
        )
    }

    fn usdc() -> Token {
        Token::new(
            &hex::decode("a0b86991c6218a76c1d19d4a2e9eb0ce3606eb48")
                .unwrap()
                .into(),
            "USDC",
            6,
            0,
            &[Some(10_000)],
            Chain::Ethereum,
            100,
        )
    }

    fn weth() -> Token {
        Token::new(
            &Bytes::from_str("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2").unwrap(),
            "WETH",
            18,
            0,
            &[],
            Default::default(),
            100,
        )
    }

    fn empty_hashflow_client() -> HashflowClient {
        HashflowClient::new(
            Chain::Ethereum,
            HashSet::new(),
            0.0,
            HashSet::new(),
            "".to_string(),
            "".to_string(),
            0,
        )
        .unwrap()
    }

    fn create_test_hashflow_state() -> HashflowState {
        HashflowState {
            base_token: weth(),
            quote_token: usdc(),
            levels: HashflowMarketMakerLevels {
                pair: HashflowPair {
                    base_token: Bytes::from_str("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2")
                        .unwrap(),
                    quote_token: Bytes::from_str("0xa0b86991c6218a76c1d19d4a2e9eb0ce3606eb48")
                        .unwrap(),
                },
                levels: vec![
                    HashflowPriceLevel { quantity: 0.5, price: 3000.0 },
                    HashflowPriceLevel { quantity: 1.5, price: 3000.0 },
                    HashflowPriceLevel { quantity: 5.0, price: 2999.0 },
                ],
            },
            client: empty_hashflow_client(),
        }
    }

    mod get_amount_out {
        use super::*;

        #[test]
        fn wbtc_to_usdc() {
            let state = create_test_hashflow_state();

            // Test swapping 1.5 WETH -> USDC
            // Should consume first level (0.5 WETH at 3000) + partial second level (1.0 WETH at
            // 3000)
            let amount_out_result = state
                .get_amount_out(
                    BigUint::from_str("1500000000000000000").unwrap(), // 1.5 WETH (18 decimals)
                    &weth(),
                    &usdc(),
                )
                .unwrap();

            // Expected: (0.5 * 3000) + (1.0 * 3000) = 1500 + 3000 = 4500 USDC
            assert_eq!(amount_out_result.amount, BigUint::from_str("4500000000").unwrap()); // 6 decimals
            assert_eq!(amount_out_result.gas, BigUint::from(134_000u64));
        }

        #[test]
        fn usdc_to_wbtc() {
            let state = create_test_hashflow_state();

            // Test swapping 10000 USDC -> WETH
            // The price levels returned by Hashflow are only valid for the requested pair,
            // and they can't be inverted to derive the reverse swap.
            // In that case, we should return an error.
            let result = state.get_amount_out(
                BigUint::from_str("10000000000").unwrap(), // 10000 USDC (6 decimals)
                &usdc(),
                &weth(),
            );

            assert!(result.is_err());
            if let Err(SimulationError::InvalidInput(msg, ..)) = result {
                assert!(msg.contains("Invalid token addresses"));
            } else {
                panic!("Expected InvalidInput");
            }
        }

        #[test]
        fn below_minimum() {
            let state = create_test_hashflow_state();

            // Test with amount below minimum (first level quantity is 0.5 WETH)
            let result = state.get_amount_out(
                BigUint::from_str("250000000000000000").unwrap(), // 0.25 WETH (18 decimals)
                &weth(),
                &usdc(),
            );

            assert!(result.is_err());
            if let Err(SimulationError::RecoverableError(msg)) = result {
                assert!(msg.contains("Amount below minimum"));
            } else {
                panic!("Expected RecoverableError");
            }
        }

        #[test]
        fn insufficient_liquidity() {
            let state = create_test_hashflow_state();

            // Test with amount exceeding total liquidity (total is 7.0 WETH)
            let result = state.get_amount_out(
                BigUint::from_str("8000000000000000000").unwrap(), // 8.0 WETH (18 decimals)
                &weth(),
                &usdc(),
            );

            assert!(result.is_err());
            if let Err(SimulationError::InvalidInput(msg, _)) = result {
                assert!(msg.contains("Pool has not enough liquidity"));
            } else {
                panic!("Expected InvalidInput");
            }
        }

        #[test]
        fn invalid_token_pair() {
            let state = create_test_hashflow_state();

            // Test with invalid token pair (WBTC not in WETH/USDC pool)
            let result = state.get_amount_out(
                BigUint::from_str("100000000").unwrap(), // 1 WBTC
                &wbtc(),
                &usdc(),
            );

            assert!(result.is_err());
            if let Err(SimulationError::InvalidInput(msg, ..)) = result {
                assert!(msg.contains("Invalid token addresses"));
            } else {
                panic!("Expected InvalidInput");
            }
        }

        #[test]
        fn no_liquidity() {
            let mut state = create_test_hashflow_state();
            state.levels.levels = vec![]; // Remove all levels

            let result = state.get_amount_out(
                BigUint::from_str("1000000000000000000").unwrap(), // 1.0 WETH
                &weth(),
                &usdc(),
            );

            assert!(result.is_err());
            if let Err(SimulationError::RecoverableError(msg)) = result {
                assert_eq!(msg, "No liquidity");
            } else {
                panic!("Expected RecoverableError");
            }
        }
    }
}
