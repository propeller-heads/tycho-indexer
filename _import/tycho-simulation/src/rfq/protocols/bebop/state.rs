use std::{any::Any, collections::HashMap};

use alloy::primitives::Address;
use num_bigint::BigUint;
use tycho_common::{
    dto::ProtocolStateDelta,
    models::token::Token,
    simulation::{
        errors::{SimulationError, TransitionError},
        protocol_sim::{Balances, GetAmountOutResult, ProtocolSim},
    },
    Bytes,
};

#[derive(Debug)]
pub struct BebopState {
    pub base_token: String,
    pub quote_token: String,
    pub last_update_ts: u64,
    pub bids: Vec<(f64, f64)>,
    pub asks: Vec<(f64, f64)>,
}

impl ProtocolSim for BebopState {
    fn fee(&self) -> f64 {
        todo!()
    }

    fn spot_price(&self, base: &Token, quote: &Token) -> Result<f64, SimulationError> {
        let base_address = Address::from_slice(&base.address).to_string();
        let quote_address = Address::from_slice(&quote.address).to_string();

        // Since this method does not care about sell direction, we average the price of the best
        // bid and ask
        let best_bid = self
            .bids
            .first()
            .map(|(price, _)| *price);
        let best_ask = self
            .asks
            .first()
            .map(|(price, _)| *price);

        // If just one is available, only consider that one
        let average_price = match (best_bid, best_ask) {
            (Some(best_bid), Some(best_ask)) => (best_bid + best_ask) / 2.0,
            (Some(best_bid), None) => best_bid,
            (None, Some(best_ask)) => best_ask,
            (None, None) => {
                return Err(SimulationError::RecoverableError("No liquidity available".to_string()))
            }
        };

        // If the base/quote token addresses are the opposite of the pool tokens, we need to invert
        // the price
        if base_address.to_lowercase() == self.quote_token.to_lowercase() &&
            quote_address.to_lowercase() == self.base_token.to_lowercase()
        {
            Ok(1.0 / average_price)
        } else if quote_address.to_lowercase() == self.quote_token.to_lowercase() &&
            base_address.to_lowercase() == self.base_token.to_lowercase()
        {
            Ok(average_price)
        } else {
            Err(SimulationError::RecoverableError(format!(
                "Invalid token addresses: {base_address}, {quote_address}"
            )))
        }
    }

    fn get_amount_out(
        &self,
        _amount_in: BigUint,
        _token_in: &Token,
        _token_out: &Token,
    ) -> Result<GetAmountOutResult, SimulationError> {
        todo!()
    }

    fn get_limits(
        &self,
        sell_token: Bytes,
        buy_token: Bytes,
    ) -> Result<(BigUint, BigUint), SimulationError> {
        let sell_token_address = Address::from_slice(&sell_token).to_string();
        let buy_token_address = Address::from_slice(&buy_token).to_string();

        // If selling BASE for QUOTE, we need to look at [BASE/QUOTE].bids
        // If buying BASE with QUOTE, we need to look at [BASE/QUOTE].asks
        let price_levels = if sell_token_address.to_lowercase() == self.base_token.to_lowercase() &&
            buy_token_address.to_lowercase() == self.quote_token.to_lowercase()
        {
            self.bids.clone()
        } else if buy_token_address.to_lowercase() == self.base_token.to_lowercase() &&
            sell_token_address.to_lowercase() == self.quote_token.to_lowercase()
        {
            self.asks.clone()
        } else {
            return Err(SimulationError::RecoverableError(format!(
                "Invalid token addresses: {sell_token_address}, {buy_token_address}"
            )))
        };

        // If there are no price levels, return 0 for both limits
        if price_levels.is_empty() {
            return Ok((BigUint::from(0u64), BigUint::from(0u64)));
        }

        let total_input_amount: f64 = price_levels
            .iter()
            .map(|(_, amount)| amount)
            .sum();
        let total_output_amount: f64 = price_levels
            .iter()
            .map(|(price, amount)| price * amount)
            .sum();

        // TODO we need decimals to properly convert to BigUint - should we store the whole Token
        //  struct when creating the state?
        let token_limit = BigUint::from((total_input_amount * 1e18) as u128);
        let quote_limit = BigUint::from((total_output_amount * 1e18) as u128);

        Ok((token_limit, quote_limit))
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
        todo!()
    }

    fn as_any(&self) -> &dyn Any {
        todo!()
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        todo!()
    }

    fn eq(&self, _other: &dyn ProtocolSim) -> bool {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use tycho_common::models::Chain;

    use super::*;

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

    fn eth() -> Token {
        Token::new(
            &hex::decode("c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2")
                .unwrap()
                .into(),
            "ETH",
            18,
            0,
            &[Some(10_000)],
            Chain::Ethereum,
            100,
        )
    }

    fn dai() -> Token {
        Token::new(
            &hex::decode("6b175474e89094c44da98b954eedeac495271d0f")
                .unwrap()
                .into(),
            "DAI",
            18,
            0,
            &[Some(10_000)],
            Chain::Ethereum,
            100,
        )
    }

    fn create_test_bebop_state() -> BebopState {
        BebopState {
            base_token: "0x2260FAC5E5542a773Aa44fBCfeDF7C193bc2C599".to_string(), // WBTC
            quote_token: "0xA0b86991c6218a76c1d19D4a2e9Eb0cE3606eB48".to_string(), // USDC
            last_update_ts: 1703097600,
            bids: vec![(65000.0, 1.5), (64950.0, 2.0), (64900.0, 0.5)],
            asks: vec![(65100.0, 1.0), (65150.0, 2.5), (65200.0, 1.5)],
        }
    }

    fn create_eth_dai_state() -> BebopState {
        BebopState {
            base_token: "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2".to_string(), // ETH
            quote_token: "0x6b175474e89094c44da98b954eedeac495271d0f".to_string(), // DAI
            last_update_ts: 1703097600,
            bids: vec![(2000.0, 10.0), (1995.0, 20.0), (1990.0, 5.0)],
            asks: vec![(2010.0, 15.0), (2015.0, 25.0), (2020.0, 10.0)],
        }
    }

    #[test]
    fn test_spot_price_matching_base_and_quote() {
        let state = create_test_bebop_state();

        // Test WBTC/USDC (base/quote) - should use average of best bid and ask
        let price = state
            .spot_price(&wbtc(), &usdc())
            .unwrap();
        assert_eq!(price, 65050.0);
    }

    #[test]
    fn test_spot_price_inverted_base_and_quote() {
        let state = create_test_bebop_state();

        // Test USDC/WBTC (quote/base) - should use average of best bid and ask, then invert
        let price = state
            .spot_price(&usdc(), &wbtc())
            .unwrap();
        let expected = 0.00001537279;
        assert!((price - expected).abs() < 1e-10);
    }

    #[test]
    fn test_spot_price_empty_asks() {
        let mut state = create_test_bebop_state();
        state.asks = vec![]; // Remove all asks

        // Test WBTC/USDC with no asks - should use only best bid
        let price = state
            .spot_price(&wbtc(), &usdc())
            .unwrap();
        assert_eq!(price, 65000.0);
    }

    #[test]
    fn test_spot_price_empty_bids() {
        let mut state = create_test_bebop_state();
        state.bids = vec![]; // Remove all bids
                             // Test WBTC/USDC with no bids - should use only best ask
        let price = state
            .spot_price(&wbtc(), &usdc())
            .unwrap();
        assert_eq!(price, 65100.0);
    }

    #[test]
    fn test_spot_price_no_liquidity() {
        let mut state = create_test_bebop_state();
        state.bids = vec![]; // Remove all bids
        state.asks = vec![]; // Remove all asks
                             // Test with no liquidity at all - should return error
        let result = state.spot_price(&wbtc(), &usdc());
        assert!(result.is_err());
    }

    #[test]
    fn test_get_limits_sell_base_for_quote() {
        let state = create_eth_dai_state();

        // Test selling ETH for DAI (should use bids)
        let (token_limit, quote_limit) = state
            .get_limits(eth().address.clone(), dai().address.clone())
            .unwrap();

        // Total ETH available: 10.0 + 20.0 + 5.0 = 35.0 ETH
        let expected_token_limit = BigUint::from(35u64) * BigUint::from(10u64).pow(18);

        // Total DAI value: (2000*10) + (1995*20) + (1990*5) = 20000 + 39900 + 9950 = 69850
        let expected_quote_limit = BigUint::from_str("69849999999999997378560").unwrap();

        assert_eq!(token_limit, expected_token_limit);
        assert_eq!(quote_limit, expected_quote_limit);
    }

    #[test]
    fn test_get_limits_buy_base_with_quote() {
        let state = create_eth_dai_state();

        // Test buying ETH with DAI (should use asks)
        let (token_limit, quote_limit) = state
            .get_limits(dai().address.clone(), eth().address.clone())
            .unwrap();

        // Total ETH available: 15.0 + 25.0 + 10.0 = 50.0 ETH
        let expected_token_limit = BigUint::from(50u64) * BigUint::from(10u64).pow(18);

        // Total DAI value: (2010*15) + (2015*25) + (2020*10) = 30150 + 50375 + 20200 = 100725
        let expected_quote_limit = BigUint::from_str("100725000000000004980736").unwrap();

        assert_eq!(token_limit, expected_token_limit);
        assert_eq!(quote_limit, expected_quote_limit);
    }

    #[test]
    fn test_get_limits_no_bids() {
        let mut state = create_eth_dai_state();
        state.bids = vec![]; // Remove all bids

        // Test selling ETH for DAI with no bids - should return 0
        let (token_limit, quote_limit) = state
            .get_limits(eth().address.clone(), dai().address.clone())
            .unwrap();

        assert_eq!(token_limit, BigUint::from(0u64));
        assert_eq!(quote_limit, BigUint::from(0u64));
    }

    #[test]
    fn test_get_limits_no_asks() {
        let mut state = create_eth_dai_state();
        state.asks = vec![]; // Remove all asks

        // Test buying ETH with DAI with no asks - should return 0
        let (token_limit, quote_limit) = state
            .get_limits(dai().address.clone(), eth().address.clone())
            .unwrap();

        assert_eq!(token_limit, BigUint::from(0u64));
        assert_eq!(quote_limit, BigUint::from(0u64));
    }

    #[test]
    fn test_get_limits_invalid_token_pair() {
        let state = create_eth_dai_state();

        // Test with invalid token pair (WBTC not in ETH/DAI pool) - should return error
        let result = state.get_limits(wbtc().address.clone(), dai().address.clone());
        assert!(result.is_err());

        if let Err(SimulationError::RecoverableError(msg)) = result {
            assert!(msg.contains("Invalid token addresses"));
        } else {
            panic!("Expected RecoverableError with invalid token addresses message");
        }
    }
}
