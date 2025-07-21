use std::{any::Any, collections::HashMap};

use num_bigint::BigUint;
use num_traits::Pow;
use tycho_common::{
    dto::ProtocolStateDelta,
    models::token::Token,
    simulation::{
        errors::{SimulationError, TransitionError},
        protocol_sim::{Balances, GetAmountOutResult, ProtocolSim},
    },
    Bytes,
};

use crate::rfq::protocols::bebop::models::BebopPriceData;

#[derive(Debug, Clone)]
pub struct BebopState {
    pub base_token: Token,
    pub quote_token: Token,
    pub price_data: BebopPriceData,
}

impl ProtocolSim for BebopState {
    fn fee(&self) -> f64 {
        todo!()
    }

    fn spot_price(&self, base: &Token, quote: &Token) -> Result<f64, SimulationError> {
        // Since this method does not care about sell direction, we average the price of the best
        // bid and ask
        let best_bid = self
            .price_data
            .bids
            .first()
            .map(|(price, _)| *price);
        let best_ask = self
            .price_data
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
        if base.address == self.quote_token.address && quote.address == self.base_token.address {
            Ok(1.0 / average_price)
        } else if quote.address == self.quote_token.address &&
            base.address == self.base_token.address
        {
            Ok(average_price)
        } else {
            Err(SimulationError::RecoverableError(format!(
                "Invalid token addresses: {}, {}",
                base.address, quote.address
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
        // If selling BASE for QUOTE, we need to look at [BASE/QUOTE].bids
        // If buying BASE with QUOTE, we need to look at [BASE/QUOTE].asks
        let (sell_decimals, buy_decimals, price_levels) = if sell_token == self.base_token.address &&
            buy_token == self.quote_token.address
        {
            (self.base_token.decimals, self.quote_token.decimals, self.price_data.bids.clone())
        } else if buy_token == self.base_token.address && sell_token == self.quote_token.address {
            (self.quote_token.decimals, self.base_token.decimals, self.price_data.asks.clone())
        } else {
            return Err(SimulationError::RecoverableError(format!(
                "Invalid token addresses: {sell_token}, {buy_token}"
            )))
        };

        // If there are no price levels, return 0 for both limits
        if price_levels.is_empty() {
            return Ok((BigUint::from(0u64), BigUint::from(0u64)));
        }

        let total_base_amount: f64 = price_levels
            .iter()
            .map(|(_, amount)| amount)
            .sum();
        let total_quote_amount: f64 = price_levels
            .iter()
            .map(|(price, amount)| price * amount)
            .sum();

        let (total_sell_amount, total_buy_amount) =
            if sell_token == self.base_token.address && buy_token == self.quote_token.address {
                (total_base_amount, total_quote_amount)
            } else {
                (total_quote_amount, total_base_amount)
            };

        let sell_limit =
            BigUint::from((total_sell_amount * 10_f64.pow(sell_decimals as f64)) as u128);
        let buy_limit = BigUint::from((total_buy_amount * 10_f64.pow(buy_decimals as f64)) as u128);

        Ok((sell_limit, buy_limit))
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

    fn create_test_bebop_state() -> BebopState {
        BebopState {
            base_token: wbtc(),
            quote_token: usdc(),
            price_data: BebopPriceData {
                last_update_ts: 1703097600.0,
                bids: vec![(65000.0, 1.5), (64950.0, 2.0), (64900.0, 0.5)],
                asks: vec![(65100.0, 1.0), (65150.0, 2.5), (65200.0, 1.5)],
            },
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
        state.price_data.asks = vec![]; // Remove all asks

        // Test WBTC/USDC with no asks - should use only best bid
        let price = state
            .spot_price(&wbtc(), &usdc())
            .unwrap();
        assert_eq!(price, 65000.0);
    }

    #[test]
    fn test_spot_price_empty_bids() {
        let mut state = create_test_bebop_state();
        state.price_data.bids = vec![]; // Remove all bids
                                        // Test WBTC/USDC with no bids - should use only best ask
        let price = state
            .spot_price(&wbtc(), &usdc())
            .unwrap();
        assert_eq!(price, 65100.0);
    }

    #[test]
    fn test_spot_price_no_liquidity() {
        let mut state = create_test_bebop_state();
        state.price_data.bids = vec![]; // Remove all bids
        state.price_data.asks = vec![]; // Remove all asks
                                        // Test with no liquidity at all - should return error
        let result = state.spot_price(&wbtc(), &usdc());
        assert!(result.is_err());
    }

    #[test]
    fn test_get_limits_sell_base_for_quote() {
        let state = create_test_bebop_state();

        // Test selling WBTC for USDC (should use bids)
        let (wbtc_limit, usdc_limit) = state
            .get_limits(wbtc().address.clone(), usdc().address.clone())
            .unwrap();

        // Use bids: vec![(65000.0, 1.5), (64950.0, 2.0), (64900.0, 0.5)]

        // Total WBTC available: 1.5 + 2.0 + 0.5 = 4.0 WBTC
        let expected_wbtc_limit = BigUint::from(4u64) * BigUint::from(10u64).pow(8u32);

        // Total USDC value: (65000*1.5) + (64950*2.0) + (64900*0.5) = 97500 + 129900 + 32450 =
        // 259850
        let expected_usdc_limit = BigUint::from(259850u64) * BigUint::from(10u64).pow(6u32);

        assert_eq!(wbtc_limit, expected_wbtc_limit);
        assert_eq!(usdc_limit, expected_usdc_limit);
    }

    #[test]
    fn test_get_limits_buy_base_with_quote() {
        let state = create_test_bebop_state();

        // Test buying WBTC with USDC (should use asks)
        let (usdc_limit, wbtc_limit) = state
            .get_limits(usdc().address.clone(), wbtc().address.clone())
            .unwrap();

        // Use asks: vec![(65100.0, 1.0), (65150.0, 2.5), (65200.0, 1.5)]

        // Total USDC needed: (65100*1.0) + (65150*2.5) + (65200*1.5) = 65100 + 162875 + 97800 =
        // 325775
        let expected_usdc_limit = BigUint::from(325775u64) * BigUint::from(10u64).pow(6u32);

        // Total WBTC available: 1.0 + 2.5 + 1.5 = 5.0 WBTC
        let expected_wbtc_limit = BigUint::from(5u64) * BigUint::from(10u64).pow(8u32);

        assert_eq!(usdc_limit, expected_usdc_limit);
        assert_eq!(wbtc_limit, expected_wbtc_limit);
    }

    #[test]
    fn test_get_limits_no_bids() {
        let mut state = create_test_bebop_state();
        state.price_data.bids = vec![]; // Remove all bids

        // Test selling WBTC for USDC with no bids - should return 0
        let (token_limit, quote_limit) = state
            .get_limits(wbtc().address.clone(), usdc().address.clone())
            .unwrap();

        assert_eq!(token_limit, BigUint::from(0u64));
        assert_eq!(quote_limit, BigUint::from(0u64));
    }

    #[test]
    fn test_get_limits_no_asks() {
        let mut state = create_test_bebop_state();
        state.price_data.asks = vec![]; // Remove all asks

        // Test buying WBTC with USDC with no asks - should return 0
        let (token_limit, quote_limit) = state
            .get_limits(usdc().address.clone(), wbtc().address.clone())
            .unwrap();

        assert_eq!(token_limit, BigUint::from(0u64));
        assert_eq!(quote_limit, BigUint::from(0u64));
    }

    #[test]
    fn test_get_limits_invalid_token_pair() {
        let state = create_test_bebop_state();

        // Create a different token (not WBTC or USDC)
        let eth = Token::new(
            &hex::decode("c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2")
                .unwrap()
                .into(),
            "ETH",
            18,
            0,
            &[Some(10_000)],
            Chain::Ethereum,
            100,
        );

        // Test with invalid token pair (ETH not in WBTC/USDC pool) - should return error
        let result = state.get_limits(eth.address.clone(), usdc().address.clone());
        assert!(result.is_err());

        if let Err(SimulationError::RecoverableError(msg)) = result {
            assert!(msg.contains("Invalid token addresses"));
        } else {
            panic!("Expected RecoverableError with invalid token addresses message");
        }
    }
}
