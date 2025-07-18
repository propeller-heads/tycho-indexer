use std::{any::Any, collections::HashMap};
use alloy::primitives::Address;
use num_bigint::BigUint;
use tycho_common::{
    dto::ProtocolStateDelta,
    models::{token::Token},
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

        // Since this method does not care about sell direction, we average the price of the best bid and ask
        let best_bid = self.bids.first().map(|(price, _)| *price);
        let best_ask = self.asks.first().map(|(price, _)| *price);

        // If just one is available, only consider that one
        let average_price = match (best_bid, best_ask) {
            (Some(best_bid), Some(best_ask)) => (best_bid + best_ask) / 2.0,
            (Some(best_bid), None) => best_bid,
            (None, Some(best_ask)) => best_ask,
            (None, None) => return Err(SimulationError::RecoverableError("No liquidity available".to_string())),
        };
        
        // If the base/quote token addresses are the opposite of the pool tokens, we need to invert the price
        if base_address.to_lowercase() == self.quote_token.to_lowercase() && 
           quote_address.to_lowercase() == self.base_token.to_lowercase() {
            Ok(1.0 / average_price)
        } else {
            // Assume they match
            Ok(average_price)
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
        _sell_token: Bytes,
        _buy_token: Bytes,
    ) -> Result<(BigUint, BigUint), SimulationError> {
        // sum(l.amount for l in levels[(token_in, token_out)])
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
    use super::*;
    use std::str::FromStr;
    use tycho_common::models::Chain;

    fn wbtc() -> Token {
        Token::new(
            &Bytes::from_str("0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599").unwrap(),
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
            &Bytes::from_str("0xA0b86991c6218a76c1d19D4a2e9Eb0cE3606eB48").unwrap(),
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
            base_token: "0x2260FAC5E5542a773Aa44fBCfeDF7C193bc2C599".to_string(), // WBTC
            quote_token: "0xA0b86991c6218a76c1d19D4a2e9Eb0cE3606eB48".to_string(), // USDC
            last_update_ts: 1703097600, // 2023-12-20 20:00:00 UTC
            bids: vec![
                (65000.0, 1.5),  // Best bid: $65,000 for 1.5 WBTC
                (64950.0, 2.0),  // Second best: $64,950 for 2.0 WBTC
                (64900.0, 0.5),  // Third: $64,900 for 0.5 WBTC
            ],
            asks: vec![
                (65100.0, 1.0),  // Best ask: $65,100 for 1.0 WBTC
                (65150.0, 2.5),  // Second: $65,150 for 2.5 WBTC
                (65200.0, 1.5),  // Third: $65,200 for 1.5 WBTC
            ],
        }
    }

    #[test]
    fn test_spot_price_matching_base_and_quote() {
        let state = create_test_bebop_state();

        // Test WBTC/USDC (base/quote) - should use average of best bid and ask
        let price = state.spot_price(&wbtc(), &usdc()).unwrap();
        assert_eq!(price, 65050.0);
    }

    #[test]
    fn test_spot_price_inverted_base_and_quote() {
        let state = create_test_bebop_state();

        // Test USDC/WBTC (quote/base) - should use average of best bid and ask, then invert
        let price = state.spot_price(&usdc(), &wbtc()).unwrap();
        let expected = 0.00001537279; 
        assert!((price - expected).abs() < 1e-10);
    }

    #[test]
    fn test_spot_price_empty_asks() {
        let mut state = create_test_bebop_state();
        state.asks = vec![]; // Remove all asks

        // Test WBTC/USDC with no asks - should use only best bid
        let price = state.spot_price(&wbtc(), &usdc()).unwrap();
        assert_eq!(price, 65000.0);
    }

    #[test]
    fn test_spot_price_empty_bids() {
        let mut state = create_test_bebop_state();
        state.bids = vec![]; // Remove all bids
        // Test WBTC/USDC with no bids - should use only best ask
        let price = state.spot_price(&wbtc(), &usdc()).unwrap();
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
}
