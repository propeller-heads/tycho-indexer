use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BebopPriceData {
    pub last_update_ts: f64,
    /// Vec where each tuple is (price, size)
    pub bids: Vec<(f64, f64)>,
    /// Vec where each tuple is (price, size)
    pub asks: Vec<(f64, f64)>,
}

impl BebopPriceData {
    /// Calculates Total Value Locked (TVL) based on bid/ask levels.
    ///
    /// TVL is calculated using the formula from Bebop's documentation:
    /// https://docs.bebop.xyz/bebop/bebop-api-pmm-rfq/rfq-api-endpoints/pricing#interpreting-price-levels
    ///
    /// Returns the average of bid and ask TVLs across all price levels.
    ///
    /// Note: This calculation normalizes the quote token in case quote_price_data is passed.
    pub fn calculate_tvl(&self, quote_price_data: Option<BebopPriceData>) -> f64 {
        let bid_tvl: f64 = self
            .bids
            .iter()
            .map(|(price, size)| price * size)
            .sum();

        let ask_tvl: f64 = self
            .asks
            .iter()
            .map(|(price, size)| price * size)
            .sum();

        let mut total_tvl = (bid_tvl + ask_tvl) / 2.0;

        // If quote price data is provided, we need to normalize the TVL to be in
        // one of the approved token (for example USDC)
        if let Some(quote_data) = quote_price_data {
            if let Some(price_of_quote_token) = quote_data.get_mid_price(total_tvl) {
                total_tvl *= price_of_quote_token;
            } else {
                // Quote token has no TVL in one of the approved tokens (for normalizations)
                return 0.0;
            }
        }
        total_tvl
    }

    /// Gets the mid price estimate of the given token in the quote token
    ///
    /// # Parameters
    /// - `base_token_amount`: The amount of tokens to price
    /// - `price_data`: The price data containing bids and asks
    ///
    /// # Returns
    /// The quote token amount at mid price, given there are both bids and asks
    pub fn get_mid_price(&self, base_token_amount: f64) -> Option<f64> {
        let sell_price = self.get_price(base_token_amount, true)?;
        let buy_price = self.get_price(base_token_amount, false)?;

        // Return average (mid price)
        Some((sell_price + buy_price) / 2.0)
    }

    /// Calculate quote token amount for trading base tokens using price levels
    ///
    /// NOTE: This method is meant just to be used as an estimate - as it does not
    /// error or return None if there is not enough liquidity to cover base token amount.
    /// This method will only return None if there are absolutely no bids or asks.
    ///
    /// # Parameters
    /// - `base_token_amount`: The amount of tokens to trade
    /// - `price_data`: The price data containing bids and asks
    /// - `is_selling`: True for selling tokens (use bids), false for buying tokens (use asks)
    ///
    /// # Returns
    /// Sell price of base token if sell = True, and buy price if otherwise
    pub fn get_price(&self, base_token_amount: f64, sell: bool) -> Option<f64> {
        // Price levels are already sorted: https://docs.bebop.xyz/bebop/bebop-api-pmm-rfq/rfq-api-endpoints/pricing#interpreting-price-levels

        // If selling AAA for USDC, we need to look at [AAA/USDC].bids
        // If buying AAA with USDC, we need to look at [AAA/USDC].asks
        let price_levels = if sell { self.bids.clone() } else { self.asks.clone() };

        // If there is absolutely no TVL, return None. Price is unavailable.
        if price_levels.is_empty() {
            return None;
        }

        let (total_quote_token, remaining_base_token) =
            self.get_amount_out_from_levels(base_token_amount, price_levels);

        // If we can't fill the whole order (ran out of liquidity), calculate the price based on
        // the amount that we could fill, in order to have at least some price estimate
        Some(total_quote_token / (base_token_amount - remaining_base_token))
    }

    pub fn get_amount_out_from_levels(
        &self,
        amount_in: f64,
        price_levels: Vec<(f64, f64)>,
    ) -> (f64, f64) {
        let mut remaining_amount_in = amount_in;
        let mut amount_out = 0.0;

        for (price, tokens_available) in price_levels.iter() {
            if remaining_amount_in <= 0.0 {
                break;
            }

            let amount_in_available_to_trade = remaining_amount_in.min(*tokens_available);

            amount_out += amount_in_available_to_trade * price;
            remaining_amount_in -= amount_in_available_to_trade;
        }
        (amount_out, remaining_amount_in)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_tvl_no_normalization() {
        let price_data = BebopPriceData {
            last_update_ts: 1234567890.0,
            bids: vec![(2000.0, 1.0), (1999.0, 2.0)],
            asks: vec![(2001.0, 1.5), (2002.0, 1.0)],
        };

        let tvl = price_data.calculate_tvl(None);

        // Expected calculation:
        // Bid TVL: (2000.0 * 1.0) + (1999.0 * 2.0) = 2000.0 + 3998.0 = 5998.0
        // Ask TVL: (2001.0 * 1.5) + (2002.0 * 1.0) = 3001.5 + 2002.0 = 5003.5
        // Total TVL: (5998.0 + 5003.5) / 2 = 5500.75
        assert!((tvl - 5500.75).abs() < 0.01);
    }

    #[test]
    fn test_calculate_tvl_with_normalization() {
        // Scenario: We have price data for ETH/TAMARA. One ETH is normally around 100 TAMARA,
        // and one TAMARA is around 10 USDC.
        let price_data_eth_tamara = BebopPriceData {
            last_update_ts: 1234567890.0,
            bids: vec![(99.0, 1.0), (98.0, 2.0)],
            asks: vec![(101.0, 1.0), (102.0, 2.0)],
        };
        let price_data_tamara_usdc = BebopPriceData {
            last_update_ts: 1234567890.0,
            bids: vec![(9.0, 300.0), (8.0, 300.0)],
            asks: vec![(11.0, 300.0), (12.0, 300.0)],
        };

        let tvl = price_data_eth_tamara.calculate_tvl(Some(price_data_tamara_usdc));

        // Expected calculation:
        // TVL of ETH in TAMARA = (99 * 1 + 98 * 2 + 101 * 1 + 102 * 2) / 2 = 300
        // Price of TAMARA in USDC = around 10
        // TVL of ETH in USDC = 300 * 10 = 3000
        assert_eq!(tvl, 3000.0);
    }

    #[test]
    fn test_get_mid_price() {
        let price_data = BebopPriceData {
            last_update_ts: 1234567890.0,
            bids: vec![(2000.0, 2.0), (1999.0, 3.0)],
            asks: vec![(2001.0, 3.0), (2002.0, 1.0)],
        };

        // Test mid price for larger amount spanning multiple levels
        let mid_price_large = price_data.get_mid_price(3.0);
        // Sell 3.0 tokens: 2.0 at 2000.0 + 1.0 at 1999.0 = 4000.0 + 1999.0 = 5999.0
        // Buy 3.0 tokens: 3.0 at 2001.0 = 6003.0
        // Mid = (5999.0 + 6003.0) / 2 = 6001.0
        assert_eq!(mid_price_large, Some(2000.3333333333335));

        // Test missing bids. Token considered untradeable.
        let price_data = BebopPriceData {
            last_update_ts: 1234567890.0,
            bids: vec![],
            asks: vec![(2001.0, 3.0), (2002.0, 1.0)],
        };
        assert_eq!(price_data.get_mid_price(3.0), None);

        // Test missing asks. Token considered untradeable.
        let price_data = BebopPriceData {
            last_update_ts: 1234567890.0,
            bids: vec![(2000.0, 2.0), (1999.0, 3.0)],
            asks: vec![],
        };
        assert_eq!(price_data.get_mid_price(3.0), None);

        // Test not enough liquidity (give estimate based on existing liquidity)
        let price_data = BebopPriceData {
            last_update_ts: 1234567890.0,
            bids: vec![(2000.0, 2.0), (1999.0, 3.0)],
            asks: vec![(2001.0, 3.0), (2002.0, 1.0)],
        };
        let insufficient_mid = price_data.get_mid_price(10.0);
        assert_eq!(insufficient_mid, Some(2000.325));
    }
}
