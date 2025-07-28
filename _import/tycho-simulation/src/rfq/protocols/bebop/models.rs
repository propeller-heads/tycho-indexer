use alloy::primitives::Address;
use prost::Message;
use serde::{Deserialize, Serialize};
use tycho_common::Bytes;

/// Protobuf message for Bebop pricing updates
#[derive(Clone, PartialEq, Message)]
pub struct BebopPricingUpdate {
    #[prost(message, repeated, tag = "1")]
    pub pairs: Vec<BebopPriceData>,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Message)]
pub struct BebopPriceData {
    #[prost(bytes, tag = "1")]
    pub base: Vec<u8>,
    #[prost(bytes, tag = "2")]
    pub quote: Vec<u8>,
    #[prost(uint64, tag = "3")]
    pub last_update_ts: u64,
    /// Flat array: [price1, size1, price2, size2, ...]
    #[prost(float, repeated, packed = "true", tag = "4")]
    pub bids: Vec<f32>,
    /// Flat array: [price1, size1, price2, size2, ...]
    #[prost(float, repeated, packed = "true", tag = "5")]
    pub asks: Vec<f32>,
}

impl BebopPriceData {
    /// Convert flat array to Vec<(f64, f64)> pairs
    /// Input: [price1, size1, price2, size2, ...]
    /// Output: [(price1, size1), (price2, size2), ...]
    pub fn to_price_size_pairs(array: &[f32]) -> Vec<(f64, f64)> {
        array
            .chunks_exact(2)
            .map(|chunk| (chunk[0] as f64, chunk[1] as f64))
            .collect()
    }

    pub fn get_bids(&self) -> Vec<(f64, f64)> {
        Self::to_price_size_pairs(&self.bids)
    }

    pub fn get_asks(&self) -> Vec<(f64, f64)> {
        Self::to_price_size_pairs(&self.asks)
    }

    pub fn get_pair_key(&self) -> String {
        // Convert raw bytes to Address (which provides checksum formatting)
        let base_addr = Address::from_slice(&self.base);
        let quote_addr = Address::from_slice(&self.quote);
        format!("{base_addr}/{quote_addr}")
    }

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
            .get_bids()
            .iter()
            .map(|(price, size)| price * size)
            .sum();

        let ask_tvl: f64 = self
            .get_asks()
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
    /// - `is_selling`: True for selling tokens (use bids), false for buying tokens (use asks)
    ///
    /// # Returns
    /// Sell price of base token if sell = True, and buy price if otherwise
    pub fn get_price(&self, base_token_amount: f64, sell: bool) -> Option<f64> {
        // Price levels are already sorted: https://docs.bebop.xyz/bebop/bebop-api-pmm-rfq/rfq-api-endpoints/pricing#interpreting-price-levels

        // If selling AAA for USDC, we need to look at [AAA/USDC].bids
        // If buying AAA with USDC, we need to look at [AAA/USDC].asks
        let price_levels = if sell { self.get_bids() } else { self.get_asks() };

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

    /// Calculates the total token output for a given token input using provided price levels.
    ///
    /// Iterates over the given `price_levels`, consuming as much liquidity as available at each
    /// price level until the input amount is fully consumed or liquidity runs out.
    ///
    /// This method assumes that the size of the price levels is already in the same token
    /// denomination as the `amount_in`. It does not return an error if liquidity is
    /// insufficient to fill the entire `amount_in`. Instead, it returns the partially filled
    /// `amount_out` along with the `remaining_amount_in`.
    ///
    ///
    /// # Parameters
    /// - `amount_in`: The amount of base tokens to trade.
    /// - `price_levels`: A vector of `(price, size)` tuples representing available liquidity at
    ///   each price level.
    ///
    /// # Returns
    /// A tuple `(amount_out, remaining_amount_in)`:
    /// - `amount_out`: The total quote token output from the trade.
    /// - `remaining_amount_in`: The portion of `amount_in` that could not be filled due to lack of
    ///   liquidity.
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum BebopQuoteResponse {
    Success(Box<BebopQuotePartial>),
    Error(BebopApiError),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BebopApiError {
    pub error: BebopErrorDetail,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BebopErrorDetail {
    #[serde(rename = "errorCode")]
    pub error_code: u32,
    pub message: String,
    #[serde(rename = "requestId")]
    pub request_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BebopQuotePartial {
    pub status: String,
    #[serde(rename = "settlementAddress")]
    pub settlement_address: Bytes,
    pub tx: TxData,
    #[serde(rename = "toSign")]
    pub to_sign: SingleOrderToSign,
    #[serde(rename = "partialFillOffset")]
    pub partial_fill_offset: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxData {
    pub to: Bytes,
    pub data: String,
    pub value: String,
    pub from: Bytes,
    pub gas: u64,
    #[serde(rename = "gasPrice")]
    pub gas_price: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SingleOrderToSign {
    pub maker_address: Bytes,
    pub taker_address: Bytes,
    pub maker_token: Bytes,
    pub taker_token: Bytes,
    pub maker_amount: String,
    pub taker_amount: String,
    pub maker_nonce: String,
    pub expiry: u64,
    pub receiver: Bytes,
    pub packed_commands: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_tvl_no_normalization() {
        let price_data = BebopPriceData {
            base: hex::decode("C02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2").unwrap(), // WETH
            quote: hex::decode("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48").unwrap(), // USDC
            last_update_ts: 1234567890,
            bids: vec![2000.0f32, 1.0f32, 1999.0f32, 2.0f32],
            asks: vec![2001.0f32, 1.5f32, 2002.0f32, 1.0f32],
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
            base: hex::decode("C02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2").unwrap(), // WETH
            quote: hex::decode("1234567890123456789012345678901234567890").unwrap(), // Mock TAMARA
            last_update_ts: 1234567890,
            bids: vec![99.0f32, 1.0f32, 98.0f32, 2.0f32],
            asks: vec![101.0f32, 1.0f32, 102.0f32, 2.0f32],
        };
        let price_data_tamara_usdc = BebopPriceData {
            base: hex::decode("1234567890123456789012345678901234567890").unwrap(), // Mock TAMARA
            quote: hex::decode("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48").unwrap(), // USDC
            last_update_ts: 1234567890,
            bids: vec![9.0f32, 300.0f32, 8.0f32, 300.0f32],
            asks: vec![11.0f32, 300.0f32, 12.0f32, 300.0f32],
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
            base: hex::decode("C02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2").unwrap(), // WETH
            quote: hex::decode("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48").unwrap(), // USDC
            last_update_ts: 1234567890,
            bids: vec![2000.0f32, 2.0f32, 1999.0f32, 3.0f32],
            asks: vec![2001.0f32, 3.0f32, 2002.0f32, 1.0f32],
        };

        // Test mid price for larger amount spanning multiple levels
        let mid_price_large = price_data.get_mid_price(3.0);
        // Sell 3.0 tokens: 2.0 at 2000.0 + 1.0 at 1999.0 = 4000.0 + 1999.0 = 5999.0
        // Buy 3.0 tokens: 3.0 at 2001.0 = 6003.0
        // Mid = (5999.0 + 6003.0) / 2 = 6001.0
        assert_eq!(mid_price_large, Some(2000.3333333333335));

        // Test missing bids. Token considered untradeable.
        let price_data = BebopPriceData {
            base: hex::decode("C02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2").unwrap(), // WETH
            quote: hex::decode("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48").unwrap(), // USDC
            last_update_ts: 1234567890,
            bids: vec![],
            asks: vec![2001.0f32, 3.0f32, 2002.0f32, 1.0f32],
        };
        assert_eq!(price_data.get_mid_price(3.0), None);

        // Test missing asks. Token considered untradeable.
        let price_data = BebopPriceData {
            base: hex::decode("C02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2").unwrap(), // WETH
            quote: hex::decode("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48").unwrap(), // USDC
            last_update_ts: 1234567890,
            bids: vec![2000.0f32, 2.0f32, 1999.0f32, 3.0f32],
            asks: vec![],
        };
        assert_eq!(price_data.get_mid_price(3.0), None);

        // Test not enough liquidity (give estimate based on existing liquidity)
        let price_data = BebopPriceData {
            base: hex::decode("C02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2").unwrap(), // WETH
            quote: hex::decode("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48").unwrap(), // USDC
            last_update_ts: 1234567890,
            bids: vec![2000.0f32, 2.0f32, 1999.0f32, 3.0f32],
            asks: vec![2001.0f32, 3.0f32, 2002.0f32, 1.0f32],
        };
        let insufficient_mid = price_data.get_mid_price(10.0);
        assert_eq!(insufficient_mid, Some(2000.325));
    }
}
