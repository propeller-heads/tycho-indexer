use std::collections::HashSet;

use tycho_common::models::Chain;

use super::client::BebopClient;
use crate::rfq::errors::RFQError;

/// Returns default quote tokens for TVL calculation based on the chain
fn default_quote_tokens_for_chain(chain: Chain) -> HashSet<String> {
    match chain {
        Chain::Ethereum => HashSet::from([
            "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48".to_string(), // USDC
            "0xdac17f958d2ee523a2206206994597c13d831ec7".to_string(), // USDT
            "0x6b175474e89094c44da98b954eedeac495271d0f".to_string(), // DAI
        ]),
        Chain::Base => HashSet::from([
            "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913".to_string(), // USDC
            "0xfde4c96c8593536e31f229ea8f37b2ada2699bb2".to_string(), // USDT
        ]),
        _ => HashSet::new(),
    }
}

/// `BebopClientBuilder` is a builder pattern implementation for creating instances of
/// `BebopClient`.
///
/// # Example
/// ```rust
/// use tycho_simulation::rfq::protocols::bebop::client_builder::BebopClientBuilder;
/// use tycho_common::models::Chain;
/// use std::collections::HashSet;
///
/// let mut pairs = HashSet::new();
/// pairs.insert(("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2".to_string(), // WETH
///               "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48".to_string())); // USDC
///
/// let client = BebopClientBuilder::new(
///     Chain::Ethereum,
///     "ws_user".to_string(),
///     "ws_key".to_string()
/// )
/// .pairs(pairs)
/// .tvl_threshold(500.0)
/// .build()
/// .unwrap();
/// ```
pub struct BebopClientBuilder {
    chain: Chain,
    ws_user: String,
    ws_key: String,
    pairs: HashSet<(String, String)>,
    tvl: f64,
    quote_tokens: Option<HashSet<String>>,
}

impl BebopClientBuilder {
    pub fn new(chain: Chain, ws_user: String, ws_key: String) -> Self {
        Self {
            chain,
            ws_user,
            ws_key,
            pairs: HashSet::new(),
            tvl: 100.0, // Default $100 minimum TVL
            quote_tokens: None,
        }
    }

    /// Set the token pairs for which to monitor prices
    pub fn pairs(mut self, pairs: HashSet<(String, String)>) -> Self {
        self.pairs = pairs;
        self
    }

    /// Set the minimum TVL threshold for pools
    pub fn tvl_threshold(mut self, tvl: f64) -> Self {
        self.tvl = tvl;
        self
    }

    /// Set custom quote tokens for TVL calculation
    /// If not set, will use chain-specific defaults
    pub fn quote_tokens(mut self, quote_tokens: HashSet<String>) -> Self {
        self.quote_tokens = Some(quote_tokens);
        self
    }

    pub fn build(self) -> Result<BebopClient, RFQError> {
        if self.pairs.is_empty() {
            return Err(RFQError::InvalidInput(
                "At least one token pair must be specified".to_string(),
            ));
        }

        let quote_tokens = self
            .quote_tokens
            .unwrap_or_else(|| default_quote_tokens_for_chain(self.chain));

        BebopClient::new(self.chain, self.pairs, self.tvl, self.ws_user, self.ws_key, quote_tokens)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bebop_client_builder_basic_config() {
        let mut pairs = HashSet::new();
        pairs.insert((
            "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2".to_string(),
            "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48".to_string(),
        ));

        let result = BebopClientBuilder::new(
            Chain::Ethereum,
            "test_user".to_string(),
            "test_key".to_string(),
        )
        .pairs(pairs)
        .build();
        assert!(result.is_ok());
    }

    #[test]
    fn test_bebop_client_builder_custom_configuration() {
        let mut custom_quote_tokens = HashSet::new();
        custom_quote_tokens.insert("0x1234567890123456789012345678901234567890".to_string());

        let mut pairs = HashSet::new();
        pairs.insert((
            "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2".to_string(),
            "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48".to_string(),
        ));

        let result = BebopClientBuilder::new(
            Chain::Ethereum,
            "test_user".to_string(),
            "test_key".to_string(),
        )
        .pairs(pairs)
        .tvl_threshold(500.0)
        .quote_tokens(custom_quote_tokens.clone())
        .build();
        assert!(result.is_ok());
    }

    #[test]
    fn test_bebop_client_builder_validation() {
        let result = BebopClientBuilder::new(
            Chain::Ethereum,
            "test_user".to_string(),
            "test_key".to_string(),
        )
        .build();

        assert!(result.is_err());
        assert!(matches!(result, Err(RFQError::InvalidInput(_))), "Wrong error.");
    }
}
