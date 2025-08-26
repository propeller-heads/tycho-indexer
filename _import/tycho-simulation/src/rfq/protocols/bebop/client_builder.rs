use std::collections::HashSet;

use tycho_common::{models::Chain, Bytes};

use super::client::BebopClient;
use crate::rfq::{errors::RFQError, protocols::utils::default_quote_tokens_for_chain};

/// `BebopClientBuilder` is a builder pattern implementation for creating instances of
/// `BebopClient`.
///
/// # Example
/// ```rust
/// use tycho_simulation::rfq::protocols::bebop::client_builder::BebopClientBuilder;
/// use tycho_common::{models::Chain, Bytes};
/// use std::{collections::HashSet, str::FromStr};
///
/// let mut tokens = HashSet::new();
/// tokens.insert(Bytes::from_str("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2").unwrap()); // WETH
/// tokens.insert(Bytes::from_str("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48").unwrap()); // USDC
///
/// let client = BebopClientBuilder::new(
///     Chain::Ethereum,
///     "ws_user".to_string(),
///     "ws_key".to_string()
/// )
/// .tokens(tokens)
/// .tvl_threshold(500.0)
/// .build()
/// .unwrap();
/// ```
pub struct BebopClientBuilder {
    chain: Chain,
    ws_user: String,
    ws_key: String,
    tokens: HashSet<Bytes>,
    tvl: f64,
    quote_tokens: Option<HashSet<Bytes>>,
}

impl BebopClientBuilder {
    pub fn new(chain: Chain, ws_user: String, ws_key: String) -> Self {
        Self {
            chain,
            ws_user,
            ws_key,
            tokens: HashSet::new(),
            tvl: 100.0, // Default $100 minimum TVL
            quote_tokens: None,
        }
    }

    /// Set the tokens for which to monitor prices
    pub fn tokens(mut self, tokens: HashSet<Bytes>) -> Self {
        self.tokens = tokens;
        self
    }

    /// Set the minimum TVL threshold for pools
    pub fn tvl_threshold(mut self, tvl: f64) -> Self {
        self.tvl = tvl;
        self
    }

    /// Set custom quote tokens for TVL calculation
    /// If not set, will use chain-specific defaults
    pub fn quote_tokens(mut self, quote_tokens: HashSet<Bytes>) -> Self {
        self.quote_tokens = Some(quote_tokens);
        self
    }

    pub fn build(self) -> Result<BebopClient, RFQError> {
        let quote_tokens;
        if let Some(tokens) = self.quote_tokens {
            quote_tokens = tokens;
        } else {
            quote_tokens = default_quote_tokens_for_chain(self.chain)?
        }

        BebopClient::new(self.chain, self.tokens, self.tvl, self.ws_user, self.ws_key, quote_tokens)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    #[test]
    fn test_bebop_client_builder_basic_config() {
        let mut tokens = HashSet::new();
        tokens.insert(Bytes::from_str("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2").unwrap());
        tokens.insert(Bytes::from_str("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48").unwrap());

        let result = BebopClientBuilder::new(
            Chain::Ethereum,
            "test_user".to_string(),
            "test_key".to_string(),
        )
        .tokens(tokens)
        .build();
        assert!(result.is_ok());
    }

    #[test]
    fn test_bebop_client_builder_custom_configuration() {
        let mut custom_quote_tokens = HashSet::new();
        custom_quote_tokens
            .insert(Bytes::from_str("0x1234567890123456789012345678901234567890").unwrap());

        let mut tokens = HashSet::new();
        tokens.insert(Bytes::from_str("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2").unwrap());
        tokens.insert(Bytes::from_str("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48").unwrap());

        let result = BebopClientBuilder::new(
            Chain::Ethereum,
            "test_user".to_string(),
            "test_key".to_string(),
        )
        .tokens(tokens)
        .tvl_threshold(500.0)
        .quote_tokens(custom_quote_tokens.clone())
        .build();
        assert!(result.is_ok());
    }
}
