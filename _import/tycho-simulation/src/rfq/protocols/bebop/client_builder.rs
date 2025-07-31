use std::{collections::HashSet, str::FromStr};

use tycho_common::{models::Chain, Bytes};

use super::client::BebopClient;
use crate::rfq::errors::RFQError;

fn str_to_bytes(address: &str) -> Result<Bytes, RFQError> {
    Bytes::from_str(address).map_err(|_| {
        RFQError::FatalError(format!("Failed to parse default quote token: {address}"))
    })
}

/// Returns default quote tokens for TVL calculation based on the chain
fn default_quote_tokens_for_chain(chain: Chain) -> Result<HashSet<Bytes>, RFQError> {
    match chain {
        Chain::Ethereum => Ok(HashSet::from([
            str_to_bytes("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48")?, // USDC
            str_to_bytes("0xdac17f958d2ee523a2206206994597c13d831ec7")?, // USDT
            str_to_bytes("0x6b175474e89094c44da98b954eedeac495271d0f")?, // DAI
        ])),
        Chain::Base => Ok(HashSet::from([
            str_to_bytes("0x833589fcd6edb6e08f4c7c32d4f71b54bda02913")?, // USDC
            str_to_bytes("0xfde4c96c8593536e31f229ea8f37b2ada2699bb2")?, // USDT
        ])),
        _ => Ok(HashSet::new()),
    }
}

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
        if self.tokens.is_empty() {
            return Err(RFQError::InvalidInput(
                "At least one token pair must be specified".to_string(),
            ));
        }
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
