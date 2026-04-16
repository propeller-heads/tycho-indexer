use std::collections::HashMap;

use alloy::primitives::Address;
use tycho_common::models::Chain;

/// Minimal configuration for trace handling
#[derive(Debug, Clone)]
pub struct TraceConfig {
    /// Etherscan API key for contract verification
    pub etherscan_api_key: Option<String>,
    /// Chain we're working with
    pub chain: Chain,
    /// Whether to work in offline mode (no external API calls)
    pub offline: bool,
    /// Optional custom contract labels
    pub labels: HashMap<Address, String>,
}

impl TraceConfig {
    /// Create a new trace config for the given chain
    pub fn new(chain: Chain) -> Self {
        Self { etherscan_api_key: None, chain, offline: false, labels: HashMap::new() }
    }

    /// Set the Etherscan API key
    pub fn with_etherscan_api_key(mut self, key: String) -> Self {
        self.etherscan_api_key = Some(key);
        self
    }

    /// Set offline mode
    pub fn with_offline(mut self, offline: bool) -> Self {
        self.offline = offline;
        self
    }

    /// Check if we can use Etherscan (have API key and not offline)
    pub fn can_use_etherscan(&self) -> bool {
        !self.offline && self.etherscan_api_key.is_some()
    }
}

impl Default for TraceConfig {
    fn default() -> Self {
        Self::new(Chain::Ethereum)
    }
}
