use anyhow::{anyhow, Result};
use serde::Deserialize;
use tycho_substreams::models::{Attribute, ChangeType};

/// Initial state values for the RocketPool component.
/// Parsed from JSON params and used to set initial attributes when the component is created.
#[derive(Deserialize)]
pub struct InitialState {
    /// Vault liquidity (ETH balance in RocketVault for rocketDepositPool)
    pub liquidity: String,

    /// Protocol settings
    pub deposits_enabled: String,
    pub min_deposit_amount: String,
    pub max_deposit_amount: String,
    pub deposit_fee: String,

    /// Minipool queue positions
    pub queue_full_start: String,
    pub queue_full_end: String,
    pub queue_half_start: String,
    pub queue_half_end: String,
    pub queue_variable_start: String,
    pub queue_variable_end: String,

    /// Network balances (from BalancesUpdated event)
    pub total_eth: String,
    pub reth_supply: String,
}

impl InitialState {
    /// Parse InitialState from a JSON string.
    pub fn from_json(json: &str) -> Result<Self> {
        serde_json::from_str(json)
            .map_err(|e| anyhow!("Failed to parse InitialState from JSON: {}", e))
    }

    /// Convert the initial state to a list of attributes with ChangeType::Creation.
    pub fn get_attributes(&self) -> Result<Vec<Attribute>> {
        Ok(vec![
            Attribute {
                name: "liquidity".to_string(),
                value: hex_to_bytes(&self.liquidity)?,
                change: ChangeType::Creation.into(),
            },
            Attribute {
                name: "deposits_enabled".to_string(),
                value: hex_to_bytes(&self.deposits_enabled)?,
                change: ChangeType::Creation.into(),
            },
            Attribute {
                name: "min_deposit_amount".to_string(),
                value: hex_to_bytes(&self.min_deposit_amount)?,
                change: ChangeType::Creation.into(),
            },
            Attribute {
                name: "max_deposit_amount".to_string(),
                value: hex_to_bytes(&self.max_deposit_amount)?,
                change: ChangeType::Creation.into(),
            },
            Attribute {
                name: "deposit_fee".to_string(),
                value: hex_to_bytes(&self.deposit_fee)?,
                change: ChangeType::Creation.into(),
            },
            Attribute {
                name: "queue_full_start".to_string(),
                value: hex_to_bytes(&self.queue_full_start)?,
                change: ChangeType::Creation.into(),
            },
            Attribute {
                name: "queue_full_end".to_string(),
                value: hex_to_bytes(&self.queue_full_end)?,
                change: ChangeType::Creation.into(),
            },
            Attribute {
                name: "queue_half_start".to_string(),
                value: hex_to_bytes(&self.queue_half_start)?,
                change: ChangeType::Creation.into(),
            },
            Attribute {
                name: "queue_half_end".to_string(),
                value: hex_to_bytes(&self.queue_half_end)?,
                change: ChangeType::Creation.into(),
            },
            Attribute {
                name: "queue_variable_start".to_string(),
                value: hex_to_bytes(&self.queue_variable_start)?,
                change: ChangeType::Creation.into(),
            },
            Attribute {
                name: "queue_variable_end".to_string(),
                value: hex_to_bytes(&self.queue_variable_end)?,
                change: ChangeType::Creation.into(),
            },
            Attribute {
                name: "total_eth".to_string(),
                value: hex_to_bytes(&self.total_eth)?,
                change: ChangeType::Creation.into(),
            },
            Attribute {
                name: "reth_supply".to_string(),
                value: hex_to_bytes(&self.reth_supply)?,
                change: ChangeType::Creation.into(),
            },
        ])
    }

    /// Get the initial ETH balance for the component.
    pub fn get_eth_balance(&self) -> Result<Vec<u8>> {
        hex_to_bytes(&self.total_eth)
    }
}

/// Convert a hex string (with or without 0x prefix) to bytes.
fn hex_to_bytes(hex: &str) -> Result<Vec<u8>> {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    hex::decode(hex).map_err(|e| anyhow!("Failed to decode hex string {}: {}", hex, e))
}
