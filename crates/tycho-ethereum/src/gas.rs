use alloy::primitives::B256;
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DisplayFromStr};

/// Represents gas pricing information for EVM blockchain transactions,
/// including the block context where the gas price was queried.
///
/// This allows you to know exactly where the node was when the gas price was retrieved.
#[serde_as]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BlockGasPrice {
    /// Block number where this gas price was queried
    pub block_number: u64,
    /// Block hash where this gas price was queried
    pub block_hash: B256,
    /// Block timestamp where this gas price was queried
    pub block_timestamp: u64,
    /// The gas pricing model and values
    #[serde(flatten)]
    pub pricing: GasPrice,
}

/// Different EVM networks use different gas pricing models:
/// - Most modern chains use EIP-1559 (base fee + priority fee model)
/// - Legacy chains (e.g., pre-London Ethereum) use a simple gas price
#[serde_as]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum GasPrice {
    /// Legacy gas pricing model with a single gas price value.
    /// Used by pre-London Ethereum and similar chains.
    Legacy {
        /// Gas price in wei
        #[serde_as(as = "DisplayFromStr")]
        gas_price: BigUint,
    },
    /// EIP-1559 gas pricing model with base fee and priority fee.
    /// Used by Ethereum after the London hard fork and most modern EVM chains.
    Eip1559 {
        /// Base fee per gas in wei, determined by the protocol
        #[serde_as(as = "DisplayFromStr")]
        base_fee_per_gas: BigUint,
        /// Maximum priority fee (tip) per gas in wei, paid to validators
        #[serde_as(as = "DisplayFromStr")]
        max_priority_fee_per_gas: BigUint,
    },
}

impl BlockGasPrice {
    /// Returns the effective gas price (base + priority).
    ///
    /// For Legacy: returns the gas_price
    /// For EIP-1559: returns base_fee + max_priority_fee
    pub fn effective_gas_price(&self) -> BigUint {
        match &self.pricing {
            GasPrice::Legacy { gas_price } => gas_price.clone(),
            GasPrice::Eip1559 { base_fee_per_gas, max_priority_fee_per_gas } => {
                base_fee_per_gas + max_priority_fee_per_gas
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_legacy_effective_gas_price() {
        let gas_price_value = BigUint::from(50_000_000_000u64); // 50 Gwei
        let legacy = BlockGasPrice {
            block_number: 12345,
            block_hash: B256::ZERO,
            block_timestamp: 1234567890,
            pricing: GasPrice::Legacy { gas_price: gas_price_value.clone() },
        };
        assert_eq!(legacy.effective_gas_price(), gas_price_value);
    }

    #[test]
    fn test_eip1559_effective_gas_price() {
        let base_fee = BigUint::from(30_000_000_000u64); // 30 Gwei
        let priority_fee = BigUint::from(2_000_000_000u64); // 2 Gwei
        let expected = base_fee.clone() + priority_fee.clone();

        let eip1559 = BlockGasPrice {
            block_number: 12345,
            block_hash: B256::ZERO,
            block_timestamp: 1234567890,
            pricing: GasPrice::Eip1559 {
                base_fee_per_gas: base_fee,
                max_priority_fee_per_gas: priority_fee,
            },
        };

        assert_eq!(eip1559.effective_gas_price(), expected);
    }

    #[test]
    fn test_serialize_legacy_gas_price() {
        let gas_price = BlockGasPrice {
            block_number: 12345,
            block_hash: B256::ZERO,
            block_timestamp: 1234567890,
            pricing: GasPrice::Legacy { gas_price: BigUint::from(50_000_000_000u64) },
        };

        let json = serde_json::to_string(&gas_price).unwrap();
        assert_eq!(
            json,
            r#"{"block_number":12345,"block_hash":"0x0000000000000000000000000000000000000000000000000000000000000000","block_timestamp":1234567890,"type":"legacy","gas_price":"50000000000"}"#
        );
    }

    #[test]
    fn test_deserialize_legacy_gas_price() {
        let json = r#"{"block_number":12345,"block_hash":"0x0000000000000000000000000000000000000000000000000000000000000000","block_timestamp":1234567890,"type":"legacy","gas_price":"50000000000"}"#;
        let gas_price: BlockGasPrice = serde_json::from_str(json).unwrap();

        assert_eq!(
            gas_price,
            BlockGasPrice {
                block_number: 12345,
                block_hash: B256::ZERO,
                block_timestamp: 1234567890,
                pricing: GasPrice::Legacy { gas_price: BigUint::from(50_000_000_000u64) },
            }
        );
    }

    #[test]
    fn test_serialize_eip1559_gas_price() {
        let gas_price = BlockGasPrice {
            block_number: 12345,
            block_hash: B256::ZERO,
            block_timestamp: 1234567890,
            pricing: GasPrice::Eip1559 {
                base_fee_per_gas: BigUint::from(30_000_000_000u64),
                max_priority_fee_per_gas: BigUint::from(2_000_000_000u64),
            },
        };

        let json = serde_json::to_string(&gas_price).unwrap();
        assert_eq!(
            json,
            r#"{"block_number":12345,"block_hash":"0x0000000000000000000000000000000000000000000000000000000000000000","block_timestamp":1234567890,"type":"eip1559","base_fee_per_gas":"30000000000","max_priority_fee_per_gas":"2000000000"}"#
        );
    }

    #[test]
    fn test_deserialize_eip1559_gas_price() {
        let json = r#"{"block_number":12345,"block_hash":"0x0000000000000000000000000000000000000000000000000000000000000000","block_timestamp":1234567890,"type":"eip1559","base_fee_per_gas":"30000000000","max_priority_fee_per_gas":"2000000000"}"#;
        let gas_price: BlockGasPrice = serde_json::from_str(json).unwrap();

        assert_eq!(
            gas_price,
            BlockGasPrice {
                block_number: 12345,
                block_hash: B256::ZERO,
                block_timestamp: 1234567890,
                pricing: GasPrice::Eip1559 {
                    base_fee_per_gas: BigUint::from(30_000_000_000u64),
                    max_priority_fee_per_gas: BigUint::from(2_000_000_000u64),
                },
            }
        );
    }

    #[test]
    fn test_roundtrip_legacy() {
        let original = BlockGasPrice {
            block_number: 12345,
            block_hash: B256::ZERO,
            block_timestamp: 1234567890,
            pricing: GasPrice::Legacy { gas_price: BigUint::from(123_456_789_000u64) },
        };

        let json = serde_json::to_string(&original).unwrap();
        let deserialized: BlockGasPrice = serde_json::from_str(&json).unwrap();

        assert_eq!(original, deserialized);
    }

    #[test]
    fn test_roundtrip_eip1559() {
        let original = BlockGasPrice {
            block_number: 12345,
            block_hash: B256::ZERO,
            block_timestamp: 1234567890,
            pricing: GasPrice::Eip1559 {
                base_fee_per_gas: BigUint::from(987_654_321_000u64),
                max_priority_fee_per_gas: BigUint::from(5_000_000_000u64),
            },
        };

        let json = serde_json::to_string(&original).unwrap();
        let deserialized: BlockGasPrice = serde_json::from_str(&json).unwrap();

        assert_eq!(original, deserialized);
    }

    #[test]
    fn test_serialize_large_numbers() {
        // Test with very large BigUint values
        let large_value = BigUint::parse_bytes(b"1000000000000000000000", 10).unwrap();
        let gas_price = BlockGasPrice {
            block_number: 12345,
            block_hash: B256::ZERO,
            block_timestamp: 1234567890,
            pricing: GasPrice::Legacy { gas_price: large_value },
        };

        let json = serde_json::to_string(&gas_price).unwrap();
        let deserialized: BlockGasPrice = serde_json::from_str(&json).unwrap();

        assert_eq!(gas_price, deserialized);
    }

    #[test]
    fn test_deserialize_invalid_json() {
        let invalid_json = r#"{"block_number":12345,"block_hash":"0x0000000000000000000000000000000000000000000000000000000000000000","block_timestamp":1234567890,"type":"legacy","gas_price":"not_a_number"}"#;
        let result: Result<BlockGasPrice, _> = serde_json::from_str(invalid_json);
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialize_missing_field() {
        let invalid_json = r#"{"block_number":12345,"block_hash":"0x0000000000000000000000000000000000000000000000000000000000000000","block_timestamp":1234567890,"type":"eip1559","base_fee_per_gas":"30000000000"}"#;
        let result: Result<BlockGasPrice, _> = serde_json::from_str(invalid_json);
        assert!(result.is_err());
    }
}
