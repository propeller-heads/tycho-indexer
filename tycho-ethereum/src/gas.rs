use num_bigint::BigUint;

/// Represents gas pricing information for EVM blockchain transactions.
///
/// Different EVM networks use different gas pricing models:
/// - Most modern chains use EIP-1559 (base fee + priority fee model)
/// - Legacy chains (e.g., pre-London Ethereum) use a simple gas price
#[derive(Debug, Clone)]
pub enum GasPrice {
    /// Legacy gas pricing model with a single gas price value.
    /// Used by pre-London Ethereum and similar chains.
    Legacy {
        /// Gas price in wei
        gas_price: BigUint,
    },
    /// EIP-1559 gas pricing model with base fee and priority fee.
    /// Used by Ethereum after the London hard fork and most modern EVM chains.
    Eip1559 {
        /// Base fee per gas in wei, determined by the protocol
        base_fee_per_gas: BigUint,
        /// Maximum priority fee (tip) per gas in wei, paid to validators
        max_priority_fee_per_gas: BigUint,
    },
}

impl GasPrice {
    /// Returns the effective gas price (base + priority).
    ///
    /// For Legacy: returns the gas_price
    /// For EIP-1559: returns base_fee + max_priority_fee
    pub fn effective_gas_price(&self) -> BigUint {
        match self {
            GasPrice::Legacy { gas_price } => gas_price.clone(),
            GasPrice::Eip1559 { base_fee_per_gas, max_priority_fee_per_gas } => {
                base_fee_per_gas + max_priority_fee_per_gas
            }
        }
    }
}
