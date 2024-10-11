use std::collections::HashMap;

use crate::{models::Chain, traits::TokenOwnerFinding, Bytes};
use serde::{Deserialize, Serialize};

use super::{Address, Balance};

/// Cost related to a token transfer, for example amount of gas in evm chains.
pub type TransferCost = u64;

/// Tax related to a token transfer. Should be given in Basis Points (1/100th of a percent)
pub type TransferTax = u64;

#[derive(PartialEq, Debug, Clone, Deserialize, Serialize)]
pub struct CurrencyToken {
    pub address: Bytes,
    pub symbol: String,
    pub decimals: u32,
    pub tax: TransferTax,
    pub gas: Vec<Option<TransferCost>>,
    pub chain: Chain,
    /// Quality is between 0-100, where:
    ///  - 100: Normal token
    ///  - 75: Rebase token
    ///  - 50: Fee token
    ///  - 10: Token analysis failed at creation
    ///  - 9-5: Token analysis failed on cronjob (after creation).
    ///  - 0: Failed to extract decimals onchain
    pub quality: u32,
}

impl CurrencyToken {
    pub fn new(
        address: &Bytes,
        symbol: &str,
        decimals: u32,
        tax: u64,
        gas: &[Option<u64>],
        chain: Chain,
        quality: u32,
    ) -> Self {
        Self {
            address: address.clone(),
            symbol: symbol.to_string(),
            decimals,
            tax,
            gas: gas.to_owned(),
            chain,
            quality,
        }
    }
}

/// Represents the quality of a token.
///
/// * `Good`: Indicates that the token has successfully passed the analysis process.
/// * `Bad`: Indicates that the token has failed the analysis process. In this case, a detailed
///   reason for the failure is provided.
///
/// Note: Transfer taxes do not impact the token's quality.
/// Even if a token has transfer taxes, as long as it successfully passes the analysis,
/// it will still be marked as `Good`.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum TokenQuality {
    Good,
    Bad { reason: String },
}

impl TokenQuality {
    pub fn is_good(&self) -> bool {
        matches!(self, Self::Good { .. })
    }

    pub fn bad(reason: impl ToString) -> Self {
        Self::Bad { reason: reason.to_string() }
    }
}

/// A store for tracking token owners and their balances.
///
/// The `TokenOwnerStore` maintains a mapping between token addresses and their respective
/// owner's address and balance. It can be used to quickly retrieve token owner information
/// without needing to query external sources.
///
/// # Fields
/// * `values` - A `HashMap` where:
///   * The key is the token `Address`, representing the address of the token being tracked.
///   * The value is a tuple containing:
///     * The owner `Address` of the token.
///     * The `Balance` of the owner for the token.
#[derive(Debug)]
pub struct TokenOwnerStore {
    values: HashMap<Address, (Address, Balance)>,
}

impl TokenOwnerStore {
    pub fn new(values: HashMap<Address, (Address, Balance)>) -> Self {
        TokenOwnerStore { values }
    }
}

#[async_trait::async_trait]
impl TokenOwnerFinding for TokenOwnerStore {
    async fn find_owner(
        &self,
        token: Address,
        _min_balance: Balance,
    ) -> Result<Option<(Address, Balance)>, String> {
        Ok(self.values.get(&token).cloned())
    }
}
