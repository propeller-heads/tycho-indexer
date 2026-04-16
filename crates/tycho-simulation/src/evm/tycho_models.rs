use std::collections::HashMap;

use alloy::primitives::{Address, B256, U256};
use serde::{Deserialize, Serialize};
pub use tycho_common::{dto::ChangeType, models::Chain};

use crate::{
    evm::protocol::u256_num,
    serde_helpers::{hex_bytes, hex_bytes_option},
};

#[derive(PartialEq, Serialize, Deserialize, Clone, Debug)]
pub struct AccountUpdate {
    pub address: Address,
    pub chain: Chain,
    pub slots: HashMap<U256, U256>,
    pub balance: Option<U256>,
    #[serde(with = "hex_bytes_option")]
    pub code: Option<Vec<u8>>,
    pub change: ChangeType,
}

impl AccountUpdate {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        address: Address,
        chain: Chain,
        slots: HashMap<U256, U256>,
        balance: Option<U256>,
        code: Option<Vec<u8>>,
        change: ChangeType,
    ) -> Self {
        Self { address, chain, slots, balance, code, change }
    }
}

impl From<tycho_common::dto::AccountUpdate> for AccountUpdate {
    fn from(value: tycho_common::dto::AccountUpdate) -> Self {
        Self {
            chain: value.chain.into(),
            address: Address::from_slice(&value.address[..20]), // Convert address field to Address
            slots: u256_num::map_slots_to_u256(value.slots),
            balance: value
                .balance
                .map(|balance| u256_num::bytes_to_u256(balance.into())),
            code: value.code.map(|code| code.to_vec()),
            change: value.change,
        }
    }
}

#[derive(PartialEq, Clone, Serialize, Deserialize, Default)]
#[serde(rename = "Account")]
/// Account struct for the response from Tycho server for a contract state request.
///
/// Code is serialized as a hex string instead of a list of bytes.
pub struct ResponseAccount {
    pub chain: Chain,
    pub address: Address,
    pub title: String,
    pub slots: HashMap<U256, U256>,
    pub native_balance: U256,
    pub token_balances: HashMap<Address, U256>,
    #[serde(with = "hex_bytes")]
    pub code: Vec<u8>,
    pub code_hash: B256,
    pub balance_modify_tx: B256,
    pub code_modify_tx: B256,
    pub creation_tx: Option<B256>,
}

impl ResponseAccount {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chain: Chain,
        address: Address,
        title: String,
        slots: HashMap<U256, U256>,
        native_balance: U256,
        token_balances: HashMap<Address, U256>,
        code: Vec<u8>,
        code_hash: B256,
        balance_modify_tx: B256,
        code_modify_tx: B256,
        creation_tx: Option<B256>,
    ) -> Self {
        Self {
            chain,
            address,
            title,
            slots,
            native_balance,
            token_balances,
            code,
            code_hash,
            balance_modify_tx,
            code_modify_tx,
            creation_tx,
        }
    }
}

/// Implement Debug for ResponseAccount manually to avoid printing the code field.
impl std::fmt::Debug for ResponseAccount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResponseAccount")
            .field("chain", &self.chain)
            .field("address", &self.address)
            .field("title", &self.title)
            .field("slots", &self.slots)
            .field("native_balance", &self.native_balance)
            .field("token_balances", &self.token_balances)
            .field("code", &format!("[{} bytes]", self.code.len()))
            .field("code_hash", &self.code_hash)
            .field("balance_modify_tx", &self.balance_modify_tx)
            .field("code_modify_tx", &self.code_modify_tx)
            .field("creation_tx", &self.creation_tx)
            .finish()
    }
}

impl From<tycho_common::dto::ResponseAccount> for ResponseAccount {
    #[allow(deprecated)]
    fn from(value: tycho_common::dto::ResponseAccount) -> Self {
        Self {
            chain: value.chain.into(),
            address: Address::from_slice(&value.address[..20]), // Convert address field to Address
            title: value.title.clone(),
            slots: u256_num::map_slots_to_u256(value.slots),
            native_balance: u256_num::bytes_to_u256(value.native_balance.into()),
            token_balances: value
                .token_balances
                .into_iter()
                .map(|(address, balance)| {
                    (Address::from_slice(&address[..20]), u256_num::bytes_to_u256(balance.into()))
                })
                .collect(),
            code: value.code.to_vec(),
            code_hash: B256::from_slice(&value.code_hash[..]),
            balance_modify_tx: B256::from_slice(&value.balance_modify_tx[..]),
            code_modify_tx: B256::from_slice(&value.code_modify_tx[..]),
            creation_tx: value
                .creation_tx
                .map(|tx| B256::from_slice(&tx[..])), // Optionally map creation_tx if present
        }
    }
}
