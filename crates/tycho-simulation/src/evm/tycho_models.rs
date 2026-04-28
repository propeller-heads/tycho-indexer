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
            address: Address::from_slice(&value.address[..20]),
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
            code_hash: u256_num::bytes_to_b256(&value.code_hash),
            balance_modify_tx: u256_num::bytes_to_b256(&value.balance_modify_tx),
            code_modify_tx: u256_num::bytes_to_b256(&value.code_modify_tx),
            creation_tx: value
                .creation_tx
                .map(|tx| u256_num::bytes_to_b256(&tx)),
        }
    }
}

#[cfg(test)]
mod tests {
    use tycho_common::Bytes;

    use super::*;

    fn make_dto_response_account(
        balance_modify_tx: Bytes,
        code_modify_tx: Bytes,
        code_hash: Bytes,
        creation_tx: Option<Bytes>,
    ) -> tycho_common::dto::ResponseAccount {
        #[allow(deprecated)]
        tycho_common::dto::ResponseAccount::new(
            tycho_common::dto::Chain::Ethereum,
            Bytes::zero(20),
            "test".to_string(),
            std::collections::HashMap::new(),
            Bytes::zero(32),
            std::collections::HashMap::new(),
            Bytes::from(vec![0xDE, 0xAD]),
            code_hash,
            balance_modify_tx,
            code_modify_tx,
            creation_tx,
        )
    }

    #[test]
    fn test_response_account_conversion_with_32_byte_hashes() {
        let dto = make_dto_response_account(
            Bytes::zero(32),
            Bytes::zero(32),
            Bytes::zero(32),
            Some(Bytes::zero(32)),
        );

        let result = ResponseAccount::from(dto);

        assert_eq!(result.balance_modify_tx, B256::ZERO);
        assert_eq!(result.code_modify_tx, B256::ZERO);
        assert_eq!(result.code_hash, B256::ZERO);
        assert_eq!(result.creation_tx, Some(B256::ZERO));
    }

    #[test]
    fn test_response_account_conversion_with_short_hashes() {
        let dto = make_dto_response_account(
            Bytes::from("0x00"),
            Bytes::from("0x00"),
            Bytes::from("0x00"),
            Some(Bytes::from("0x01")),
        );

        let result = ResponseAccount::from(dto);

        assert_eq!(result.balance_modify_tx, B256::ZERO);
        assert_eq!(result.code_modify_tx, B256::ZERO);
        assert_eq!(result.code_hash, B256::ZERO);
        let mut expected = [0u8; 32];
        expected[31] = 0x01;
        assert_eq!(result.creation_tx, Some(B256::from(expected)));
    }

    #[test]
    fn test_response_account_conversion_with_empty_hashes() {
        let dto = make_dto_response_account(
            Bytes::from(vec![]),
            Bytes::from(vec![]),
            Bytes::from(vec![]),
            None,
        );

        let result = ResponseAccount::from(dto);

        assert_eq!(result.balance_modify_tx, B256::ZERO);
        assert_eq!(result.code_modify_tx, B256::ZERO);
        assert_eq!(result.code_hash, B256::ZERO);
        assert_eq!(result.creation_tx, None);
    }
}
