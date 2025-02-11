pub mod blockchain;
pub mod contract;
pub mod protocol;
pub mod token;

use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fmt::Display, str::FromStr, sync::Arc};
use strum_macros::{Display, EnumString};
use thiserror::Error;

use crate::{dto, Bytes};
use token::CurrencyToken;

/// Address hash literal type to uniquely identify contracts/accounts on a
/// blockchain.
pub type Address = Bytes;

/// Block hash literal type to uniquely identify a block in the chain and
/// likely across chains.
pub type BlockHash = Bytes;

/// Transaction hash literal type to uniquely identify a transaction in the
/// chain and likely across chains.
pub type TxHash = Bytes;

/// Smart contract code is represented as a byte vector containing opcodes.
pub type Code = Bytes;

/// The hash of a contract's code is used to identify it.
pub type CodeHash = Bytes;

/// The balance of an account is a big endian serialised integer of variable size.
pub type Balance = Bytes;

/// Key literal type of the contract store.
pub type StoreKey = Bytes;

/// Key literal type of the attribute store.
pub type AttrStoreKey = String;

/// Value literal type of the contract store.
pub type StoreVal = Bytes;

/// A binary key value store for an account.
pub type ContractStore = HashMap<StoreKey, Option<StoreVal>>;

/// Multiple key values stores grouped by account address.
pub type AccountToContractStore = HashMap<Address, ContractStore>;

/// Component id literal type to uniquely identify a component.
pub type ComponentId = String;

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, EnumString, Display, Default,
)]
#[serde(rename_all = "lowercase")]
#[strum(serialize_all = "lowercase")]
pub enum Chain {
    #[default]
    Ethereum,
    Starknet,
    ZkSync,
    Arbitrum,
    Base,
}

impl From<dto::Chain> for Chain {
    fn from(value: dto::Chain) -> Self {
        match value {
            dto::Chain::Ethereum => Chain::Ethereum,
            dto::Chain::Starknet => Chain::Starknet,
            dto::Chain::ZkSync => Chain::ZkSync,
            dto::Chain::Arbitrum => Chain::Arbitrum,
            dto::Chain::Base => Chain::Base,
        }
    }
}

fn native_eth(chain: Chain) -> CurrencyToken {
    CurrencyToken::new(
        &Bytes::from_str("0x0000000000000000000000000000000000000000").unwrap(),
        "ETH",
        18,
        0,
        &[Some(2300)],
        chain,
        100,
    )
}

impl Chain {
    /// Returns the native token symbol for the chain.
    pub fn native_token(&self) -> CurrencyToken {
        match self {
            Chain::Ethereum => native_eth(Chain::Ethereum),
            // It was decided that STRK token will be tracked as a dedicated AccountBalance on
            // Starknet accounts and ETH balances will be tracked as a native balance.
            Chain::Starknet => native_eth(Chain::Starknet),
            Chain::ZkSync => native_eth(Chain::ZkSync),
            Chain::Arbitrum => native_eth(Chain::Arbitrum),
            Chain::Base => native_eth(Chain::Base),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct ExtractorIdentity {
    pub chain: Chain,
    pub name: String,
}

impl ExtractorIdentity {
    pub fn new(chain: Chain, name: &str) -> Self {
        Self { chain, name: name.to_owned() }
    }
}

impl std::fmt::Display for ExtractorIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.chain, self.name)
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct ExtractionState {
    pub name: String,
    pub chain: Chain,
    pub attributes: serde_json::Value,
    pub cursor: Vec<u8>,
    pub block_hash: Bytes,
}

impl ExtractionState {
    pub fn new(
        name: String,
        chain: Chain,
        attributes: Option<serde_json::Value>,
        cursor: &[u8],
        block_hash: Bytes,
    ) -> Self {
        ExtractionState {
            name,
            chain,
            attributes: attributes.unwrap_or_default(),
            cursor: cursor.to_vec(),
            block_hash,
        }
    }
}

// TODO: replace with types from dto on extractor
#[typetag::serde(tag = "type")]
pub trait NormalisedMessage:
    std::any::Any + std::fmt::Debug + std::fmt::Display + Send + Sync + 'static
{
    fn source(&self) -> ExtractorIdentity;

    fn drop_state(&self) -> Arc<dyn NormalisedMessage>;

    fn as_any(&self) -> &dyn std::any::Any;
}

#[derive(PartialEq, Debug, Clone, Default, Deserialize, Serialize)]
pub enum ImplementationType {
    #[default]
    Vm,
    Custom,
}

#[derive(PartialEq, Debug, Clone, Default, Deserialize, Serialize)]
pub enum FinancialType {
    #[default]
    Swap,
    Psm,
    Debt,
    Leverage,
}

#[derive(Debug, PartialEq, Clone, Default, Deserialize, Serialize)]
pub struct ProtocolType {
    pub name: String,
    pub financial_type: FinancialType,
    pub attribute_schema: Option<serde_json::Value>,
    pub implementation: ImplementationType,
}

impl ProtocolType {
    pub fn new(
        name: String,
        financial_type: FinancialType,
        attribute_schema: Option<serde_json::Value>,
        implementation: ImplementationType,
    ) -> Self {
        ProtocolType { name, financial_type, attribute_schema, implementation }
    }
}

#[derive(Debug, PartialEq, Default, Copy, Clone, Deserialize, Serialize)]
pub enum ChangeType {
    #[default]
    Update,
    Deletion,
    Creation,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct ContractId {
    pub address: Address,
    pub chain: Chain,
}

/// Uniquely identifies a contract on a specific chain.
impl ContractId {
    pub fn new(chain: Chain, address: Address) -> Self {
        Self { address, chain }
    }

    pub fn address(&self) -> &Address {
        &self.address
    }
}

impl Display for ContractId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}: 0x{}", self.chain, hex::encode(&self.address))
    }
}

#[derive(Debug, PartialEq, Clone, Default, Deserialize, Serialize)]
pub struct PaginationParams {
    pub page: i64,
    pub page_size: i64,
}

impl PaginationParams {
    pub fn new(page: i64, page_size: i64) -> Self {
        Self { page, page_size }
    }

    pub fn offset(&self) -> i64 {
        self.page * self.page_size
    }
}

impl From<&dto::PaginationParams> for PaginationParams {
    fn from(value: &dto::PaginationParams) -> Self {
        PaginationParams { page: value.page, page_size: value.page_size }
    }
}

#[derive(Error, Debug, PartialEq)]
pub enum DeltaError {
    #[error("Id mismatch: {0} vs {1}")]
    IdMismatch(String, String),
}
