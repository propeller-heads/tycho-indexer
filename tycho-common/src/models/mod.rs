pub mod blockchain;
pub mod contract;
pub mod error;
pub mod protocol;
pub mod token;

use std::{collections::HashMap, fmt::Display, str::FromStr};

use serde::{Deserialize, Serialize};
use strum_macros::{Display, EnumString};
use thiserror::Error;
use token::Token;

use crate::{dto, Bytes};

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

/// A binary key-value store for an account.
pub type ContractStore = HashMap<StoreKey, StoreVal>;
pub type ContractStoreDeltas = HashMap<StoreKey, Option<StoreVal>>;
pub type AccountToContractStoreDeltas = HashMap<Address, ContractStoreDeltas>;

/// Component id literal type to uniquely identify a component.
pub type ComponentId = String;

/// Protocol system literal type to uniquely identify a protocol system.
pub type ProtocolSystem = String;

/// Entry point id literal type to uniquely identify an entry point.
pub type EntryPointId = String;

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
    Unichain,
}

impl From<dto::Chain> for Chain {
    fn from(value: dto::Chain) -> Self {
        match value {
            dto::Chain::Ethereum => Chain::Ethereum,
            dto::Chain::Starknet => Chain::Starknet,
            dto::Chain::ZkSync => Chain::ZkSync,
            dto::Chain::Arbitrum => Chain::Arbitrum,
            dto::Chain::Base => Chain::Base,
            dto::Chain::Unichain => Chain::Unichain,
        }
    }
}

fn native_eth(chain: Chain) -> Token {
    Token::new(
        &Bytes::from_str("0x0000000000000000000000000000000000000000").unwrap(),
        "ETH",
        18,
        0,
        &[Some(2300)],
        chain,
        100,
    )
}

fn wrapped_native_eth(chain: Chain, address: &str) -> Token {
    Token::new(&Bytes::from_str(address).unwrap(), "WETH", 18, 0, &[Some(2300)], chain, 100)
}

impl Chain {
    pub fn id(&self) -> u64 {
        match self {
            Chain::Ethereum => 1,
            Chain::ZkSync => 324,
            Chain::Arbitrum => 42161,
            Chain::Starknet => 0,
            Chain::Base => 8453,
            Chain::Unichain => 130,
        }
    }

    /// Returns the native token for the chain.
    pub fn native_token(&self) -> Token {
        match self {
            Chain::Ethereum => native_eth(Chain::Ethereum),
            // It was decided that STRK token will be tracked as a dedicated AccountBalance on
            // Starknet accounts and ETH balances will be tracked as a native balance.
            Chain::Starknet => native_eth(Chain::Starknet),
            Chain::ZkSync => native_eth(Chain::ZkSync),
            Chain::Arbitrum => native_eth(Chain::Arbitrum),
            Chain::Base => native_eth(Chain::Base),
            Chain::Unichain => native_eth(Chain::Unichain),
        }
    }

    /// Returns the wrapped native token for the chain.
    pub fn wrapped_native_token(&self) -> Token {
        match self {
            Chain::Ethereum => {
                wrapped_native_eth(Chain::Ethereum, "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2")
            }
            // Starknet does not have a wrapped native token
            Chain::Starknet => {
                wrapped_native_eth(Chain::Starknet, "0x0000000000000000000000000000000000000000")
            }
            Chain::ZkSync => {
                wrapped_native_eth(Chain::ZkSync, "0x5AEa5775959fBC2557Cc8789bC1bf90A239D9a91")
            }
            Chain::Arbitrum => {
                wrapped_native_eth(Chain::Arbitrum, "0x82aF49447D8a07e3bd95BD0d56f35241523fBab1")
            }
            Chain::Base => {
                wrapped_native_eth(Chain::Base, "0x4200000000000000000000000000000000000006")
            }
            Chain::Unichain => {
                wrapped_native_eth(Chain::Unichain, "0x4200000000000000000000000000000000000006")
            }
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

impl From<ExtractorIdentity> for dto::ExtractorIdentity {
    fn from(value: ExtractorIdentity) -> Self {
        dto::ExtractorIdentity { chain: value.chain.into(), name: value.name }
    }
}

impl From<dto::ExtractorIdentity> for ExtractorIdentity {
    fn from(value: dto::ExtractorIdentity) -> Self {
        Self { chain: value.chain.into(), name: value.name }
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
pub enum MergeError {
    #[error("Can't merge {0} from differring idendities: Expected {1}, got {2}")]
    IdMismatch(String, String, String),
    #[error("Can't merge {0} from different blocks: 0x{1:x} != 0x{2:x}")]
    BlockMismatch(String, Bytes, Bytes),
    #[error("Can't merge {0} from the same transaction: 0x{1:x}")]
    SameTransaction(String, Bytes),
    #[error("Can't merge {0} with lower transaction index: {1} > {2}")]
    TransactionOrderError(String, u64, u64),
}
