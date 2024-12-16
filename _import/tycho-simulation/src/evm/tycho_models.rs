use std::{collections::HashMap, fmt::Display};

use alloy_primitives::{Address, B256, U256};
use chrono::{NaiveDateTime, Utc};
use serde::{Deserialize, Serialize};
use strum_macros::{Display, EnumString};
use uuid::Uuid;

use super::engine_db::simulation_db::BlockHeader;
use crate::{
    evm::protocol::u256_num,
    serde_helpers::{hex_bytes, hex_bytes_option},
};

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

/// A command sent from the client to the server
#[derive(Deserialize, Serialize, Debug, PartialEq, Eq)]
#[serde(tag = "method", rename_all = "lowercase")]
pub enum Command {
    Subscribe { extractor_id: ExtractorIdentity },
    Unsubscribe { subscription_id: Uuid },
}

/// A response sent from the server to the client
#[derive(Deserialize, Serialize, Debug, PartialEq, Eq)]
#[serde(tag = "method", rename_all = "lowercase")]
pub enum Response {
    NewSubscription { extractor_id: ExtractorIdentity, subscription_id: Uuid },
    SubscriptionEnded { subscription_id: Uuid },
}

/// A message sent from the server to the client
#[derive(Serialize, Deserialize, Debug)]
#[serde(untagged)]
pub enum WebSocketMessage {
    BlockAccountChanges(BlockAccountChanges),
    Response(Response),
}

#[derive(Debug, PartialEq, Copy, Clone, Deserialize, Serialize, Default)]
pub struct Block {
    pub number: u64,
    pub hash: B256,
    pub parent_hash: B256,
    pub chain: Chain,
    pub ts: NaiveDateTime,
}

impl From<Block> for BlockHeader {
    fn from(value: Block) -> Self {
        Self {
            number: value.number,
            hash: value.hash,
            timestamp: value.ts.and_utc().timestamp() as u64,
        }
    }
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct SwapPool {}

#[derive(Debug, PartialEq, Copy, Clone, Default, Deserialize, Serialize)]
pub struct Transaction {
    pub hash: B256,
    pub block_hash: B256,
    pub from: Address,
    pub to: Option<Address>,
    pub index: u64,
}

/// A container for account updates grouped by account.
///
/// Hold a single update per account. This is a condensed form of
/// [BlockStateChanges].
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, Default)]
pub struct BlockAccountChanges {
    extractor: String,
    chain: Chain,
    pub block: Block,
    pub account_updates: HashMap<Address, AccountUpdate>,
    pub new_pools: HashMap<Address, SwapPool>,
}

impl BlockAccountChanges {
    pub fn new(
        extractor: String,
        chain: Chain,
        block: Block,
        account_updates: HashMap<Address, AccountUpdate>,
        new_pools: HashMap<Address, SwapPool>,
    ) -> Self {
        Self { extractor, chain, block, account_updates, new_pools }
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, EnumString, Display, Default,
)]
#[serde(rename_all = "lowercase")]
#[strum(serialize_all = "lowercase")]
pub enum Chain {
    #[default]
    Ethereum,
    ZkSync,
    Starknet,
    Arbitrum,
}

impl From<tycho_core::dto::Chain> for Chain {
    fn from(value: tycho_core::dto::Chain) -> Self {
        match value {
            tycho_core::dto::Chain::Ethereum => Chain::Ethereum,
            tycho_core::dto::Chain::ZkSync => Chain::ZkSync,
            tycho_core::dto::Chain::Starknet => Chain::Starknet,
            tycho_core::dto::Chain::Arbitrum => Chain::Arbitrum,
        }
    }
}

#[derive(Debug, PartialEq, Default, Copy, Clone, Deserialize, Serialize, Display, EnumString)]
pub enum ChangeType {
    #[default]
    Update,
    Deletion,
    Creation,
    Unspecified,
}

impl From<tycho_core::dto::ChangeType> for ChangeType {
    fn from(value: tycho_core::dto::ChangeType) -> Self {
        match value {
            tycho_core::dto::ChangeType::Update => ChangeType::Update,
            tycho_core::dto::ChangeType::Deletion => ChangeType::Deletion,
            tycho_core::dto::ChangeType::Creation => ChangeType::Creation,
            tycho_core::dto::ChangeType::Unspecified => ChangeType::Unspecified,
        }
    }
}

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

impl From<tycho_core::dto::AccountUpdate> for AccountUpdate {
    fn from(value: tycho_core::dto::AccountUpdate) -> Self {
        Self {
            chain: value.chain.into(),
            address: Address::from_slice(&value.address[..20]), // Convert address field to Address
            slots: u256_num::map_slots_to_u256(value.slots),
            balance: value
                .balance
                .map(|balance| u256_num::bytes_to_u256(balance.into())),
            code: value.code.map(|code| code.to_vec()),
            change: value.change.into(),
        }
    }
}

#[derive(Serialize, Debug, Default)]
pub struct StateRequestBody {
    #[serde(rename = "contractIds")]
    pub contract_ids: Option<Vec<ContractId>>,
    #[serde(default = "Version::default")]
    pub version: Version,
}

impl StateRequestBody {
    pub fn new(contract_ids: Option<Vec<Address>>, version: Version) -> Self {
        Self {
            contract_ids: contract_ids.map(|ids| {
                ids.into_iter()
                    .map(|id| ContractId::new(Chain::Ethereum, id))
                    .collect()
            }),
            version,
        }
    }

    pub fn from_block(block: Block) -> Self {
        Self { contract_ids: None, version: Version { timestamp: block.ts, block: Some(block) } }
    }

    pub fn from_timestamp(timestamp: NaiveDateTime) -> Self {
        Self { contract_ids: None, version: Version { timestamp, block: None } }
    }
}

/// Response from Tycho server for a contract state request.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct StateRequestResponse {
    pub accounts: Vec<ResponseAccount>,
}

impl StateRequestResponse {
    pub fn new(accounts: Vec<ResponseAccount>) -> Self {
        Self { accounts }
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
    pub balance: U256,
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
        balance: U256,
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
            balance,
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
            .field("balance", &self.balance)
            .field("code", &format!("[{} bytes]", self.code.len()))
            .field("code_hash", &self.code_hash)
            .field("balance_modify_tx", &self.balance_modify_tx)
            .field("code_modify_tx", &self.code_modify_tx)
            .field("creation_tx", &self.creation_tx)
            .finish()
    }
}

impl From<tycho_core::dto::ResponseAccount> for ResponseAccount {
    fn from(value: tycho_core::dto::ResponseAccount) -> Self {
        Self {
            chain: value.chain.into(),
            address: Address::from_slice(&value.address[..20]), // Convert address field to Address
            title: value.title.clone(),
            slots: u256_num::map_slots_to_u256(value.slots),
            balance: u256_num::bytes_to_u256(value.native_balance.into()),
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
        write!(f, "{:?}: 0x{}", self.chain, hex::encode(self.address))
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct Version {
    timestamp: NaiveDateTime,
    block: Option<Block>,
}

impl Version {
    pub fn new(timestamp: NaiveDateTime, block: Option<Block>) -> Self {
        Self { timestamp, block }
    }
}

impl Default for Version {
    fn default() -> Self {
        Version { timestamp: Utc::now().naive_utc(), block: None }
    }
}

#[derive(Serialize, Deserialize, Default, Debug)]
pub struct StateRequestParameters {
    #[serde(default = "Chain::default")]
    chain: Chain,
    tvl_gt: Option<u64>,
    inertia_min_gt: Option<u64>,
}

impl StateRequestParameters {
    pub fn to_query_string(&self) -> String {
        let mut parts = vec![];

        parts.push(format!("chain={}", self.chain));

        if let Some(tvl_gt) = self.tvl_gt {
            parts.push(format!("tvl_gt={}", tvl_gt));
        }

        if let Some(inertia) = self.inertia_min_gt {
            parts.push(format!("inertia_min_gt={}", inertia));
        }

        parts.join("&")
    }
}
