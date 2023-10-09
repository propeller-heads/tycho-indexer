use std::collections::HashMap;

use chrono::NaiveDateTime;
use revm::primitives::{B160, B256, U256};
use serde::{Deserialize, Serialize};
use strum_macros::{Display, EnumString};
use uuid::Uuid;

use crate::serde_helpers::hex_bytes_option;

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

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct SwapPool {}

#[derive(Debug, PartialEq, Copy, Clone, Default, Deserialize, Serialize)]
pub struct Transaction {
    pub hash: B256,
    pub block_hash: B256,
    pub from: B160,
    pub to: Option<B160>,
    pub index: u64,
}

impl Transaction {
    #[allow(clippy::too_many_arguments)]
    pub fn new(hash: B256, block_hash: B256, from: B160, to: Option<B160>, index: u64) -> Self {
        Self { hash, block_hash, from, to, index }
    }
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
    pub account_updates: HashMap<B160, AccountUpdate>,
    pub new_pools: HashMap<B160, SwapPool>,
}

impl BlockAccountChanges {
    pub fn new(
        extractor: String,
        chain: Chain,
        block: Block,
        account_updates: HashMap<B160, AccountUpdate>,
        new_pools: HashMap<B160, SwapPool>,
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
    Starknet,
    ZkSync,
}

#[derive(Debug, PartialEq, Default, Copy, Clone, Deserialize, Serialize)]
pub enum ChangeType {
    #[default]
    Update,
    Deletion,
    Creation,
}

#[derive(PartialEq, Serialize, Deserialize, Clone, Debug)]
pub struct AccountUpdate {
    pub address: B160,
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
        address: B160,
        chain: Chain,
        slots: HashMap<U256, U256>,
        balance: Option<U256>,
        code: Option<Vec<u8>>,
        change: ChangeType,
    ) -> Self {
        Self { address, chain, slots, balance, code, change }
    }
}
