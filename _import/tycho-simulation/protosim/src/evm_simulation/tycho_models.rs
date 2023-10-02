use std::collections::HashMap;

use chrono::NaiveDateTime;
use revm::primitives::{B160, B256, U256 as rU256};
use serde::{Deserialize, Serialize};

use strum_macros::{Display, EnumString};

#[derive(Debug, PartialEq, Copy, Clone, Deserialize)]
pub struct Block {
    pub number: u64,
    pub hash: B256,
    pub parent_hash: B256,
    pub chain: Chain,
    pub ts: NaiveDateTime,
}

#[derive(Deserialize, PartialEq, Debug, Clone)]
pub struct SwapPool {}

#[derive(Debug, PartialEq, Copy, Clone, Default, Deserialize)]
pub struct Transaction {
    pub hash: B256,
    pub block_hash: B256,
    pub from: B160,
    pub to: Option<B160>,
    pub index: u64,
}

#[derive(Deserialize, PartialEq, Debug, Clone)]
pub struct BlockStateChanges {
    pub block: Block,
    pub account_updates: HashMap<B160, AccountUpdate>,
    pub new_pools: HashMap<B160, SwapPool>,
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

#[derive(PartialEq, Debug, Deserialize, Clone)]
pub struct AccountUpdate {
    extractor: String,
    chain: Chain,
    pub address: B160,
    pub slots: Option<HashMap<rU256, rU256>>,
    pub balance: Option<rU256>,
    pub code: Option<Vec<u8>>,
    pub tx: Transaction,
}

impl AccountUpdate {
    pub fn new(
        extractor: String,
        chain: Chain,
        address: B160,
        slots: Option<HashMap<rU256, rU256>>,
        balance: Option<rU256>,
        code: Option<Vec<u8>>,
        tx: Transaction,
    ) -> Self {
        Self { extractor, chain, address, slots, balance, code, tx }
    }
}
