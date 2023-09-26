use std::collections::HashMap;

use chrono::NaiveDateTime;
use revm::primitives::{B160, B256, U256 as rU256};
use serde::{de, Deserialize, Deserializer, Serialize};
use thiserror::Error;

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

#[derive(Error, Debug)]
pub enum ChainError {
    #[error("Unknown blockchain value: {0}")]
    UnknownChain(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum Chain {
    Ethereum,
    Starknet,
    ZkSync,
}
impl<'de> Deserialize<'de> for Chain {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: String = Deserialize::deserialize(deserializer)?;
        Chain::try_from(s).map_err(de::Error::custom)
    }
}

impl TryFrom<String> for Chain {
    type Error = ChainError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        match value.to_lowercase().as_str() {
            "ethereum" => Ok(Chain::Ethereum),
            "starknet" => Ok(Chain::Starknet),
            "zksync" => Ok(Chain::ZkSync),
            _ => Err(ChainError::UnknownChain(value)),
        }
    }
}

impl ToString for Chain {
    fn to_string(&self) -> String {
        format!("{:?}", self).to_lowercase()
    }
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
        Self {
            extractor,
            chain,
            address,
            slots,
            balance,
            code,
            tx,
        }
    }
}
