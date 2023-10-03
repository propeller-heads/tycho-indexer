use std::{collections::HashMap, ops::Deref};

use chrono::NaiveDateTime;
use revm::primitives::{B160, B256, U256};
use serde::{Deserialize, Serialize};

use strum_macros::{Display, EnumString};

#[derive(Debug, PartialEq, Copy, Clone, Deserialize, Serialize)]
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
    pub fn new(
        hash: B256,
        block_hash: B256,
        from: B160,
        to: Option<B160>,
        index: u64,
    ) -> Self {
        Self { hash, block_hash, from, to, index }
    }
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct BlockStateChanges {
    pub extractor: String,
    pub chain: Chain,
    pub block: Block,
    pub tx_updates: Vec<AccountUpdateWithTx>,
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

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct AccountUpdateWithTx {
    pub update: AccountUpdate,
    pub tx: Transaction,
}

impl AccountUpdateWithTx {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        address: B160,
        chain: Chain,
        slots: HashMap<U256, U256>,
        balance: Option<U256>,
        code: Option<Vec<u8>>,
        change: ChangeType,
        tx: Transaction,
    ) -> Self {
        Self { update: AccountUpdate { address, chain, slots, balance, code, change }, tx }
    }
}

impl Deref for AccountUpdateWithTx {
    type Target = AccountUpdate;

    fn deref(&self) -> &Self::Target {
        &self.update
    }
}
