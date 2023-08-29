pub mod ambient;

use crate::{
    models::{Chain, ExtractorIdentity, NormalisedMessage},
    storage::StateGatewayType,
};
use std::collections::HashMap;

use chrono::NaiveDateTime;
use ethers::types::{H160, H256, U256};

pub struct SwapPool {}

pub struct ERC20Token {}

#[derive(Debug, PartialEq, Copy, Clone)]
pub struct Block {
    pub number: u64,
    pub hash: H256,
    pub parent_hash: H256,
    pub chain: Chain,
    pub ts: NaiveDateTime,
}

#[derive(Debug, PartialEq, Copy, Clone)]
pub struct Transaction {
    pub hash: H256,
    pub block_hash: H256,
    pub from: H160,
    pub to: H160,
    pub index: u64,
}

#[derive(PartialEq, Debug)]
pub struct Account {
    pub chain: Chain,
    pub address: H160,
    pub title: String,
    pub slots: HashMap<U256, U256>,
    pub balance: U256,
    pub code: Vec<u8>,
    pub code_hash: H256,
    pub modify_tx: H256,
    pub creation_tx: Option<H256>,
}

impl Account {
    pub fn new(
        chain: Chain,
        address: H160,
        title: String,
        slots: HashMap<U256, U256>,
        balance: U256,
        code: Vec<u8>,
        code_hash: H256,
        modify_tx: H256,
        creation_tx: Option<H256>,
    ) -> Self {
        Self {
            chain,
            address,
            title,
            slots,
            balance,
            code,
            code_hash,
            modify_tx,
            creation_tx,
        }
    }
}

#[derive(PartialEq, Debug)]
pub struct AccountUpdate {
    extractor: String,
    chain: Chain,
    pub address: H160,
    pub slots: HashMap<U256, U256>,
    pub balance: Option<U256>,
    pub code: Option<Vec<u8>>,
    pub code_hash: Option<H256>,
    pub tx_hash: Option<H256>,
}

impl AccountUpdate {
    pub fn new(
        extractor: String,
        chain: Chain,
        address: H160,
        slots: HashMap<U256, U256>,
        balance: Option<U256>,
        code: Option<Vec<u8>>,
        code_hash: Option<H256>,
        tx_hash: Option<H256>,
    ) -> Self {
        Self {
            extractor,
            chain,
            address,
            slots,
            balance,
            code,
            code_hash,
            tx_hash,
        }
    }
}

struct UpdateWithTransaction(Transaction, AccountUpdate);

struct BlockStateChanges {
    block: Block,
    account_updates: HashMap<H256, UpdateWithTransaction>,
    new_pools: HashMap<H160, SwapPool>,
}

impl NormalisedMessage for AccountUpdate {
    fn source(&self) -> ExtractorIdentity {
        ExtractorIdentity {
            chain: self.chain,
            name: self.extractor.clone(),
        }
    }
}

pub type EVMStateGateway<DB> =
    StateGatewayType<DB, Block, Transaction, ERC20Token, SwapPool, Account, H160, U256, U256>;
