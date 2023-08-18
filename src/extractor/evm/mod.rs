pub mod ambient;

use crate::models::{Chain, ExtractorIdentity, NormalisedMessage};
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

pub struct Account {}

pub struct AccountUpdate {
    extractor: String,
    pub slots: HashMap<U256, U256>,
    pub balance: Option<U256>,
    pub code: Option<Vec<u8>>,
    pub code_hash: Option<H256>,
}

impl NormalisedMessage for AccountUpdate {
    fn source(&self) -> ExtractorIdentity {
        return ExtractorIdentity {
            chain: Chain::Ethereum,
            name: self.extractor.clone(),
        };
    }
}
