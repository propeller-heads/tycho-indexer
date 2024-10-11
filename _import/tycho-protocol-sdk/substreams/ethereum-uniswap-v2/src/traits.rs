use ethabi::ethereum_types::Address;
use substreams::store::{StoreGet, StoreGetProto};
use substreams_ethereum::pb::eth::v2::{self as eth};

use substreams_helper::{common::HasAddresser, hex::Hexable};

use crate::{
    pb::tycho::evm::v1::{Block, ProtocolComponent, Transaction},
    store_key::StoreKey,
};

pub struct PoolAddresser<'a> {
    pub store: &'a StoreGetProto<ProtocolComponent>,
}

impl<'a> HasAddresser for PoolAddresser<'a> {
    fn has_address(&self, key: Address) -> bool {
        let pool = self
            .store
            .get_last(StoreKey::Pool.get_unique_pool_key(&key.to_hex()));

        pool.is_some()
    }
}

impl From<eth::Block> for Block {
    fn from(block: eth::Block) -> Self {
        Self {
            hash: block.hash.clone(),
            parent_hash: block
                .header
                .as_ref()
                .expect("Block header not present")
                .parent_hash
                .clone(),
            number: block.number,
            ts: block.timestamp_seconds(),
        }
    }
}

impl From<&eth::TransactionTrace> for Transaction {
    fn from(tx: &eth::TransactionTrace) -> Self {
        Self {
            hash: tx.hash.clone(),
            from: tx.from.clone(),
            to: tx.to.clone(),
            index: tx.index.into(),
        }
    }
}
