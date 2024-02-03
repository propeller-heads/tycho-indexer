use substreams_ethereum::pb::eth::v2::{self as eth};

use crate::pb::tycho::evm::v1::{Block, Transaction};

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
