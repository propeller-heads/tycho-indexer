use ethers::{
    prelude::LogMeta,
    types::{H160, H256},
};

use super::errors::TransitionError;

pub type LogIndex = (u64, u32);

pub fn check_log_idx(
    index: LogIndex,
    log_meta: &EVMLogMeta,
) -> Result<(), TransitionError<LogIndex>> {
    if index >= log_meta.index() {
        return Err(TransitionError::OutOfOrder { state: index, event: log_meta.index() });
    }
    Ok(())
}

#[derive(Debug, Clone)]
pub struct EVMLogMeta {
    pub from: H160,
    pub block_number: u64,
    pub block_hash: H256,
    pub transaction_index: u32,
    pub transaction_hash: H256,
    pub log_index: u32,
}

impl EVMLogMeta {
    pub fn new(
        from: H160,
        block_number: u64,
        block_hash: H256,
        transaction_index: u32,
        transaction_hash: H256,
        log_index: u32,
    ) -> Self {
        EVMLogMeta {
            from,
            block_number,
            block_hash,
            transaction_index,
            transaction_hash,
            log_index,
        }
    }
}

impl From<LogMeta> for EVMLogMeta {
    fn from(log: LogMeta) -> Self {
        EVMLogMeta {
            from: log.address,
            block_number: log.block_number.as_u64(),
            block_hash: log.block_hash,
            transaction_index: log.transaction_index.as_u32(),
            transaction_hash: log.transaction_hash,
            log_index: log.log_index.as_u32(),
        }
    }
}

impl EVMLogMeta {
    pub fn index(&self) -> (u64, u32) {
        (self.block_number, self.log_index)
    }
}
