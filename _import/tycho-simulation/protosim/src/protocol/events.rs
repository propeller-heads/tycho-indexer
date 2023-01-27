use ethers::{
    prelude::LogMeta,
    types::{H160, H256},
};

use super::errors::TransitionError;

pub type LogIndex = (u64, u32, u32);

pub fn check_log_idx(
    index: LogIndex,
    log_meta: &EVMLogMeta,
) -> Result<(), TransitionError<(u64, u32, u32)>> {
    if index >= log_meta.index() {
        return Err(TransitionError::OutOfOrder {
            state: index,
            event: log_meta.index(),
        });
    }
    Ok(())
}

#[derive(Debug, Clone)]
pub struct EVMLogMeta {
    from: H160,
    block_number: u64,
    block_hash: H256,
    transaction_index: u32,
    transaction_hash: H256,
    log_index: u32,
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
    fn from(value: LogMeta) -> Self {
        todo!()
    }
}

impl EVMLogMeta {
    pub fn index(&self) -> (u64, u32, u32) {
        (self.block_number, self.transaction_index, self.log_index)
    }
}
