use tycho_client::feed::{BlockHeader, HeaderLike};

#[derive(Clone, Default)]
pub struct TimestampHeader {
    pub timestamp: u64,
}

impl HeaderLike for TimestampHeader {
    fn block(self) -> Option<BlockHeader> {
        None
    }

    fn block_number_or_timestamp(self) -> u64 {
        self.timestamp
    }
}
