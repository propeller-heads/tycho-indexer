use num_bigint::BigUint;
use tycho_client::feed::{BlockHeader, HeaderLike};
use tycho_common::{models::token::Token, Bytes};

// TODO: for now this is here. But it should be moved to tycho-common and used in the ProtocolSim
// interface. This is waiting for the interfaces of tycho v1 to be defined
pub struct GetAmountOutParams {
    pub amount_in: BigUint,
    pub token_in: Token,
    pub token_out: Token,
    pub sender: Bytes,
    pub receiver: Bytes,
}

pub struct TimestampHeader {
    pub timestamp: u64,
}

impl HeaderLike for TimestampHeader {
    fn block(self) -> Option<BlockHeader> {
        None
    }

    fn ts(self) -> u64 {
        self.timestamp
    }
}
