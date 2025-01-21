use num_bigint::BigUint;
use tycho_core::Bytes;

use crate::encoding::errors::EncodingError;

#[allow(dead_code)]
pub struct Approval {
    pub spender: Bytes,
    pub owner: Bytes,
    pub token: Bytes,
    pub amount: BigUint,
}

pub trait UserApprovalsManager {
    #[allow(dead_code)]
    fn encode_approvals(&self, approvals: Vec<Approval>) -> Result<Vec<Vec<u8>>, EncodingError>;
}
