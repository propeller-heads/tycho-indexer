use num_bigint::BigUint;
use tycho_core::Bytes;

pub struct Approval {
    pub spender: Bytes,
    pub owner: Bytes,
    pub token: Bytes,
    pub amount: BigUint,
}

pub trait ApprovalsManager {
    fn encode_approvals(&self, approvals: Vec<Approval>) -> Vec<u8>;
}
