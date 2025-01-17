use num_bigint::BigUint;
use tycho_core::Bytes;

#[allow(dead_code)]
pub struct Approval {
    pub spender: Bytes,
    pub owner: Bytes,
    pub token: Bytes,
    pub amount: BigUint,
}

pub trait UserApprovalsManager {
    #[allow(dead_code)]
    fn encode_approvals(&self, approvals: Vec<Approval>) -> Vec<u8>;
}
