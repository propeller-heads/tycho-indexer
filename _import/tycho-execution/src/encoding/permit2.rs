use alloy_primitives::{Address, U256};
use num_bigint::BigUint;
use std::str::FromStr;
use tycho_core::Bytes;

pub struct PermitRequest {
    pub token: Bytes,
    pub amount: BigUint,
    pub spender: Bytes,
    pub router_address: Bytes,
}

pub struct Permit2 {
    pub address: Bytes,
}

impl Permit2 {
    pub fn new() -> Self {
        Self {
            address: Bytes::from_str("0x000000000022D473030F116dDEE9F6B43aC78BA3")
                .expect("Permit2 address not valid"),
        }
    }
    pub fn encode_permit(&self, details: Vec<PermitRequest>) -> Vec<u8> {
        // calls get_allowance_data to get nonce
        // checks if we are not permitted already
        // puts data into a permitSingle struct if there is only 1 PermitDetails, if there are several, use PermitBatch
        //   adds the nonce and the expiration (uniswap recommends 30 days for expiration)
        // signs data
        // returns encoded data
        todo!()
    }

    fn get_allowance_data(
        &self,
        user: Bytes,
        router_address: Bytes,
        token: Bytes,
    ) -> (U256, u64, U256) {
        // get allowance data (if it exists) and the nonce
        //  returns permitAmount, expiration, nonce
        todo!()
    }
}
