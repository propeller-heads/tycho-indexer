use alloy_primitives::hex;
use lazy_static::lazy_static;
use tycho_core::Bytes;

lazy_static! {
    pub static ref NATIVE_ADDRESS: Bytes =
        Bytes::from(hex!("0000000000000000000000000000000000000000").to_vec());
    pub static ref WETH_ADDRESS: Bytes =
        Bytes::from(hex!("c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2").to_vec());
}
