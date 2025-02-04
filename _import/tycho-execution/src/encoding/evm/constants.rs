use alloy_primitives::hex;
use tycho_core::{models::Chain, Bytes};

pub fn native_address(chain: Chain) -> Bytes {
    match chain {
        Chain::Ethereum => Bytes::from(hex!("0000000000000000000000000000000000000000").to_vec()),
        // Placeholder values for other chains; update with real addresses
        _ => Bytes::from(hex!("0000000000000000000000000000000000000000").to_vec()),
    }
}

pub fn wrapped_address(chain: Chain) -> Bytes {
    match chain {
        Chain::Ethereum => Bytes::from(hex!("c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2").to_vec()),
        // Placeholder values for other chains; update with real addresses
        _ => Bytes::from(hex!("0000000000000000000000000000000000000000").to_vec()),
    }
}
