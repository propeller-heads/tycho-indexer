use alloy::hex;

/// Native ETH address (zero address)
const ETH_ADDRESS: [u8; 20] = hex!("0000000000000000000000000000000000000000");

mod decoder;
pub mod state;
