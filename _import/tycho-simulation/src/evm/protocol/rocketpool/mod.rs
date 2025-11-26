use alloy::hex;

/// Native ETH address (zero address)
const ETH_ADDRESS: [u8; 20] = hex!("0000000000000000000000000000000000000000");
/// Protocol Component ID for Rocket Pool
const ROCKET_POOL_COMPONENT_ID: &str = "0xdd3f50f8a6cafbe9b31a427582963f465e745af8";

mod decoder;
pub mod state;
