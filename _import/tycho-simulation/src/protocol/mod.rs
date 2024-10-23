//! Supported Swap Protocols

pub mod errors;
pub mod events;
pub mod models;
pub mod state;
#[cfg(feature = "evm")]
pub mod uniswap_v2;
#[cfg(feature = "evm")]
pub mod uniswap_v3;
// TODO: This gate should ideally not be required
#[cfg(feature = "evm")]
pub mod vm;
