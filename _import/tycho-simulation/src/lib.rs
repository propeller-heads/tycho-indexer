//! Tycho Simulation: a decentralized exchange simulation library
//!
//! This library allows to simulate trades against a wide range
//! of different protocols, including uniswap-v2 and uniswap-v3.
//! It allows to simulate chained trades over different venues
//! together to exploit price differences by using token prices
//! calculated from the protocol's state.

extern crate core;

// Reexports
pub use tycho_client;
pub use tycho_core;
pub use tycho_ethereum;

#[cfg(feature = "evm")]
pub mod evm;
pub mod models;
pub mod protocol;
pub mod serde_helpers;
pub mod utils;
