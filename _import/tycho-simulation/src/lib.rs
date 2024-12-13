//! Tycho Simulation: a decentralized exchange simulation library
//!
//! This library allows to simulate trades against a wide range
//! of different protocols, including uniswap-v2 and uniswap-v3.
//! It allows to simulate chained trades over different venues
//! together to exploit price differences by using token prices
//! calculated from the protocol's state.
//!
//! The main data structure is a graph which allows to search
//! for a sequence of swaps that provide some desired outcome,
//! such as atomic arbitrage opportunities. The graph models
//! each token as a node and decentralised exchange protocols
//! as edges.
//!
//! The crate also provides optimization methods, such as golden
//! section search, to find optimal amounts for a specific sequence.

extern crate core;

// Reexports
pub use num_traits;
#[cfg(feature = "evm")]
pub mod evm;
pub mod models;
pub mod protocol;
pub mod serde_helpers;
pub(crate) mod utils;
