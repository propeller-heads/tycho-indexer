//! Protosim: a decentralized exchange simulation library
//!
//! This library allows to simulate trades against a wide range
//! of different protocols, including uniswap-v2 and uniswap-v3.
//! It allows to simulate chained trades over different venues
//! together to exploit price differences by using token prices
//! calculated from the protocols state.
//!
//! The main data structure is a graph which allows to search
//! for a sequence of swaps that provide some desired outcome,
//! such as atomic arbitrage opportunities. The graph models
//! each token as a node and decentralised exchange protocols
//! as edges.
//!
//! The crate also provides optimization methods, such as golden
//! section search, to find optimal amounts for a specific sequence.

pub mod graph;
pub mod models;
pub mod optimize;
pub mod protocol;
mod u256_num;
