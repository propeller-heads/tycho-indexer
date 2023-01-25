//! Protosim: a decentralized exchange simulation library
//!
//! This library allows to simulate trades against a wide range of different protocols.
//! It allows to simulate chained trades over different venues together to exploit price differences.
//!
//! The main data structure is a graph which allows to search for a sequence of swaps that provide
//! some desired outcome. The graph models each token as a node and decentralised exchange protocls
//! as edges.
//!
//! The crate also provides optimization methods to find optimal amounts for a specific sequence.

pub mod graph;
pub mod models;
pub mod optimize;
pub mod protocol;
mod u256_num;
