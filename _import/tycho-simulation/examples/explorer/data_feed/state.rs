//! Message structs for state updates
//!
//! A BlockState typically groups changes together based on the latency of the data source,
//! for example, on the Ethereum network, a BlockState is emitted every block and contains
//! all the changes from that block.
use std::collections::HashMap;
use tycho_core::Bytes;

use tycho_simulation::protocol::{models::ProtocolComponent, state::ProtocolSim};

#[derive(Debug)]
pub struct BlockState {
    pub time: u64,
    /// The current state of all pools
    pub states: HashMap<Bytes, Box<dyn ProtocolSim>>,
    /// The new pairs that were added in this block
    pub new_pairs: HashMap<Bytes, ProtocolComponent>,
    /// The pairs that were removed in this block
    pub removed_pairs: HashMap<Bytes, ProtocolComponent>,
}

impl BlockState {
    pub fn new(
        time: u64,
        states: HashMap<Bytes, Box<dyn ProtocolSim>>,
        new_pairs: HashMap<Bytes, ProtocolComponent>,
    ) -> Self {
        BlockState { time, states, new_pairs, removed_pairs: HashMap::new() }
    }

    pub fn set_removed_pairs(mut self, pairs: HashMap<Bytes, ProtocolComponent>) -> Self {
        self.removed_pairs = pairs;
        self
    }
}
