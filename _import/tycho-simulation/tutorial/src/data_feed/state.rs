//! Message structs for state updates
//!
//! A BlockState typically groups changes together based on the latency of the data source,
//! for example, on the Ethereum network, a BlockState is emitted every block and contains
//! all the changes from that block.
use std::collections::HashMap;

use ethers::types::H160;

use tycho_simulation::protocol::{models::ProtocolComponent, state::ProtocolSim};

#[derive(Debug)]
pub struct BlockState {
    pub time: u64,
    /// The current state of all pools
    pub states: HashMap<H160, Box<dyn ProtocolSim>>,
    /// The new pairs that were added in this block
    pub new_pairs: HashMap<H160, ProtocolComponent>,
    /// The pairs that were removed in this block
    pub removed_pairs: HashMap<H160, ProtocolComponent>,
}

impl BlockState {
    pub fn new(
        time: u64,
        states: HashMap<H160, Box<dyn ProtocolSim>>,
        new_pairs: HashMap<H160, ProtocolComponent>,
    ) -> Self {
        BlockState { time, states, new_pairs, removed_pairs: HashMap::new() }
    }

    pub fn set_removed_pairs(mut self, pairs: HashMap<H160, ProtocolComponent>) -> Self {
        self.removed_pairs = pairs;
        self
    }
}
