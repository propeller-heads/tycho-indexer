//! Message structs for state updates
//!
//! A tick typically groups changes together based on the latency of the data source,
//! for example, on the Ethereum network, a tick is emitted every block and contains
//! all the changes from that block.
//!
//! It is generally a good idea to start any data processing whenever a tick has been fully
//! processed. However, this is not always possible, for example, centralized trading
//! venues do not have periods of latency. In such cases, the ticks should be
//! grouped into regular time intervals, such as 100 milliseconds.
use std::collections::HashMap;

use ethers::types::H160;

use protosim::protocol::{models::ProtocolComponent, state::ProtocolSim};

#[derive(Debug)]
pub struct Tick {
    pub time: u64,
    pub states: HashMap<H160, Box<dyn ProtocolSim>>,
    pub new_pairs: HashMap<H160, ProtocolComponent>,
    pub removed_pairs: HashMap<H160, ProtocolComponent>,
}

impl Tick {
    pub fn new(
        time: u64,
        states: HashMap<H160, Box<dyn ProtocolSim>>,
        new_pairs: HashMap<H160, ProtocolComponent>,
    ) -> Self {
        Tick { time, states, new_pairs, removed_pairs: HashMap::new() }
    }

    pub fn set_removed_pairs(mut self, pairs: HashMap<H160, ProtocolComponent>) -> Self {
        self.removed_pairs = pairs;
        self
    }
}
