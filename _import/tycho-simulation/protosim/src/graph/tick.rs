//! Message structs for state updates
//!
//! A tick typically groups changes together based on the latency of the data source,
//! for example, on the Ethereum network, a tick is emitted every block and contains
//! all the changes from that block.
//!
//! It is generally a good idea to start searches whenever a tick has been fully
//! processed. However, this is not always possible, for example, centralized trading
//! venues do not have periods of latency. In such cases, the ticks should be
//! grouped into regular time intervals, such as 100 milliseconds.
use std::collections::HashMap;

use ethers::types::H160;

use crate::protocol::{models::ProtocolComponent, state::ProtocolState};

#[derive(Debug, Clone)]
pub struct Tick {
    pub time: u64,
    pub states: HashMap<H160, ProtocolState>,
    pub new_pairs: HashMap<H160, ProtocolComponent>,
}

impl Tick {
    pub fn new(
        time: u64,
        states: HashMap<H160, ProtocolState>,
        new_pairs: HashMap<H160, ProtocolComponent>,
    ) -> Self {
        Tick { time, states, new_pairs }
    }
}
