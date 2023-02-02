use std::collections::HashMap;

use ethers::types::H160;

use crate::protocol::state::ProtocolState;

#[derive(Debug, Clone)]
pub struct Tick {
    pub time: u64,
    pub states: HashMap<H160, ProtocolState>,
}

impl Tick {
    pub fn new(time: u64, states: HashMap<H160, ProtocolState>) -> Self {
        Tick { time, states }
    }
}
