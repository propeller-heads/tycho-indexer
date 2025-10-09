pub mod protocol_stream_processor;
pub mod rfq_stream_processor;

use std::{fmt, fmt::Display};

use tycho_simulation::protocol::models::Update;

#[derive(Debug)]
pub struct StreamUpdate {
    pub update_type: UpdateType,
    pub update: Update,
    pub is_first_update: bool,
}

#[derive(Debug)]
pub enum UpdateType {
    Protocol,
    Rfq,
}

impl Display for UpdateType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UpdateType::Protocol => write!(f, "Protocol"),
            UpdateType::Rfq => write!(f, "RFQ"),
        }
    }
}
