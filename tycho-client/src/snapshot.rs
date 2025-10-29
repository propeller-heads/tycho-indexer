use std::collections::HashMap;

use tycho_common::{
    dto::{Chain, EntryPointWithTracingParams, ProtocolComponent, TracingResult},
    models::ComponentId,
    Bytes,
};

/// Request body for fetching a snapshot of protocol states and VM storage.
///
/// This struct helps to coordinate fetching  multiple pieces of related data
/// (protocol states, contract storage, TVL, entry points).
#[derive(Clone, Debug, PartialEq)]
pub struct SnapshotParameters {
    /// Which chain to fetch snapshots for
    pub chain: Chain,
    /// Protocol system name, required for correct state resolution
    pub protocol_system: String,
    /// Components to fetch protocol states for
    pub components: HashMap<ComponentId, ProtocolComponent>,
    /// Traced entry points data mapped by component id
    pub entrypoints: HashMap<String, Vec<(EntryPointWithTracingParams, TracingResult)>>,
    /// Contract addresses to fetch VM storage for
    pub contract_ids: Vec<Bytes>,
    /// Block number for versioning
    pub block_number: u64,
    /// Whether to include balance information
    pub include_balances: bool,
    /// Whether to fetch TVL data
    pub include_tvl: bool,
}

impl SnapshotParameters {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chain: Chain,
        protocol_system: String,
        components: HashMap<ComponentId, ProtocolComponent>,
        entrypoints: HashMap<String, Vec<(EntryPointWithTracingParams, TracingResult)>>,
        contract_ids: Vec<Bytes>,
        block_number: u64,
        include_balances: bool,
        include_tvl: bool,
    ) -> Self {
        Self {
            chain,
            protocol_system,
            components,
            entrypoints,
            contract_ids,
            block_number,
            include_balances,
            include_tvl,
        }
    }
}
