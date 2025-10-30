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
pub struct SnapshotParameters<'a> {
    /// Which chain to fetch snapshots for
    pub chain: Chain,
    /// Protocol system name, required for correct state resolution
    pub protocol_system: &'a str,
    /// Components to fetch protocol states for
    pub components: &'a HashMap<ComponentId, ProtocolComponent>,
    /// Traced entry points data mapped by component id
    pub entrypoints: &'a HashMap<String, Vec<(EntryPointWithTracingParams, TracingResult)>>,
    /// Contract addresses to fetch VM storage for
    pub contract_ids: &'a [Bytes],
    /// Block number for versioning
    pub block_number: u64,
    /// Whether to include balance information
    pub include_balances: bool,
    /// Whether to fetch TVL data
    pub include_tvl: bool,
}

impl<'a> SnapshotParameters<'a> {
    pub fn new(
        chain: Chain,
        protocol_system: &'a str,
        components: &'a HashMap<ComponentId, ProtocolComponent>,
        entrypoints: &'a HashMap<String, Vec<(EntryPointWithTracingParams, TracingResult)>>,
        contract_ids: &'a [Bytes],
        block_number: u64,
    ) -> Self {
        Self {
            chain,
            protocol_system,
            components,
            entrypoints,
            contract_ids,
            block_number,
            include_balances: true,
            include_tvl: true,
        }
    }

    /// Set whether to include balance information (default: true)
    pub fn include_balances(mut self, include_balances: bool) -> Self {
        self.include_balances = include_balances;
        self
    }

    /// Set whether to fetch TVL data (default: true)
    pub fn include_tvl(mut self, include_tvl: bool) -> Self {
        self.include_tvl = include_tvl;
        self
    }
}
