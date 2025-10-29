use std::collections::HashMap;

use tycho_common::{
    dto::{
        Chain, EntryPointWithTracingParams, ResponseAccount, ResponseProtocolState, TracingResult,
    },
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
    /// Component IDs to fetch protocol states for
    pub component_ids: Vec<String>,
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
    pub fn new(
        chain: Chain,
        protocol_system: String,
        component_ids: Vec<String>,
        contract_ids: Vec<Bytes>,
        block_number: u64,
        include_balances: bool,
        include_tvl: bool,
    ) -> Self {
        Self {
            chain,
            protocol_system,
            component_ids,
            contract_ids,
            block_number,
            include_balances,
            include_tvl,
        }
    }
}

/// Response containing snapshot data for protocol states and VM storage.
///
/// This aggregates data from multiple RPC endpoints into a single response
/// for client convenience.
/// TODO replace this with the Snapshot struct
#[derive(Clone, Debug, PartialEq)]
pub struct SnapshotRequestResponse {
    /// Protocol states indexed by component ID
    pub protocol_states: HashMap<String, ResponseProtocolState>,
    /// VM storage (contract accounts) indexed by address
    pub vm_storage: HashMap<Bytes, ResponseAccount>,
    /// Component TVL values (if requested)
    pub component_tvl: HashMap<String, f64>,
    /// Traced entry points (if requested for Ethereum)
    pub traced_entry_points: HashMap<String, Vec<(EntryPointWithTracingParams, TracingResult)>>,
}

impl SnapshotRequestResponse {
    pub fn new(
        protocol_states: HashMap<String, ResponseProtocolState>,
        vm_storage: HashMap<Bytes, ResponseAccount>,
        component_tvl: HashMap<String, f64>,
        traced_entry_points: HashMap<String, Vec<(EntryPointWithTracingParams, TracingResult)>>,
    ) -> Self {
        Self { protocol_states, vm_storage, component_tvl, traced_entry_points }
    }
}
