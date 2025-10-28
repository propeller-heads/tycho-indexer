//! Snapshot request and response types for retrieving protocol state and contract storage.
//!
//! This module contains higher-level abstractions used by the client library to fetch
//! complete snapshots of protocol state. These are not DTOs - they're constructed and
//! consumed entirely in Rust code.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use tycho_common::{
    dto::{
        Chain, EntryPointWithTracingParams, ResponseAccount, ResponseProtocolState, TracingResult,
    },
    Bytes,
};

/// Request body for fetching a snapshot of protocol states and VM storage.
///
/// This is a higher-level struct used by the client library to coordinate fetching
/// multiple pieces of related data (protocol states, contract storage, TVL, entry points).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SnapshotRequestBody {
    #[serde(default)]
    pub chain: Chain,
    /// Protocol system name, required for correct state resolution
    #[serde(alias = "protocolSystem")]
    pub protocol_system: String,
    /// Component IDs to fetch protocol states for
    #[serde(alias = "componentIds", default)]
    pub component_ids: Vec<String>,
    /// Contract addresses to fetch VM storage for
    #[serde(alias = "contractIds", default)]
    pub contract_ids: Vec<Bytes>,
    /// Block number for versioning
    #[serde(alias = "blockNumber")]
    pub block_number: u64,
    /// Whether to include balance information
    #[serde(alias = "includeBalances", default)]
    pub include_balances: bool,
    /// Whether to fetch TVL data
    #[serde(alias = "includeTvl", default)]
    pub include_tvl: bool,
}

impl SnapshotRequestBody {
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
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SnapshotRequestResponse {
    /// Protocol states indexed by component ID
    #[serde(alias = "protocolStates")]
    pub protocol_states: HashMap<String, ResponseProtocolState>,
    /// VM storage (contract accounts) indexed by address
    #[serde(alias = "vmStorage")]
    pub vm_storage: HashMap<Bytes, ResponseAccount>,
    /// Component TVL values (if requested)
    #[serde(alias = "componentTvl", default)]
    pub component_tvl: HashMap<String, f64>,
    /// Traced entry points (if requested for Ethereum)
    #[serde(alias = "tracedEntryPoints", default)]
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
