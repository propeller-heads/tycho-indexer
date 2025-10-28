use alloy::{
    primitives::map::AddressHashMap,
    rpc::types::{state::AccountOverride, TransactionRequest},
};
use num_bigint::BigUint;
use tycho_execution::encoding::models::{Solution, Transaction};

use crate::execution::tenderly::OverwriteMetadata;

#[derive(Debug, Clone)]
pub struct TychoExecutionInfo {
    pub solution: Solution,
    pub transaction: Transaction,
    pub expected_amount_out: BigUint,
    pub protocol_system: String,
    pub component_id: String,
}

#[derive(Clone)]
pub enum TychoExecutionResult {
    Success {
        amount_out: BigUint,
        gas_used: u64,
    },
    // Simulation reverted
    Revert {
        reason: String,
        state_overwrites: Option<AddressHashMap<AccountOverride>>,
        overwrite_metadata: Option<OverwriteMetadata>,
    },
    // There was an error when preparing or processing the data
    Failed {
        error_msg: String,
    },
}

#[derive(Debug, Clone)]
pub(super) struct SimulationInput {
    pub tx: TransactionRequest,
    pub state_overwrites: Option<AddressHashMap<AccountOverride>>,
    pub overwrite_metadata: Option<OverwriteMetadata>,
}

/// Result of a simulation with trace
#[derive(Debug, Clone)]
pub(super) enum SimulationResult {
    Success { return_data: Vec<u8>, gas_used: u64 },
    Revert { reason: String },
}
