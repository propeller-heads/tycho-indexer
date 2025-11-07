use alloy::{
    primitives::map::AddressHashMap,
    rpc::types::{state::AccountOverride, TransactionRequest},
};
use num_bigint::BigUint;
use tycho_execution::encoding::models::{Solution, Transaction};

use crate::execution::tenderly::OverwriteMetadata;

/// Information required to execute a Tycho transaction simulation.
/// Contains the solution data, transaction details, and data needed for verification.
#[derive(Debug, Clone)]
pub struct TychoExecutionInput {
    pub solution: Solution,
    pub transaction: Transaction,
    pub expected_amount_out: BigUint,
    pub protocol_system: String,
    pub component_id: String,
    pub token_in: String,
    pub token_out: String,
}

/// Result of executing a Tycho transaction simulation.
/// Represents the three possible outcomes: successful execution, transaction revert, or execution
/// failure.
#[derive(Clone)]
pub enum TychoExecutionResult {
    /// Successful execution with output amount and gas consumption
    Success { amount_out: BigUint, gas_used: u64 },
    /// Simulation reverted with reason and optional state overrides for debugging
    Revert {
        reason: String,
        state_overwrites: Option<AddressHashMap<AccountOverride>>,
        overwrite_metadata: Option<OverwriteMetadata>,
    },
    /// Execution failed due to error during preparation or processing
    Failed { error_msg: String },
}

/// Input parameters for simulating a transaction.
/// Contains the transaction request and optional state modifications.
#[derive(Debug, Clone)]
pub(super) struct SimulationInput {
    pub tx: TransactionRequest,
    pub state_overwrites: Option<AddressHashMap<AccountOverride>>,
    pub overwrite_metadata: Option<OverwriteMetadata>,
}

/// Result of a transaction simulation with execution trace.
/// Contains either successful execution data or revert information.
#[derive(Debug, Clone)]
pub(super) enum SimulationResult {
    /// Successful simulation with return data and gas consumption
    Success { return_data: Vec<u8>, gas_used: u64 },
    /// Simulation reverted with reason
    Revert { reason: String },
}
