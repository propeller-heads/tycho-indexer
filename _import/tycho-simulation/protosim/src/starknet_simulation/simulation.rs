use std::collections::HashMap;

use cairo_vm::felt::Felt252;
use starknet_in_rust::{
    state::{cached_state::CachedState, state_api::StateReader, state_cache::StorageEntry},
    utils::{Address, ClassHash},
};
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum SimulationError {
    #[error("Failed to initialise a contract: {0}")]
    InitError(String),
    #[error("Override Starknet state failed: {0}")]
    OverrideError(String),
}

#[derive(Debug)]
pub struct StarknetSimulationEngine<SR: StateReader> {
    pub state: CachedState<SR>,
}

/// The override map associates a tuple of a variable name and its arguments to its new value.
pub type Overrides = HashMap<(String, Vec<Felt252>), Felt252>;
#[derive(Debug)]
pub struct SimulationParameters {
    /// Address of the sending account
    pub caller: Address,
    /// Address of the receiving account/contract
    pub to: Address,
    /// Calldata
    pub data: Vec<Felt252>,
    /// The contract function/entry point to call e.g. "transfer"
    pub entry_point: String,
    /// Starknet state overrides.
    /// Will be merged with the existing state. Will take effect only for current simulation.
    /// Must be given as a contract address to its variable override map.
    pub overrides: Option<HashMap<Address, Overrides>>,
    /// Limit of gas to be used by the transaction
    pub gas_limit: Option<u128>,
    /// The block number to be used by the transaction. This is independent of the states block.
    pub block_number: u64,
}

pub struct SimulationResult {
    /// Output of transaction execution
    pub result: Vec<Felt252>,
    /// State changes caused by the transaction
    pub state_updates: HashMap<Address, Overrides>,
    /// Gas used by the transaction (already reduced by the refunded gas)
    pub gas_used: u64,
}

trait SimulationEngine {
    // Inserts a contract with set storage into state
    fn init_contract(
        &self,
        contract_address: Address,
        class_hash: ClassHash,
        path: String,
    ) -> Result<(), SimulationError>;
    // Overrides storage
    fn set_state(
        &self,
        storage_entry: &StorageEntry,
        value: Felt252,
    ) -> Result<(), SimulationError>;
    // Run Simulation
    fn simulate(&self, params: &SimulationParameters) -> Result<SimulationResult, SimulationError>;
    // Interpret simulation result
    fn interpret_evm_result(
        &self,
        starknet_result: Result<(), SimulationError>,
    ) -> Result<SimulationResult, SimulationError>;
}

impl<SR: StateReader> SimulationEngine for StarknetSimulationEngine<SR> {
    fn init_contract(
        &self,
        contract_address: Address,
        class_hash: ClassHash,
        path: String,
    ) -> Result<(), SimulationError> {
        todo!()
    }

    fn set_state(
        &self,
        storage_entry: &StorageEntry,
        value: Felt252,
    ) -> Result<(), SimulationError> {
        todo!()
    }

    fn simulate(&self, params: &SimulationParameters) -> Result<SimulationResult, SimulationError> {
        todo!()
    }

    fn interpret_evm_result(
        &self,
        starknet_result: Result<(), SimulationError>,
    ) -> Result<SimulationResult, SimulationError> {
        todo!()
    }
}
