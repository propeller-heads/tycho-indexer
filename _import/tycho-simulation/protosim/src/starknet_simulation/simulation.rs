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

pub struct SimulationParameters;
pub struct StarknetSimulationResult;

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
    fn simulate(
        &self,
        params: &SimulationParameters,
    ) -> Result<StarknetSimulationResult, SimulationError>;
    // Interpret simulation result
    fn interpret_evm_result(
        &self,
        starknet_result: Result<(), SimulationError>,
    ) -> Result<StarknetSimulationResult, SimulationError>;
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

    fn simulate(
        &self,
        params: &SimulationParameters,
    ) -> Result<StarknetSimulationResult, SimulationError> {
        todo!()
    }

    fn interpret_evm_result(
        &self,
        starknet_result: Result<(), SimulationError>,
    ) -> Result<StarknetSimulationResult, SimulationError> {
        todo!()
    }
}
