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

#[allow(unused_variables)]
#[allow(dead_code)]
impl<SR: StateReader> StarknetSimulationEngine<SR> {
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
