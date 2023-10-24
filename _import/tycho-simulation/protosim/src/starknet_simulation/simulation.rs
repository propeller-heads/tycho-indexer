use std::{collections::HashMap, sync::Arc};

use cairo_vm::felt::Felt252;
use starknet_in_rust::{
    execution::execution_entry_point::ExecutionResult,
    state::{cached_state::CachedState, state_api::StateReader},
    utils::{Address, ClassHash},
};
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum SimulationError {
    #[error("Failed to initialise a contract: {0}")]
    InitError(String),
    #[error("Override Starknet state failed: {0}")]
    OverrideError(String),
    /// Simulation didn't succeed; likely not related to network, so retrying won't help
    #[error("Simulated transaction failed: {0}")]
    TransactionError(String),
    /// Error reading state
    #[error("Accessing contract state failed: {0}")]
    StateError(String),
}

pub type StorageHash = [u8; 32];
pub type Overrides = HashMap<StorageHash, Felt252>;

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
    pub gas_used: u128,
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct SimulationEngine<SR: StateReader> {
    state: CachedState<SR>,
}

#[allow(unused_variables)]
#[allow(dead_code)]
impl<SR: StateReader> SimulationEngine<SR> {
    pub fn new(rpc_state_reader: Arc<SR>) -> Self {
        // Create default class cache
        let class_cache = ContractClassCache::default();

        // Create state
        let state = CachedState::new(rpc_state_reader, class_cache);

        // instantiate and return self
        Self { state }
    }

    pub fn init_contract(
        &self,
        contract_address: Address,
        class_hash: ClassHash,
        path: String,
    ) -> Result<(), SimulationError> {
        todo!()
    }

    fn set_state(&self, state: HashMap<Address, Overrides>) {
        todo!()
    }

    pub fn simulate(
        &self,
        params: &SimulationParameters,
    ) -> Result<SimulationResult, SimulationError> {
        todo!()
    }

    fn interpret_result(
        &self,
        result: ExecutionResult,
    ) -> Result<SimulationResult, SimulationError> {
        todo!()
    }
}

#[cfg(test)]
mod tests {}
