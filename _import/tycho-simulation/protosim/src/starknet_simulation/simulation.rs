use std::{collections::HashMap, sync::Arc};

use cairo_vm::felt::Felt252;
use starknet_in_rust::{
    definitions::block_context::BlockContext,
    execution::{
        execution_entry_point::{ExecutionEntryPoint, ExecutionResult},
        CallType, TransactionExecutionContext,
    },
    state::{
        cached_state::{CachedState, ContractClassCache},
        state_api::StateReader,
        ExecutionResourcesManager,
    },
    utils::{calculate_sn_keccak, Address, ClassHash},
    EntryPointType,
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

    /// Simulate a transaction
    ///
    /// State's block will be modified to be the last block before the simulation's block.
    pub fn simulate(
        &self,
        params: &SimulationParameters,
    ) -> Result<SimulationResult, SimulationError> {
        // Create a transactional state copy - to be used for simulations and not alter the original
        // state cache
        let mut test_state = self.state.create_transactional();

        // Create the simulated call
        let entry_point = params.entry_point.as_bytes();
        let entrypoint_selector = Felt252::from_bytes_be(&calculate_sn_keccak(entry_point));

        let class_hash = self
            .state
            .get_class_hash_at(&params.to)
            .map_err(|err| SimulationError::StateError(err.to_string()))?;

        let call = ExecutionEntryPoint::new(
            params.to.clone(),
            params.data.clone(),
            entrypoint_selector,
            params.caller.clone(),
            EntryPointType::External,
            Some(CallType::Delegate),
            Some(class_hash),
            params.gas_limit.unwrap_or(0),
        );

        // Set up the call context
        let block_context = BlockContext::default();
        let mut resources_manager = ExecutionResourcesManager::default();
        let mut tx_execution_context = TransactionExecutionContext::default();

        // Execute the simulated call
        let result = call
            .execute(
                &mut test_state,
                &block_context,
                &mut resources_manager,
                &mut tx_execution_context,
                false,
                block_context.invoke_tx_max_n_steps(),
            )
            .map_err(|err| SimulationError::TransactionError(err.to_string()))?;

        // Interpret and return the results
        self.interpret_result(result)
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
