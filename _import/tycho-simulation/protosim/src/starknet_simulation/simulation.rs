use starknet_in_rust::state::state_api::State;
use std::collections::HashMap;

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
    pub fn init_contract(
        &self,
        contract_address: Address,
        class_hash: ClassHash,
        path: String,
    ) -> Result<(), SimulationError> {
        todo!()
    }

    fn set_state(&mut self, state: HashMap<Address, Overrides>) {
        for (address, slot_update) in state {
            for (slot, value) in slot_update {
                let storage_entry = (address.clone(), slot);
                self.state
                    .set_storage_at(&storage_entry, value);
            }
        }
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
mod tests {
    use starknet_in_rust::state::cached_state::ContractClassCache;

    use super::*;
    use std::{collections::HashMap, sync::Arc};

    struct MockStateReader;
    #[allow(unused_variables)]
    impl StateReader for MockStateReader {
        fn get_contract_class(
            &self,
            class_hash: &ClassHash,
        ) -> Result<
            starknet_in_rust::services::api::contract_classes::compiled_class::CompiledClass,
            starknet_in_rust::core::errors::state_errors::StateError,
        > {
            todo!()
        }

        fn get_class_hash_at(
            &self,
            contract_address: &Address,
        ) -> Result<ClassHash, starknet_in_rust::core::errors::state_errors::StateError> {
            todo!()
        }

        fn get_nonce_at(
            &self,
            contract_address: &Address,
        ) -> Result<Felt252, starknet_in_rust::core::errors::state_errors::StateError> {
            todo!()
        }

        fn get_storage_at(
            &self,
            storage_entry: &(starknet_in_rust::utils::Address, [u8; 32]),
        ) -> Result<Felt252, starknet_in_rust::core::errors::state_errors::StateError> {
            todo!()
        }

        fn get_compiled_class_hash(
            &self,
            class_hash: &ClassHash,
        ) -> Result<
            starknet_in_rust::utils::CompiledClassHash,
            starknet_in_rust::core::errors::state_errors::StateError,
        > {
            todo!()
        }
    }

    #[test]
    fn test_set_state() {
        let mut engine = SimulationEngine {
            state: CachedState::new(Arc::new(MockStateReader), ContractClassCache::default()),
        };

        let mut state = HashMap::new();
        let mut overrides = HashMap::new();

        let address = Address(123.into());
        let slot = [0; 32];
        let value = Felt252::from(1);

        overrides.insert(slot, value.clone());
        state.insert(address.clone(), overrides);

        engine.set_state(state.clone());

        let storage_entry = (address, slot);
        let retrieved_value = engine
            .state
            .get_storage_at(&storage_entry)
            .unwrap();
        assert_eq!(retrieved_value, value, "State was not set correctly");
    }
}
