use std::{collections::HashMap, path::Path, sync::Arc};

use cairo_vm::felt::Felt252;
use starknet_in_rust::{
    execution::execution_entry_point::ExecutionResult,
    services::api::contract_classes::{
        compiled_class::CompiledClass, deprecated_contract_class::ContractClass,
    },
    state::{cached_state::CachedState, state_api::StateReader, state_cache::StorageEntry},
    utils::{Address, ClassHash},
    CasmContractClass,
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

fn load_compiled_class_from_path<P: AsRef<Path>>(
    path: P,
) -> Result<CompiledClass, Box<dyn std::error::Error>> {
    let contents = std::fs::read_to_string(&path)?;

    match path
        .as_ref()
        .extension()
        .and_then(std::ffi::OsStr::to_str)
    {
        Some("casm") => {
            // Parse and load .casm file
            let casm_contract_class: CasmContractClass = serde_json::from_str(&contents)?;
            Ok(CompiledClass::Casm(Arc::new(casm_contract_class)))
        }
        Some("json") => {
            // Deserialize the JSON file
            let contract_class: ContractClass = ContractClass::from_path(&path)?;
            Ok(CompiledClass::Deprecated(Arc::new(contract_class)))
        }
        _ => Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Unsupported file type",
        ))),
    }
}

#[allow(unused_variables)]
#[allow(dead_code)]
impl<SR: StateReader> SimulationEngine<SR> {
    pub fn init_contract(
        &mut self,
        contract_address: Address,
        class_hash: ClassHash,
        path: String,
        storage_overrides: Option<HashMap<StorageEntry, Felt252>>,
    ) -> Result<(), SimulationError> {
        // Read CompiledClass from file based on suffix
        let compiled_class: CompiledClass = load_compiled_class_from_path(path).unwrap();

        // Borrow mutable reference to cache
        let cache = self.state.cache_mut();

        // Prepare state updates
        let address_to_class_hash = [(contract_address.clone(), class_hash)];
        let address_to_nonce = [(contract_address, Felt252::from(0u8))];
        let storage_updates = storage_overrides.unwrap_or_default();

        // Update cache initial values
        cache
            .class_hash_writes_mut()
            .extend(address_to_class_hash);
        // Deprecated ContractClass is already compiled
        if let CompiledClass::Casm(casm_contract_class) = compiled_class {
            let class_hash_to_compiled_class_hash =
                [(class_hash, CompiledClass::Casm(casm_contract_class))];
            cache
                .compiled_class_hash_writes_mut()
                .extend(class_hash_to_compiled_class_hash.clone());
        }
        cache
            .nonce_writes_mut()
            .extend(address_to_nonce);
        cache
            .storage_writes_mut()
            .extend(storage_updates);

        Ok(())
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
