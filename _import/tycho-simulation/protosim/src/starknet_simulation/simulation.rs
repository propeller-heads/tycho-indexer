use std::{collections::HashMap, path::Path, sync::Arc};

use cairo_vm::felt::Felt252;
use starknet_in_rust::{
    core::contract_address::{compute_casm_class_hash, compute_deprecated_class_hash},
    execution::execution_entry_point::ExecutionResult,
    services::api::contract_classes::{
        compiled_class::CompiledClass, deprecated_contract_class::ContractClass,
    },
    state::{
        cached_state::{CachedState, TransactionalCachedStateReader},
        state_api::StateReader,
        state_cache::{StateCache, StorageEntry},
    },
    utils::{felt_to_hash, Address, ClassHash, CompiledClassHash},
    CasmContractClass,
};
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum SimulationError {
    #[error("Failed to initialise contracts: {0}")]
    InitError(String),
    #[error("ContractState is already initialized: {0}")]
    AlreadyInitialized(String),
    #[error("Override Starknet state failed: {0}")]
    OverrideError(String),
    /// Simulation didn't succeed; likely not related to network, so retrying won't help
    #[error("Simulated transaction failed: {0}")]
    TransactionError(String),
    #[error("Failed to decode result: {0}")]
    ResultError(String),
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

/**
 * Loads a Starknet contract from a given file path and returns it as a `CompiledClass` enum.
 *
 * # Arguments
 *
 * * `path: impl AsRef<Path>` - A path to the contract file.
 *
 * # Returns
 *
 * * `Ok(CompiledClass)` - The loaded contract as a `CompiledClass` enum.
 * * `Err(Box<dyn std::error::Error>)` - An error indicating the reason for the failure.
 *
 * # Contract Formats
 *
 * Starknet contracts can be represented in two main formats: `.casm` and `.json`.
 * You can read more about these formats in the [Starknet documentation](https://docs.starknet.io/documentation/architecture_and_concepts/Smart_Contracts/cairo-and-sierra/).
 *
 * ## .json Format (Cairo 0)
 *
 * * This format is older and represents Cairo 0 contracts. It is in JSON format, but sometimes
 *   for clarity it is given the `.sierra` extension.
 *
 * ## .casm Format (Cairo 1 / Cairo 2)
 *
 * * This format is newer and is used for Cairo 1 and Cairo 2 contracts.
 *
 * If the file extension is neither `.casm` nor `.json`, the function will return an `Err`
 * indicating an unsupported file type.
 */
fn load_compiled_class_from_path(
    path: impl AsRef<Path>,
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
            // Deserialize the .json file
            let contract_class: ContractClass = ContractClass::from_path(&path)?;
            Ok(CompiledClass::Deprecated(Arc::new(contract_class)))
        }
        _ => Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Unsupported file type",
        ))),
    }
}

/// Computes the class hash of a given contract.
///
/// # Arguments
///
/// * `compiled_class: &CompiledClass` - The contract to compute the class hash of.
///
/// # Returns
///
/// * `Result<Felt252, Box<dyn std::error::Error>>` - The computed class hash.
fn compute_class_hash(
    compiled_class: &CompiledClass,
) -> Result<Felt252, Box<dyn std::error::Error>> {
    match compiled_class {
        CompiledClass::Casm(casm_contract_class) => {
            let class_hash = compute_casm_class_hash(casm_contract_class)?;
            Ok(class_hash)
        }
        CompiledClass::Deprecated(contract_class) => {
            let class_hash = compute_deprecated_class_hash(contract_class)?;
            Ok(class_hash)
        }
    }
}

/// A struct with metadata about a contract to be initialized.
///
/// # Fields
///
/// * `contract_address: Address` - The address of the contract.
/// * `class_hash: ClassHash` - The class hash of the contract.
/// * `path: Option<String>` - The path to the contract file. If `None`, the contract is going to be
///   fetched from the state reader.
/// * `storage_overrides: Option<HashMap<StorageEntry, Felt252>>` - The storage overrides for the
///   contract.
#[derive(Debug, Clone)]
pub struct ContractInitialization {
    pub contract_address: Address,
    pub class_hash: ClassHash,
    pub path: Option<String>,
    pub storage_overrides: Option<HashMap<StorageEntry, Felt252>>,
}

impl ContractInitialization {
    pub fn new(
        contract_address: Address,
        class_hash: ClassHash,
        path: Option<String>,
        storage_overrides: Option<HashMap<StorageEntry, Felt252>>,
    ) -> Self {
        Self { contract_address, class_hash, path, storage_overrides }
    }
}

#[allow(unused_variables)]
#[allow(dead_code)]
impl<SR: StateReader> SimulationEngine<SR> {
    pub fn new(
        rpc_state_reader: Arc<SR>,
        input_contracts: impl IntoIterator<Item = ContractInitialization>,
    ) -> Result<Self, SimulationError> {
        // Prepare initial values
        let mut address_to_class_hash: HashMap<Address, ClassHash> = HashMap::new();
        let mut class_hash_to_compiled_class: HashMap<ClassHash, CompiledClass> = HashMap::new();
        let mut address_to_nonce: HashMap<Address, Felt252> = HashMap::new();
        let mut storage_updates: HashMap<StorageEntry, Felt252> = HashMap::new();

        let mut class_hash_to_compiled_class_hash: HashMap<ClassHash, CompiledClassHash> =
            HashMap::new();

        // Load contracts
        for input_contract in input_contracts {
            if let Some(path) = input_contract.path {
                let compiled_class = load_compiled_class_from_path(&path).map_err(|e| {
                    SimulationError::InitError(format!(
                        "Failed to load contract from path: {:?} with error: {:?}",
                        path, e
                    ))
                })?;
                let class_hash = input_contract.class_hash;
                // Compute compiled class hash
                let compiled_class_hash = compute_class_hash(&compiled_class).map_err(|e| {
                    SimulationError::InitError(format!(
                        "Failed to compute class hash for contract: {:?} with error: {:?}",
                        path, e
                    ))
                })?;
                // Convert Felt252 to ClassHash
                let compiled_class_hash = felt_to_hash(&compiled_class_hash);

                // Update caches
                address_to_class_hash.insert(input_contract.contract_address.clone(), class_hash);
                class_hash_to_compiled_class.insert(compiled_class_hash, compiled_class.clone());
                address_to_nonce.insert(input_contract.contract_address, Felt252::from(0u8));
                storage_updates.extend(
                    input_contract
                        .storage_overrides
                        .unwrap_or_default(),
                );

                class_hash_to_compiled_class_hash.insert(class_hash, compiled_class_hash);
            }
        }

        // Set StateCache initial values
        let cache: StateCache = StateCache::new(
            address_to_class_hash,
            class_hash_to_compiled_class.clone(),
            address_to_nonce,
            storage_updates,
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            class_hash_to_compiled_class_hash,
        );

        // Initialize CachedState contract classes
        let state: CachedState<SR> =
            CachedState::new_for_testing(rpc_state_reader, cache, class_hash_to_compiled_class);

        Ok(Self { state })
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

    /// Interpret the result of a simulated execution.
    ///
    /// Transforms the raw outcome of a simulated execution into a `SimulationResult`.
    ///
    /// # Arguments
    ///
    /// * `result` - An instance of the `ExecutionResult` struct, containing the result data from a
    ///   simulated execution.
    /// * `result_state` - A `CachedState` wrapped in a `TransactionalCachedStateReader`,
    ///   representing the state after simulation.
    ///
    /// # Return Value
    ///
    /// On successful simulation, this function returns `SimulationResult` containing the return
    /// data, state updates, and gas consumed. If an error occurs during the simulation, it
    /// returns a `SimulationError`.
    ///
    /// # Errors
    ///
    /// This function will return an error in the following situations:
    ///
    /// * If the execution reverts with an error (there exists a `revert_error` in the
    ///   `ExecutionResult`)
    /// * If the `call_info` field of the `ExecutionResult` is empty (None)
    /// * If the simulated execution fails (as indicated by the `failure_flag` in `call_info`)
    fn interpret_result(
        &self,
        result: ExecutionResult,
        state: CachedState<TransactionalCachedStateReader<SR>>,
    ) -> Result<SimulationResult, SimulationError> {
        // Check if revertError is not None
        if let Some(revert_error) = result.revert_error {
            return Err(SimulationError::TransactionError(format!(
                "Execution reverted with error: {}",
                revert_error
            )));
        }

        // Extract call info
        let call_info = result
            .call_info
            .ok_or(SimulationError::ResultError("Call info is empty".to_owned()))?;
        // Check if call failed
        if call_info.failure_flag {
            return Err(SimulationError::ResultError("Execution failed".to_owned()));
        }
        let gas_used = call_info.gas_consumed;
        let result = call_info.retdata;

        // Collect state changes
        let writes = state.cache().storage_writes();
        let mut state_updates = HashMap::new();
        for ((addr, hash), value) in writes {
            state_updates
                .entry(addr.clone())
                .or_insert_with(HashMap::new)
                .insert(*hash, value.clone());
        }

        Ok(SimulationResult { result, state_updates, gas_used })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;
    use starknet_in_rust::{core::errors::state_errors::StateError, execution::CallInfo};

    // Mock empty StateReader
    struct StateReaderMock {}

    impl StateReaderMock {
        fn new() -> Self {
            Self {}
        }
    }

    #[allow(unused_variables)]
    #[allow(dead_code)]
    impl StateReader for StateReaderMock {
        fn get_contract_class(&self, class_hash: &ClassHash) -> Result<CompiledClass, StateError> {
            todo!()
        }

        fn get_class_hash_at(&self, contract_address: &Address) -> Result<ClassHash, StateError> {
            todo!()
        }

        fn get_nonce_at(&self, contract_address: &Address) -> Result<Felt252, StateError> {
            todo!()
        }

        fn get_storage_at(&self, storage_entry: &StorageEntry) -> Result<Felt252, StateError> {
            todo!()
        }

        fn get_compiled_class_hash(
            &self,
            class_hash: &ClassHash,
        ) -> Result<CompiledClassHash, StateError> {
            todo!()
        }
    }

    #[rstest]
    #[case::cairo_0("tests/resources/fibonacci.json")]
    #[case::cairo_1("tests/resources/fibonacci.casm")]
    fn test_create_engine_with_contract_from_path(#[case] path: &str) {
        let cargo_manifest_path = Path::new(env!("CARGO_MANIFEST_DIR"));
        dbg!("Cargo manifest path is: {:?}", cargo_manifest_path);

        let path = cargo_manifest_path.join(path);
        dbg!("Contract path is: {:?}", &path);
        let path_str: String = path.to_str().unwrap().to_owned();

        let address: Address = Address(Felt252::from(0u8));
        let input_contract = ContractInitialization::new(address, [0u8; 32], Some(path_str), None);
        let rpc_state_reader = Arc::new(StateReaderMock::new());
        let engine_result = SimulationEngine::new(rpc_state_reader, vec![input_contract]);
        if let Err(err) = engine_result {
            panic!("Failed to create engine with error: {:?}", err);
        }
        assert!(engine_result.is_ok());
    }

    #[rstest]
    fn test_interpret_results() {
        let address = Address(Felt252::from(0u8));
        let rpc_state_reader = Arc::new(StateReaderMock::new());
        let engine = SimulationEngine::new(rpc_state_reader.clone(), vec![]).unwrap();

        // Construct expected values
        let gas_consumed = 10;
        let retdata: Vec<Felt252> = vec![1, 2, 3]
            .into_iter()
            .map(Felt252::from)
            .collect();
        let mut state_updates = HashMap::new();
        let mut storage_write: HashMap<[u8; 32], Felt252> = HashMap::new();
        let hash = [0u8; 32];
        let value: Felt252 = 0.into();
        storage_write.insert(hash, value.clone());
        state_updates.insert(address.clone(), storage_write);

        // Set up execution result
        let mut call_info =
            CallInfo::empty_constructor_call(address.clone(), address.clone(), None);
        call_info.gas_consumed = gas_consumed;
        call_info.retdata = retdata.clone();
        let execution_result =
            ExecutionResult { call_info: Some(call_info), revert_error: None, n_reverted_steps: 0 };

        // Set up state
        let state = CachedState::new(rpc_state_reader, HashMap::new());
        let mut result_state = state.create_transactional();
        result_state
            .cache_mut()
            .storage_writes_mut()
            .insert((address, hash), value);

        // Call interpret_result
        let result = engine
            .interpret_result(execution_result, result_state)
            .unwrap();

        assert_eq!(result.gas_used, gas_consumed);
        assert_eq!(result.result, retdata);
        assert_eq!(result.state_updates, state_updates);
    }

    #[rstest]
    fn test_interpret_results_with_revert_error() {
        // Construct state and engine
        let rpc_state_reader = Arc::new(StateReaderMock::new());
        let engine = SimulationEngine::new(rpc_state_reader.clone(), vec![]).unwrap();
        let state = CachedState::new(rpc_state_reader, HashMap::new());
        let result_state = state.create_transactional();

        // Construct reverted execution result
        let execution_result_with_revert = ExecutionResult {
            call_info: None,
            revert_error: Some("Test Revert".to_string()),
            n_reverted_steps: 0,
        };

        match engine.interpret_result(execution_result_with_revert, result_state) {
            Err(SimulationError::TransactionError(message)) => {
                assert!(message.contains("Execution reverted with error: Test Revert"));
            }
            _ => panic!("Expected TransactionError for revert"),
        }
    }

    #[rstest]
    fn test_interpret_results_with_empty_call_info() {
        // Construct state and engine
        let rpc_state_reader = Arc::new(StateReaderMock::new());
        let engine = SimulationEngine::new(rpc_state_reader.clone(), vec![]).unwrap();
        let state = CachedState::new(rpc_state_reader, HashMap::new());
        let result_state = state.create_transactional();

        // Construct execution result with no call info
        let execution_result_no_call_info =
            ExecutionResult { call_info: None, revert_error: None, n_reverted_steps: 0 };

        match engine.interpret_result(execution_result_no_call_info, result_state) {
            Err(SimulationError::ResultError(message)) => {
                assert_eq!(message, "Call info is empty");
            }
            _ => panic!("Expected ResultError for empty call_info"),
        }
    }

    #[rstest]
    fn test_interpret_results_with_failure_flag() {
        // Construct state and engine
        let address = Address(Felt252::from(0u8));
        let rpc_state_reader = Arc::new(StateReaderMock::new());
        let engine = SimulationEngine::new(rpc_state_reader.clone(), vec![]).unwrap();
        let state = CachedState::new(rpc_state_reader, HashMap::new());
        let result_state = state.create_transactional();

        // Construct execution result with failed call
        let mut call_info =
            CallInfo::empty_constructor_call(address.clone(), address.clone(), None);
        call_info.failure_flag = true;
        let execution_result_fail_flag =
            ExecutionResult { call_info: Some(call_info), revert_error: None, n_reverted_steps: 0 };

        match engine.interpret_result(execution_result_fail_flag, result_state) {
            Err(SimulationError::ResultError(message)) => {
                assert_eq!(message, "Execution failed");
            }
            _ => panic!("Expected ResultError for failed call"),
        }
    }
}
