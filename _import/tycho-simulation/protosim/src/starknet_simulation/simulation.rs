use rpc_state_reader::rpc_state::BlockValue;
use starknet_api::block::BlockNumber;
use starknet_in_rust::state::state_api::State;
use std::{collections::HashMap, path::Path, sync::Arc};

use cairo_vm::felt::Felt252;
use starknet_in_rust::{
    core::contract_address::{compute_casm_class_hash, compute_deprecated_class_hash},
    definitions::block_context::BlockContext,
    execution::{
        execution_entry_point::{ExecutionEntryPoint, ExecutionResult},
        CallType, TransactionExecutionContext,
    },
    services::api::contract_classes::{
        compiled_class::CompiledClass, deprecated_contract_class::ContractClass,
    },
    state::{
        cached_state::CachedState,
        state_api::StateReader,
        state_cache::{StateCache, StorageEntry},
        ExecutionResourcesManager,
    },
    utils::{calculate_sn_keccak, felt_to_hash, Address, ClassHash, CompiledClassHash},
    CasmContractClass, EntryPointType,
};
use thiserror::Error;
use tracing::{debug, info};

use super::rpc_reader::RpcStateReader;

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
    /// Error reading state
    #[error("Accessing contract state failed: {0}")]
    StateError(String),
}

pub type StorageHash = [u8; 32];
pub type Overrides = HashMap<StorageHash, Felt252>;

#[derive(Debug, Clone)]
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

impl SimulationParameters {
    pub fn new(
        caller: Address,
        to: Address,
        data: Vec<Felt252>,
        entry_point: String,
        overrides: Option<HashMap<Address, Overrides>>,
        gas_limit: Option<u128>,
        block_number: u64,
    ) -> Self {
        Self { caller, to, data, entry_point, overrides, gas_limit, block_number }
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct SimulationResult {
    /// Output of transaction execution
    pub result: Vec<Felt252>,
    /// State changes caused by the transaction
    pub state_updates: HashMap<Address, Overrides>,
    /// Gas used by the transaction (already reduced by the refunded gas)
    pub gas_used: u128,
}

impl SimulationResult {
    pub fn new(
        result: Vec<Felt252>,
        state_updates: HashMap<Address, Overrides>,
        gas_used: u128,
    ) -> Self {
        Self { result, state_updates, gas_used }
    }
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
/// These overrides are permanent over
///
/// # Fields
///
/// * `contract_address: Address` - The address of the contract.
/// * `class_hash: ClassHash` - The class hash of the contract (can differ from that of the contract
///   onchain if you wish to mock the contract)
/// * `path: Option<String>` - The path to the contract file. WARNING: if `None`, the contract will
///   be fetched from the state reader, adding rpc overhead. This should be avoided if possible!
#[derive(Debug, Clone)]
pub struct ContractOverride {
    pub contract_address: Address,
    pub class_hash: ClassHash,
    pub path: Option<String>,
}

impl ContractOverride {
    pub fn new(contract_address: Address, class_hash: ClassHash, path: Option<String>) -> Self {
        Self { contract_address, class_hash, path }
    }
}

/// Simulation engine for Starknet transactions.
///
/// Warning: Given that the used libraries are in development,
/// this code is also considered to not be very stable and production ready.
///
/// One of the issues in current state is that the trait [StateReader] does not operate in a context
/// of a given block and the simulation engine expects the data to be correct for the given block.
/// This is unforunately not enforcable by the trait and thus the simulation `simulate()` function
/// is implemented over a concrete type (more info on [SimulationEngine<RpcStateReader>]).
///
/// # Fields
///
/// * `state: CachedState<SR>` - The state of the simulation engine.
/// * `contract_overrides: Vec<ContractOverride>` - A permanent list of contract overrides persisted
///   across simulations, does not reset on a new block.
#[derive(Debug)]
#[allow(dead_code)]
pub struct SimulationEngine<SR: StateReader> {
    state: CachedState<SR>,
    contract_overrides: Vec<ContractOverride>,
}

#[allow(unused_variables)]
#[allow(dead_code)]
impl<SR: StateReader> SimulationEngine<SR> {
    pub fn new(
        rpc_state_reader: Arc<SR>,
        contract_overrides: Option<Vec<ContractOverride>>,
    ) -> Result<Self, SimulationError> {
        // Prepare initial values
        let mut address_to_class_hash: HashMap<Address, ClassHash> = HashMap::new();
        let mut class_hash_to_compiled_class: HashMap<ClassHash, CompiledClass> = HashMap::new();
        let mut address_to_nonce: HashMap<Address, Felt252> = HashMap::new();
        let storage_updates: HashMap<StorageEntry, Felt252> = HashMap::new();

        let mut class_hash_to_compiled_class_hash: HashMap<ClassHash, CompiledClassHash> =
            HashMap::new();

        // Load contracts
        for input_contract in contract_overrides
            .clone()
            .unwrap_or_default()
            .iter()
        {
            let class_hash = input_contract.class_hash;
            let compiled_class_hash;
            let compiled_class;
            if let Some(path) = input_contract.path.clone() {
                // Load contract from path
                compiled_class = load_compiled_class_from_path(&path).map_err(|e| {
                    SimulationError::InitError(format!(
                        "Failed to load contract from path: {:?} with error: {:?}",
                        path, e
                    ))
                })?;
                // Compute compiled class hash
                compiled_class_hash =
                    felt_to_hash(&compute_class_hash(&compiled_class).map_err(|e| {
                        SimulationError::InitError(format!(
                            "Failed to compute class hash for contract: {:?} with error: {:?}",
                            path, e
                        ))
                    })?);
            } else {
                // Load contract from rpc
                compiled_class = rpc_state_reader
                    .get_contract_class(&class_hash)
                    .map_err(|err| {
                        SimulationError::InitError(format!(
                            "Could not fetch compiled class: {}",
                            err
                        ))
                    })?;
                compiled_class_hash = rpc_state_reader
                    .get_compiled_class_hash(&class_hash)
                    .map_err(|err| {
                        SimulationError::InitError(format!(
                            "Could not fetch compiled class hash: {}",
                            err
                        ))
                    })?;
            }
            // Update caches
            address_to_class_hash.insert(input_contract.contract_address.clone(), class_hash);
            class_hash_to_compiled_class.insert(compiled_class_hash, compiled_class.clone());
            address_to_nonce.insert(input_contract.contract_address.clone(), Felt252::from(0u8));

            class_hash_to_compiled_class_hash.insert(class_hash, compiled_class_hash);
        }

        info!(
            "Initialising SimulationEngine with {} contracts",
            class_hash_to_compiled_class_hash.len()
        );

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

        Ok(Self { state, contract_overrides: contract_overrides.unwrap_or_default() })
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

    /// Interpret the result of a simulated execution.
    ///
    /// Transforms the raw outcome of a simulated execution into a `SimulationResult`.
    ///
    /// # Arguments
    ///
    /// * `result` - An instance of the `ExecutionResult` struct, containing the result data from a
    ///   simulated execution.
    /// * `state_cache` - A `StateCache` giving the state's cache after simulation.
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
        let result = call_info.retdata.clone();

        debug!("Simulation successful: {:#?} {:#?}", result, gas_used);

        // Collect state changes
        let all_writes = self.state.cache().storage_writes();
        let simultation_write_keys = call_info.get_visited_storage_entries();
        let state_updates: HashMap<Address, HashMap<[u8; 32], Felt252>> = all_writes
            .iter()
            .filter(|(key, _)| simultation_write_keys.contains(key)) // filter for those applied during simulation
            .map(|((addr, hash), value)| (addr.clone(), (*hash, value.clone()))) // map to our Override struct format
            .fold(HashMap::new(), |mut acc, (addr, (hash, value))| {
                acc.entry(addr)
                    .or_default()
                    .insert(hash, value);
                acc
            });

        Ok(SimulationResult { result, state_updates, gas_used })
    }

    /// Clear the cache of the simulation engine.
    ///
    /// This is useful when the state of the RPC reader has changed and the cache is no longer
    /// valid. For example if the StateReader was set to a concrete block and a new block was
    /// added to the chain.
    ///
    /// Note: This function does not clean up the contract cache. This is not necessary as it
    /// contains immutable contract code.
    pub fn clear_cache(&mut self, rpc_state_reader: Arc<SR>) {
        // We keep contracts code in the cache.
        let contract_cache: HashMap<ClassHash, CompiledClass> =
            self.state.contract_classes().clone();
        // We initiate the class_hash_initial_values from permanent contract overrides
        // Also we persist compiled_class_hash_initial_values and compiled_class_hash_writes,
        // because they can't change.
        let cache = StateCache::new(
            self.contract_overrides
                .iter()
                .map(|contract_override| {
                    (
                        contract_override
                            .contract_address
                            .clone(),
                        contract_override.class_hash,
                    )
                })
                .collect(),
            self.state
                .cache_mut()
                .compiled_class_hash_initial_values_mut()
                .clone(),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            self.state
                .cache_mut()
                .compiled_class_hash_writes_mut()
                .clone(),
            HashMap::new(),
            HashMap::new(),
            self.state
                .cache_mut()
                .class_hash_to_compiled_class_hash_mut()
                .clone(),
        );
        self.state = CachedState::new_for_testing(rpc_state_reader, cache, contract_cache);
    }

    /// Clears storage and nonce writes from the cache of the simulation engine.
    ///
    /// This should be called after every simulation to reset the contract writes applied during
    /// simulation. This will not reset the entirety of the contract's cache, so all data retrieved
    /// from the rpc persists.
    pub fn clear_cache_writes(&mut self) {
        let cache = self.state.cache_mut();
        cache.storage_writes_mut().clear();
        cache.nonce_writes_mut().clear();
    }
}

/// The rest of the functions are implemented over the concrete [RpcStateReader],
/// because we need to have info about the block the StateReader is reading, which means what block
/// the data in the CachedState is valid for.
impl SimulationEngine<RpcStateReader> {
    /// Clear the cache and create a new RpcStateReader with the given block if and only if the
    /// given block is different from the block in the RpcStateReader.
    fn set_block_and_reset_cache(&mut self, new_block: BlockValue) {
        if self.state.state_reader.block() != &new_block {
            let new_state_reader = self
                .state
                .state_reader
                .with_updated_block(new_block);
            self.clear_cache(new_state_reader.into());
        }
    }

    /// Simulate a transaction
    ///
    /// State's block will be modified to be the last block before the simulation's block.
    pub fn simulate(
        &mut self,
        params: &SimulationParameters,
    ) -> Result<SimulationResult, SimulationError> {
        // Reset cache if the internal block is different from the block in params
        let block_value = BlockValue::Number(BlockNumber(params.block_number));
        self.set_block_and_reset_cache(block_value);

        // Apply overrides
        if let Some(overrides) = &params.overrides {
            for (address, storage_update) in overrides {
                for (slot, value) in storage_update {
                    let storage_entry = ((*address).clone(), *slot);
                    self.state
                        .set_storage_at(&storage_entry, (*value).clone());
                }
            }
        }

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
            params.gas_limit.unwrap_or(u128::MAX),
        );

        debug!("Starting simulation with tx parameters: {:#?} {:#?}", call, block_value);

        // Set up the call context
        let block_context = BlockContext::default();
        let mut resources_manager = ExecutionResourcesManager::default();
        let mut tx_execution_context = TransactionExecutionContext::default();

        // Execute the simulated call
        let execution_result = call
            .execute(
                &mut self.state,
                &block_context,
                &mut resources_manager,
                &mut tx_execution_context,
                false,
                block_context.invoke_tx_max_n_steps(),
            )
            .map_err(|err| SimulationError::TransactionError(err.to_string()))?;

        // Interpret and return the results
        let simulation_result = self.interpret_result(execution_result);

        // Clear simulation writes from cache
        self.clear_cache_writes();

        simulation_result
    }
}

#[cfg(test)]
pub mod tests {
    use std::{collections::HashSet, env};

    use crate::starknet_simulation::{
        address_str, class_hash_str, felt_str, rpc_reader::tests::setup_reader,
    };

    use super::*;
    use rpc_state_reader::rpc_state::RpcChain;
    use rstest::rstest;
    use starknet_in_rust::{
        core::errors::state_errors::StateError, execution::CallInfo,
        state::cached_state::ContractClassCache,
    };

    #[test]
    fn test_address_str_with_prefix() {
        let input = "3658190653781265738165783961758321";

        let expected_felt = Felt252::from(3658190653781265738165783961758321u128);
        let expected = Address(expected_felt);
        let result = address_str(input);

        assert_eq!(result, expected);
    }

    fn setup_engine(
        block_number: u64,
        rpc_chain: RpcChain,
        contract_overrides: Option<Vec<ContractOverride>>,
    ) -> SimulationEngine<RpcStateReader> {
        let rpc_state_reader = Arc::new(setup_reader(block_number, rpc_chain));

        // Initialize the engine
        SimulationEngine::new(rpc_state_reader, contract_overrides)
            .expect("should initialize engine")
    }

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
            Ok(Felt252::from(1))
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
        let input_contract = ContractOverride::new(address, [0u8; 32], Some(path_str));
        let rpc_state_reader = Arc::new(StateReaderMock::new());
        let engine_result = SimulationEngine::new(rpc_state_reader, vec![input_contract].into());
        if let Err(err) = engine_result {
            panic!("Failed to create engine with error: {:?}", err);
        }
        assert!(engine_result.is_ok());
    }

    #[rstest]
    #[cfg_attr(not(feature = "network_tests"), ignore)]
    fn test_create_engine_with_contract_without_path() {
        // USDC token contract
        let address =
            address_str("0x053c91253bc9682c04929ca02ed00b3e423f6710d2ee7e0d5ebb06f3ecf368a8");
        let class_hash: ClassHash =
            hex::decode("052c7ba99c77fc38dd3346beea6c0753c3471f2e3135af5bb837d6c9523fff62")
                .unwrap()
                .as_slice()
                .try_into()
                .unwrap();
        let input_contract = ContractOverride::new(address, class_hash, None);

        // Create engine
        let rpc_state_reader = setup_reader(333333, RpcChain::MainNet);
        let engine_result =
            SimulationEngine::new(Arc::new(rpc_state_reader), vec![input_contract].into());
        if let Err(err) = engine_result {
            panic!("Failed to create engine with error: {:?}", err);
        }

        assert!(engine_result.is_ok());
    }

    #[test]
    fn test_set_state() {
        let mut engine = SimulationEngine {
            state: CachedState::new(
                Arc::new(StateReaderMock::new()),
                ContractClassCache::default(),
            ),
            contract_overrides: vec![],
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

    #[rstest]
    fn test_clear_cache_writes() {
        let rpc_state_reader = Arc::new(StateReaderMock::new());
        let mut engine = SimulationEngine::new(rpc_state_reader.clone(), None).unwrap();
        let address = Address(Felt252::from(0u8));
        let write_hash = [0u8; 32];
        let value: Felt252 = 0.into();

        // Add a cache write
        engine
            .state
            .set_storage_at(&(address.clone(), write_hash), value);
        // Add a nonce write
        engine
            .state
            .increment_nonce(&address)
            .ok();

        // Check writes exist
        let cache = engine.state.cache_mut();
        assert!(!cache.storage_writes().is_empty());
        assert!(!cache.nonce_writes_mut().is_empty());

        // Clear writes
        engine.clear_cache_writes();

        // Check writes are empty
        let final_cache = engine.state.cache_mut();
        assert!(final_cache.storage_writes().is_empty());
        assert!(final_cache
            .nonce_writes_mut()
            .is_empty())
    }

    #[rstest]
    fn test_interpret_results() {
        let address = Address(Felt252::from(0u8));
        let rpc_state_reader = Arc::new(StateReaderMock::new());
        let mut engine = SimulationEngine::new(rpc_state_reader.clone(), None).unwrap();

        // Construct expected values
        let gas_consumed = 10;
        let retdata: Vec<Felt252> = vec![1, 2, 3]
            .into_iter()
            .map(Felt252::from)
            .collect();
        let mut state_updates = HashMap::new();
        let mut storage_write: HashMap<[u8; 32], Felt252> = HashMap::new();
        let write_hash = [0u8; 32];
        let value: Felt252 = 0.into();
        storage_write.insert(write_hash, value.clone());
        state_updates.insert(address.clone(), storage_write);

        // Apply overrides (state changes that mustn't appear in the result)
        let override_hash = [1u8; 32];
        engine
            .state
            .set_storage_at(&(address.clone(), override_hash), value.clone());
        // Apply mock simulation write (state change that must appear in the result)
        engine
            .state
            .set_storage_at(&(address.clone(), write_hash), value);

        // Construct execution result
        let mut call_info =
            CallInfo::empty_constructor_call(address.clone(), address.clone(), None);
        call_info.gas_consumed = gas_consumed;
        call_info.retdata = retdata.clone();
        // Flag relevant storage slots as updated during simulation
        call_info.accessed_storage_keys = HashSet::new();
        call_info
            .accessed_storage_keys
            .insert(write_hash);
        let execution_result =
            ExecutionResult { call_info: Some(call_info), revert_error: None, n_reverted_steps: 0 };

        // Call interpret_result
        let result = engine
            .interpret_result(execution_result)
            .unwrap();

        assert_eq!(result.gas_used, gas_consumed);
        assert_eq!(result.result, retdata);
        assert_eq!(result.state_updates, state_updates);
    }

    #[rstest]
    fn test_interpret_results_with_revert_error() {
        // Construct state and engine
        let rpc_state_reader = Arc::new(StateReaderMock::new());
        let engine = SimulationEngine::new(rpc_state_reader.clone(), None).unwrap();

        // Construct reverted execution result
        let execution_result_with_revert = ExecutionResult {
            call_info: None,
            revert_error: Some("Test Revert".to_string()),
            n_reverted_steps: 0,
        };

        match engine.interpret_result(execution_result_with_revert) {
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
        let engine = SimulationEngine::new(rpc_state_reader.clone(), None).unwrap();

        // Construct execution result with no call info
        let execution_result_no_call_info =
            ExecutionResult { call_info: None, revert_error: None, n_reverted_steps: 0 };

        match engine.interpret_result(execution_result_no_call_info) {
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
        let engine = SimulationEngine::new(rpc_state_reader.clone(), None).unwrap();

        // Construct execution result with failed call
        let mut call_info =
            CallInfo::empty_constructor_call(address.clone(), address.clone(), None);
        call_info.failure_flag = true;
        let execution_result_fail_flag =
            ExecutionResult { call_info: Some(call_info), revert_error: None, n_reverted_steps: 0 };

        match engine.interpret_result(execution_result_fail_flag) {
            Err(SimulationError::ResultError(message)) => {
                assert_eq!(message, "Execution failed");
            }
            _ => panic!("Expected ResultError for failed call"),
        }
    }

    #[rstest]
    #[cfg_attr(not(feature = "network_tests"), ignore)]
    fn test_simulate_cairo0_call() {
        // https://starkscan.co/tx/0x046e50c398bf08a69c7bbf1dedc35760556ba7c426a704d1ecb67378f01ffe59

        // Set up the engine
        let block_number = 366118; // actual block is 366119
        let mut engine = setup_engine(block_number, RpcChain::MainNet, None);

        // Prepare the simulation parameters
        let params = SimulationParameters::new(
            address_str("0x035fc5a31b2cf06af3a7e9b9b00a508b72dea342277c7415b770fbd69a6c5933"),
            address_str("0x022b05f9396d2c48183f6deaf138a57522bcc8b35b67dee919f76403d1783136"),
            vec![
                felt_str("0x10884171baf1914edc28d7afb619b40a4051cfae78a094a55d230f19e944a28"), /* Felt252 */
                felt_str("62399604864"), // The lower bits of Uint256
                felt_str("0"),           // The upper bits of Uint256
            ],
            "approve".to_owned(),
            None,
            Some(u128::MAX),
            block_number,
        );

        // Simulate the transaction
        let result = engine
            .simulate(&params)
            .expect("should simulate");

        let expected_result = SimulationResult::new(
            vec![felt_str("1")],
            vec![(
                address_str(
                    "980641348758169158361564622616439166824113829417782360965256920656439161142",
                ),
                vec![
                    (
                        class_hash_str(
                            "0x04ec12998482b49cff9925cf695c114762a27c32bcd1afe898073bdab6f0d307",
                        ),
                        felt_str("0"),
                    ),
                    (
                        class_hash_str(
                            "0x04ec12998482b49cff9925cf695c114762a27c32bcd1afe898073bdab6f0d306",
                        ),
                        felt_str("62399604864"),
                    ),
                ]
                .into_iter()
                .collect(),
            )]
            .into_iter()
            .collect(),
            0,
        );
        assert_eq!(result, expected_result);
    }

    #[rstest]
    #[cfg_attr(not(feature = "network_tests"), ignore)]
    fn test_simulate_cairo1_call() {
        // https://starkscan.co/tx/0x008f1f8ee931f40aa5ef9111e0836d68d8d1cf07801c0d17750d66937f02fb54

        // Set up the engine
        let block_number = 368719; // actual tx block is 368720
        let mut engine = setup_engine(block_number, RpcChain::MainNet, None);

        // Prepare the simulation parameters
        let params = SimulationParameters::new(
            address_str("0x04eb4dcf306e28e13e6361bca368056d4bfd3051ee96fe6b7207662fbcaf3d2d"),
            address_str("0x07d14dfd8ee95b41fce179170d88ba1f0d5a512e13aeb232f19cfeec0a88f8bf"),
            vec![
                felt_str("602131441545"),
                felt_str("1698855348"),
                felt_str("28263441981469284"),
                felt_str("841052542115774484"),
                felt_str(
                    "3254871180842845207740459874836292658857302757892203765805208854602709573266",
                ),
                felt_str(
                    "3507176392343394624391389069340504903187207915538258427726787963729562556344",
                ),
            ],
            "write_confirmation".to_owned(),
            None,
            Some(u128::MAX),
            block_number,
        );

        // Simulate the transaction
        let result = engine.simulate(&params);

        // Check the result
        if let Err(err) = result {
            panic!("Failed to simulate transaction with error: {:?}", err);
        }
        assert!(result.is_ok());
        dbg!("Simulation result is: {:?}", result.unwrap());
    }

    #[rstest]
    fn test_set_block_and_reset_cache() {
        let contract_override_address =
            address_str("0xda114221cb83fa859dbdb4c44beeaa0bb37c7537ad5ae66fe5e0efd20e6eb3");

        // Set up the engine
        let block_number = 354498;
        let contract_overrides = vec![ContractOverride::new(
            contract_override_address.clone(),
            class_hash_str(
                "0x052c7ba99c77fc38dd3346beea6c0753c3471f2e3135af5bb837d6c9523fff62", /* Needs to be an actuall class hash to work with state reader */
            ),
            None,
        )];
        let mut engine = setup_engine(block_number, RpcChain::MainNet, contract_overrides.into());

        // Set state storage inital value
        engine
            .state
            .cache_mut()
            .storage_initial_values_mut()
            .extend(vec![(
                (contract_override_address.clone(), class_hash_str("0123")),
                felt_str("0123"),
            )]);
        // Set state storage writes
        engine
            .state
            .cache_mut()
            .storage_writes_mut()
            .extend(vec![(
                (contract_override_address.clone(), class_hash_str("456")),
                felt_str("456"),
            )]);

        assert_eq!(engine.state.state_reader.block(), &BlockNumber(block_number).into());

        // Set the block to a different block
        let new_block_number = 354499;
        engine.set_block_and_reset_cache(BlockNumber(new_block_number).into());

        assert_eq!(engine.state.state_reader.block(), &BlockNumber(new_block_number).into());
        assert_eq!(
            felt_str("0"),
            engine
                .state
                .get_storage_at(&(contract_override_address.clone(), class_hash_str("0123")))
                .unwrap()
        );
        assert_eq!(
            felt_str("0"),
            engine
                .state
                .get_storage_at(&(contract_override_address.clone(), class_hash_str("456")))
                .unwrap()
        );
    }

    #[rstest]
    fn test_clear_cache() {
        // Set up the engine
        let rpc_state_reader = Arc::new(StateReaderMock::new());
        let mut engine = SimulationEngine::new(rpc_state_reader.clone(), None).unwrap();

        // Insert contracts in cache
        let mut contract_classes = HashMap::new();
        let contract_hash: [u8; 32] = [1; 32];

        let cargo_manifest_path = Path::new(env!("CARGO_MANIFEST_DIR"));
        let path = cargo_manifest_path.join("tests/resources/fibonacci.json");
        let compiled_class = load_compiled_class_from_path(path).unwrap();
        contract_classes.insert(contract_hash, compiled_class.clone());

        engine
            .state
            .set_contract_classes(contract_classes)
            .unwrap();

        // Clear cache
        engine.clear_cache(rpc_state_reader.clone());

        // Assert that we still have contracts cached
        let contract_cache = engine.state.contract_classes();
        let cached_contract = contract_cache
            .get(&contract_hash)
            .unwrap()
            .clone();

        assert_eq!(cached_contract, compiled_class);
    }
}
