use std::collections::{hash_map::Entry, HashMap};

use num_bigint::BigUint;
use pyo3::{exceptions::PyRuntimeError, prelude::*};

use protosim::{
    num_traits::Num,
    starknet_in_rust::{
        felt::Felt252,
        state::state_cache::StorageEntry,
        utils::{string_to_hash, Address},
    },
    starknet_simulation::simulation::{
        ContractOverride as RustContractOverride, Overrides, SimulationError, SimulationParameters,
        SimulationResult,
    },
};

pub fn string_to_address(address: &str) -> Address {
    Address(Felt252::from_str_radix(address, 16).expect("hex address"))
}

pub fn python_overrides_to_rust(
    input: HashMap<(String, BigUint), BigUint>,
) -> HashMap<Address, Overrides> {
    input
        .into_iter()
        .fold(HashMap::new(), |mut acc, ((address, slot), value)| {
            let address = string_to_address(&address);
            let slot = Felt252::from(slot).to_be_bytes();
            let value = Felt252::from(value);
            match acc.entry(address) {
                Entry::Occupied(mut entry) => {
                    entry.get_mut().insert(slot, value);
                }
                Entry::Vacant(entry) => {
                    let mut new_map = HashMap::new();
                    new_map.insert(slot, value);
                    entry.insert(new_map);
                }
            }
            acc
        })
}

pub fn rust_overrides_to_python(
    input: HashMap<Address, Overrides>,
) -> HashMap<(String, BigUint), BigUint> {
    input
        .into_iter()
        .fold(HashMap::new(), |mut acc, (address, overrides)| {
            overrides
                .into_iter()
                .for_each(|(slot, value)| {
                    acc.insert(
                        (address.0.to_str_radix(16), Felt252::from_bytes_be(&slot).to_biguint()),
                        value.to_biguint(),
                    );
                });
            acc
        })
}

/// Parameters for Starknet transaction simulation.
#[pyclass]
#[derive(Clone, Debug)]
pub struct StarknetSimulationParameters {
    /// Address of the sending account
    #[pyo3(get)]
    pub caller: String,
    /// Address of the receiving account/contract
    #[pyo3(get)]
    pub to: String,
    /// Calldata
    #[pyo3(get)]
    pub data: Vec<BigUint>,
    /// The contract function/entry point to call e.g. "transfer"
    pub entry_point: String,
    #[pyo3(get)]
    /// Starknet state overrides.
    /// Will be merged with the existing state. Will take effect only for current simulation.
    /// Must be given as a contract address to its variable override map.
    pub overrides: Option<HashMap<(String, BigUint), BigUint>>,
    /// Limit of gas to be used by the transaction
    #[pyo3(get)]
    pub gas_limit: Option<u128>,
    /// The block number to be used by the transaction. This is independent of the states block.
    #[pyo3(get)]
    pub block_number: u64,
}

impl From<StarknetSimulationParameters> for SimulationParameters {
    fn from(value: StarknetSimulationParameters) -> Self {
        Self {
            caller: string_to_address(&value.caller),
            to: string_to_address(&value.to),
            data: value
                .data
                .into_iter()
                .map(Felt252::from)
                .collect(),
            entry_point: value.entry_point,
            overrides: value
                .overrides
                .map(python_overrides_to_rust),
            gas_limit: value.gas_limit,
            block_number: value.block_number,
        }
    }
}

/// Starknet transaction simulation result.
#[pyclass]
#[derive(Clone, Debug)]
pub struct StarknetSimulationResult {
    /// Output of transaction execution
    #[pyo3(get)]
    pub result: Vec<BigUint>,
    /// State changes caused by the transaction
    #[pyo3(get)]
    pub states_updates: HashMap<(String, BigUint), BigUint>,
    /// Gas used by the transaction (already reduced by the refunded gas)
    #[pyo3(get)]
    pub gas_used: u128,
}

impl From<SimulationResult> for StarknetSimulationResult {
    fn from(value: SimulationResult) -> Self {
        Self {
            result: value
                .result
                .into_iter()
                .map(|felt| felt.to_biguint())
                .collect(),
            states_updates: rust_overrides_to_python(value.state_updates),
            gas_used: value.gas_used,
        }
    }
}

/// Contract override for simulation engine.
///
/// For example to override an ERC20 contract to a standardized implementation.
#[pyclass]
#[derive(Clone, Debug)]
pub struct ContractOverride {
    /// Address of the contract to override represented as a hexadecimal string.
    #[pyo3(get)]
    pub address: String,
    /// Class hash of the overriden contract code represented as a hexadecimal string.
    #[pyo3(get)]
    pub class_hash: String,
    /// Path to contract source code
    ///
    /// Supports .casm (Cairo 0) and .json () files.
    #[pyo3(get)]
    pub path: Option<String>,
    /// Storage overrides for the contract
    ///
    /// Mapping of tuple (contract address, storage slot) to storage value.
    #[pyo3(get)]
    pub storage_overrides: Option<HashMap<(String, BigUint), BigUint>>,
}

impl From<ContractOverride> for RustContractOverride {
    fn from(contract_override: ContractOverride) -> Self {
        let ContractOverride { address, class_hash, path, storage_overrides } = contract_override;

        // Convert storage overrides to format
        let storage_overrides: Option<HashMap<StorageEntry, Felt252>> =
            storage_overrides.map(|storages| {
                storages
                    .into_iter()
                    .map(|((address, slot), value)| {
                        (
                            (string_to_address(&address), Felt252::from(slot).to_be_bytes()),
                            Felt252::from(value),
                        )
                    })
                    .collect()
            });
        RustContractOverride::new(
            string_to_address(&address),
            string_to_hash(&class_hash),
            path,
            storage_overrides,
        )
    }
}

/// Details of a Starknet simulation error.
#[pyclass]
#[derive(Debug)]
pub(crate) struct StarknetSimulationErrorDetails {
    #[pyo3(get)]
    pub reason: String,
}

#[pymethods]
impl StarknetSimulationErrorDetails {
    fn __repr__(&self) -> String {
        format!("SimulationError(reason={})", self.reason)
    }
}

impl From<StarknetSimulationErrorDetails> for PyErr {
    fn from(err: StarknetSimulationErrorDetails) -> PyErr {
        PyRuntimeError::new_err(err)
    }
}

// This indirection is needed cause SimulationError
//  is defined in an external create
impl From<SimulationError> for StarknetSimulationErrorDetails {
    fn from(err: SimulationError) -> Self {
        match err {
            SimulationError::InitError(reason) |
            SimulationError::AlreadyInitialized(reason) |
            SimulationError::OverrideError(reason) => StarknetSimulationErrorDetails { reason },
        }
    }
}
