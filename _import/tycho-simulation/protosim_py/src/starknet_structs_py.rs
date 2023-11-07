use std::collections::{hash_map::Entry, HashMap};

use num_bigint::BigUint;
use pyo3::{exceptions::PyRuntimeError, prelude::*};

use protosim::{
    starknet_in_rust::{felt::Felt252, utils::Address},
    starknet_simulation::{
        address_str, class_hash_str,
        simulation::{
            ContractOverride as RustContractOverride, Overrides, SimulationError,
            SimulationParameters, SimulationResult, StorageHash,
        },
    },
};

pub fn python_overrides_to_rust(
    input: HashMap<(String, BigUint), BigUint>,
) -> HashMap<Address, Overrides> {
    input
        .into_iter()
        .fold(HashMap::new(), |mut acc, ((address, slot), value)| {
            let address = address_str(&address).expect("should be valid address");
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
    input: HashMap<Address, HashMap<StorageHash, Felt252>>,
) -> HashMap<String, HashMap<BigUint, BigUint>> {
    input
        .into_iter()
        .fold(HashMap::new(), |mut result, (address, inner_map)| {
            let inner_result =
                inner_map
                    .into_iter()
                    .fold(HashMap::new(), |mut inner_result, (slot, value)| {
                        inner_result.insert(BigUint::from_bytes_be(&slot), value.to_biguint());
                        inner_result
                    });
            result.insert(address.0.to_str_radix(16), inner_result);
            result
        })
}

/// Parameters for Starknet transaction simulation.
#[derive(Clone, Debug)]
#[pyclass]
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

#[pymethods]
impl StarknetSimulationParameters {
    #[new]
    pub fn new(
        caller: String,
        to: String,
        data: Vec<BigUint>,
        entry_point: String,
        block_number: u64,
        overrides: Option<HashMap<(String, BigUint), BigUint>>,
        gas_limit: Option<u128>,
    ) -> Self {
        Self { caller, to, data, entry_point, overrides, gas_limit, block_number }
    }
}

impl From<StarknetSimulationParameters> for SimulationParameters {
    fn from(value: StarknetSimulationParameters) -> Self {
        Self {
            caller: address_str(&value.caller).expect("should be valid address"),
            to: address_str(&value.to).expect("should be valid address"),
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
    pub states_updates: HashMap<String, HashMap<BigUint, BigUint>>,
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
pub struct StarknetContractOverride {
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
}

#[pymethods]
impl StarknetContractOverride {
    #[new]
    pub fn new(address: String, class_hash: String, path: Option<String>) -> Self {
        Self { address, class_hash, path }
    }
}

impl From<StarknetContractOverride> for RustContractOverride {
    fn from(contract_override: StarknetContractOverride) -> Self {
        let StarknetContractOverride { address, class_hash, path } = contract_override;

        RustContractOverride::new(
            address_str(&address).expect("should be valid address"),
            class_hash_str(&class_hash).expect("should be valid class hash"),
            path,
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
        StarknetSimulationErrorDetails { reason: err.to_string() }
    }
}
