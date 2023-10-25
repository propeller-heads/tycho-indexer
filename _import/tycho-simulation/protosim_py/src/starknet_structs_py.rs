use std::collections::HashMap;

use num_bigint::BigUint;
use pyo3::prelude::*;

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
    pub overrides: Option<HashMap<String, HashMap<BigUint, BigUint>>>,
    /// Limit of gas to be used by the transaction
    #[pyo3(get)]
    pub gas_limit: Option<u128>,
    /// The block number to be used by the transaction. This is independent of the states block.
    #[pyo3(get)]
    pub block_number: u64,
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

/// Contract override for simulation engine.
///
/// For example to override an ERC20 contract to a standardized implementation.
#[pyclass]
#[derive(Clone, Debug)]
pub struct ContractOverride {
    /// Address of the contract to override
    #[pyo3(get)]
    pub address: String,
    /// Class hash of the overriden contract code
    #[pyo3(get)]
    pub class_hash: String,
    /// Path to contract source code
    ///
    /// Supports .casm (Cairo 0) and .json () files.
    #[pyo3(get)]
    pub path: Option<String>,
    /// Storage overrides for the contract
    #[pyo3(get)]
    pub storage_overrides: Option<HashMap<BigUint, BigUint>>,
}
