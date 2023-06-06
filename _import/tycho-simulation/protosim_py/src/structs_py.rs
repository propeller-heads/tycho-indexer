use ethers::types::{Address, Bytes, H256, U256};
use num_bigint::BigUint;
use pyo3;
use pyo3::{exceptions::PyRuntimeError, prelude::*};
use revm::primitives::{Bytecode, B256, U256 as rU256};

use std::{collections::HashMap, str::FromStr};

use protosim::evm_simulation::{account_storage, simulation};
use std::fmt::Debug;

/// Data needed to invoke a transaction simulation
#[pyclass]
#[derive(Clone, Debug)]
pub struct SimulationParameters {
    /// Address of the sending account
    pub caller: String,
    /// Address of the receiving account/contract
    pub to: String,
    /// Calldata
    pub data: Vec<u8>,
    /// Amount of native token sent
    pub value: BigUint,
    /// EVM state overrides.
    /// Will be merged with existing state. Will take effect only for current simulation.
    pub overrides: Option<HashMap<String, HashMap<BigUint, BigUint>>>,
    /// Limit of gas to be used by the transaction
    pub gas_limit: Option<u64>,
}

#[pymethods]
impl SimulationParameters {
    #[new]
    fn new(
        caller: String,
        to: String,
        data: Vec<u8>,
        value: BigUint,
        overrides: Option<HashMap<String, HashMap<BigUint, BigUint>>>,
        gas_limit: Option<u64>,
    ) -> Self {
        Self {
            caller,
            to,
            data,
            value,
            overrides,
            gas_limit,
        }
    }
}

impl From<SimulationParameters> for simulation::SimulationParameters {
    fn from(params: SimulationParameters) -> Self {
        let overrides = match params.overrides {
            Some(py_overrides) => {
                let mut rust_overrides: HashMap<Address, HashMap<U256, U256>> = HashMap::new();
                for (address, py_slots) in py_overrides {
                    let mut rust_slots: HashMap<U256, U256> = HashMap::new();
                    for (index, value) in py_slots {
                        rust_slots.insert(
                            U256::from_big_endian(index.to_bytes_be().as_slice()),
                            U256::from_big_endian(value.to_bytes_be().as_slice()),
                        );
                    }
                    rust_overrides.insert(
                        Address::from_str(address.as_str()).expect("Wrong address format"),
                        rust_slots,
                    );
                }
                Some(rust_overrides)
            }
            None => None,
        };
        simulation::SimulationParameters {
            caller: Address::from_str(params.caller.as_str()).unwrap(),
            to: Address::from_str(params.to.as_str()).unwrap(),
            data: Bytes::from(params.data),
            value: U256::from_big_endian(params.value.to_bytes_be().as_slice()),
            overrides,
            gas_limit: params.gas_limit,
        }
    }
}

#[pyclass]
#[derive(Clone, Debug)]
pub struct StateUpdate {
    #[pyo3(get)]
    pub storage: Option<HashMap<BigUint, BigUint>>,
    #[pyo3(get)]
    pub balance: Option<BigUint>,
}

#[pymethods]
impl StateUpdate {
    #[new]
    #[pyo3(signature = (storage=None, balance=None))]
    fn new(storage: Option<HashMap<BigUint, BigUint>>, balance: Option<BigUint>) -> Self {
        Self { storage, balance }
    }
}

impl From<account_storage::StateUpdate> for StateUpdate {
    fn from(state_update: account_storage::StateUpdate) -> Self {
        let mut py_storage = HashMap::new();
        if let Some(rust_storage) = state_update.storage {
            for (key, val) in rust_storage {
                py_storage.insert(
                    BigUint::from_bytes_le(key.as_le_slice()),
                    BigUint::from_bytes_le(val.as_le_slice()),
                );
            }
        }

        let mut py_balances = None;
        if let Some(rust_balances) = state_update.balance {
            py_balances = Some(BigUint::from_bytes_le(rust_balances.as_le_slice()))
        }

        StateUpdate {
            storage: Some(py_storage),
            balance: py_balances,
        }
    }
}

impl From<StateUpdate> for account_storage::StateUpdate {
    fn from(py_state_update: StateUpdate) -> Self {
        let mut rust_storage = HashMap::new();
        if let Some(py_storage) = py_state_update.storage {
            for (key, val) in py_storage {
                rust_storage.insert(
                    rU256::from_limbs_slice(key.to_u64_digits().as_slice()),
                    rU256::from_limbs_slice(val.to_u64_digits().as_slice()),
                );
            }
        }

        let mut rust_balance = None;
        if let Some(py_balance) = py_state_update.balance {
            rust_balance = Some(rU256::from_limbs_slice(
                py_balance.to_u64_digits().as_slice(),
            ));
        }

        account_storage::StateUpdate {
            storage: Some(rust_storage),
            balance: rust_balance,
        }
    }
}

#[pyclass]
#[derive(Clone)]
pub struct PySimulationResult {
    /// Output of transaction execution as bytes
    #[pyo3(get)]
    pub result: Vec<u8>,
    /// State changes caused by the transaction
    #[pyo3(get)]
    pub state_updates: HashMap<String, StateUpdate>,
    /// Gas used by the transaction (already reduced by the refunded gas)
    #[pyo3(get)]
    pub gas_used: u64,
}

impl From<simulation::SimulationResult> for PySimulationResult {
    fn from(rust_result: simulation::SimulationResult) -> Self {
        let mut py_state_updates = HashMap::new();
        for (key, val) in rust_result.state_updates {
            py_state_updates.insert(
                Address::from(&key.to_fixed_bytes()).to_string(),
                StateUpdate::from(val),
            );
        }
        PySimulationResult {
            result: rust_result
                .result
                .try_into()
                .expect("Can't convert output bytes to a Python-compatible type"),
            state_updates: py_state_updates,
            gas_used: rust_result.gas_used,
        }
    }
}

#[pyclass]
#[derive(Clone)]
pub struct AccountInfo {
    /// Account balance.
    #[pyo3(get, set)]
    pub balance: BigUint,
    /// Account nonce.
    #[pyo3(get, set)]
    pub nonce: u64,
    /// code hash,
    #[pyo3(get, set)]
    pub code_hash: String,
    /// code: if None, `code_by_hash` will be used to fetch it if code needs to be loaded from
    /// inside of revm.
    #[pyo3(get, set)]
    pub code: Option<Vec<u8>>,
}

#[pymethods]
impl AccountInfo {
    #[new]
    #[pyo3(signature = (balance, nonce, code_hash, code=None))]
    fn new(balance: BigUint, nonce: u64, code_hash: String, code: Option<Vec<u8>>) -> Self {
        Self {
            balance,
            nonce,
            code_hash,
            code,
        }
    }
}

impl From<AccountInfo> for revm::primitives::AccountInfo {
    fn from(py_info: AccountInfo) -> Self {
        let mut code = None;
        if let Some(c) = py_info.code {
            code = Some(Bytecode::new_raw(Bytes::from(c).0));
        }

        revm::primitives::AccountInfo {
            balance: rU256::from_limbs_slice(py_info.balance.to_u64_digits().as_slice()),
            nonce: py_info.nonce,
            code_hash: B256::from_str(&py_info.code_hash).unwrap(),
            code,
        }
    }
}

#[pyclass]
#[derive(Clone)]
pub struct BlockHeader {
    number: u64,
    hash: String,
    timestamp: u64,
}

#[pymethods]
impl BlockHeader {
    #[new]
    #[pyo3(signature = (number, hash, timestamp))]
    fn new(number: u64, hash: String, timestamp: u64) -> Self {
        Self {
            number,
            hash,
            timestamp,
        }
    }
}

impl From<BlockHeader> for protosim::evm_simulation::database::BlockHeader {
    fn from(py_header: BlockHeader) -> Self {
        protosim::evm_simulation::database::BlockHeader {
            number: py_header.number,
            hash: H256::from_str(&py_header.hash).unwrap(),
            timestamp: py_header.timestamp,
        }
    }
}

#[pyclass]
pub(crate) struct PySimulationError(simulation::SimulationError);

impl From<PySimulationError> for PyErr {
    fn from(err: PySimulationError) -> PyErr {
        PyRuntimeError::new_err(format!("{:?}", err.0))
    }
}

impl From<simulation::SimulationError> for PySimulationError {
    fn from(err: simulation::SimulationError) -> Self {
        Self(err)
    }
}
