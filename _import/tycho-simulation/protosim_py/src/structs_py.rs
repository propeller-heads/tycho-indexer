use ethers::{
    providers::{Http, Provider},
    types::{Address, Bytes, H256, U256},
};
use num_bigint::BigUint;
use pyo3::{exceptions::PyRuntimeError, prelude::*};
use revm::primitives::{Bytecode, U256 as rU256};
use tokio::runtime::Runtime;
use tracing::info;

use std::{collections::HashMap, str::FromStr, sync::Arc};

use protosim::evm_simulation::{account_storage, database, simulation, tycho_db};
use std::fmt::Debug;

/// Data needed to invoke a transaction simulation
///
/// Attributes
/// ----------
/// caller: str
///     Address of the sending account
/// to: str
///     Address of the receiving account/contract
/// data: bytearray
///     Calldata
/// value: int
///     Amount of native token sent
/// overrides: Optional[dict[str, dict[int, int]]]
///     EVM state overrides. Will be merged with existing state. Will take effect only for current
///     simulation. It's a ``dict[account_address, dict[storage_slot, storage_value]]``.
/// gas_limit: Optional[int]
///     Limit of gas to be used by the transaction
/// block_number: int
///     Block number available to the transaction
/// timestamp: int
///     Timestamp value available to the transaction
#[pyclass]
#[derive(Clone, Debug)]
pub struct SimulationParameters {
    #[pyo3(get)]
    pub caller: String,
    #[pyo3(get)]
    pub to: String,
    #[pyo3(get)]
    pub data: Vec<u8>,
    #[pyo3(get)]
    pub value: BigUint,
    #[pyo3(get)]
    pub overrides: Option<HashMap<String, HashMap<BigUint, BigUint>>>,
    #[pyo3(get)]
    pub gas_limit: Option<u64>,
    #[pyo3(get)]
    pub block_number: Option<u64>,
    #[pyo3(get)]
    pub timestamp: Option<u64>,
}

#[pymethods]
impl SimulationParameters {
    #[new]
    #[pyo3(
        text_signature = "(caller, to, data, value, overrides=None, gas_limit=None, block_number=0, timestamp=0)"
    )]
    #[allow(clippy::too_many_arguments)]
    fn new(
        caller: String,
        to: String,
        data: Vec<u8>,
        value: BigUint,
        overrides: Option<HashMap<String, HashMap<BigUint, BigUint>>>,
        gas_limit: Option<u64>,
        block_number: Option<u64>,
        timestamp: Option<u64>,
    ) -> Self {
        Self { caller, to, data, value, overrides, gas_limit, block_number, timestamp }
    }

    fn __repr__(&self) -> String {
        format!("{:#?}", self)
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
            block_number: params.block_number.unwrap_or(0),
            timestamp: params.timestamp.unwrap_or(0),
        }
    }
}

/// Changes to an account made by a transaction
///
/// Attributes
/// ----------
/// storage: Optional[dict[int, int]]
///     New values of storage slots
/// balance: Optional[int]
///     New native token balance
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

        StateUpdate { storage: Some(py_storage), balance: py_balances }
    }
}

impl From<StateUpdate> for account_storage::StateUpdate {
    fn from(py_state_update: StateUpdate) -> Self {
        let mut rust_storage = HashMap::new();
        if let Some(py_storage) = py_state_update.storage {
            for (key, val) in py_storage {
                rust_storage.insert(
                    rU256::from_str(&key.to_string()).unwrap(),
                    rU256::from_str(&val.to_string()).unwrap(),
                );
            }
        }

        let mut rust_balance = None;
        if let Some(py_balance) = py_state_update.balance {
            rust_balance = Some(rU256::from_str(&py_balance.to_string()).unwrap());
        }

        account_storage::StateUpdate { storage: Some(rust_storage), balance: rust_balance }
    }
}

/// The result of a successful simulation
///
/// Attributes
/// ----------
///
/// result: bytearray
///     Output of transaction execution as bytes
/// state_updates: dict[str, StateUpdate]
///     State changes caused by the transaction
/// gas_used: int
///     Gas used by the transaction (already reduced by the refunded gas)
#[pyclass]
#[derive(Clone, Debug)]
pub struct SimulationResult {
    #[pyo3(get)]
    pub result: Vec<u8>,
    #[pyo3(get)]
    pub state_updates: HashMap<String, StateUpdate>,
    #[pyo3(get)]
    pub gas_used: u64,
}

#[pymethods]
impl SimulationResult {
    fn __repr__(&self) -> String {
        format!("{:#?}", self)
    }
}

impl From<simulation::SimulationResult> for SimulationResult {
    fn from(rust_result: simulation::SimulationResult) -> Self {
        let mut py_state_updates = HashMap::new();
        for (key, val) in rust_result.state_updates {
            py_state_updates.insert(format!("{:#x}", key), StateUpdate::from(val));
        }
        SimulationResult {
            result: rust_result.result.into(),
            state_updates: py_state_updates,
            gas_used: rust_result.gas_used,
        }
    }
}

/// Basic info about an ethereum account
///
/// Attributes
/// ----------
/// balance: int
///     Account balance.
/// nonce: int
///     Account nonce.
/// code_hash: str
///     Hash of the contract code.
/// code: Optional[bytearray]
///     Contract code. Note: empty code also has a hash.
#[pyclass]
#[derive(Clone)]
pub struct AccountInfo {
    #[pyo3(get, set)]
    pub balance: BigUint,
    #[pyo3(get, set)]
    pub nonce: u64,
    #[pyo3(get, set)]
    pub code: Option<Vec<u8>>,
}

#[pymethods]
impl AccountInfo {
    #[new]
    #[pyo3(signature = (balance, nonce, code=None))]
    fn new(balance: BigUint, nonce: u64, code: Option<Vec<u8>>) -> Self {
        Self { balance, nonce, code }
    }
}

impl From<AccountInfo> for revm::primitives::AccountInfo {
    fn from(py_info: AccountInfo) -> Self {
        let code;
        if let Some(c) = py_info.code {
            code = Bytecode::new_raw(Bytes::from(c).0);
        } else {
            code = Bytecode::new()
        }

        revm::primitives::AccountInfo::new(
            rU256::from_str(&py_info.balance.to_string()).unwrap(),
            py_info.nonce,
            code.hash_slow(),
            code,
        )
    }
}

/// Block header
///
/// Attributes
/// ----------
/// number: int
///     block number
/// hash: str
///     block hash
/// timestamp: int
///     block timestamp
#[pyclass]
#[derive(Clone, Debug)]
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
        Self { number, hash, timestamp }
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
#[derive(Debug)]
pub(crate) struct SimulationErrorDetails {
    #[pyo3(get)]
    pub data: String,
    #[pyo3(get)]
    pub gas_used: Option<u64>,
}

#[pymethods]
impl SimulationErrorDetails {
    fn __repr__(&self) -> String {
        match self.gas_used {
            Some(gas_usage) => {
                format!("SimulationError(data={}, gas_used={})", self.data, gas_usage)
            }
            None => format!("SimulationError(data={})", self.data),
        }
    }
}

impl From<SimulationErrorDetails> for PyErr {
    fn from(err: SimulationErrorDetails) -> PyErr {
        PyRuntimeError::new_err(err)
    }
}

// This indirection is needed cause SimulationError
//  is defined in an external create
impl From<simulation::SimulationError> for SimulationErrorDetails {
    fn from(err: simulation::SimulationError) -> Self {
        match err {
            simulation::SimulationError::StorageError(reason) => {
                SimulationErrorDetails { data: reason, gas_used: None }
            }
            simulation::SimulationError::TransactionError { data, gas_used } => {
                SimulationErrorDetails { data, gas_used }
            }
        }
    }
}

fn get_runtime() -> Option<Arc<Runtime>> {
    let runtime = tokio::runtime::Handle::try_current()
        .is_err()
        .then(|| Runtime::new().unwrap())
        .unwrap();

    Some(Arc::new(runtime))
}

fn get_client(rpc_url: &str) -> Arc<Provider<Http>> {
    let client = Provider::<Http>::try_from(rpc_url).unwrap();
    Arc::new(client)
}

/// A database using a real Ethereum node as a backend.
///
/// Uses a local cache to speed up queries.
#[pyclass]
#[derive(Clone, Debug)]
pub struct SimulationDB {
    pub inner: database::SimulationDB<Provider<Http>>,
}

#[pymethods]
impl SimulationDB {
    #[new]
    #[pyo3(signature = (rpc_url, block))]
    pub fn new(rpc_url: String, block: Option<BlockHeader>) -> Self {
        info!(?rpc_url, ?block, "Creating python SimulationDB wrapper instance");
        let db =
            database::SimulationDB::new(get_client(&rpc_url), get_runtime(), block.map(Into::into));
        Self { inner: db }
    }
}

/// A database that prechaches all data from a Tycho Indexer instance.
#[pyclass]
#[derive(Clone, Debug)]
pub struct TychoDB {
    pub inner: tycho_db::PreCachedDB,
}

#[pymethods]
impl TychoDB {
    /// Create a new TychoDB instance.
    ///
    /// Arguments
    /// * `tycho_url` - URL of the Tycho Indexer instance.
    /// * `block` - Block header to use as a starting point for the database.
    #[new]
    pub fn new(tycho_url: &str) -> Self {
        info!(?tycho_url, "Creating python TychoDB wrapper instance");
        let db = tycho_db::PreCachedDB::new(tycho_url);
        Self { inner: db }
    }
}
