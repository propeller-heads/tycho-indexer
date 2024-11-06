use ethers::{
    providers::{Http, Provider},
    types::{Bytes, H256, U256},
};
use num_bigint::BigUint;
use pyo3::{exceptions::PyRuntimeError, prelude::*};
use revm::primitives::{Address as RevmAddress, Bytecode, U256 as rU256};
use tokio::runtime::Runtime;
use tracing::info;

use std::{collections::HashMap, str::FromStr, sync::Arc};

use std::fmt::Debug;
use tycho_simulation::evm::{account_storage, simulation, simulation_db, tycho_db, tycho_models};

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
                let mut rust_overrides: HashMap<RevmAddress, HashMap<U256, U256>> = HashMap::new();
                for (address, py_slots) in py_overrides {
                    let mut rust_slots: HashMap<U256, U256> = HashMap::new();
                    for (index, value) in py_slots {
                        rust_slots.insert(
                            U256::from_big_endian(index.to_bytes_be().as_slice()),
                            U256::from_big_endian(value.to_bytes_be().as_slice()),
                        );
                    }
                    rust_overrides.insert(
                        RevmAddress::from_str(address.as_str()).expect("Wrong address format"),
                        rust_slots,
                    );
                }
                Some(rust_overrides)
            }
            None => None,
        };
        simulation::SimulationParameters {
            caller: RevmAddress::from_str(params.caller.as_str()).unwrap(),
            to: RevmAddress::from_str(params.to.as_str()).unwrap(),
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
    #[pyo3(signature = (storage = None, balance = None))]
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

/// An update for an account
///
/// Attributes
/// ----------
/// address: str
///     The account's address
/// chain: str
///     The chain name
/// slots: dict[int, int]
///    The updated storage slots
/// balance: Optional[int]
///    The updated native balance
/// code: Optional[bytearray]
///     The updated contract code
/// change: str
///     The ChangeType of the update
#[pyclass]
#[derive(Clone, Debug)]
pub struct AccountUpdate {
    #[pyo3(get)]
    pub address: String,
    #[pyo3(get)]
    pub chain: String,
    #[pyo3(get)]
    pub slots: HashMap<BigUint, BigUint>,
    #[pyo3(get)]
    pub balance: Option<BigUint>,
    #[pyo3(get)]
    pub code: Option<Vec<u8>>,
    #[pyo3(get)]
    pub change: String,
}

#[pymethods]
impl AccountUpdate {
    #[new]
    #[pyo3(signature = (address, chain, slots, change, balance = None, code = None))]
    fn new(
        address: String,
        chain: String,
        slots: HashMap<BigUint, BigUint>,
        change: String,
        balance: Option<BigUint>,
        code: Option<Vec<u8>>,
    ) -> Self {
        Self { address, chain, slots, balance, code, change }
    }
}

impl From<tycho_models::AccountUpdate> for AccountUpdate {
    fn from(update: tycho_models::AccountUpdate) -> Self {
        let mut py_slots = HashMap::new();
        for (key, val) in update.slots {
            py_slots.insert(
                BigUint::from_bytes_le(key.as_le_slice()),
                BigUint::from_bytes_le(val.as_le_slice()),
            );
        }

        let py_balance = update
            .balance
            .map(|b| BigUint::from_bytes_le(b.as_le_slice()));

        AccountUpdate {
            address: update.address.to_string(),
            chain: update.chain.to_string(),
            slots: py_slots,
            balance: py_balance,
            code: update.code,
            change: update.change.to_string(),
        }
    }
}

impl From<AccountUpdate> for tycho_models::AccountUpdate {
    fn from(py_update: AccountUpdate) -> Self {
        let mut rust_slots = HashMap::new();
        for (key, val) in py_update.slots {
            rust_slots.insert(
                rU256::from_str(&key.to_string()).unwrap(),
                rU256::from_str(&val.to_string()).unwrap(),
            );
        }

        let rust_balance = py_update
            .balance
            .map(|b| rU256::from_str(&b.to_string()).unwrap());

        tycho_models::AccountUpdate {
            address: RevmAddress::from_str(py_update.address.as_str()).unwrap(),
            chain: tycho_models::Chain::from_str(py_update.chain.as_str()).unwrap(),
            slots: rust_slots,
            balance: rust_balance,
            code: py_update.code,
            change: tycho_models::ChangeType::from_str(py_update.change.as_str()).unwrap(),
        }
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
    #[pyo3(signature = (balance, nonce, code = None))]
    fn new(balance: BigUint, nonce: u64, code: Option<Vec<u8>>) -> Self {
        Self { balance, nonce, code }
    }
}

impl From<AccountInfo> for revm::primitives::AccountInfo {
    fn from(py_info: AccountInfo) -> Self {
        let code;
        if let Some(c) = py_info.code {
            code = Bytecode::new_raw(revm::primitives::Bytes::from(c));
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

impl From<BlockHeader> for tycho_simulation::evm::simulation_db::BlockHeader {
    fn from(py_header: BlockHeader) -> Self {
        tycho_simulation::evm::simulation_db::BlockHeader {
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
impl From<simulation::SimulationEngineError> for SimulationErrorDetails {
    fn from(err: simulation::SimulationEngineError) -> Self {
        match err {
            simulation::SimulationEngineError::StorageError(reason) => {
                SimulationErrorDetails { data: reason, gas_used: None }
            }
            simulation::SimulationEngineError::TransactionError { data, gas_used } => {
                SimulationErrorDetails { data, gas_used }
            }
            simulation::SimulationEngineError::OutOfGas(reason, _) => {
                SimulationErrorDetails { data: reason, gas_used: None }
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
    pub inner: simulation_db::SimulationDB<Provider<Http>>,
}

#[pymethods]
impl SimulationDB {
    #[new]
    #[pyo3(signature = (rpc_url, block))]
    pub fn new(rpc_url: String, block: Option<BlockHeader>) -> Self {
        info!(?rpc_url, ?block, "Creating python SimulationDB wrapper instance");
        let db = simulation_db::SimulationDB::new(
            get_client(&rpc_url),
            get_runtime(),
            block.map(Into::into),
        );
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
    ///
    /// * `tycho_http_url` - URL of the Tycho Indexer HTTP endpoint.
    /// * `block` - Block header to use as a starting point for the database.
    #[new]
    #[pyo3(signature = (tycho_http_url))]
    pub fn new(tycho_http_url: &str) -> PyResult<Self> {
        info!(?tycho_http_url, "Creating python TychoDB wrapper instance");
        let db = tycho_db::PreCachedDB::new()
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to create TychoDB: {}", e)))?;
        Ok(Self { inner: db })
    }

    /// Get the current block number of a TychoDB instance.
    pub fn block_number(self_: PyRefMut<Self>) -> Option<u64> {
        self_.inner.block_number()
    }

    // Apply a list of account updates to TychoDB instance.
    #[pyo3(signature = (account_updates, block))]
    pub fn update(
        self_: PyRefMut<Self>,
        account_updates: Vec<AccountUpdate>,
        block: Option<BlockHeader>,
    ) {
        let account_updates: Vec<tycho_models::AccountUpdate> = account_updates
            .into_iter()
            .map(Into::into)
            .collect();

        let block = block.map(tycho_simulation::evm::simulation_db::BlockHeader::from);

        let runtime = tokio::runtime::Runtime::new().unwrap(); // Create a new Tokio runtime
        runtime.block_on(async {
            self_
                .inner
                .update(account_updates, block)
                .await;
        })
    }
}
