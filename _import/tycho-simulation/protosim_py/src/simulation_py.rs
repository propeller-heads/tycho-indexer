use ethers::{
    providers::{Http, Provider},
    types::{Address, Bytes, U256},
};

use num_bigint::BigUint;
use pyo3::{exceptions::PyRuntimeError, prelude::*};
use std::{collections::HashMap, str::FromStr, sync::Arc};
use tokio::runtime::Runtime;

use protosim::evm_simulation::{account_storage, database::SimulationDB, simulation};

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
    pub storage: Option<HashMap<String, String>>,
    #[pyo3(get)]
    pub balance: Option<String>,
}

impl From<account_storage::StateUpdate> for StateUpdate {
    fn from(state_update: account_storage::StateUpdate) -> Self {
        let mut py_storage = HashMap::new();
        if let Some(rust_storage) = state_update.storage {
            for (key, val) in rust_storage {
                py_storage.insert(key.to_string(), val.to_string());
            }
        }

        StateUpdate {
            storage: Some(py_storage),
            balance: Some(state_update.balance.unwrap().to_string()),
        }
    }
}

#[pyclass]
#[derive(Clone)]
pub struct SimulationResult {
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

impl From<simulation::SimulationResult> for SimulationResult {
    fn from(rust_result: simulation::SimulationResult) -> Self {
        let mut py_state_updates = HashMap::new();
        for (key, val) in rust_result.state_updates {
            py_state_updates.insert(
                Address::from(&key.to_fixed_bytes()).to_string(),
                StateUpdate::from(val),
            );
        }
        SimulationResult {
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
struct SimulationError(simulation::SimulationError);

impl From<SimulationError> for PyErr {
    fn from(err: SimulationError) -> PyErr {
        PyRuntimeError::new_err(format!("{:?}", err.0))
    }
}

impl From<simulation::SimulationError> for SimulationError {
    fn from(err: simulation::SimulationError) -> Self {
        Self(err)
    }
}

fn get_runtime() -> Option<Arc<Runtime>> {
    let runtime = tokio::runtime::Handle::try_current()
        .is_err()
        .then(|| Runtime::new().unwrap())
        .unwrap();

    Some(Arc::new(runtime))
}

fn get_client() -> Arc<Provider<Http>> {
    let client = Provider::<Http>::try_from(
        "https://eth-mainnet.g.alchemy.com/v2/OTD5W7gdTPrzpVot41Lx9tJD9LUiAhbs",
    )
    .unwrap();
    Arc::new(client)
}

#[pyclass]
pub struct SimulationEngine(simulation::SimulationEngine<Provider<Http>>);

#[pymethods]
impl SimulationEngine {
    #[new]
    fn new() -> Self {
        let db = SimulationDB::new(get_client(), get_runtime(), None);
        let engine = simulation::SimulationEngine { state: db };
        Self(engine)
    }

    fn run_sim(self_: PyRef<Self>, params: SimulationParameters) -> PyResult<SimulationResult> {
        let rust_result = self_
            .0
            .simulate(&simulation::SimulationParameters::from(params));
        match rust_result {
            Ok(sim_res) => Ok(SimulationResult::from(sim_res)),
            Err(sim_err) => Err(PyErr::from(SimulationError::from(sim_err))),
        }
    }
}
