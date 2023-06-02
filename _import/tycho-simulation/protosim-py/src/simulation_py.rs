use ethers::{
    providers::{Http, Provider},
    types::{Address, Bytes, U256},
};
use protosim::evm_simulation::{account_storage::StateUpdate, database::SimulationDB, simulation::{self, SimulationEngine}};
use pyo3::prelude::*;
use revm::precompile::HashMap as revmHashMap;
use std::{collections::HashMap as stdHashMap, str::FromStr, sync::Arc};
use tokio::runtime::Runtime;
use protosim::evm_simulation::simulation::{SimulationParameters, SimulationResult};

/// Data needed to invoke a transaction simulation
#[derive(FromPyObject, Clone, Debug)]
pub struct PySimulationParameters {
    /// Address of the sending account
    pub caller: String,
    /// Address of the receiving account/contract
    pub to: String,
    /// Calldata
    pub data: Vec<u8>,
    /// Amount of native token sent
    pub value: String,
    /// EVM state overrides.
    /// Will be merged with existing state. Will take effect only for current simulation.
    pub overrides: Option<stdHashMap<String, stdHashMap<String, String>>>,
    /// Limit of gas to be used by the transaction
    pub gas_limit: Option<u64>,
}

impl From<PySimulationParameters> for SimulationParameters {
    fn from(params: PySimulationParameters) -> Self {
        let overrides = match params.overrides {
            Some(py_overrides) => {
                let mut rust_overrides: revmHashMap<Address, revmHashMap<U256, U256>> = revmHashMap::new();
                for (address, py_slots) in py_overrides {
                    let mut rust_slots = revmHashMap::new();
                    for (index, value) in py_slots {
                        rust_slots.insert(
                            U256::from_str(index.as_str())
                                .expect("Can't decode storage slot index"),
                            U256::from_str(value.as_str())
                                .expect("Can't decode storage value"),
                        );
                    }
                    rust_overrides.insert(
                        Address::from_str(address.as_str())
                            .expect("Wrong address format"),
                        rust_slots,
                    );
                }
                Some(rust_overrides)
            },
            None => None,
        };
        SimulationParameters {
            caller: Address::from_str(params.caller.as_str()).unwrap(),
            to: Address::from_str(params.to.as_str()).unwrap(),
            data: Bytes::from(params.data),
            value: U256::from_str(params.value.as_str()).unwrap(),
            overrides,
            gas_limit: params.gas_limit,
        }
    }
}

#[pyclass]
#[derive(Clone, Debug)]
pub struct PyStateUpdate {
    pub storage: Option<stdHashMap<String, String>>,
    pub balance: Option<String>,
}

impl From<StateUpdate> for PyStateUpdate {
    fn from(state_update: StateUpdate) -> Self {
        let mut py_storage = stdHashMap::new();
        if let Some(rust_storage) = state_update.storage {
            for (key, val) in rust_storage {
                py_storage.insert(key.to_string(), val.to_string());
            }
        }

        PyStateUpdate {
            storage: Some(py_storage),
            balance: Some(state_update.balance.unwrap().to_string()),
        }
    }
}

#[pyclass]
#[derive(Clone)]
pub struct PySimulationResult {
    /// Output of transaction execution as bytes
    pub result: Vec<u8>,
    /// State changes caused by the transaction
    pub state_updates: stdHashMap<String, PyStateUpdate>,
    /// Gas used by the transaction (already reduced by the refunded gas)
    pub gas_used: u64,
}

impl From<SimulationResult> for PySimulationResult {
    fn from(rust_result: SimulationResult) -> Self {
        let mut py_state_updates = stdHashMap::new();
        for (key, val) in rust_result.state_updates {
            py_state_updates.insert(
                Address::from(&key.to_fixed_bytes()).to_string(),
                PyStateUpdate::from(val),
            );
        }
        PySimulationResult {
            result: rust_result.result.try_into()
                .expect("Can't convert output bytes to a Python-compatible type"),
            state_updates: py_state_updates,
            gas_used: rust_result.gas_used,
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

fn get_client() -> Arc<Provider<Http>> {
    let client = Provider::<Http>::try_from(
        "https://eth-mainnet.g.alchemy.com/v2/OTD5W7gdTPrzpVot41Lx9tJD9LUiAhbs",
    )
    .unwrap();
    Arc::new(client)
}

#[pyclass]
pub struct WrappedSimulationEnginePy(SimulationEngine<Provider<Http>>);

#[pymethods]
impl WrappedSimulationEnginePy {
    #[new]
    fn new() -> Self {
        let db = SimulationDB::new(get_client(), get_runtime(), None);
        let engine = SimulationEngine { state: db };
        Self(engine)
    }

    fn run_sim(self_: PyRef<Self>, params: PySimulationParameters) -> PyResult<PySimulationResult> {
        let res = self_.0
            .simulate(&SimulationParameters::from(params))
            .unwrap();  // TODO return error
        Ok(PySimulationResult::from(res))
    }
}
