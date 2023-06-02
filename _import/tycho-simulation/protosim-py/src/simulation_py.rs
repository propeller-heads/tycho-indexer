use ethers::{
    providers::{Http, Provider},
    types::{Address, Bytes, U256},
};
use protosim::evm_simulation::{
    account_storage::StateUpdate,
    database::SimulationDB,
    simulation::{self, SimulationEngine},
};
use pyo3::prelude::*;
use revm::primitives::hash_map;
use std::{collections::HashMap, str::FromStr, sync::Arc};
use tokio::runtime::Runtime;

#[derive(FromPyObject, Clone, Debug)]
/// Data needed to invoke a transaction simulation
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
    pub overrides: Option<HashMap<String, String>>,
    /// Limit of gas to be used by the transaction
    pub gas_limit: Option<u64>,
}

#[pyclass]
#[derive(Clone, Debug)]
pub struct PyStateUpdate {
    pub storage: Option<HashMap<String, String>>,
    pub balance: Option<String>,
}

impl PyStateUpdate {
    fn new(state_update: StateUpdate) -> Self {
        let mut storage = HashMap::new();
        if let Some(rust_storage) = state_update.storage {
            for (key, val) in rust_storage {
                storage.insert(key.to_string(), val.to_string());
            }
        }

        PyStateUpdate {
            storage: Some(storage),
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
    pub state_updates: HashMap<String, PyStateUpdate>,
    /// Gas used by the transaction (already reduced by the refunded gas)
    pub gas_used: u64,
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
pub struct WrappedSimulationEnginePy {
    engine: SimulationEngine<Provider<Http>>,
}

#[pymethods]
impl WrappedSimulationEnginePy {
    #[new]
    fn new() -> Self {
        let db = SimulationDB::new(get_client(), get_runtime(), None);
        let engine = SimulationEngine { state: db };
        Self { engine }
    }

    fn run_sim(self_: PyRef<Self>, params: PySimulationParameters) -> PyResult<PySimulationResult> {
        let mut overrides = hash_map::HashMap::default();
        println!("PySimulationParameters:");
        println!("params.caller {:?}", params.caller);
        println!("params.to {:?}", params.to);
        println!("params.gas_limit {:?}", params.gas_limit);
        println!("params.value {:?}", params.value);
        if let Some(py_overrides) = params.overrides {
            for (key, val) in py_overrides {
                overrides.insert(
                    U256::from_str(key.as_str()).unwrap(),
                    U256::from_str(val.as_str()).unwrap(),
                );
            }
        }
        let parameter = simulation::SimulationParameters {
            caller: Address::from_str(params.caller.as_str()).unwrap(),
            to: Address::from_str(params.to.as_str()).unwrap(),
            data: Bytes::from(params.data),
            value: U256::from_str(params.value.as_str()).unwrap(),
            overrides: Some(overrides),
            gas_limit: params.gas_limit,
        };

        println!("simulation::SimulationParameters:");
        println!("params.caller {:?}", parameter.caller);
        println!("params.to {:?}", parameter.to);
        println!("params.gas_limit {:?}", parameter.gas_limit);
        println!("params.value {:?}", parameter.value);

        let res = self_.engine.simulate(&parameter).unwrap();

        let mut state_updated = HashMap::default();
        for (key, val) in res.state_updates {
            state_updated.insert(
                Address::from(&key.to_fixed_bytes()).to_string(),
                PyStateUpdate::new(val),
            );
        }
        Ok(PySimulationResult {
            result: res.result.try_into().unwrap(),
            state_updates: state_updated,
            gas_used: res.gas_used,
        })
    }
}
