use ethers::providers::{Http, Provider};
use num_bigint::BigUint;
use revm::primitives::{B160, U256 as rU256};

use crate::structs_py::{
    AccountInfo, BlockHeader, PySimulationError, PySimulationResult, SimulationParameters,
    StateUpdate,
};
use pyo3::prelude::*;
use std::{collections::HashMap, str::FromStr, sync::Arc};
use tokio::runtime::Runtime;

use protosim::evm_simulation::{account_storage, database::SimulationDB, simulation};

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

    fn run_sim(self_: PyRef<Self>, params: SimulationParameters) -> PyResult<PySimulationResult> {
        let rust_result = self_
            .0
            .simulate(&simulation::SimulationParameters::from(params));
        match rust_result {
            Ok(sim_res) => Ok(PySimulationResult::from(sim_res)),
            Err(sim_err) => Err(PyErr::from(PySimulationError::from(sim_err))),
        }
    }

    fn init_account(
        self_: PyRef<Self>,
        address: String,
        account: AccountInfo,
        mocked: bool,
        permanent_storage: Option<HashMap<BigUint, BigUint>>,
    ) {
        let address = B160::from_str(&address).unwrap();
        let account = revm::primitives::AccountInfo::from(account);

        let mut rust_slots: HashMap<rU256, rU256> = HashMap::new();
        if let Some(storage) = permanent_storage {
            for (index, value) in storage {
                rust_slots.insert(
                    rU256::from_limbs_slice(index.to_u64_digits().as_slice()),
                    rU256::from_limbs_slice(value.to_u64_digits().as_slice()),
                );
            }
        }

        self_
            .0
            .state
            .init_account(address, account, Some(rust_slots), mocked);
    }

    fn update_state(
        mut self_: PyRefMut<Self>,
        updates: HashMap<String, StateUpdate>,
        block: BlockHeader,
    ) -> PyResult<HashMap<String, StateUpdate>> {
        let block = protosim::evm_simulation::database::BlockHeader::from(block);

        let mut rust_updates: HashMap<B160, account_storage::StateUpdate> = HashMap::new();
        for (key, value) in updates {
            rust_updates.insert(
                B160::from_str(&key).unwrap(),
                account_storage::StateUpdate::from(value),
            );
        }

        let revers_update = self_.0.state.update_state(&rust_updates, block);

        let mut py_reverse_updates: HashMap<String, StateUpdate> = HashMap::new();
        for (key, value) in revers_update {
            py_reverse_updates.insert(key.to_string(), StateUpdate::from(value));
        }
        Ok(py_reverse_updates)
    }

    fn clear_temp_storage(self_: PyRef<Self>) {
        self_.0.state.clear_temp_storage();
    }
}
