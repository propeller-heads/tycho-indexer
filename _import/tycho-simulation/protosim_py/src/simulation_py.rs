use ethers::providers::{Http, Provider};
use num_bigint::BigUint;
use revm::primitives::{B160, U256 as rU256};

use crate::structs_py::{
    AccountInfo, BlockHeader, SimulationDB, SimulationErrorDetails, SimulationParameters,
    SimulationResult, StateUpdate, TychoDB,
};
use pyo3::{prelude::*, types::PyType};
use std::{collections::HashMap, str::FromStr};

use protosim::evm_simulation::{account_storage, database, simulation, tycho_db};

/// It is very hard and messy to implement polymorphism with PyO3.
/// Instead we use an enum to store the all possible simulation engines.
/// and we keep them invisible to the Python user.
enum SimulationEngineInner {
    SimulationDB(simulation::SimulationEngine<database::SimulationDB<Provider<Http>>>),
    TychoDB(simulation::SimulationEngine<tycho_db::PreCachedDB>),
}

impl SimulationEngineInner {
    fn simulate(
        &self,
        params: &simulation::SimulationParameters,
    ) -> Result<simulation::SimulationResult, simulation::SimulationError> {
        match self {
            SimulationEngineInner::SimulationDB(engine) => engine.simulate(params),
            SimulationEngineInner::TychoDB(engine) => engine.simulate(params),
        }
    }

    fn init_account(
        &self,
        address: B160,
        account: revm::primitives::AccountInfo,
        permanent_storage: Option<HashMap<rU256, rU256>>,
        mocked: bool,
    ) {
        match self {
            SimulationEngineInner::SimulationDB(engine) => {
                engine
                    .state
                    .init_account(address, account, permanent_storage, mocked)
            }
            SimulationEngineInner::TychoDB(engine) => {
                engine
                    .state
                    .init_account(address, account, permanent_storage)
            }
        }
    }

    fn update_state(
        &mut self,
        updates: &HashMap<B160, account_storage::StateUpdate>,
        block: database::BlockHeader,
    ) -> HashMap<B160, account_storage::StateUpdate> {
        match self {
            SimulationEngineInner::SimulationDB(engine) => engine
                .state
                .update_state(updates, block),
            SimulationEngineInner::TychoDB(engine) => engine
                .state
                .update_state(updates, block),
        }
    }

    fn query_storage(&self, address: B160, slot: rU256) -> Option<rU256> {
        match self {
            SimulationEngineInner::SimulationDB(engine) => engine
                .state
                .query_storage(address, slot)
                .ok(),
            SimulationEngineInner::TychoDB(engine) => engine
                .state
                .get_storage(&address, &slot),
        }
    }

    fn clear_temp_storage(&mut self) {
        match self {
            SimulationEngineInner::SimulationDB(engine) => engine.state.clear_temp_storage(),
            SimulationEngineInner::TychoDB(engine) => engine.state.clear_temp_storage(),
        }
    }
}

/// This class lets you simulate transactions.
///
/// Data will be queried from an Ethereum node, if needed. You can also override account balance or
/// storage. See the methods.
///
/// Attributes
/// ----------
/// rpc_url: str
///     Ethereum node connection string.
/// block: Optional[BlockHeader]
///     Optional BlockHeader. If None, current block will be used.
/// trace: Optional[bool]
///     If set to true, simulations will print the entire execution trace.
#[pyclass]
pub struct SimulationEngine(SimulationEngineInner);

#[pymethods]
impl SimulationEngine {
    #[classmethod]
    fn new_with_simulation_db(_cls: &PyType, db: SimulationDB, trace: Option<bool>) -> Self {
        let engine = simulation::SimulationEngine::new(db.inner, trace.unwrap_or(false));
        Self(SimulationEngineInner::SimulationDB(engine))
    }

    #[classmethod]
    fn new_with_tycho_db(_cls: &PyType, db: TychoDB, trace: Option<bool>) -> Self {
        let engine = simulation::SimulationEngine::new(db.inner, trace.unwrap_or(false));
        Self(SimulationEngineInner::TychoDB(engine))
    }

    /// Simulate transaction.
    ///
    /// Pass all details as an instance of `SimulationParameters`. See that class' docs for details.
    fn run_sim(self_: PyRef<Self>, params: SimulationParameters) -> PyResult<SimulationResult> {
        match self_.0.simulate(&params.into()) {
            Ok(sim_res) => Ok(SimulationResult::from(sim_res)),
            Err(sim_err) => Err(PyErr::from(SimulationErrorDetails::from(sim_err))),
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
                    rU256::from_str(&index.to_string()).unwrap(),
                    rU256::from_str(&value.to_string()).unwrap(),
                );
            }
        }

        self_
            .0
            .init_account(address, account, Some(rust_slots), mocked)
    }

    fn update_state(
        mut self_: PyRefMut<Self>,
        updates: HashMap<String, StateUpdate>,
        block: BlockHeader,
    ) -> PyResult<HashMap<String, StateUpdate>> {
        let block = protosim::evm_simulation::database::BlockHeader::from(block);
        let mut rust_updates: HashMap<B160, account_storage::StateUpdate> = HashMap::new();
        for (key, value) in updates {
            rust_updates
                .insert(B160::from_str(&key).unwrap(), account_storage::StateUpdate::from(value));
        }

        let reverse_updates = self_
            .0
            .update_state(&rust_updates, block);

        let mut py_reverse_updates: HashMap<String, StateUpdate> = HashMap::new();
        for (key, value) in reverse_updates {
            py_reverse_updates.insert(key.to_string(), StateUpdate::from(value));
        }
        Ok(py_reverse_updates)
    }

    fn query_storage(
        self_: PyRef<Self>,
        address: String,
        slot: String,
    ) -> PyResult<Option<String>> {
        let address = B160::from_str(&address).unwrap();
        let slot = rU256::from_str(&slot).unwrap();
        match self_.0.query_storage(address, slot) {
            Some(state_update) => Ok(Some(state_update.to_string())),
            None => Ok(None),
        }
    }

    fn clear_temp_storage(mut self_: PyRefMut<Self>) {
        self_.0.clear_temp_storage()
    }
}
