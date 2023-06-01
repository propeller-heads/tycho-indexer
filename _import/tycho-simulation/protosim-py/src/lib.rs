use ethers::providers::{Http, Middleware, MiddlewareError, Provider};
use once_cell::sync::Lazy;
use protosim::evm_simulation::{database::SimulationDB, simulation::SimulationEngine};
use pyo3::prelude::*;
use std::sync::Arc;
use std::sync::Mutex;
use tokio::runtime::{Handle, Runtime};

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

// https://stackoverflow.com/questions/27791532/how-do-i-create-a-global-mutable-singleton
static DB_INSTANCE: Lazy<Mutex<SimulationDB<Provider<Http>>>> = Lazy::new(|| {
    let mut db = SimulationDB::new(get_client(), get_runtime(), None);
    Mutex::new(db)
});

//static SIM_INSTANCE: Lazy<Mutex<SimulationEngine<Provider<Http>>>> = Lazy::new(|| {
//    let sim = SimulationEngine {
//        state: &DB_INSTANCE.lock().unwrap(),
//    };
//    Mutex::new(sim)
//});

/// Formats the sum of two numbers as string.
#[pyfunction]
fn sum_as_string(a: usize, b: usize) -> PyResult<String> {
    println!("Call function");
    DB_INSTANCE.lock().unwrap().increase_val();
    //DB_INSTANCE.increase_val();

    println!("The test val {:?}", DB_INSTANCE.lock().unwrap().test_val);
    Ok((a + b).to_string())
}

/// A Python module implemented in Rust.
#[pymodule]
fn protosim_py(_py: Python, m: &PyModule) -> PyResult<()> {
    println!("Init Module");
    m.add_function(wrap_pyfunction!(sum_as_string, m)?)?;
    Ok(())
}
