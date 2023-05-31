use ethers::providers::{Http, Middleware, MiddlewareError, Provider};
use protosim::evm_simulation::{database::SimulationDB, simulation::SimulationEngine};
use pyo3::prelude::*;
use std::sync::Arc;
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

const SIMULATION: SimulationEngine<Provider<Http>> = SimulationEngine::new();
//static SIM_DB: SimulationDB<Provider<Http>> = SimulationDB::new(get_client(), get_runtime(), None);

/// Formats the sum of two numbers as string.
#[pyfunction]
fn sum_as_string(a: usize, b: usize) -> PyResult<String> {
    println!("Call function");

    Ok((a + b).to_string())
}

/// A Python module implemented in Rust.
#[pymodule]
fn protosim_py(_py: Python, m: &PyModule) -> PyResult<()> {
    println!("Init Module");
    m.add_function(wrap_pyfunction!(sum_as_string, m)?)?;
    Ok(())
}
