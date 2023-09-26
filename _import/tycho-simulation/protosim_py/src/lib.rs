use pyo3::prelude::*;
use simulation_py::SimulationEngine;
use structs_py::{AccountInfo, BlockHeader, SimulationParameters, StateUpdate, SimulationResult};

mod simulation_py;
mod structs_py;

/// Transaction simulation using EVM implemented in Rust
#[pymodule]
fn protosim_py(_py: Python, m: &PyModule) -> PyResult<()> {
    // Start configuring a `fmt` subscriber
    tracing_subscriber::fmt()
        // Set default log level from RUST_LOG env variable
        .with_env_filter(EnvFilter::from_default_env())
        // Build the subscriber
        .finish();
    m.add_class::<SimulationEngine>()?;
    m.add_class::<SimulationParameters>()?;
    m.add_class::<SimulationResult>()?;
    m.add_class::<StateUpdate>()?;
    m.add_class::<BlockHeader>()?;
    m.add_class::<AccountInfo>()?;
    Ok(())
}
