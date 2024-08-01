use pyo3::prelude::*;
use simulation_py::SimulationEngine;
use starknet_simulation_py::StarknetSimulationEngine;
use starknet_structs_py::{
    StarknetContractOverride, StarknetSimulationParameters, StarknetSimulationResult,
};
use structs_py::{
    AccountInfo, AccountUpdate, BlockHeader, SimulationDB, SimulationParameters, SimulationResult,
    StateUpdate, TychoDB,
};
use tracing_subscriber::EnvFilter;

mod simulation_py;
mod starknet_simulation_py;
mod starknet_structs_py;
mod structs_py;

/// Transaction simulation using EVM implemented in Rust
#[pymodule]
fn _protosim_py(_py: Python, m: &PyModule) -> PyResult<()> {
    // initialize up a logger
    pyo3_log::init();

    // Start configuring a `fmt` subscriber
    let subscriber = tracing_subscriber::fmt()
        // Use a more compact, abbreviated log format
        .compact()
        // Display source code file paths
        .with_file(true)
        // Display source code line numbers
        .with_line_number(true)
        // Display the thread ID an event was recorded on
        .with_thread_ids(true)
        // Don't display the event's target (module path)
        .with_target(false)
        // Set default log level from RUST_LOG env variable
        .with_env_filter(EnvFilter::from_default_env())
        // Build the subscriber
        .finish();

    let _ = tracing::subscriber::set_global_default(subscriber);

    m.add_class::<SimulationEngine>()?;
    m.add_class::<SimulationParameters>()?;
    m.add_class::<SimulationResult>()?;
    m.add_class::<StateUpdate>()?;
    m.add_class::<BlockHeader>()?;
    m.add_class::<AccountInfo>()?;
    m.add_class::<SimulationDB>()?;
    m.add_class::<TychoDB>()?;
    m.add_class::<AccountUpdate>()?;
    m.add_class::<StarknetSimulationEngine>()?;
    m.add_class::<StarknetContractOverride>()?;
    m.add_class::<StarknetSimulationParameters>()?;
    m.add_class::<StarknetSimulationResult>()?;

    Ok(())
}
