use logging::init_custom_logging;
use pyo3::prelude::*;
use simulation_py::SimulationEngine;
use starknet_simulation_py::StarknetSimulationEngine;
use starknet_structs_py::{
    StarknetContractOverride, StarknetSimulationParameters, StarknetSimulationResult,
};
use structs_py::{
    AccountInfo, BlockHeader, SimulationDB, SimulationParameters, SimulationResult, StateUpdate,
    TychoDB,
};

mod logging;
mod simulation_py;
mod starknet_simulation_py;
mod starknet_structs_py;
mod structs_py;

/// Transaction simulation using EVM implemented in Rust
#[pymodule]
fn protosim_py(_py: Python, m: &PyModule) -> PyResult<()> {
    // initialize up a logger
    pyo3_log::init();

    init_custom_logging()?;

    m.add_class::<SimulationEngine>()?;
    m.add_class::<SimulationParameters>()?;
    m.add_class::<SimulationResult>()?;
    m.add_class::<StateUpdate>()?;
    m.add_class::<BlockHeader>()?;
    m.add_class::<AccountInfo>()?;
    m.add_class::<SimulationDB>()?;
    m.add_class::<TychoDB>()?;
    m.add_class::<StarknetSimulationEngine>()?;
    m.add_class::<StarknetContractOverride>()?;
    m.add_class::<StarknetSimulationParameters>()?;
    m.add_class::<StarknetSimulationResult>()?;

    // // Function to forward rust logs to python
    // m.add_function(wrap_pyfunction!(init_custom_logging, m)?)?;
    Ok(())
}
