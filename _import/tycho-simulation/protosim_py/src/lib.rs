use pyo3::prelude::*;
use simulation_py::SimulationEngine;
use structs_py::{AccountInfo, BlockHeader, SimulationParameters, StateUpdate};

mod simulation_py;
mod structs_py;
/// A Python module implemented in Rust.
#[pymodule]
fn protosim_py(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<SimulationEngine>()?;
    m.add_class::<SimulationParameters>()?;
    m.add_class::<StateUpdate>()?;
    m.add_class::<BlockHeader>()?;
    m.add_class::<AccountInfo>()?;
    Ok(())
}
