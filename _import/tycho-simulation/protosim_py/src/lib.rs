use pyo3::prelude::*;
use simulation_py::SimulationEngine;

mod simulation_py;

/// A Python module implemented in Rust.
#[pymodule]
fn protosim_py(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<SimulationEngine>()?;
    Ok(())
}
