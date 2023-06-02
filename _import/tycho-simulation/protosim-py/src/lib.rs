pub mod simulation_py;
use ethers::providers::{Http, Provider};
use ethers::types::{Address, Bytes, U256};
use once_cell::sync::Lazy;
use protosim::evm_simulation::simulation;
use protosim::evm_simulation::{database::SimulationDB, simulation::SimulationEngine};
use pyo3::prelude::*;
use simulation_py::WrappedSimulationEnginePy;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::Mutex;
use tokio::runtime::{Handle, Runtime};

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
    m.add_class::<WrappedSimulationEnginePy>()?;
    Ok(())
}
