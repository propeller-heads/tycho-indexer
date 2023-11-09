use protosim::{
    rpc_state_reader::rpc_state::{BlockTag, BlockValue, RpcChain, RpcState},
    starknet_simulation::{rpc_reader::RpcStateReader, simulation::SimulationEngine},
};
use pyo3::prelude::*;
use std::sync::Arc;

use crate::starknet_structs_py::{
    StarknetContractOverride, StarknetSimulationErrorDetails, StarknetSimulationParameters,
    StarknetSimulationResult,
};

/// Starknet transaction simulation engine.
///
/// Data not provided in overrides will be fetched from an RPC node and cached locally.
#[pyclass]
pub struct StarknetSimulationEngine(SimulationEngine<RpcStateReader>);

#[pymethods]
impl StarknetSimulationEngine {
    /// Create a new Starknet simulation engine.
    ///
    /// # Arguments
    ///
    /// * `rpc_endpoint` - The RPC endpoint to use for RPC calls.
    /// * `feeder_url` - The feeder URL to use for RPC calls.
    /// * `contract_overrides` - A list of contract overrides to use for simulation.
    #[allow(unused_variables)]
    #[new]
    fn new(
        rpc_endpoint: String,
        feeder_url: String,
        contract_overrides: Vec<StarknetContractOverride>,
    ) -> Self {
        // Create a state reader. It does not matter what block we use as running the simulation
        // will set it to the correct block from parameters.
        let state_reader = RpcStateReader::new(RpcState::new(
            RpcChain::MainNet,
            BlockValue::Tag(BlockTag::Latest),
            &rpc_endpoint,
            &feeder_url,
        ));
        let engine = SimulationEngine::new(
            Arc::new(state_reader),
            Some(
                contract_overrides
                    .into_iter()
                    .map(|override_| override_.into())
                    .collect(),
            ),
        )
        .expect("Failed to create simulation engine");
        Self(engine)
    }

    /// Simulate a Starknet transaction.
    ///
    /// # Arguments
    ///
    /// * `params` - The simulation parameters of type `StarknetSimulationParameters`.
    #[allow(unused_variables)]
    fn run_sim(
        mut self_: PyRefMut<Self>,
        params: StarknetSimulationParameters,
    ) -> PyResult<StarknetSimulationResult> {
        match self_.0.simulate(&params.into()) {
            Ok(sim_res) => Ok(sim_res.into()),
            Err(sim_err) => Err(PyErr::from(StarknetSimulationErrorDetails::from(sim_err))),
        }
    }
}
