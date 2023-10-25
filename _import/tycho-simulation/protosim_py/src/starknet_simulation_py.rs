use num_bigint::BigUint;
use protosim::starknet_simulation::{rpc_reader::RpcStateReader, simulation::SimulationEngine};
use pyo3::prelude::*;
use std::collections::HashMap;

use crate::starknet_structs_py::{
    ContractOverride, StarknetSimulationParameters, StarknetSimulationResult,
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
    /// * `chain` - The chain name to use for RPC calls. One of "starknet-mainnet",
    ///   "starknet-goerli", "starknet-goerli2".
    /// * `rpc_endpoint` - The RPC endpoint to use for RPC calls.
    /// * `feeder_url` - The feeder URL to use for RPC calls.
    /// * `contract_overrides` - A list of contract overrides to use for simulation.
    /// * `block_tag` - The block tag to use for RPC calls. One of "latest", "pending". Defaults to
    ///   "latest".
    /// * `block_number` - The block number to use for RPC calls. Overrides `block_tag` if provided.
    #[new]
    #[allow(unused_variables)]
    fn new(
        chain: String,
        rpc_endpoint: String,
        feeder_url: String,
        contract_overrides: Vec<ContractOverride>,
        block_tag: Option<String>,
        block_number: Option<u64>,
    ) -> Self {
        todo!()
    }

    /// Simulate a Starknet transaction.
    ///
    /// # Arguments
    ///
    /// * `params` - The simulation parameters of type `StarknetSimulationParameters`.
    #[allow(unused_variables)]
    fn run_sim(
        self_: PyRef<Self>,
        params: StarknetSimulationParameters,
    ) -> PyResult<StarknetSimulationResult> {
        todo!()
    }

    /// Update the state of the simulation engine.
    #[allow(unused_variables)]
    fn update_state(
        #[allow(unused_mut)] mut self_: PyRefMut<Self>,
        updates: HashMap<String, HashMap<BigUint, BigUint>>,
    ) -> PyResult<HashMap<String, HashMap<BigUint, BigUint>>> {
        todo!()
    }
}
