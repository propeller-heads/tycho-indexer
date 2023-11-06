use protosim::{
    rpc_state_reader::rpc_state::{BlockTag, BlockValue, RpcChain, RpcState},
    starknet_api::{block::BlockNumber, hash::StarkFelt},
    starknet_simulation::{rpc_reader::RpcStateReader, simulation::SimulationEngine},
};
use pyo3::prelude::*;
use std::sync::Arc;

use crate::starknet_structs_py::{
    ContractOverride, StarknetSimulationErrorDetails, StarknetSimulationParameters,
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
    /// * `chain` - The chain name to use for RPC calls. One of "starknet-mainnet",
    ///   "starknet-goerli", "starknet-goerli2".
    /// * `rpc_endpoint` - The RPC endpoint to use for RPC calls.
    /// * `feeder_url` - The feeder URL to use for RPC calls.
    /// * `contract_overrides` - A list of contract overrides to use for simulation.
    /// * `block` - The block to use for RPC calls. Either a block number as a decimal string, a
    ///   block tag of "latest" or "pending", or block hash as a hex string prefixed with 0x.
    #[new]
    #[allow(unused_variables)]
    fn new(
        chain: String,
        rpc_endpoint: String,
        feeder_url: String,
        contract_overrides: Vec<ContractOverride>,
        block: String,
    ) -> Self {
        let block = match block.parse::<u64>() {
            Ok(block_number) => BlockValue::Number(BlockNumber(block_number)),
            Err(_) => match block.as_str() {
                "latest" => BlockValue::Tag(BlockTag::Latest),
                "pending" => BlockValue::Tag(BlockTag::Pending),
                val => BlockValue::Hash(StarkFelt::try_from(val).unwrap()),
            },
        };
        let chain = match chain.as_str() {
            "starknet-mainnet" => RpcChain::MainNet,
            "starknet-goerli" => RpcChain::TestNet,
            "starknet-goerli2" => RpcChain::TestNet2,
            _ => panic!("Invalid chain {}", chain),
        };
        let state_reader =
            RpcStateReader::new(RpcState::new(chain, block, &rpc_endpoint, &feeder_url));
        let engine = SimulationEngine::new(
            Arc::new(state_reader),
            contract_overrides
                .into_iter()
                .map(Into::into),
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
