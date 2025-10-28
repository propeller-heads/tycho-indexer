use std::collections::HashMap;

use alloy::{
    primitives::U256,
    rpc::types::{state::AccountOverride, Block},
    sol_types::SolValue,
};
use miette::miette;
use tokio_retry2::{
    strategy::{jitter, ExponentialFactorBackoff},
    Retry, RetryError,
};
use tycho_simulation::{
    evm::protocol::u256_num::u256_to_biguint,
    foundry_evm::revm::primitives::{map::AddressHashMap, Address},
};

use crate::{
    execution::{
        execution_simulator::ExecutionSimulator,
        models::{SimulationInput, SimulationResult, TychoExecutionInfo, TychoExecutionResult},
    },
    RPCTools,
};

pub mod encoding;
mod execution_simulator;
mod four_byte_client;
pub mod models;
pub mod tenderly;
mod traces;

pub async fn simulate_swap_transaction(
    rpc_tools: &RPCTools,
    execution_info: HashMap<String, TychoExecutionInfo>,
    block: &Block,
) -> Result<
    HashMap<String, TychoExecutionResult>,
    (miette::Error, Option<AddressHashMap<AccountOverride>>, Option<tenderly::OverwriteMetadata>),
> {
    let mut inputs: HashMap<String, SimulationInput> = HashMap::new();
    let mut tycho_execution_results: HashMap<String, TychoExecutionResult> = HashMap::new();

    // Get to_address from the first transaction (same for all transactions - tycho router)
    let to_address = execution_info
        .values()
        .next()
        .map(|info| info.transaction.to.clone())
        .expect("To address must be set");

    for (simulation_id, info) in &execution_info {
        let user_address = Address::from_slice(&info.solution.sender[..20]);

        let request = match encoding::swap_request(&info.transaction, block, user_address) {
            Ok(request) => request,
            Err(e) => {
                tycho_execution_results.insert(
                    simulation_id.clone(),
                    TychoExecutionResult::Failed {
                        error_msg: format!("Failed to create swap request: {}", e),
                    },
                );
                continue;
            }
        };

        let (state_overwrites, metadata) = match encoding::setup_user_overwrites(
            rpc_tools,
            block,
            &to_address,
            &info.solution.given_token,
            &info.solution.given_amount,
        )
        .await
        {
            Ok((overwrites, metadata)) => (overwrites, metadata),
            Err(e) => {
                tycho_execution_results.insert(
                    simulation_id.clone(),
                    TychoExecutionResult::Failed {
                        error_msg: format!("Failed to setup user overwrites: {}", e),
                    },
                );
                continue;
            }
        };

        inputs.insert(
            simulation_id.clone(),
            SimulationInput {
                tx: request,
                state_overwrites: Some(state_overwrites),
                overwrite_metadata: Some(metadata),
            },
        );
    }

    // If no transactions left to simulate, return early
    if inputs.is_empty() {
        return Ok(tycho_execution_results);
    }

    // Use debug_traceCallMany from the start with retry logic
    // Worst case, it will take ~100s (20 retries with max 5s delay)
    let retry_strategy = ExponentialFactorBackoff::from_millis(1000, 2.)
        .max_delay_millis(5000)
        .map(jitter)
        .take(20);

    // Clone inputs before moving into closure
    let inputs_for_retry = inputs.clone();
    let execution_results = Retry::spawn(retry_strategy, move || {
        let mut simulator = ExecutionSimulator::new(rpc_tools.rpc_url.clone());
        let inputs = inputs_for_retry.clone();

        async move {
            match simulator
                .batch_simulate_with_trace(inputs, block)
                .await
            {
                Ok(res) => Ok(res),
                Err(e) => Err(RetryError::transient(e)),
            }
        }
    })
    .await
    .map_err(|e| {
        (miette!("{e}").wrap_err("Failed to simulate transaction after retries"), None, None)
    })?;

    // Process simulation results and add successful simulations to tycho_execution_results
    for (simulation_id, result) in execution_results {
        match result {
            SimulationResult::Success { return_data, gas_used } => {
                match U256::abi_decode(&return_data) {
                    Ok(amount_out) => {
                        tycho_execution_results.insert(
                            simulation_id,
                            TychoExecutionResult::Success {
                                amount_out: u256_to_biguint(amount_out),
                                gas_used,
                            },
                        );
                    }
                    Err(e) => {
                        tycho_execution_results.insert(
                            simulation_id,
                            TychoExecutionResult::Failed {
                                error_msg: format!("Failed to decode swap amount: {e:?}"),
                            },
                        );
                    }
                }
            }
            SimulationResult::Revert { reason } => {
                let simulation_input = inputs
                    .get(&simulation_id)
                    .expect("Simulation must be present in inputs HashMap")
                    .clone();
                let overwrite_metadata = simulation_input.overwrite_metadata;
                let state_overwrites = simulation_input.state_overwrites;
                tycho_execution_results.insert(
                    simulation_id,
                    TychoExecutionResult::Revert { reason, state_overwrites, overwrite_metadata },
                );
            }
        }
    }

    Ok(tycho_execution_results)
}
