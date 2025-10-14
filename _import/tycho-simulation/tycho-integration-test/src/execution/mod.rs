use std::str::FromStr;

use alloy::{
    rpc::types::{state::AccountOverride, Block},
    sol_types::SolValue,
};
use miette::{miette, IntoDiagnostic};
use num_bigint::BigUint;
use tokio_retry2::{
    strategy::{jitter, ExponentialFactorBackoff},
    Retry, RetryError,
};
use tracing::info;
use tycho_execution::encoding::models::{Solution, Transaction};
use tycho_simulation::foundry_evm::revm::primitives::{map::AddressHashMap, Address, U256};

use crate::{execution::execution_simulator::ExecutionSimulator, RPCTools};

pub mod encoding;
mod execution_simulator;
mod four_byte_client;
pub mod tenderly;
mod traces;

pub async fn simulate_swap_transaction(
    rpc_tools: &RPCTools,
    simulation_id: &str,
    solution: &Solution,
    transaction: &Transaction,
    block: &Block,
) -> Result<
    BigUint,
    (miette::Error, Option<AddressHashMap<AccountOverride>>, Option<tenderly::OverwriteMetadata>),
> {
    let user_address = Address::from_slice(&solution.sender[..20]);
    let request =
        encoding::swap_request(transaction, block, user_address).map_err(|e| (e, None, None))?;
    let (state_overwrites, metadata) =
        encoding::setup_user_overwrites(rpc_tools, solution, transaction, block, user_address)
            .await
            .map_err(|e| (e, None, None))?;

    // Use debug_traceCall from the start with retry logic
    // Worst case, it will take ~100s (20 retries with max 5s delay)
    let retry_strategy = ExponentialFactorBackoff::from_millis(1000, 2.)
        .max_delay_millis(5000)
        .map(jitter)
        .take(20);

    // Clone state_overwrites before moving into closure
    let state_overwrites_for_retry = state_overwrites.clone();
    let result = Retry::spawn(retry_strategy, move || {
        let mut simulator = ExecutionSimulator::new(rpc_tools.rpc_url.clone());
        let request = request.clone();
        let state_overwrites = state_overwrites_for_retry.clone();

        async move {
            match simulator
                .simulate_with_trace(request, Some(state_overwrites), block.number())
                .await
            {
                Ok(res) => Ok(res),
                Err(e) => Err(RetryError::transient(e)),
            }
        }
    })
    .await
    .map_err(|e| {
        (
            miette!("{e}").wrap_err("Failed to simulate transaction after retries"),
            Some(state_overwrites.clone()),
            Some(metadata.clone()),
        )
    })?;

    match result {
        execution_simulator::SimulationResult::Success { return_data, gas_used } => {
            info!("[{simulation_id}] Transaction succeeded, gas used: {gas_used}");
            let amount_out = U256::abi_decode(&return_data).map_err(|e| {
                (
                    miette!("Failed to decode swap amount: {e:?}"),
                    Some(state_overwrites.clone()),
                    Some(metadata.clone()),
                )
            })?;
            BigUint::from_str(amount_out.to_string().as_str())
                .into_diagnostic()
                .map_err(|e| (e, Some(state_overwrites.clone()), Some(metadata.clone())))
        }
        execution_simulator::SimulationResult::Revert { reason } => Err((
            miette!("Transaction reverted: {}", reason),
            Some(state_overwrites),
            Some(metadata),
        )),
    }
}
