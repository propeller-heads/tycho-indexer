use std::{env, sync::Arc};

use alloy::providers::ProviderBuilder;
use dotenv::dotenv;
use tokio::runtime::Runtime;
use tycho_common::simulation::errors::SimulationError;

use crate::evm::engine_db::simulation_db::EVMProvider;

pub fn get_runtime() -> Result<Option<Arc<Runtime>>, SimulationError> {
    if tokio::runtime::Handle::try_current().is_ok() {
        Err(SimulationError::FatalError(
            "A Tokio runtime is already running in this context".to_string(),
        ))?;
    }

    Runtime::new()
        .map(|runtime| Some(Arc::new(runtime)))
        .map_err(|err| {
            SimulationError::FatalError(format!("Failed to create Tokio runtime: {err}"))
        })
}

pub fn get_client(rpc_url: Option<String>) -> Result<Arc<EVMProvider>, SimulationError> {
    let runtime = get_runtime()?.ok_or(SimulationError::FatalError(
        "A Tokio runtime is required to create the EVM client".to_string(),
    ))?;

    let url = match rpc_url {
        Some(r) => r,
        None => match env::var("RPC_URL") {
            Ok(v) => v,
            Err(_) => {
                dotenv().map_err(|e| {
                    SimulationError::FatalError(format!("Failed to load .env file: {e}"))
                })?;
                env::var("RPC_URL").map_err(|_| {
                    SimulationError::InvalidInput(
                        "RPC_URL environment variable is required when no RPC URL is provided"
                            .to_string(),
                        None,
                    )
                })?
            }
        },
    };

    let connect_future = async {
        ProviderBuilder::new()
            .connect(&url)
            .await
            .map_err(|err| {
                SimulationError::RecoverableError(format!(
                    "Failed to connect to RPC `{url}`: {err}"
                ))
            })
    };

    let client = runtime.block_on(connect_future)?;

    Ok(Arc::new(client))
}
