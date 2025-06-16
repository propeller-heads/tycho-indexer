use std::{env, sync::Arc};

use alloy::providers::ProviderBuilder;
use dotenv::dotenv;
use tokio::runtime::Runtime;

use crate::evm::engine_db::simulation_db::EVMProvider;

pub fn get_runtime() -> Option<Arc<Runtime>> {
    let runtime = tokio::runtime::Handle::try_current()
        .is_err()
        .then(|| Runtime::new().unwrap())
        .unwrap();
    Some(Arc::new(runtime))
}

pub fn get_client(rpc_url: Option<String>) -> Arc<EVMProvider> {
    let runtime = get_runtime().unwrap();
    let url = if let Some(r) = rpc_url {
        r
    } else {
        env::var("RPC_URL").unwrap_or_else(|_| {
            dotenv().expect("Missing .env file");
            env::var("RPC_URL").expect("Missing RPC_URL in .env file")
        })
    };
    let client = runtime.block_on(async {
        ProviderBuilder::new()
            .connect(&url)
            .await
            .unwrap()
    });
    Arc::new(client)
}
