use std::{env, sync::Arc};

use alloy::{
    providers::{Provider, ProviderBuilder, RootProvider},
    transports::BoxTransport,
};
use alloy_primitives::Address;
use dotenv::dotenv;

pub struct ProtocolApprovalsManager {
    client: Arc<RootProvider<BoxTransport>>,
}
impl ProtocolApprovalsManager {
    pub fn new() -> Self {
        Self {
            client: get_client(),
        }
    }
    pub async fn approval_needed(
        &self,
        token: Address,
        spender_address: Address,
        router_address: Address,
    ) -> bool {
        todo!()
        // should be something like
        // let allowance = self
        //     .client
        //     .call(token, "allowance(address,address)(uint256)", (router_address, spender_address))
        //     .await;
        //
        // allowance == U256::ZERO // If allowance is 0, approval is needed
    }
}

pub fn get_client() -> Arc<RootProvider<BoxTransport>> {
    dotenv().ok();
    let eth_rpc_url = env::var("ETH_RPC_URL").expect("Missing ETH_RPC_URL in environment");
    let runtime = tokio::runtime::Handle::try_current()
        .is_err()
        .then(|| tokio::runtime::Runtime::new().unwrap())
        .unwrap();
    let client = runtime.block_on(async {
        ProviderBuilder::new()
            .on_builtin(&eth_rpc_url)
            .await
            .unwrap()
    });
    Arc::new(client)
}
