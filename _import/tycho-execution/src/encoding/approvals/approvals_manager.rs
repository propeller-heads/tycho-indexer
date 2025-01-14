use std::{env, sync::Arc};

use crate::encoding::approvals::interface::{Approval, ApprovalsManager};
use alloy::{
    providers::{Provider, ProviderBuilder, RootProvider},
    transports::BoxTransport,
};
use dotenv::dotenv;

pub struct TokenApprovalsManager {
    client: Arc<RootProvider<BoxTransport>>,
}
impl TokenApprovalsManager {
    pub fn new() -> Self {
        Self {
            client: get_client(),
        }
    }
    pub async fn approval_needed(&self, approval: Approval) -> bool {
        todo!()
    }
}

impl ApprovalsManager for TokenApprovalsManager {
    fn encode_approvals(&self, approvals: Vec<Approval>) -> Vec<u8> {
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
