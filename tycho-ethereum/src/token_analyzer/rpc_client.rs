use alloy::providers::{Provider, ProviderBuilder, RootProvider};

use crate::{RPCError, RequestError};

pub struct EthereumRpcClient {
    alloy_client: RootProvider,
}

impl EthereumRpcClient {
    pub fn new_from_url(rpc_url: &str) -> Self {
        let provider = ProviderBuilder::new()
            .connect_http(
                rpc_url
                    .parse()
                    .expect("Invalid RPC URL"),
            )
            .root()
            .clone();
        Self { alloy_client: provider }
    }

    pub async fn get_block_number(&self) -> Result<u64, RPCError> {
        self.alloy_client
            .get_block_number()
            .await
            .map_err(|e| RPCError::RequestError(RequestError::Other(e.to_string())))
    }
}
