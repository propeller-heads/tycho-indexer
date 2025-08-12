use ethers::providers::{Http, Middleware, Provider};

use crate::RPCError;

pub struct EthereumRpcClient {
    ethers_client: ethers::providers::Provider<Http>,
}

impl EthereumRpcClient {
    pub fn new_from_url(rpc_url: &str) -> Self {
        Self {
            ethers_client: Provider::<Http>::try_from(rpc_url)
                .expect("Error creating HTTP provider"),
        }
    }

    pub async fn get_block_number(&self) -> Result<u64, RPCError> {
        self.ethers_client
            .get_block_number()
            .await
            .map(|number| number.as_u64())
            .map_err(|e| RPCError::RequestError(e.to_string()))
    }
}
