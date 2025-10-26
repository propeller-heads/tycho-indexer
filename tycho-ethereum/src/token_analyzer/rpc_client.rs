use alloy::rpc::{
    client::{ClientBuilder, ReqwestClient},
    types::BlockNumberOrTag,
};

use crate::{RPCError, RequestError};

pub struct EthereumRpcClient {
    rpc: ReqwestClient,
}

impl EthereumRpcClient {
    pub fn new_from_url(rpc_url: &str) -> Self {
        let url = rpc_url
            .parse()
            .expect("Invalid RPC URL");
        let rpc = ClientBuilder::default().http(url);
        Self { rpc }
    }

    pub fn new(rpc: ReqwestClient) -> Self {
        Self { rpc }
    }

    pub async fn get_block_number(&self) -> Result<u64, RPCError> {
        let block_number: BlockNumberOrTag = self
            .rpc
            .request_noparams("eth_blockNumber")
            .await
            .map_err(|e| RPCError::RequestError(RequestError::Other(e.to_string())))?;

        if let BlockNumberOrTag::Number(num) = block_number {
            Ok(num)
        } else {
            Err(RPCError::RequestError(RequestError::Other("Unexpected block ID type".to_string())))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "require RPC connection"]
    async fn test_get_block_number() -> Result<(), RPCError> {
        let rpc_url = std::env::var("RPC_URL").expect("RPC_URL must be set for testing");
        let client = EthereumRpcClient::new_from_url(&rpc_url);

        let block_number = client.get_block_number().await?;

        // For Ethereum mainnet, we know block numbers are in the millions
        // This is a sanity check to ensure we're not getting garbage data
        assert!(
            block_number > 20_378_314,
            "Block number seems too low for Ethereum mainnet: {}",
            block_number
        );

        Ok(())
    }
}
