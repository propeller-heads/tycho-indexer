use std::{env, sync::Arc};

use alloy::{
    providers::{Provider, ProviderBuilder, RootProvider},
    rpc::types::{TransactionInput, TransactionRequest},
    transports::BoxTransport,
};
use alloy_primitives::{Address, Bytes, TxKind, U256};
use alloy_sol_types::SolValue;
use dotenv::dotenv;
use tokio::runtime::Runtime;

use crate::encoding::{errors::EncodingError, evm::utils::encode_input};

#[allow(dead_code)]
pub struct ProtocolApprovalsManager {
    client: Arc<RootProvider<BoxTransport>>,
    runtime: Runtime,
}
impl ProtocolApprovalsManager {
    pub fn new() -> Result<Self, EncodingError> {
        let runtime = Runtime::new()
            .map_err(|_| EncodingError::FatalError("Failed to create runtime".to_string()))?;
        let client = runtime.block_on(get_client())?;
        Ok(Self { client, runtime })
    }
    pub fn approval_needed(
        &self,
        token: Address,
        owner_address: Address,
        spender_address: Address,
    ) -> Result<bool, EncodingError> {
        let args = (owner_address, spender_address);
        let data = encode_input("allowance(address,address)", args.abi_encode());
        let tx = TransactionRequest {
            to: Some(TxKind::from(token)),
            input: TransactionInput { input: Some(Bytes::from(data)), data: None },
            ..Default::default()
        };

        let output = self
            .runtime
            .block_on(async { self.client.call(&tx).await });
        match output {
            Ok(response) => {
                let allowance: U256 = U256::abi_decode(&response, true).map_err(|_| {
                    EncodingError::FatalError("Failed to decode response for allowance".to_string())
                })?;

                Ok(allowance.is_zero())
            }
            Err(err) => Err(EncodingError::RecoverableError(format!(
                "Allowance call failed with error: {:?}",
                err
            ))),
        }
    }
}

pub async fn get_client() -> Result<Arc<RootProvider<BoxTransport>>, EncodingError> {
    dotenv().ok();
    let eth_rpc_url = env::var("ETH_RPC_URL")
        .map_err(|_| EncodingError::FatalError("Missing ETH_RPC_URL in environment".to_string()))?;
    let client = ProviderBuilder::new()
        .on_builtin(&eth_rpc_url)
        .await
        .map_err(|_| EncodingError::FatalError("Failed to build provider".to_string()))?;
    Ok(Arc::new(client))
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use rstest::rstest;

    use super::*;
    #[rstest]
    #[case::approval_not_needed(
        "0xba12222222228d8ba445958a75a0704d566bf2c8",
        "0x2c6a3cd97c6283b95ac8c5a4459ebb0d5fd404f4",
        false
    )]
    #[case::approval_needed(
        "0x2c6a3cd97c6283b95ac8c5a4459ebb0d5fd404f4",
        "0xba12222222228d8ba445958a75a0704d566bf2c8",
        true
    )]
    fn test_approval_needed(#[case] spender: &str, #[case] owner: &str, #[case] expected: bool) {
        let manager = ProtocolApprovalsManager::new().unwrap();

        let token = Address::from_str("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48").unwrap();
        let spender = Address::from_str(spender).unwrap();
        let owner = Address::from_str(owner).unwrap();

        let result = manager
            .approval_needed(token, owner, spender)
            .unwrap();
        assert_eq!(result, expected);
    }
}
