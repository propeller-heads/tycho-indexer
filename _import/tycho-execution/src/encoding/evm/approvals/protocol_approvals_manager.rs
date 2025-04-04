use std::sync::Arc;

use alloy::{
    providers::{Provider, RootProvider},
    rpc::types::{TransactionInput, TransactionRequest},
    transports::BoxTransport,
};
use alloy_primitives::{Address, Bytes, TxKind, U256};
use alloy_sol_types::SolValue;
use tokio::{
    runtime::{Handle, Runtime},
    task::block_in_place,
};

use crate::encoding::{
    errors::EncodingError,
    evm::utils::{encode_input, get_client, get_runtime},
};

/// A manager for checking if an approval is needed for interacting with a certain spender.
pub struct ProtocolApprovalsManager {
    client: Arc<RootProvider<BoxTransport>>,
    runtime_handle: Handle,
    // Store the runtime to prevent it from being dropped before use.
    // This is required since tycho-execution does not have a pre-existing runtime.
    // However, if the library is used in a context where a runtime already exists, it is not
    // necessary to store it.
    #[allow(dead_code)]
    runtime: Option<Arc<Runtime>>,
}
impl ProtocolApprovalsManager {
    pub fn new() -> Result<Self, EncodingError> {
        let (handle, runtime) = get_runtime()?;
        let client = block_in_place(|| handle.block_on(get_client()))?;
        Ok(Self { client, runtime_handle: handle, runtime })
    }

    /// Checks the current allowance for the given token, owner, and spender, and returns true
    /// if the current allowance is zero.
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

        let output = block_in_place(|| {
            self.runtime_handle
                .block_on(async { self.client.call(&tx).await })
        });
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
