use std::{str::FromStr, sync::Arc};

use alloy::{
    primitives::{aliases::U48, Address, Bytes as AlloyBytes, TxKind, U160, U256},
    providers::{Provider, RootProvider},
    rpc::types::{TransactionInput, TransactionRequest},
    transports::BoxTransport,
};
use alloy_sol_types::{sol, SolValue};
use chrono::Utc;
use num_bigint::BigUint;
use tokio::{
    runtime::{Handle, Runtime},
    task::block_in_place,
};
use tycho_common::Bytes;

use crate::encoding::{
    errors::EncodingError,
    evm::{
        encoding_utils::encode_input,
        utils::{biguint_to_u256, bytes_to_address, get_client, get_runtime},
    },
    models,
};

/// Struct for managing Permit2 operations, including encoding approvals and fetching allowance
/// data.
#[derive(Clone)]
pub struct Permit2 {
    address: Address,
    client: Arc<RootProvider<BoxTransport>>,
    runtime_handle: Handle,
    // Store the runtime to prevent it from being dropped before use.
    // This is required since tycho-execution does not have a pre-existing runtime.
    // However, if the library is used in a context where a runtime already exists, it is not
    // necessary to store it.
    #[allow(dead_code)]
    runtime: Option<Arc<Runtime>>,
}

/// Type alias for representing allowance data as a tuple of (amount, expiration, nonce). Used for
/// decoding
type Allowance = (U160, U48, U48);
/// Expiration period for permits, set to 30 days (in seconds).
const PERMIT_EXPIRATION: u64 = 30 * 24 * 60 * 60;
/// Expiration period for signatures, set to 30 minutes (in seconds).
const PERMIT_SIG_EXPIRATION: u64 = 30 * 60;

sol! {
     #[derive(Debug)]
    struct PermitSingle {
        PermitDetails details;
        address spender;
        uint256 sigDeadline;
    }

    #[derive(Debug)]
    struct PermitDetails {
        address token;
        uint160 amount;
        uint48 expiration;
        uint48 nonce;
    }
}

impl TryFrom<&PermitSingle> for models::PermitSingle {
    type Error = EncodingError;

    fn try_from(sol: &PermitSingle) -> Result<Self, EncodingError> {
        Ok(models::PermitSingle {
            details: models::PermitDetails {
                token: Bytes::from(sol.details.token.to_vec()),
                amount: BigUint::from_bytes_be(&sol.details.amount.to_be_bytes::<20>()),
                expiration: BigUint::from_bytes_be(
                    &sol.details
                        .expiration
                        .to_be_bytes::<6>(),
                ),
                nonce: BigUint::from_bytes_be(&sol.details.nonce.to_be_bytes::<6>()),
            },
            spender: Bytes::from(sol.spender.to_vec()),
            sig_deadline: BigUint::from_bytes_be(&sol.sigDeadline.to_be_bytes::<32>()),
        })
    }
}

impl TryFrom<&models::PermitSingle> for PermitSingle {
    type Error = EncodingError;

    fn try_from(p: &models::PermitSingle) -> Result<Self, EncodingError> {
        Ok(PermitSingle {
            details: PermitDetails {
                token: bytes_to_address(&p.details.token)?,
                amount: U160::from(biguint_to_u256(&p.details.amount)),
                expiration: U48::from(biguint_to_u256(&p.details.expiration)),
                nonce: U48::from(biguint_to_u256(&p.details.nonce)),
            },
            spender: bytes_to_address(&p.spender)?,
            sigDeadline: biguint_to_u256(&p.sig_deadline),
        })
    }
}

impl Permit2 {
    pub fn new() -> Result<Self, EncodingError> {
        let (handle, runtime) = get_runtime()?;
        let client = block_in_place(|| handle.block_on(get_client()))?;
        Ok(Self {
            address: Address::from_str("0x000000000022D473030F116dDEE9F6B43aC78BA3")
                .map_err(|_| EncodingError::FatalError("Permit2 address not valid".to_string()))?,
            client,
            runtime_handle: handle,
            runtime,
        })
    }

    /// Fetches allowance data for a specific owner, spender, and token.
    fn get_existing_allowance(
        &self,
        owner: &Bytes,
        spender: &Bytes,
        token: &Bytes,
    ) -> Result<Allowance, EncodingError> {
        let args = (bytes_to_address(owner)?, bytes_to_address(token)?, bytes_to_address(spender)?);
        let data = encode_input("allowance(address,address,address)", args.abi_encode());
        let tx = TransactionRequest {
            to: Some(TxKind::from(self.address)),
            input: TransactionInput { input: Some(AlloyBytes::from(data)), data: None },
            ..Default::default()
        };

        let output = block_in_place(|| {
            self.runtime_handle
                .block_on(async { self.client.call(&tx).await })
        });
        match output {
            Ok(response) => {
                let allowance: Allowance =
                    Allowance::abi_decode(&response, true).map_err(|_| {
                        EncodingError::FatalError(
                            "Failed to decode response for permit2 allowance".to_string(),
                        )
                    })?;
                Ok(allowance)
            }
            Err(err) => Err(EncodingError::RecoverableError(format!(
                "Call to permit2 allowance method failed with error: {err}"
            ))),
        }
    }
    /// Creates permit single
    pub fn get_permit(
        &self,
        spender: &Bytes,
        owner: &Bytes,
        token: &Bytes,
        amount: &BigUint,
    ) -> Result<models::PermitSingle, EncodingError> {
        let current_time = Utc::now()
            .naive_utc()
            .and_utc()
            .timestamp() as u64;

        let (_, _, nonce) = self.get_existing_allowance(owner, spender, token)?;
        let expiration = U48::from(current_time + PERMIT_EXPIRATION);
        let sig_deadline = U256::from(current_time + PERMIT_SIG_EXPIRATION);
        let amount = U160::from(biguint_to_u256(amount));

        let details = PermitDetails { token: bytes_to_address(token)?, amount, expiration, nonce };

        let permit_single = PermitSingle {
            details,
            spender: bytes_to_address(spender)?,
            sigDeadline: sig_deadline,
        };

        models::PermitSingle::try_from(&permit_single)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use alloy::signers::local::PrivateKeySigner;
    use alloy_primitives::{Uint, B256};
    use num_bigint::BigUint;
    use tycho_common::models::Chain as TychoCommonChain;

    use super::*;
    use crate::encoding::{evm::encoding_utils::sign_permit, models::Chain};

    // These two implementations are to avoid comparing the expiration and sig_deadline fields
    // because they are timestamps
    impl PartialEq for PermitSingle {
        fn eq(&self, other: &Self) -> bool {
            if self.details != other.details {
                return false;
            }
            if self.spender != other.spender {
                return false;
            }
            true
        }
    }

    impl PartialEq for PermitDetails {
        fn eq(&self, other: &Self) -> bool {
            if self.token != other.token {
                return false;
            }
            if self.amount != other.amount {
                return false;
            }
            // Compare `nonce`
            if self.nonce != other.nonce {
                return false;
            }

            true
        }
    }

    fn eth_chain() -> Chain {
        TychoCommonChain::Ethereum.into()
    }

    #[test]
    fn test_get_existing_allowance() {
        let manager = Permit2::new().unwrap();

        let token = Bytes::from_str("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48").unwrap();
        let owner = Bytes::from_str("0x2c6a3cd97c6283b95ac8c5a4459ebb0d5fd404f4").unwrap();
        let spender = Bytes::from_str("0xba12222222228d8ba445958a75a0704d566bf2c8").unwrap();

        let result = manager
            .get_existing_allowance(&owner, &spender, &token)
            .unwrap();
        assert_eq!(
            result,
            (Uint::<160, 3>::from(0), Uint::<48, 1>::from(0), Uint::<48, 1>::from(0))
        );
    }

    #[test]
    fn test_get_permit() {
        let permit2 = Permit2::new().expect("Failed to create Permit2");

        let owner = Bytes::from_str("0x2c6a3cd97c6283b95ac8c5a4459ebb0d5fd404f4").unwrap();
        let spender = Bytes::from_str("0xba12222222228d8ba445958a75a0704d566bf2c8").unwrap();
        let token = Bytes::from_str("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48").unwrap();
        let amount = BigUint::from(1000u64);

        let permit = permit2
            .get_permit(&spender, &owner, &token, &amount)
            .unwrap();

        let expected_details = models::PermitDetails {
            token,
            amount,
            expiration: BigUint::from(Utc::now().timestamp() as u64 + PERMIT_EXPIRATION),
            nonce: BigUint::from(0u64),
        };
        let expected_permit_single = models::PermitSingle {
            details: expected_details,
            spender: Bytes::from_str("0xba12222222228d8ba445958a75a0704d566bf2c8").unwrap(),
            sig_deadline: BigUint::from(Utc::now().timestamp() as u64 + PERMIT_SIG_EXPIRATION),
        };

        assert_eq!(
            permit, expected_permit_single,
            "Decoded PermitSingle does not match expected values"
        );
    }

    /// This test actually calls the permit method on the Permit2 contract to verify the encoded
    /// data works. It requires an Anvil fork, so please run with the following command: anvil
    /// --fork-url <RPC-URL> And set up the following env var as RPC_URL=127.0.0.1:8545
    /// Use an account from anvil to fill the anvil_account and anvil_private_key variables
    #[test]
    #[cfg_attr(not(feature = "fork-tests"), ignore)]
    fn test_permit() {
        let anvil_account = Bytes::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap();
        let anvil_private_key =
            "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80".to_string();

        let pk = B256::from_str(&anvil_private_key)
            .map_err(|_| {
                EncodingError::FatalError(
                    "Failed to convert swapper private key to B256".to_string(),
                )
            })
            .unwrap();
        let signer = PrivateKeySigner::from_bytes(&pk)
            .map_err(|_| {
                EncodingError::FatalError("Failed to create signer from private key".to_string())
            })
            .unwrap();
        let permit2 = Permit2::new().expect("Failed to create Permit2");

        let token = Bytes::from_str("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48").unwrap();
        let amount = BigUint::from(1000u64);

        // Approve token allowance for permit2 contract
        let approve_function_signature = "approve(address,uint256)";
        let args = (permit2.address, biguint_to_u256(&BigUint::from(1000000u64)));
        let data = encode_input(approve_function_signature, args.abi_encode());

        let tx = TransactionRequest {
            to: Some(TxKind::from(bytes_to_address(&token).unwrap())),
            input: TransactionInput { input: Some(AlloyBytes::from(data)), data: None },
            ..Default::default()
        };
        let receipt = block_in_place(|| {
            permit2.runtime_handle.block_on(async {
                let pending_tx = permit2
                    .client
                    .send_transaction(tx)
                    .await
                    .unwrap();
                // Wait for the transaction to be mined
                pending_tx.get_receipt().await.unwrap()
            })
        });
        assert!(receipt.status(), "Approve transaction failed");

        let spender = Bytes::from_str("0xba12222222228d8ba445958a75a0704d566bf2c8").unwrap();

        let permit = permit2
            .get_permit(&spender, &anvil_account, &token, &amount)
            .unwrap();
        let sol_permit: PermitSingle =
            PermitSingle::try_from(&permit).expect("Failed to convert to PermitSingle");

        let signature = sign_permit(eth_chain().id, &permit, signer).unwrap();
        let encoded =
            (bytes_to_address(&anvil_account).unwrap(), sol_permit, signature.as_bytes().to_vec())
                .abi_encode();

        let function_signature =
            "permit(address,((address,uint160,uint48,uint48),address,uint256),bytes)";
        let data = encode_input(function_signature, encoded.to_vec());

        let tx = TransactionRequest {
            to: Some(TxKind::from(permit2.address)),
            input: TransactionInput { input: Some(AlloyBytes::from(data)), data: None },
            gas: Some(10_000_000u64),
            ..Default::default()
        };

        let result = permit2.runtime_handle.block_on(async {
            let pending_tx = permit2
                .client
                .send_transaction(tx)
                .await
                .unwrap();
            pending_tx.get_receipt().await.unwrap()
        });
        assert!(result.status(), "Permit transaction failed");

        // Assert that the allowance was set correctly in the permit2 contract
        let (allowance_amount, _, nonce) = permit2
            .get_existing_allowance(&anvil_account, &spender, &token)
            .unwrap();
        assert_eq!(allowance_amount, U160::from(biguint_to_u256(&amount)));
        assert_eq!(nonce, U48::from(1));
    }
}
