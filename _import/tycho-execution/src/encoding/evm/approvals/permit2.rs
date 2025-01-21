use std::{str::FromStr, sync::Arc};

use alloy::{
    primitives::{aliases::U48, Address, Bytes as AlloyBytes, TxKind, U160},
    providers::{Provider, RootProvider},
    rpc::types::{TransactionInput, TransactionRequest},
    signers::{local::PrivateKeySigner, SignerSync},
    transports::BoxTransport,
};
use alloy_primitives::{ChainId, U256};
use alloy_sol_types::{eip712_domain, sol, SolStruct, SolValue};
use chrono::Utc;
use tokio::runtime::Runtime;
use tycho_core::Bytes;

use crate::encoding::{
    errors::EncodingError,
    evm::{
        approvals::protocol_approvals_manager::get_client,
        utils::{biguint_to_u256, bytes_to_address, encode_input},
    },
    user_approvals_manager::{Approval, UserApprovalsManager},
};

/// Struct for managing Permit2 operations, including encoding approvals and fetching allowance
/// data.
pub struct Permit2 {
    address: Address,
    client: Arc<RootProvider<BoxTransport>>,
    runtime: Runtime,
    signer: PrivateKeySigner,
    chain_id: ChainId,
}

/// Type alias for representing allowance data as a tuple of (amount, expiration, nonce). Used for
/// decoding
type Allowance = (U160, U48, U48); // (amount, expiration, nonce)
/// Expiration period for permits, set to 30 days (in seconds).
const PERMIT_EXPIRATION: u64 = 30 * 24 * 60 * 60;
/// Expiration period for signatures, set to 30 minutes (in seconds).
const PERMIT_SIG_EXPIRATION: u64 = 30 * 60;

sol! {
     #[derive(PartialEq, Debug)]
    struct PermitSingle {
        PermitDetails details;
        address spender;
        uint256 sigDeadline;
    }

    #[derive(PartialEq, Debug)]
    struct PermitDetails {
        address token;
        uint160 amount;
        uint48 expiration;
        uint48 nonce;
    }
}

#[allow(dead_code)]
impl Permit2 {
    pub fn new(signer: PrivateKeySigner, chain_id: ChainId) -> Result<Self, EncodingError> {
        let runtime = Runtime::new()
            .map_err(|_| EncodingError::FatalError("Failed to create runtime".to_string()))?;
        let client = runtime.block_on(get_client());
        Ok(Self {
            address: Address::from_str("0x000000000022D473030F116dDEE9F6B43aC78BA3")
                .map_err(|_| EncodingError::FatalError("Permit2 address not valid".to_string()))?,
            client,
            runtime,
            signer,
            chain_id,
        })
    }

    /// Fetches allowance data for a specific owner, spender, and token.
    fn get_allowance_data(
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

        let output = self
            .runtime
            .block_on(async { self.client.call(&tx).await });
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
                "Call to permit 2 allowance method failed with error: {:?}",
                err
            ))),
        }
    }
}
impl UserApprovalsManager for Permit2 {
    /// Encodes multiple approvals into ABI-encoded data and signs them.
    fn encode_approvals(&self, approvals: Vec<Approval>) -> Result<Vec<Vec<u8>>, EncodingError> {
        let current_time = Utc::now()
            .naive_utc()
            .and_utc()
            .timestamp() as u64;

        let mut encoded_approvals = Vec::new();

        for approval in approvals {
            let (_, _, nonce) =
                self.get_allowance_data(&approval.owner, &approval.spender, &approval.token)?;
            let expiration = current_time + PERMIT_EXPIRATION;
            let sig_deadline = current_time + PERMIT_SIG_EXPIRATION;

            let details = PermitDetails {
                token: bytes_to_address(&approval.token)?,
                amount: U160::from(biguint_to_u256(&approval.amount)),
                expiration: U48::from(expiration),
                nonce,
            };

            let permit_single = PermitSingle {
                details,
                spender: bytes_to_address(&approval.spender)?,
                sigDeadline: U256::from(sig_deadline),
            };
            let mut encoded = permit_single.abi_encode();

            let domain = eip712_domain! {
                name: "Permit",
                chain_id: self.chain_id,
                verifying_contract: self.address,
            };
            let hash = permit_single.eip712_signing_hash(&domain);
            let signature = self
                .signer
                .sign_hash_sync(&hash)
                .map_err(|e| {
                    EncodingError::FatalError(format!(
                        "Failed to sign permit2 approval with error: {}",
                        e
                    ))
                })?;

            encoded.extend(signature.as_bytes());
            encoded_approvals.push(encoded);
        }

        Ok(encoded_approvals)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use alloy_primitives::{Uint, B256};
    use num_bigint::BigUint;

    use super::*;
    #[test]
    fn test_get_allowance_data() {
        let signer = PrivateKeySigner::random();
        let manager = Permit2::new(signer, 1).unwrap();

        let token = Bytes::from_str("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48").unwrap();
        let owner = Bytes::from_str("0x2c6a3cd97c6283b95ac8c5a4459ebb0d5fd404f4").unwrap();
        let spender = Bytes::from_str("0xba12222222228d8ba445958a75a0704d566bf2c8").unwrap();

        let result = manager
            .get_allowance_data(&owner, &spender, &token)
            .unwrap();
        assert_eq!(
            result,
            (Uint::<160, 3>::from(0), Uint::<48, 1>::from(0), Uint::<48, 1>::from(0))
        );
    }
    #[test]
    fn test_encode_approvals() {
        // Set up a mock private key for signing
        let private_key =
            B256::from_str("4c0883a69102937d6231471b5dbb6204fe512961708279feb1be6ae5538da033")
                .expect("Invalid private key");
        let signer = PrivateKeySigner::from_bytes(&private_key).expect("Failed to create signer");
        let permit2 = Permit2::new(signer, 1).expect("Failed to create Permit2");

        let owner = Bytes::from_str("0x2c6a3cd97c6283b95ac8c5a4459ebb0d5fd404f4").unwrap();
        let spender = Bytes::from_str("0xba12222222228d8ba445958a75a0704d566bf2c8").unwrap();
        let token = Bytes::from_str("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48").unwrap();
        let amount = BigUint::from(1000u64);
        let approvals =
            vec![Approval { owner, spender, token: token.clone(), amount: amount.clone() }];

        let encoded_approvals = permit2
            .encode_approvals(approvals)
            .unwrap();
        assert_eq!(encoded_approvals.len(), 1, "Expected 1 encoded approval");

        let encoded = &encoded_approvals[0];

        // Calculate the PermitSingle ABI-encoded length
        let permit_details_length = 32 + 32 + 32 + 32; // token + amount + expiration + nonce
        let permit_single_length = permit_details_length + 32 + 32; // details + spender + sigDeadline
        let (permit_single_encoded, signature_encoded) = encoded.split_at(permit_single_length);

        assert_eq!(signature_encoded.len(), 65, "Expected 65 bytes for signature");

        let decoded_permit_single = PermitSingle::abi_decode(permit_single_encoded, false)
            .expect("Failed to decode PermitSingle");

        let expected_details = PermitDetails {
            token: bytes_to_address(&token).unwrap(),
            amount: U160::from(biguint_to_u256(&amount)),
            expiration: U48::from(Utc::now().timestamp() as u64 + PERMIT_EXPIRATION),
            nonce: U48::from(0),
        };
        let expected_permit_single = PermitSingle {
            details: expected_details,
            spender: Address::from_str("0xba12222222228d8ba445958a75a0704d566bf2c8").unwrap(),
            sigDeadline: U256::from(Utc::now().timestamp() as u64 + PERMIT_SIG_EXPIRATION),
        };

        assert_eq!(
            decoded_permit_single, expected_permit_single,
            "Decoded PermitSingle does not match expected values"
        );
    }
}
