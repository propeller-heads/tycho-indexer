use std::str::FromStr;

use alloy::{
    primitives::U256,
    signers::{local::PrivateKeySigner, Signature, SignerSync},
};
use alloy_primitives::Address;
use alloy_sol_types::{eip712_domain, SolStruct, SolValue};
use num_bigint::BigUint;
use tycho_common::Bytes;

use crate::encoding::{
    errors::EncodingError,
    evm::{
        approvals::permit2::PermitSingle,
        utils,
        utils::{biguint_to_u256, bytes_to_address},
    },
    models,
    models::{EncodedSolution, NativeAction, Solution, Transaction, UserTransferType},
};

/// Encodes a transaction for the Tycho Router using one of its supported swap methods.
///
/// # Overview
///
/// This function provides an **example implementation** of how to encode a call to the Tycho
/// Router. It handles all currently supported swap selectors such as:
/// - `singleSwap`
/// - `singleSwapPermit2`
/// - `sequentialSwap`
/// - `sequentialSwapPermit2`
/// - `splitSwap`
/// - `splitSwapPermit2`
///
/// The encoding includes handling of native asset wrapping/unwrapping, permit2 support,
/// and proper input argument formatting based on the function signature string.
///
/// # ⚠️ Important Responsibility Note
///
/// This function is intended as **an illustrative example only**. **Users must implement
/// their own encoding logic** to ensure:
/// - Full control of parameters passed to the router.
/// - Proper validation and setting of critical inputs such as `minAmountOut`.
/// - Signing of permit2 objects.
///
/// While Tycho is responsible for encoding the swap paths themselves, the input arguments
/// to the router's methods act as **guardrails** for on-chain execution safety.
/// Thus, the user must **take responsibility** for ensuring correctness of all input parameters,
/// including `minAmountOut`, `receiver`, and permit2 logic.
///
/// # Min Amount Out
///
/// The `minAmountOut` calculation used here is just an example.
/// You should ideally:
/// - Query an external service (e.g., DEX aggregators, oracle, off-chain price feed).
/// - Use your own strategy to determine an accurate and safe minimum acceptable output amount.
///
/// ⚠️ If `minAmountOut` is too low, your swap may be front-run or sandwiched, resulting in loss of
/// funds.
///
/// # Parameters
/// - `encoded_solution`: The solution already encoded by Tycho.
/// - `solution`: The high-level solution including tokens, amounts, and receiver info.
/// - `token_in_already_in_router`: Whether the input token is already present in the router.
/// - `router_address`: The address of the Tycho Router contract.
/// - `native_address`: The address used to represent the native token
///
/// # Returns
/// A `Result<Transaction, EncodingError>` that either contains the full transaction data (to,
/// value, data), or an error if the inputs are invalid.
///
/// # Errors
/// - Returns `EncodingError::FatalError` if the function signature is unsupported or required
///   fields (e.g., permit or signature) are missing.
pub fn encode_tycho_router_call(
    chain_id: u64,
    encoded_solution: EncodedSolution,
    solution: &Solution,
    user_transfer_type: UserTransferType,
    native_address: Bytes,
    signer: Option<PrivateKeySigner>,
) -> Result<Transaction, EncodingError> {
    let (mut unwrap, mut wrap) = (false, false);
    if let Some(action) = solution.native_action.clone() {
        match action {
            NativeAction::Wrap => wrap = true,
            NativeAction::Unwrap => unwrap = true,
        }
    }

    let given_amount = biguint_to_u256(&solution.given_amount);
    let min_amount_out = biguint_to_u256(&solution.checked_amount);
    let given_token = bytes_to_address(&solution.given_token)?;
    let checked_token = bytes_to_address(&solution.checked_token)?;
    let receiver = bytes_to_address(&solution.receiver)?;
    let n_tokens = U256::from(encoded_solution.n_tokens);
    let (permit, signature) = if let Some(p) = encoded_solution.permit {
        let permit = Some(
            PermitSingle::try_from(&p)
                .map_err(|_| EncodingError::InvalidInput("Invalid permit".to_string()))?,
        );
        let signer = signer
            .ok_or(EncodingError::FatalError("Signer must be set to use permit2".to_string()))?;
        let signature = sign_permit(chain_id, &p, signer)?;
        (permit, signature.as_bytes().to_vec())
    } else {
        (None, vec![])
    };

    let method_calldata = if encoded_solution
        .function_signature
        .contains("singleSwapPermit2")
    {
        (
            given_amount,
            given_token,
            checked_token,
            min_amount_out,
            wrap,
            unwrap,
            receiver,
            permit.ok_or(EncodingError::FatalError(
                "permit2 object must be set to use permit2".to_string(),
            ))?,
            signature,
            encoded_solution.swaps,
        )
            .abi_encode()
    } else if encoded_solution
        .function_signature
        .contains("singleSwap")
    {
        (
            given_amount,
            given_token,
            checked_token,
            min_amount_out,
            wrap,
            unwrap,
            receiver,
            user_transfer_type == UserTransferType::TransferFrom,
            encoded_solution.swaps,
        )
            .abi_encode()
    } else if encoded_solution
        .function_signature
        .contains("sequentialSwapPermit2")
    {
        (
            given_amount,
            given_token,
            checked_token,
            min_amount_out,
            wrap,
            unwrap,
            receiver,
            permit.ok_or(EncodingError::FatalError(
                "permit2 object must be set to use permit2".to_string(),
            ))?,
            signature,
            encoded_solution.swaps,
        )
            .abi_encode()
    } else if encoded_solution
        .function_signature
        .contains("sequentialSwap")
    {
        (
            given_amount,
            given_token,
            checked_token,
            min_amount_out,
            wrap,
            unwrap,
            receiver,
            user_transfer_type == UserTransferType::TransferFrom,
            encoded_solution.swaps,
        )
            .abi_encode()
    } else if encoded_solution
        .function_signature
        .contains("splitSwapPermit2")
    {
        (
            given_amount,
            given_token,
            checked_token,
            min_amount_out,
            wrap,
            unwrap,
            n_tokens,
            receiver,
            permit.ok_or(EncodingError::FatalError(
                "permit2 object must be set to use permit2".to_string(),
            ))?,
            signature,
            encoded_solution.swaps,
        )
            .abi_encode()
    } else if encoded_solution
        .function_signature
        .contains("splitSwap")
    {
        (
            given_amount,
            given_token,
            checked_token,
            min_amount_out,
            wrap,
            unwrap,
            n_tokens,
            receiver,
            user_transfer_type == UserTransferType::TransferFrom,
            encoded_solution.swaps,
        )
            .abi_encode()
    } else {
        Err(EncodingError::FatalError("Invalid function signature for Tycho router".to_string()))?
    };

    let contract_interaction =
        utils::encode_input(&encoded_solution.function_signature, method_calldata);
    let value = if solution.given_token == native_address {
        solution.given_amount.clone()
    } else {
        BigUint::ZERO
    };
    Ok(Transaction { to: encoded_solution.interacting_with, value, data: contract_interaction })
}

/// Signs a Permit2 `PermitSingle` struct using the EIP-712 signing scheme.
///
/// This function constructs an EIP-712 domain specific to the Permit2 contract and computes the
/// hash of the provided `PermitSingle`. It then uses the given `PrivateKeySigner` to produce
/// a cryptographic signature of the permit.
///
/// # Warning
/// This is only an **example implementation** provided for reference purposes.
/// **Do not rely on this in production.** You should implement your own version.
pub fn sign_permit(
    chain_id: u64,
    permit_single: &models::PermitSingle,
    signer: PrivateKeySigner,
) -> Result<Signature, EncodingError> {
    let permit2_address = Address::from_str("0x000000000022D473030F116dDEE9F6B43aC78BA3")
        .map_err(|_| EncodingError::FatalError("Permit2 address not valid".to_string()))?;
    let domain = eip712_domain! {
        name: "Permit2",
        chain_id: chain_id,
        verifying_contract: permit2_address,
    };
    let permit_single: PermitSingle = PermitSingle::try_from(permit_single)?;
    let hash = permit_single.eip712_signing_hash(&domain);
    signer
        .sign_hash_sync(&hash)
        .map_err(|e| {
            EncodingError::FatalError(format!("Failed to sign permit2 approval with error: {e}"))
        })
}
