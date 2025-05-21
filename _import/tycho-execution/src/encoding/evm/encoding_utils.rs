use alloy_primitives::{Keccak256, U256};
use alloy_sol_types::SolValue;
use num_bigint::BigUint;
use tycho_common::Bytes;

use crate::encoding::{
    errors::EncodingError,
    evm::utils::{biguint_to_u256, bytes_to_address},
    models::{EncodedSolution, NativeAction, Solution, Transaction},
};

/// Encodes the input data for a function call to the given function selector.
pub fn encode_input(selector: &str, mut encoded_args: Vec<u8>) -> Vec<u8> {
    let mut hasher = Keccak256::new();
    hasher.update(selector.as_bytes());
    let selector_bytes = &hasher.finalize()[..4];
    let mut call_data = selector_bytes.to_vec();
    // Remove extra prefix if present (32 bytes for dynamic data)
    // Alloy encoding is including a prefix for dynamic data indicating the offset or length
    // but at this point we don't want that
    if encoded_args.len() > 32 &&
        encoded_args[..32] ==
            [0u8; 31]
                .into_iter()
                .chain([32].to_vec())
                .collect::<Vec<u8>>()
    {
        encoded_args = encoded_args[32..].to_vec();
    }
    call_data.extend(encoded_args);
    call_data
}

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
/// and proper input argument formatting based on the selector string.
///
/// # ⚠️ Important Responsibility Note
///
/// This function is intended as **an illustrative example only**. **Users must implement
/// their own encoding logic** to ensure:
/// - Full control of parameters passed to the router.
/// - Proper validation and setting of critical inputs such as `minAmountOut`.
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
/// - `encoded_solution`: The solution already encoded by Tycho, including selector and swap path.
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
/// - Returns `EncodingError::FatalError` if the selector is unsupported or required fields (e.g.,
///   permit or signature) are missing.
pub fn encode_tycho_router_call(
    encoded_solution: EncodedSolution,
    solution: &Solution,
    token_in_already_in_router: bool,
    router_address: Bytes,
    native_address: Bytes,
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

    let method_calldata = if encoded_solution
        .selector
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
            encoded_solution
                .permit
                .ok_or(EncodingError::FatalError(
                    "permit2 object must be set to use permit2".to_string(),
                ))?,
            encoded_solution
                .signature
                .ok_or(EncodingError::FatalError(
                    "Signature must be set to use permit2".to_string(),
                ))?
                .as_bytes()
                .to_vec(),
            encoded_solution.swaps,
        )
            .abi_encode()
    } else if encoded_solution
        .selector
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
            !token_in_already_in_router,
            encoded_solution.swaps,
        )
            .abi_encode()
    } else if encoded_solution
        .selector
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
            encoded_solution
                .permit
                .ok_or(EncodingError::FatalError(
                    "permit2 object must be set to use permit2".to_string(),
                ))?,
            encoded_solution
                .signature
                .ok_or(EncodingError::FatalError(
                    "Signature must be set to use permit2".to_string(),
                ))?
                .as_bytes()
                .to_vec(),
            encoded_solution.swaps,
        )
            .abi_encode()
    } else if encoded_solution
        .selector
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
            !token_in_already_in_router,
            encoded_solution.swaps,
        )
            .abi_encode()
    } else if encoded_solution
        .selector
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
            encoded_solution
                .permit
                .ok_or(EncodingError::FatalError(
                    "permit2 object must be set to use permit2".to_string(),
                ))?,
            encoded_solution
                .signature
                .ok_or(EncodingError::FatalError(
                    "Signature must be set to use permit2".to_string(),
                ))?
                .as_bytes()
                .to_vec(),
            encoded_solution.swaps,
        )
            .abi_encode()
    } else if encoded_solution
        .selector
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
            !token_in_already_in_router,
            encoded_solution.swaps,
        )
            .abi_encode()
    } else {
        Err(EncodingError::FatalError("Invalid selector for Tycho router".to_string()))?
    };

    let contract_interaction = encode_input(&encoded_solution.selector, method_calldata);
    let value = if solution.given_token == native_address {
        solution.given_amount.clone()
    } else {
        BigUint::ZERO
    };
    Ok(Transaction { to: router_address, value, data: contract_interaction })
}
