use std::str::FromStr;

use alloy::{
    primitives::{keccak256, Address, Keccak256, B256, U256},
    signers::{local::PrivateKeySigner, Signature, SignerSync},
    sol_types::{eip712_domain, SolStruct, SolValue},
};
use num_bigint::BigUint;
use tycho_common::Bytes;
use tycho_contracts::encoding::{
    errors::EncodingError,
    evm::{
        approvals::permit2::PermitSingle,
        utils::{biguint_to_u256, bytes_to_address},
    },
    models,
    models::{EncodedSolution, Solution},
};

/// Represents a transaction to be executed.
///
/// # Fields
/// * `to`: Address of the contract to call with the calldata
/// * `value`: Native token value to be sent with the transaction.
/// * `data`: Encoded calldata for the transaction.
#[derive(Clone, Debug)]
pub struct Transaction {
    pub to: Bytes,
    pub value: BigUint,
    pub data: Vec<u8>,
}

/// Private key for client fee signing in tests.
/// Matches `CLIENT_FEE_RECEIVER_PK` in `foundry/test/Constants.sol`.
/// The corresponding address is `vm.addr(CLIENT_FEE_RECEIVER_PK)`.
const CLIENT_FEE_RECEIVER_PK: &str =
    "0x6789abcdef1234567890abcdef1234567890abcdef1234567890abcdef123456";

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
/// The encoding includes permit2 support and proper input argument formatting based on the
/// function signature string.
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
/// - `client_fee_bps`: Fee in basis points to be paid to the client (0-10000, where 10000 = 100%)
/// - `client_fee_receiver`: Address to receive the client fee
/// - `max_client_contribution`: Maximum amount the client is willing to pay out of pocket to
///   subsidize this trade. This represents the maximum slippage the client will cover. If
///   (min_amount_out - actual_swap_output) > max_client_contribution, the tx reverts.
///
/// # Returns
/// A `Result<Transaction, EncodingError>` that either contains the full transaction data (to,
/// value, data), or an error if the inputs are invalid.
///
/// # Errors
/// - Returns `EncodingError::FatalError` if the function signature is unsupported or required
///   fields (e.g., permit or signature) are missing.
#[allow(clippy::too_many_arguments)]
pub fn encode_tycho_router_call(
    chain_id: u64,
    encoded_solution: EncodedSolution,
    solution: &Solution,
    native_address: &Bytes,
    signer: Option<PrivateKeySigner>,
    client_fee_bps: u16,
    client_fee_receiver: Bytes,
    max_client_contribution: BigUint,
) -> Result<Transaction, EncodingError> {
    let given_amount = biguint_to_u256(solution.amount_in());
    let min_amount_out = biguint_to_u256(solution.min_amount_out());
    let given_token = bytes_to_address(solution.token_in())?;
    let checked_token = bytes_to_address(solution.token_out())?;
    let receiver = bytes_to_address(solution.receiver())?;
    let n_tokens = U256::from(encoded_solution.n_tokens());
    let max_client_contribution = biguint_to_u256(&max_client_contribution);
    let deadline = U256::MAX;
    let (client_fee_receiver, client_signature) = if client_fee_receiver == Bytes::zero(20) {
        (Address::ZERO, vec![])
    } else {
        let router_address = bytes_to_address(encoded_solution.interacting_with())?;
        let client_fee_receiver = bytes_to_address(&client_fee_receiver)?;
        let sig = sign_client_fee(
            chain_id,
            router_address,
            client_fee_bps,
            client_fee_receiver,
            max_client_contribution,
            deadline,
        )?;
        (client_fee_receiver, sig)
    };

    // ABI tuple matching ClientFeeParams: (uint16, address, uint256, uint256, bytes)
    let client_fee_params =
        (client_fee_bps, client_fee_receiver, max_client_contribution, deadline, client_signature);
    let permit_single = encoded_solution.permit().cloned();
    let (permit, signature) = if let Some(ref p) = permit_single {
        let permit = Some(
            PermitSingle::try_from(p)
                .map_err(|_| EncodingError::InvalidInput("Invalid permit".to_string()))?,
        );
        let signer = signer
            .ok_or(EncodingError::FatalError("Signer must be set to use permit2".to_string()))?;
        let signature = sign_permit(chain_id, p, signer)?;
        (permit, signature.as_bytes().to_vec())
    } else {
        (None, vec![])
    };

    let function_signature = encoded_solution.function_signature();
    let swaps = encoded_solution.swaps().to_vec();

    let method_calldata = if function_signature.contains("singleSwapPermit2") {
        (
            given_amount,
            given_token,
            checked_token,
            min_amount_out,
            receiver,
            client_fee_params,
            permit.ok_or(EncodingError::FatalError(
                "permit2 object must be set to use permit2".to_string(),
            ))?,
            signature,
            swaps,
        )
            .abi_encode()
    } else if function_signature.contains("singleSwapUsingVault") ||
        function_signature.contains("singleSwap")
    {
        (
            given_amount,
            given_token,
            checked_token,
            min_amount_out,
            receiver,
            client_fee_params,
            swaps,
        )
            .abi_encode()
    } else if function_signature.contains("sequentialSwapPermit2") {
        (
            given_amount,
            given_token,
            checked_token,
            min_amount_out,
            receiver,
            client_fee_params,
            permit.ok_or(EncodingError::FatalError(
                "permit2 object must be set to use permit2".to_string(),
            ))?,
            signature,
            swaps,
        )
            .abi_encode()
    } else if function_signature.contains("sequentialSwapUsingVault") ||
        function_signature.contains("sequentialSwap")
    {
        (
            given_amount,
            given_token,
            checked_token,
            min_amount_out,
            receiver,
            client_fee_params,
            swaps,
        )
            .abi_encode()
    } else if function_signature.contains("splitSwapPermit2") {
        (
            given_amount,
            given_token,
            checked_token,
            min_amount_out,
            n_tokens,
            receiver,
            client_fee_params,
            permit.ok_or(EncodingError::FatalError(
                "permit2 object must be set to use permit2".to_string(),
            ))?,
            signature,
            swaps,
        )
            .abi_encode()
    } else if function_signature.contains("splitSwapUsingVault") ||
        function_signature.contains("splitSwap")
    {
        (
            given_amount,
            given_token,
            checked_token,
            min_amount_out,
            n_tokens,
            receiver,
            client_fee_params,
            swaps,
        )
            .abi_encode()
    } else {
        Err(EncodingError::FatalError("Invalid function signature for Tycho router".to_string()))?
    };

    let contract_interaction = encode_input(function_signature, method_calldata);
    let value = if solution.token_in() == native_address {
        solution.amount_in().clone()
    } else {
        BigUint::ZERO
    };
    Ok(Transaction {
        to: encoded_solution
            .interacting_with()
            .clone(),
        value,
        data: contract_interaction,
    })
}

/// Signs `ClientFeeParams` using EIP-712, with the hardcoded `CLIENT_FEE_RECEIVER_PK`
/// that matches `foundry/test/Constants.sol`.
///
/// The signer address equals `vm.addr(CLIENT_FEE_RECEIVER_PK)` and must match the
/// `clientFeeReceiver` field passed in.
///
/// Uses `deadline = U256::MAX` so signatures never expire in fork tests.
fn sign_client_fee(
    chain_id: u64,
    router_address: Address,
    client_fee_bps: u16,
    client_fee_receiver: Address,
    max_client_contribution: U256,
    deadline: U256,
) -> Result<Vec<u8>, EncodingError> {
    let signer = PrivateKeySigner::from_str(CLIENT_FEE_RECEIVER_PK)
        .map_err(|e| EncodingError::FatalError(format!("Invalid CLIENT_FEE_RECEIVER_PK: {e}")))?;

    assert_eq!(signer.address(), client_fee_receiver);
    // Must match CLIENT_FEE_TYPEHASH in TychoRouter.sol.
    let type_hash: B256 = keccak256(
        b"ClientFee(uint16 clientFeeBps,address clientFeeReceiver,\
uint256 maxClientContribution,uint256 deadline)",
    );

    // EIP-712 domain separator for TychoRouter ("TychoRouter", "1")
    let domain_type_hash: B256 = keccak256(
        b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
    );
    let domain_separator: B256 = keccak256(
        (
            domain_type_hash,
            keccak256(b"TychoRouter"),
            keccak256(b"1"),
            U256::from(chain_id),
            router_address,
        )
            .abi_encode(),
    );

    let struct_hash: B256 = keccak256(
        (
            type_hash,
            U256::from(client_fee_bps),
            client_fee_receiver,
            max_client_contribution,
            deadline,
        )
            .abi_encode(),
    );

    // Digest: keccak256("\x19\x01" ++ domainSeparator ++ structHash)
    let mut data = [0u8; 66];
    data[0] = 0x19;
    data[1] = 0x01;
    data[2..34].copy_from_slice(domain_separator.as_ref());
    data[34..66].copy_from_slice(struct_hash.as_ref());
    let digest: B256 = keccak256(data);

    signer
        .sign_hash_sync(&digest)
        .map(|sig| sig.as_bytes().to_vec())
        .map_err(|e| EncodingError::FatalError(format!("Failed to sign ClientFeeParams: {e}")))
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
fn sign_permit(
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

/// Encodes the input data for a function call to the given function selector.
fn encode_input(selector: &str, mut encoded_args: Vec<u8>) -> Vec<u8> {
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
