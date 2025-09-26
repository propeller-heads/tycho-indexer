//! Transaction encoding utilities for swap solutions.
//!
//! This module provides functions to encode swap parameters into executable transactions
//! using the Tycho framework. It handles the conversion of high-level swap
//! specifications into low-level transaction data that can be executed on-chain.

use std::str::FromStr;

use alloy::{primitives::Keccak256, sol_types::SolValue};
use miette::{IntoDiagnostic, WrapErr};
use num_bigint::BigUint;
use serde_json::json;
use tycho_simulation::{
    evm::protocol::u256_num::biguint_to_u256,
    protocol::models::ProtocolComponent,
    tycho_common::{dto::Chain, Bytes},
    tycho_execution::encoding::{
        errors::EncodingError,
        evm::{encoder_builders::TychoRouterEncoderBuilder, utils::bytes_to_address},
        models::{
            EncodedSolution, NativeAction, Solution, SwapBuilder, Transaction, UserTransferType,
        },
    },
};

use crate::execution::EXECUTOR_ADDRESS;

/// Creates a Solution for the given swap parameters.
///
/// # Parameters
/// - `component`: The protocol component to swap through
/// - `token_in`: Input token address
/// - `token_out`: Output token address
/// - `amount_in`: Amount of input token to swap
/// - `amount_out`: Expected amount of output token
///
/// # Returns
/// A `Result<Solution, EncodingError>` containing the solution, or an error if creation fails.
pub fn get_solution(
    component: &ProtocolComponent,
    token_in: &Bytes,
    token_out: &Bytes,
    amount_in: &BigUint,
    amount_out: &BigUint,
) -> miette::Result<Solution> {
    let user_address = Bytes::from_str("0xf847a638E44186F3287ee9F8cAF73FF4d4B80784")
        .into_diagnostic()
        .wrap_err("Failed to parse Alice's address for Tycho router encoding")?;

    let swap = SwapBuilder::new(component.clone(), token_in.clone(), token_out.clone()).build();

    let slippage = 0.0025; // 0.25% slippage
    let bps = BigUint::from(10_000u32);
    let slippage_percent = BigUint::from((slippage * 10000.0) as u32);
    let multiplier = &bps - slippage_percent;
    let min_amount_out = (amount_out * &multiplier) / &bps;

    Ok(Solution {
        sender: user_address.clone(),
        receiver: user_address.clone(),
        given_token: token_in.clone(),
        given_amount: amount_in.clone(),
        checked_token: token_out.clone(),
        exact_out: false,
        checked_amount: min_amount_out,
        swaps: vec![swap],
        ..Default::default()
    })
}

/// Encodes swap data for the Tycho router.
///
/// Assumes a single swap solution and encodes the data ready to be used by the Tycho router
/// directly.
///
/// # Parameters
/// - `component`: The protocol component to swap through
/// - `token_in`: Input token address
/// - `token_out`: Output token address
/// - `amount_in`: Amount of input token to swap
/// - `amount_out`: Expected amount of output token
///
/// # Returns
/// A `Result<Transaction, EncodingError>` containing the encoded transaction data for the Tycho
/// router, or an error if encoding fails.
pub fn encode_swap(
    component: &ProtocolComponent,
    token_in: &Bytes,
    token_out: &Bytes,
    amount_in: &BigUint,
    amount_out: &BigUint,
) -> miette::Result<(Transaction, Solution)> {
    let protocol_system = component.protocol_system.clone();
    let executors_json = json!({
        "ethereum": {
            (protocol_system):EXECUTOR_ADDRESS
        }
    })
    .to_string();

    let chain: tycho_simulation::tycho_common::models::Chain = Chain::Ethereum.into();

    let encoder = TychoRouterEncoderBuilder::new()
        .chain(chain)
        .user_transfer_type(UserTransferType::TransferFrom)
        .executors_addresses(executors_json)
        .historical_trade()
        .build()
        .into_diagnostic()
        .wrap_err("Failed to build encoder")?;

    let solution = get_solution(component, token_in, token_out, amount_in, amount_out)?;

    let encoded_solution = encoder
        .encode_solutions(vec![solution.clone()])
        .into_diagnostic()
        .wrap_err("Failed to encode solution")?[0]
        .clone();

    let transaction =
        encode_tycho_router_call(encoded_solution, &solution, &chain.native_token().address)
            .into_diagnostic()
            .wrap_err("Failed to encode router calldata")?;
    Ok((transaction, solution))
}

/// Encodes a transaction for the Tycho Router using `singleSwap` method and regular token
/// transfers.
///
/// # Parameters
/// - `encoded_solution`: The solution already encoded by Tycho.
/// - `solution`: The high-level solution including tokens, amounts, and receiver info.
/// - `native_address`: The address used to represent the native token
///
/// # Returns
/// A `Result<Transaction, EncodingError>` that either contains the full transaction data (to,
/// value, data), or an error if the inputs are invalid.
pub fn encode_tycho_router_call(
    encoded_solution: EncodedSolution,
    solution: &Solution,
    native_address: &Bytes,
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

    let method_calldata = if encoded_solution
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
            true,
            encoded_solution.swaps,
        )
            .abi_encode()
    } else {
        Err(EncodingError::FatalError("Invalid function signature for Tycho router".to_string()))?
    };

    let contract_interaction = encode_input(&encoded_solution.function_signature, method_calldata);
    let value = if solution.given_token == *native_address {
        solution.given_amount.clone()
    } else {
        BigUint::ZERO
    };
    Ok(Transaction { to: encoded_solution.interacting_with, value, data: contract_interaction })
}

/// Encodes the input data for a function call to the given function signature (e.g.
/// transfer(address,uint256))
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
