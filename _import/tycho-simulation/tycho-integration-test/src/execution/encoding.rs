use std::{str::FromStr, sync::Arc};

use alloy::{
    rpc::types::{state::AccountOverride, Block, TransactionRequest},
    sol_types::SolValue,
};
use miette::{miette, IntoDiagnostic, WrapErr};
use num_bigint::BigUint;
use tracing::debug;
use tycho_common::{
    models::{token::Token, Chain},
    simulation::protocol_sim::ProtocolSim,
    traits::{AllowanceSlotDetector, BalanceSlotDetector},
    Bytes,
};
use tycho_execution::encoding::{
    evm::encoder_builders::TychoRouterEncoderBuilder,
    models::{EncodedSolution, Solution, SwapBuilder, Transaction, UserTransferType},
};
use tycho_simulation::{
    evm::protocol::u256_num::biguint_to_u256,
    foundry_evm::revm::primitives::{
        alloy_primitives::Keccak256, map::AddressHashMap, Address, U256,
    },
    protocol::models::ProtocolComponent,
};

use crate::{execution::tenderly::OverwriteMetadata, RPCTools};

pub fn encode_swap(
    component: &ProtocolComponent,
    state: Arc<dyn ProtocolSim>,
    sell_token: &Token,
    buy_token: &Token,
    amount_in: BigUint,
    expected_amount_out: BigUint,
    chain: Chain,
) -> miette::Result<(Solution, Transaction)> {
    let solution = create_solution(
        component.clone(),
        state,
        sell_token.clone(),
        buy_token.clone(),
        amount_in.clone(),
        expected_amount_out.clone(),
    )?;
    let encoded_solution = {
        let encoder = TychoRouterEncoderBuilder::new()
            .chain(chain)
            .user_transfer_type(UserTransferType::TransferFrom)
            .build()
            .into_diagnostic()
            .wrap_err("Failed to build encoder")?;
        encoder
            .encode_solutions(vec![solution.clone()])
            .into_diagnostic()
            .wrap_err("Failed to encode router calldata")?
            .into_iter()
            .next()
            .ok_or_else(|| miette!("Missing solution"))?
    };
    let transaction =
        encoded_transaction(encoded_solution.clone(), &solution, chain.native_token().address)?;
    Ok((solution, transaction))
}

fn create_solution(
    component: ProtocolComponent,
    state: Arc<dyn ProtocolSim>,
    sell_token: Token,
    buy_token: Token,
    amount_in: BigUint,
    expected_amount_out: BigUint,
) -> miette::Result<Solution> {
    let user_address =
        Bytes::from_str("0xf847a638E44186F3287ee9F8cAF73FF4d4B80784").into_diagnostic()?;

    // Prepare data to encode. First we need to create a swap object
    let simple_swap =
        SwapBuilder::new(component, sell_token.address.clone(), buy_token.address.clone())
            .protocol_state(state)
            .estimated_amount_in(amount_in.clone())
            .build();

    // Compute a minimum amount out
    //
    // # ⚠️ Important Responsibility Note
    // For maximum security, in production code, this minimum amount out should be computed
    // from a third-party source.
    let slippage = 0.0025; // 0.25% slippage
    let bps = BigUint::from(10_000u32);
    let slippage_percent = BigUint::from((slippage * 10000.0) as u32);
    let multiplier = &bps - slippage_percent;
    let min_amount_out = (expected_amount_out * &multiplier) / &bps;

    // Then we create a solution object with the previous swap
    Ok(Solution {
        sender: user_address.clone(),
        receiver: user_address,
        given_token: sell_token.address,
        given_amount: amount_in,
        checked_token: buy_token.address,
        exact_out: false, // it's an exact in solution
        checked_amount: min_amount_out,
        swaps: vec![simple_swap],
        ..Default::default()
    })
}

fn encoded_transaction(
    encoded_solution: EncodedSolution,
    solution: &Solution,
    native_address: Bytes,
) -> miette::Result<Transaction> {
    let given_amount = biguint_to_u256(&solution.given_amount);
    let min_amount_out = biguint_to_u256(&solution.checked_amount);
    let given_token = Address::from_slice(&solution.given_token);
    let checked_token = Address::from_slice(&solution.checked_token);
    let receiver = Address::from_slice(&solution.receiver);

    let method_calldata = (
        given_amount,
        given_token,
        checked_token,
        min_amount_out,
        false,
        false,
        receiver,
        true,
        encoded_solution.swaps,
    )
        .abi_encode();

    let contract_interaction = encode_input(&encoded_solution.function_signature, method_calldata);
    let value = if solution.given_token == native_address {
        solution.given_amount.clone()
    } else {
        BigUint::ZERO
    };
    Ok(Transaction { to: encoded_solution.interacting_with, value, data: contract_interaction })
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

/// Set up all state overrides needed for simulation.
///
/// This includes balance overrides and allowance overrides of the sell token for the sender.
/// Returns both the overwrites and metadata for human-readable logging.
pub(crate) async fn setup_user_overwrites(
    rpc_tools: &RPCTools,
    solution: &Solution,
    transaction: &Transaction,
    block: &Block,
    user_address: Address,
) -> miette::Result<(AddressHashMap<AccountOverride>, OverwriteMetadata)> {
    let mut overwrites = AddressHashMap::default();
    let mut metadata = OverwriteMetadata::new();
    let token_address = Address::from_slice(&solution.given_token[..20]);
    // If given token is ETH, add the given amount + 10 ETH for gas
    if solution.given_token == Bytes::zero(20) {
        let eth_balance = biguint_to_u256(&solution.given_amount) +
            U256::from_str("10000000000000000000").unwrap(); // given_amount + 1 ETH for gas
        overwrites.insert(user_address, AccountOverride::default().with_balance(eth_balance));
    // if the given token is not ETH, do balance and allowance slots overwrites
    } else {
        let results = rpc_tools
            .evm_balance_slot_detector
            .detect_balance_slots(
                std::slice::from_ref(&solution.given_token),
                (**user_address).into(),
                (*block.header.hash).into(),
            )
            .await;

        let (balance_storage_addr, balance_slot) =
            if let Some(Ok((storage_addr, slot))) = results.get(&solution.given_token.clone()) {
                (storage_addr, slot)
            } else {
                return Err(miette!("Couldn't find balance storage slot for token {token_address}"));
            };

        let results = rpc_tools
            .evm_allowance_slot_detector
            .detect_allowance_slots(
                std::slice::from_ref(&solution.given_token),
                (**user_address).into(),
                transaction.to.clone(), // tycho router
                (*block.header.hash).into(),
            )
            .await;

        let (allowance_storage_addr, allowance_slot) = if let Some(Ok((storage_addr, slot))) =
            results.get(&solution.given_token.clone())
        {
            (storage_addr, slot)
        } else {
            return Err(miette!("Couldn't find allowance storage slot for token {token_address}"));
        };

        // Use the exact given amount for balance and allowance (no buffer, no max)
        let token_balance = biguint_to_u256(&solution.given_amount);
        let token_allowance = biguint_to_u256(&solution.given_amount);

        let balance_storage_address = Address::from_slice(&balance_storage_addr[..20]);
        let allowance_storage_address = Address::from_slice(&allowance_storage_addr[..20]);

        let balance_slot_b256 = alloy::primitives::B256::from_slice(balance_slot);
        let allowance_slot_b256 = alloy::primitives::B256::from_slice(allowance_slot);
        let spender_address = Address::from_slice(&transaction.to[..20]);

        debug!(
            "Setting token override for {token_address}: balance={}, allowance={}, balance_storage={}, allowance_storage={}",
            token_balance, token_allowance, balance_storage_address, allowance_storage_address
        );

        // Add metadata for human-readable logging
        metadata.add_balance(balance_storage_address, user_address, balance_slot_b256);
        metadata.add_allowance(
            allowance_storage_address,
            user_address,
            spender_address,
            allowance_slot_b256,
        );

        // Apply balance and allowance overrides
        // If both storage addresses are the same, combine them into one override
        if balance_storage_address == allowance_storage_address {
            overwrites.insert(
                balance_storage_address,
                AccountOverride::default().with_state_diff(vec![
                    (
                        balance_slot_b256,
                        alloy::primitives::B256::from_slice(&token_balance.to_be_bytes::<32>()),
                    ),
                    (
                        allowance_slot_b256,
                        alloy::primitives::B256::from_slice(&token_allowance.to_be_bytes::<32>()),
                    ),
                ]),
            );
        } else {
            // Different storage addresses, apply separately
            overwrites.insert(
                balance_storage_address,
                AccountOverride::default().with_state_diff(vec![(
                    balance_slot_b256,
                    alloy::primitives::B256::from_slice(&token_balance.to_be_bytes::<32>()),
                )]),
            );
            overwrites.insert(
                allowance_storage_address,
                AccountOverride::default().with_state_diff(vec![(
                    allowance_slot_b256,
                    alloy::primitives::B256::from_slice(&token_allowance.to_be_bytes::<32>()),
                )]),
            );
        }

        // Add 10 ETH for gas for non-ETH token swaps
        let eth_balance = U256::from_str("10000000000000000000").unwrap(); // 1 ETH for gas
        overwrites.insert(user_address, AccountOverride::default().with_balance(eth_balance));
        debug!("Setting ETH balance override for user {user_address}: {eth_balance} (for gas)");
    }

    Ok((overwrites, metadata))
}

pub(crate) fn swap_request(
    transaction: &Transaction,
    block: &Block,
    user_address: Address,
) -> miette::Result<TransactionRequest> {
    let (max_fee_per_gas, max_priority_fee_per_gas) = calculate_gas_fees(block)?;
    Ok(TransactionRequest::default()
        .to(Address::from_slice(&transaction.to[..20]))
        .input(transaction.data.clone().into())
        .value(U256::from_str(&transaction.value.to_string()).unwrap_or_default())
        .from(user_address)
        .gas_limit(100_000_000)
        .max_fee_per_gas(
            max_fee_per_gas
                .try_into()
                .unwrap_or(u128::MAX),
        )
        .max_priority_fee_per_gas(
            max_priority_fee_per_gas
                .try_into()
                .unwrap_or(u128::MAX),
        ))
}

/// Calculate gas fees based on block base fee
fn calculate_gas_fees(block: &Block) -> miette::Result<(U256, U256)> {
    let base_fee = block
        .header
        .base_fee_per_gas
        .ok_or_else(|| miette::miette!("Block does not have base fee (pre-EIP-1559)"))?;
    // Set max_priority_fee_per_gas to a reasonable value (2 Gwei)
    let max_priority_fee_per_gas = U256::from(2_000_000_000u64);
    // Set max_fee_per_gas to base_fee * 2 + max_priority_fee_per_gas to handle fee fluctuations
    let max_fee_per_gas = U256::from(base_fee) * U256::from(2u64) + max_priority_fee_per_gas;
    debug!(
        "Gas pricing: base_fee={}, max_priority_fee_per_gas={}, max_fee_per_gas={}",
        base_fee, max_priority_fee_per_gas, max_fee_per_gas
    );
    Ok((max_fee_per_gas, max_priority_fee_per_gas))
}
