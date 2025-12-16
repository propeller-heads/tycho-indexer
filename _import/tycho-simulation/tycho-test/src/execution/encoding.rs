use std::{collections::HashMap, str::FromStr, sync::Arc};

use alloy::{
    primitives::{keccak256, map::AddressHashMap, Address, FixedBytes, Keccak256, U256},
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
    evm::protocol::u256_num::biguint_to_u256, protocol::models::ProtocolComponent,
};

use crate::{execution::tenderly::OverwriteMetadata, rpc_tools::RPCTools};

const USER_ADDR: &str = "0xf847a638E44186F3287ee9F8cAF73FF4d4B80784";
pub const EXECUTOR_ADDRESS: &str = "0xaE04CA7E9Ed79cBD988f6c536CE11C621166f41B";

/// Contains the detected storage slots for a token.
#[derive(Debug, Clone, Default)]
pub struct TokenSlots {
    pub balance_storage_addr: Vec<u8>,
    pub balance_slot: Vec<u8>,
    pub allowance_storage_addr: Vec<u8>,
    pub allowance_slot: Vec<u8>,
}

#[allow(clippy::too_many_arguments)]
pub fn encode_swap(
    component: &ProtocolComponent,
    state: Option<Arc<dyn ProtocolSim>>,
    sell_token: &Token,
    buy_token: &Token,
    amount_in: BigUint,
    chain: Chain,
    executors_json: Option<String>,
    historical_trade: bool,
) -> miette::Result<(Solution, Transaction)> {
    let solution = create_solution(
        component.clone(),
        state,
        sell_token.clone(),
        buy_token.clone(),
        amount_in.clone(),
    )?;
    let encoded_solution = {
        let mut builder = TychoRouterEncoderBuilder::new()
            .chain(chain)
            .user_transfer_type(UserTransferType::TransferFrom);

        if let Some(executors) = executors_json {
            builder = builder.executors_addresses(executors);
        }
        if historical_trade {
            builder = builder.historical_trade();
        }

        builder
            .build()
            .into_diagnostic()
            .wrap_err("Failed to build encoder")?
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
    state: Option<Arc<dyn ProtocolSim>>,
    sell_token: Token,
    buy_token: Token,
    amount_in: BigUint,
) -> miette::Result<Solution> {
    let user_address = Bytes::from_str(USER_ADDR).into_diagnostic()?;

    // Prepare data to encode. First we need to create a swap object
    let simple_swap = {
        let mut builder =
            SwapBuilder::new(component, sell_token.address.clone(), buy_token.address.clone())
                .estimated_amount_in(amount_in.clone());

        if let Some(state) = state {
            builder = builder.protocol_state(state);
        }

        builder.build()
    };

    Ok(Solution {
        sender: user_address.clone(),
        receiver: user_address,
        given_token: sell_token.address,
        given_amount: amount_in,
        checked_token: buy_token.address,
        exact_out: false, // it's an exact in solution
        // We want to keep track of how bad the slippage really is and not just error at execution
        // time. NEVER DO THIS IN PRODUCTION!
        checked_amount: BigUint::from(1u64),
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

/// Detects balance and allowance storage slots for all given tokens in a single batch operation.
///
/// Returns a mapping from token address to their detected storage slots.
/// This function should be called once per block with all tokens of interest to optimize RPC calls.
/// Tokens that fail slot detection are silently skipped and not included in the result.
pub(crate) async fn detect_token_slots(
    rpc_tools: &RPCTools,
    block: &Block,
    token_addresses: &[Bytes],
    to_address: &Bytes,
) -> HashMap<Bytes, TokenSlots> {
    let user_address = match Address::from_str(USER_ADDR).into_diagnostic() {
        Ok(addr) => addr,
        Err(_) => return HashMap::new(),
    };

    let mut token_slots = HashMap::new();
    // Add one entry for ETH
    token_slots.insert(Bytes::zero(20), TokenSlots::default());

    // Filter out ETH (zero address) as it doesn't need slot detection
    let erc20_tokens: Vec<Bytes> = token_addresses
        .iter()
        .filter(|&addr| addr != &Bytes::zero(20))
        .cloned()
        .collect();

    if erc20_tokens.is_empty() {
        return token_slots;
    }

    let balance_results = rpc_tools
        .evm_balance_slot_detector
        .detect_balance_slots(&erc20_tokens, (**user_address).into(), (*block.header.hash).into())
        .await;

    let allowance_results = rpc_tools
        .evm_allowance_slot_detector
        .detect_allowance_slots(
            &erc20_tokens,
            (**user_address).into(),
            to_address.clone(),
            (*block.header.hash).into(),
        )
        .await;

    for token_address in &erc20_tokens {
        let balance_slot_data = match balance_results.get(token_address) {
            Some(Ok((storage_addr, slot))) => (storage_addr.clone(), slot.clone()),
            Some(Err(_)) | None => continue, // Skip tokens with detection failures
        };

        let allowance_slot_data = match allowance_results.get(token_address) {
            Some(Ok((storage_addr, slot))) => (storage_addr.clone(), slot.clone()),
            Some(Err(_)) | None => continue, // Skip tokens with detection failures
        };

        token_slots.insert(
            token_address.clone(),
            TokenSlots {
                balance_storage_addr: balance_slot_data.0.to_vec(),
                balance_slot: balance_slot_data.1.to_vec(),
                allowance_storage_addr: allowance_slot_data.0.to_vec(),
                allowance_slot: allowance_slot_data.1.to_vec(),
            },
        );
    }

    token_slots
}

/// Set up all state overrides needed for simulation using pre-computed token slots.
///
/// This includes balance overrides and allowance overrides of the sell token for the sender.
/// Returns both the overwrites and metadata for human-readable logging.
pub(crate) fn setup_user_overwrites(
    to_address: &Bytes,
    token_address: &Bytes,
    amount: &BigUint,
    token_slots: &TokenSlots,
) -> (AddressHashMap<AccountOverride>, OverwriteMetadata) {
    let mut overwrites = AddressHashMap::default();
    let mut metadata = OverwriteMetadata::new();
    let user_address = Address::from_str(USER_ADDR).expect("Valid user address");
    let spender_address = Address::from_slice(&to_address[..20]);

    // ETH
    if token_address == &Bytes::zero(20) {
        let eth_balance = biguint_to_u256(amount) +
            U256::from_str("100000000000000000000").expect("Couldn't convert eth amount to U256"); // given_amount + 10 ETH for gas
        overwrites.insert(user_address, AccountOverride::default().with_balance(eth_balance));
    } else {
        let token_balance = biguint_to_u256(amount);
        let token_allowance = biguint_to_u256(amount);

        let balance_storage_address = Address::from_slice(&token_slots.balance_storage_addr[..20]);
        let allowance_storage_address =
            Address::from_slice(&token_slots.allowance_storage_addr[..20]);

        let balance_slot_b256 = alloy::primitives::B256::from_slice(&token_slots.balance_slot);
        let allowance_slot_b256 = alloy::primitives::B256::from_slice(&token_slots.allowance_slot);

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
        let eth_balance =
            U256::from_str("10000000000000000000").expect("Couldn't convert eth amount to U256");
        overwrites.insert(user_address, AccountOverride::default().with_balance(eth_balance));
    }

    (overwrites, metadata)
}

pub(crate) fn swap_request(
    transaction: &Transaction,
    block: &Block,
) -> miette::Result<TransactionRequest> {
    let (max_fee_per_gas, max_priority_fee_per_gas) = calculate_gas_fees(block)?;
    let user_address = Address::from_str(USER_ADDR).expect("Valid user address");
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

/// Calculate storage slot for Solidity mapping.
///
/// The solidity code:
/// keccak256(abi.encodePacked(bytes32(key), bytes32(slot)))
pub fn calculate_executor_storage_slot(key: Address) -> FixedBytes<32> {
    // Convert key (20 bytes) to 32-byte left-padded array (uint256)
    let mut key_bytes = [0u8; 32];
    key_bytes[12..].copy_from_slice(key.as_slice());

    // The base of the executor storage slot is 1, since there is only one
    // variable that is initialized before it (which is _roles in AccessControl.sol).
    // In this case, _roles gets slot 0.
    // The slots are given in order to the parent contracts' variables first and foremost.
    let slot = U256::from(1);

    // Convert U256 slot to 32-byte big-endian array
    let slot_bytes = slot.to_be_bytes::<32>();

    // Concatenate key_bytes + slot_bytes, then keccak hash
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(&key_bytes);
    buf[32..].copy_from_slice(&slot_bytes);
    keccak256(buf)
}

/// Sets up Angstrom-specific storage overwrites for simulation.
///
/// This function creates storage overwrites specifically for Angstrom hooks to ensure
/// proper simulation behavior. It sets the _lastBlockUpdated storage parameter to
/// unlock the pool in the simulator.
///
/// # Arguments
/// * `angstrom_address` - The address of the Angstrom hook contract
///   (0x0000000AA8c2Fb9b232F78D2B286dC2aE53BfAD4)
/// * `current_block_number` - The current block number to set as _lastBlockUpdated
///
/// # Returns
/// A HashMap containing account overwrites for the Angstrom contract.
/// The override includes:
///   - Storage slot 3, offset 0, bytes 8: Sets _lastBlockUpdated to current block number
pub fn setup_angstrom_overwrites(
    angstrom_address: Address,
    current_block_number: u64,
) -> AddressHashMap<AccountOverride> {
    let mut overwrites = AddressHashMap::default();

    // Angstrom storage slot 3, offset 0, 8 bytes for _lastBlockUpdated
    let storage_slot = alloy::primitives::B256::from([
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 3,
    ]);

    // Use the actual storage pattern and only update the block number at the end
    // Pattern: 0x00000000e40df67976149fe316ca8437300da6fec92629ea00000000016d620b
    let mut storage_value =
        hex::decode("00000000e40df67976149fe316ca8437300da6fec92629ea00000000016d620b").unwrap();
    storage_value[24..32].copy_from_slice(&current_block_number.to_be_bytes());

    let storage_value_b256 = alloy::primitives::B256::from_slice(&storage_value);
    overwrites.insert(
        angstrom_address,
        AccountOverride::default().with_state_diff(vec![(storage_slot, storage_value_b256)]),
    );

    overwrites
}

/// Sets up state overwrites for the Tycho router and its associated executor.
///
/// This function prepares the router for execution simulation by applying bytecode overwrites
/// to both the router and executor contracts. It ensures that the router recognizes the executor
/// as an approved executor by setting the appropriate storage slot values.
///
/// # Process
/// 1. Override the router's bytecode with the provided router bytecode
/// 2. Calculate and set the executor approval storage slot in the router
/// 3. Override the executor's bytecode with the provided executor bytecode
///
/// # Arguments
/// * `router_address` - The address where the Tycho router contract will be deployed/overridden
/// * `router_bytecode` - The compiled runtime bytecode for the Tycho router contract
/// * `executor_bytecode` - The compiled runtime bytecode for the protocol-specific executor
///
/// # Returns
/// A HashMap containing account overwrites for both the router and executor addresses.
/// The router override includes:
///   - Router contract bytecode
///   - Storage slot setting executor approval (executors mapping slot = 1)
///
/// The executor override includes:
///   - Protocol-specific executor contract bytecode
///
/// # Errors
/// Returns an error if:
/// - Executor address parsing fails
/// - Storage slot calculation fails
pub async fn setup_router_overwrites(
    router_address: Address,
    router_bytecode: Vec<u8>,
    executor_bytecode: Vec<u8>,
) -> miette::Result<AddressHashMap<AccountOverride>> {
    // Start with the router bytecode override
    let mut state_overwrites = AddressHashMap::default();
    let mut tycho_router_override = AccountOverride::default().with_code(router_bytecode);

    let executor_address = Address::from_str(EXECUTOR_ADDRESS).into_diagnostic()?;

    // Find executor address approval storage slot
    let storage_slot = calculate_executor_storage_slot(executor_address);

    // The executors mapping starts at storage value 1
    let storage_value = FixedBytes::<32>::from(U256::ONE);

    tycho_router_override =
        tycho_router_override.with_state_diff(vec![(storage_slot, storage_value)]);

    state_overwrites.insert(router_address, tycho_router_override);

    // Add bytecode overwrite for the executor
    state_overwrites
        .insert(executor_address, AccountOverride::default().with_code(executor_bytecode.to_vec()));
    Ok(state_overwrites)
}
