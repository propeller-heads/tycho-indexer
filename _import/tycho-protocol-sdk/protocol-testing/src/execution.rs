//! Swap execution simulation module.
//!
//! This module provides functionality to simulate executing swaps through RPC requests
//! using state overwrites and historical blockchain data. It allows testing swap execution
//! against specific block states without actually performing on-chain transactions.

use std::{collections::HashMap, str::FromStr, sync::LazyLock};

use alloy::{
    primitives::{keccak256, map::AddressHashMap, Address, FixedBytes, U256},
    rpc::types::{state::AccountOverride, Block, TransactionRequest},
};
use miette::{miette, IntoDiagnostic, WrapErr};
use num_bigint::BigUint;
use tracing::info;
use tycho_simulation::{
    evm::protocol::u256_num::{biguint_to_u256, u256_to_biguint},
    tycho_common::{
        traits::{AllowanceSlotDetector, BalanceSlotDetector},
        Bytes,
    },
    tycho_ethereum::entrypoint_tracer::{
        allowance_slot_detector::{AllowanceSlotDetectorConfig, EVMAllowanceSlotDetector},
        balance_slot_detector::{BalanceSlotDetectorConfig, EVMBalanceSlotDetector},
    },
    tycho_execution::encoding::models::Solution,
};

use crate::rpc::RPCProvider;
pub const ROUTER_BYTECODE_JSON: &str =
    include_str!("../../evm/test/router/TychoRouter.runtime.json");
pub const EXECUTOR_ADDRESS: &str = "0xaE04CA7E9Ed79cBD988f6c536CE11C621166f41B";

// Include all executor bytecode files at compile time
const UNISWAP_V2_BYTECODE_JSON: &str =
    include_str!("../../evm/test/executors/UniswapV2.runtime.json");
const UNISWAP_V3_BYTECODE_JSON: &str =
    include_str!("../../evm/test/executors/UniswapV3.runtime.json");
const UNISWAP_V4_BYTECODE_JSON: &str =
    include_str!("../../evm/test/executors/UniswapV4.runtime.json");
const BALANCER_V2_BYTECODE_JSON: &str =
    include_str!("../../evm/test/executors/BalancerV2.runtime.json");
const BALANCER_V3_BYTECODE_JSON: &str =
    include_str!("../../evm/test/executors/BalancerV3.runtime.json");
const CURVE_BYTECODE_JSON: &str = include_str!("../../evm/test/executors/Curve.runtime.json");
const MAVERICK_V2_BYTECODE_JSON: &str =
    include_str!("../../evm/test/executors/MaverickV2.runtime.json");
const EKUBO_BYTECODE_JSON: &str = include_str!("../../evm/test/executors/Ekubo.runtime.json");

/// Mapping from protocol component patterns to executor bytecode JSON strings
static EXECUTOR_MAPPING: LazyLock<HashMap<&'static str, &'static str>> = LazyLock::new(|| {
    let mut map = HashMap::new();
    map.insert("uniswap_v2", UNISWAP_V2_BYTECODE_JSON);
    map.insert("sushiswap", UNISWAP_V2_BYTECODE_JSON);
    map.insert("pancakeswap_v2", UNISWAP_V2_BYTECODE_JSON);
    map.insert("uniswap_v3", UNISWAP_V3_BYTECODE_JSON);
    map.insert("pancakeswap_v3", UNISWAP_V3_BYTECODE_JSON);
    map.insert("uniswap_v4", UNISWAP_V4_BYTECODE_JSON);
    map.insert("balancer_v2", BALANCER_V2_BYTECODE_JSON);
    map.insert("balancer_v3", BALANCER_V3_BYTECODE_JSON);
    map.insert("curve", CURVE_BYTECODE_JSON);
    map.insert("maverick_v2", MAVERICK_V2_BYTECODE_JSON);
    map.insert("ekubo", EKUBO_BYTECODE_JSON);
    map
});

/// Get executor bytecode JSON based on component ID
fn get_executor_bytecode_json(component_id: &str) -> miette::Result<&'static str> {
    for (pattern, executor_json) in EXECUTOR_MAPPING.iter() {
        if component_id.contains(pattern) {
            return Ok(executor_json);
        }
    }
    Err(miette!("Unknown component type '{}' - no matching executor found", component_id))
}

/// Load executor bytecode from embedded constants based on the protocol system
pub fn load_executor_bytecode(protocol_system: &str) -> miette::Result<Vec<u8>> {
    let executor_json = get_executor_bytecode_json(protocol_system)?;

    let json_value: serde_json::Value = serde_json::from_str(executor_json)
        .into_diagnostic()
        .wrap_err("Failed to parse executor JSON")?;

    let bytecode_str = json_value["runtimeBytecode"]
        .as_str()
        .ok_or_else(|| miette!("No bytecode field found in executor JSON"))?;

    // Remove 0x prefix if present
    let bytecode_hex =
        if let Some(stripped) = bytecode_str.strip_prefix("0x") { stripped } else { bytecode_str };

    hex::decode(bytecode_hex)
        .into_diagnostic()
        .wrap_err("Failed to decode executor bytecode from hex")
}

/// Calculate gas fees based on block base fee
fn calculate_gas_fees(block_header: &Block) -> miette::Result<(U256, U256)> {
    let base_fee = block_header
        .header
        .base_fee_per_gas
        .ok_or_else(|| miette::miette!("Block does not have base fee (pre-EIP-1559)"))?;
    // Set max_priority_fee_per_gas to a reasonable value (2 Gwei)
    let max_priority_fee_per_gas = U256::from(2_000_000_000u64); // 2 Gwei
                                                                 // Set max_fee_per_gas to base_fee * 2 + max_priority_fee_per_gas to handle fee fluctuations
    let max_fee_per_gas = U256::from(base_fee) * U256::from(2u64) + max_priority_fee_per_gas;

    info!(
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

/// Sets up state overwrites for the Tycho router and its associated executor.
///
/// This method prepares the router for simulation by:
/// 1. Overriding the router's bytecode with the embedded runtime bytecode
/// 2. Copying executor approval storage from the current block to maintain permissions
/// 3. Overriding the executor's bytecode based on the protocol system
///
/// # Arguments
/// * `router_address` - The address of the Tycho router contract
/// * `protocol_system` - The protocol system identifier (e.g., "uniswap_v2", "vm:balancer_v2")
///
/// # Returns
/// A HashMap containing account overwrites for both the router and executor addresses.
/// The router override includes bytecode and executor approval storage.
/// The executor override includes the appropriate bytecode for the protocol.
///
/// # Errors
/// Returns an error if:
/// - Router bytecode JSON parsing fails
/// - Executor address parsing fails
/// - Storage slot fetching fails
/// - Executor bytecode loading fails
pub async fn setup_router_overwrites(
    router_address: Address,
    protocol_system: &str,
) -> miette::Result<AddressHashMap<AccountOverride>> {
    let json_value: serde_json::Value = serde_json::from_str(ROUTER_BYTECODE_JSON)
        .into_diagnostic()
        .wrap_err("Failed to parse router JSON")?;

    let bytecode_str = json_value["runtimeBytecode"]
        .as_str()
        .ok_or_else(|| miette::miette!("No runtimeBytecode field found in router JSON"))?;

    // Remove 0x prefix if present
    let bytecode_hex =
        if let Some(stripped) = bytecode_str.strip_prefix("0x") { stripped } else { bytecode_str };

    let router_bytecode = hex::decode(bytecode_hex)
        .into_diagnostic()
        .wrap_err("Failed to decode router bytecode from hex")?;

    // Start with the router bytecode override
    let mut state_overwrites = AddressHashMap::default();
    let mut tycho_router_override = AccountOverride::default().with_code(router_bytecode);

    // Find executor address approval storage slot
    let executor_address = Address::from_str(EXECUTOR_ADDRESS).into_diagnostic()?;
    let storage_slot = calculate_executor_storage_slot(executor_address);

    // The executors mapping starts at storage value 1
    let storage_value = FixedBytes::<32>::from(U256::ONE);

    tycho_router_override =
        tycho_router_override.with_state_diff(vec![(storage_slot, storage_value)]);

    state_overwrites.insert(router_address, tycho_router_override);

    // Add bytecode overwrite for the executor
    let executor_bytecode = load_executor_bytecode(protocol_system)?;
    state_overwrites
        .insert(executor_address, AccountOverride::default().with_code(executor_bytecode.to_vec()));
    Ok(state_overwrites)
}

/// Sets up state overwrites for user accounts and tokens required for swap simulation.
///
/// This method prepares the user environment for historical block simulation by:
/// 1. Providing the user with sufficient ETH balance (100 ETH) for gas payments
/// 2. For ETH swaps: Adding the swap amount to the user's ETH balance
/// 3. For ERC20 swaps: Overriding token balance and allowance storage slots to ensure:
///    - User has sufficient tokens for the swap
///    - Router has unlimited allowance to spend user's tokens
///
/// The function uses EVM storage slot detection to find the correct storage locations
/// for token balances and allowances, then applies state overwrites to simulate the
/// required pre-conditions without executing actual token transfers.
///
/// # Arguments
/// * `solution` - The encoded swap solution containing token and amount information
/// * `transaction` - The transaction details for determining router address
/// * `user_address` - The address of the user performing the swap
/// * `rpc_url` - RPC endpoint URL for storage slot detection
/// * `block` - The historical block context for storage queries
///
/// # Returns
/// A HashMap containing account overwrites for:
/// - User account: ETH balance override
/// - Token contract: Balance and allowance storage slot overwrites (for ERC20 swaps)
///
/// # Errors
/// Returns an error if:
/// - Storage slot detection fails for balance or allowance
/// - Token address parsing fails
/// - RPC queries for storage detection fail
async fn setup_user_overwrites(
    solution: &Solution,
    transaction: &tycho_simulation::tycho_execution::encoding::models::Transaction,
    user_address: Address,
    rpc_url: String,
    block: &Block,
) -> miette::Result<AddressHashMap<AccountOverride>> {
    let mut overwrites = AddressHashMap::default();
    // Add ETH balance override for the user to ensure they have enough gas funds
    let mut eth_balance = U256::from_str("100000000000000000000").unwrap(); // 100 ETH

    let token_address = Address::from_slice(&solution.given_token[..20]);
    // If given token is ETH, add the given amount to the balance
    if solution.given_token == Bytes::zero(20) {
        eth_balance += biguint_to_u256(&solution.given_amount);
    // if the given token is not ETH, do balance and allowance slots overwrites
    } else {
        let detector = EVMBalanceSlotDetector::new(BalanceSlotDetectorConfig {
            rpc_url: rpc_url.clone(),
            ..Default::default()
        })
        .into_diagnostic()?;

        let results = detector
            .detect_balance_slots(
                std::slice::from_ref(&solution.given_token),
                (**user_address).into(),
                (*block.header.hash).into(),
            )
            .await;

        let balance_slot =
            if let Some(Ok((_storage_addr, slot))) = results.get(&solution.given_token.clone()) {
                slot
            } else {
                return Err(miette!("Couldn't find balance storage slot for token {token_address}"));
            };

        let detector = EVMAllowanceSlotDetector::new(AllowanceSlotDetectorConfig {
            rpc_url,
            ..Default::default()
        })
        .into_diagnostic()?;

        let results = detector
            .detect_allowance_slots(
                std::slice::from_ref(&solution.given_token),
                (**user_address).into(),
                transaction.to.clone(), // tycho router
                (*block.header.hash).into(),
            )
            .await;

        let allowance_slot = if let Some(Ok((_storage_addr, slot))) =
            results.get(&solution.given_token.clone())
        {
            slot
        } else {
            return Err(miette!("Couldn't find allowance storage slot for token {token_address}"));
        };

        overwrites.insert(
            token_address,
            AccountOverride::default().with_state_diff(vec![
                (
                    alloy::primitives::B256::from_slice(allowance_slot),
                    alloy::primitives::B256::from_slice(&U256::MAX.to_be_bytes::<32>()),
                ),
                (
                    alloy::primitives::B256::from_slice(balance_slot),
                    alloy::primitives::B256::from_slice(
                        &biguint_to_u256(&solution.given_amount).to_be_bytes::<32>(),
                    ),
                ),
            ]),
        );
    }
    overwrites.insert(user_address, AccountOverride::default().with_balance(eth_balance));

    Ok(overwrites)
}

/// Simulate a trade using eth_call for historical blocks
pub async fn simulate_trade_with_eth_call(
    rpc_provider: &RPCProvider,
    transaction: &tycho_simulation::tycho_execution::encoding::models::Transaction,
    solution: &Solution,
    block: &Block,
) -> miette::Result<BigUint> {
    let first_swap = solution.swaps.first().unwrap();
    let protocol_system = &first_swap.component.protocol_system;

    let user_address = Address::from_slice(&solution.sender[..20]);
    let (max_fee_per_gas, max_priority_fee_per_gas) = calculate_gas_fees(block)?;
    // Convert main transaction to alloy TransactionRequest
    let execution_tx = TransactionRequest::default()
        .to(Address::from_slice(&transaction.to[..20]))
        .input(transaction.data.clone().into())
        .value(U256::from_str(&transaction.value.to_string()).unwrap_or_default())
        .from(user_address)
        .max_fee_per_gas(
            max_fee_per_gas
                .try_into()
                .unwrap_or(u128::MAX),
        )
        .max_priority_fee_per_gas(
            max_priority_fee_per_gas
                .try_into()
                .unwrap_or(u128::MAX),
        );
    let tycho_router_address = Address::from_slice(&transaction.to[..20]);

    let router_overwrites = setup_router_overwrites(tycho_router_address, protocol_system)
        .await
        .wrap_err("Failed to create router override")?;

    let mut user_overwrites = setup_user_overwrites(
        solution,
        transaction,
        user_address,
        rpc_provider.url.to_string(),
        block,
    )
    .await?;

    // Merge router overwrites with user overwrites
    user_overwrites.extend(router_overwrites);

    let execution_amount_out = rpc_provider
        .simulate_transactions_with_tracing(execution_tx, block.number(), user_overwrites)
        .await
        .map_err(|e| {
            info!("Execution transaction failed with error: {}", e);
            e
        })
        .wrap_err("Execution simulation failed")?;

    Ok(u256_to_biguint(execution_amount_out))
}
