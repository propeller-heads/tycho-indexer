//! Swap execution simulation module.
//!
//! This module provides functionality to simulate executing swaps through RPC requests
//! using state overwrites and historical blockchain data. It allows testing swap execution
//! against specific block states without actually performing on-chain transactions.

use std::{collections::HashMap, str::FromStr, sync::LazyLock};

use alloy::{
    primitives::{Address, U256},
    rpc::types::{Block, TransactionRequest},
};
use miette::{miette, IntoDiagnostic, WrapErr};
use num_bigint::BigUint;
use serde_json::Value;
use tracing::info;
use tycho_common::traits::{AllowanceSlotDetector, BalanceSlotDetector};
use tycho_ethereum::entrypoint_tracer::{
    allowance_slot_detector::{AllowanceSlotDetectorConfig, EVMAllowanceSlotDetector},
    balance_slot_detector::{BalanceSlotDetectorConfig, EVMBalanceSlotDetector},
};
use tycho_simulation::{
    evm::protocol::u256_num::u256_to_biguint, tycho_execution::encoding::models::Solution,
};

use crate::rpc::RPCProvider;
const ROUTER_BYTECODE_JSON: &str = include_str!("../../evm/test/router/TychoRouter.runtime.json");
pub const EXECUTORS_JSON: &str = include_str!("../test_executor_addresses.json");

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

/// Executor addresses loaded from test_executor_addresses.json at startup
pub static EXECUTOR_ADDRESSES: LazyLock<HashMap<String, Address>> = LazyLock::new(|| {
    let json_value: Value = serde_json::from_str(&EXECUTORS_JSON)
        .expect("Failed to parse test_executor_addresses.json");

    let ethereum_addresses = json_value["ethereum"]
        .as_object()
        .expect("Missing 'ethereum' key in test_executor_addresses.json");

    let mut addresses = HashMap::new();
    for (protocol_name, address_value) in ethereum_addresses {
        let address_str = address_value
            .as_str()
            .unwrap_or_else(|| panic!("Invalid address format for protocol '{protocol_name}'"));

        let address = Address::from_str(address_str).unwrap_or_else(|_| {
            panic!("Invalid address '{address_str}' for protocol '{protocol_name}'")
        });

        addresses.insert(protocol_name.clone(), address);
    }
    addresses
});

#[derive(Debug, Clone)]
pub struct StateOverride {
    pub code: Option<Vec<u8>>,
    pub balance: Option<U256>,
    pub state_diff: HashMap<alloy::primitives::Bytes, alloy::primitives::Bytes>,
}

impl StateOverride {
    pub fn new() -> Self {
        Self { code: None, balance: None, state_diff: HashMap::new() }
    }

    pub fn with_code(mut self, code: Vec<u8>) -> Self {
        self.code = Some(code);
        self
    }

    pub fn with_balance(mut self, balance: U256) -> Self {
        self.balance = Some(balance);
        self
    }

    pub fn with_state_diff(
        mut self,
        slot: alloy::primitives::Bytes,
        value: alloy::primitives::Bytes,
    ) -> Self {
        self.state_diff.insert(slot, value);
        self
    }
}

/// Get executor bytecode JSON based on component ID
fn get_executor_bytecode_json(component_id: &str) -> miette::Result<&'static str> {
    for (pattern, executor_json) in EXECUTOR_MAPPING.iter() {
        if component_id.contains(pattern) {
            return Ok(executor_json);
        }
    }
    Err(miette!("Unknown component type '{}' - no matching executor found", component_id))
}

/// Get executor address for a given component ID
fn get_executor_address(component_id: &str) -> miette::Result<Address> {
    if let Some(&address) = EXECUTOR_ADDRESSES.get(component_id) {
        return Ok(address);
    }
    Err(miette!("No executor address found for component type '{}'", component_id))
}

/// Load executor bytecode from embedded constants based on solution component
fn load_executor_bytecode(solution: &Solution) -> miette::Result<Vec<u8>> {
    let first_swap = solution.swaps.first().unwrap();
    let component_id = &first_swap.component;

    let executor_json = get_executor_bytecode_json(&component_id.protocol_system)?;

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

/// Set up all state overrides needed for simulation
async fn setup_state_overrides(
    solution: &Solution,
    transaction: &tycho_simulation::tycho_execution::encoding::models::Transaction,
    user_address: Address,
    executor_bytecode: &[u8],
    rpc_url: String,
    block: &Block,
) -> miette::Result<HashMap<Address, StateOverride>> {
    let mut state_overwrites = HashMap::new();
    let token_address = Address::from_slice(&solution.given_token[..20]);

    // Extract executor address from the encoded solution's swaps data.
    // The solution should only have one swap for the test, so this should be safe.
    let executor_address = if let Some(first_swap) = solution.swaps.first() {
        get_executor_address(&first_swap.component.protocol_system)?
    } else {
        return Err(miette!("No swaps in solution - cannot determine executor address"));
    };

    // Add bytecode overwrite for the executor
    state_overwrites
        .insert(executor_address, StateOverride::new().with_code(executor_bytecode.to_vec()));

    // Add ETH balance override for the user to ensure they have enough gas funds
    state_overwrites.insert(
        user_address,
        StateOverride::new().with_balance(U256::from_str("100000000000000000000").unwrap()), // 100 ETH
    );

    let detector = EVMBalanceSlotDetector::new(BalanceSlotDetectorConfig {
        rpc_url: rpc_url.clone(),
        ..Default::default()
    })
    .into_diagnostic()?;

    let results = detector
        .detect_balance_slots(
            &[solution.given_token.clone()],
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
            &[solution.given_token.clone()],
            (**user_address).into(),
            transaction.to.clone(), // tycho router
            (*block.header.hash).into(),
        )
        .await;

    let allowance_slot =
        if let Some(Ok((_storage_addr, slot))) = results.get(&solution.given_token.clone()) {
            slot
        } else {
            return Err(miette!("Couldn't find allowance storage slot for token {token_address}"));
        };

    state_overwrites.insert(
        token_address,
        StateOverride::new()
            .with_state_diff(
                alloy::primitives::Bytes::from(allowance_slot.to_vec()),
                alloy::primitives::Bytes::from(U256::MAX.to_be_bytes::<32>()),
            )
            .with_state_diff(
                alloy::primitives::Bytes::from(balance_slot.to_vec()),
                alloy::primitives::Bytes::from(U256::MAX.to_be_bytes::<32>()),
            ),
    );

    Ok(state_overwrites)
}

/// Simulate a trade using eth_call for historical blocks
pub async fn simulate_trade_with_eth_call(
    rpc_provider: &RPCProvider,
    transaction: &tycho_simulation::tycho_execution::encoding::models::Transaction,
    solution: &Solution,
    block_number: u64,
    block: &Block,
) -> miette::Result<BigUint> {
    let executor_bytecode = load_executor_bytecode(solution)?;
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

    // Copy router storage and code from current block to historical block
    let router_override = rpc_provider
        .copy_contract_storage_and_code(tycho_router_address, ROUTER_BYTECODE_JSON)
        .await
        .wrap_err("Failed to create router override")?;

    // Set up state overrides including router override
    let mut state_overwrites = setup_state_overrides(
        solution,
        transaction,
        user_address,
        &executor_bytecode,
        rpc_provider.url.to_string(),
        block,
    )
    .await?; // Include executor override for historical blocks

    // Add the router override
    state_overwrites.insert(tycho_router_address, router_override);

    let execution_amount_out = rpc_provider
        .simulate_transactions_with_tracing(execution_tx, block_number, state_overwrites)
        .await
        .map_err(|e| {
            info!("Execution transaction failed with error: {}", e);
            e
        })
        .wrap_err("Execution simulation failed")?;

    Ok(u256_to_biguint(execution_amount_out))
}
