use std::{collections::HashMap, str::FromStr};

use alloy::{
    contract::{ContractInstance, Interface},
    dyn_abi::DynSolValue,
    eips::eip1898::BlockId,
    primitives::{address, keccak256, map::AddressHashMap, Address, FixedBytes, U256},
    providers::{Provider, ProviderBuilder},
    rpc::types::{
        state::AccountOverride,
        trace::geth::{
            GethDebugBuiltInTracerType, GethDebugTracerType, GethDebugTracingCallOptions,
            GethDebugTracingOptions,
        },
        Block, TransactionRequest,
    },
    sol_types::SolValue,
    transports::http::reqwest::Url,
};
use miette::{IntoDiagnostic, WrapErr};
use serde_json::Value;
use tracing::info;
use tycho_common::Bytes;

use crate::{
    execution::{StateOverride, EXECUTOR_ADDRESSES},
    traces::print_call_trace,
};

const NATIVE_ALIASES: &[Address] = &[
    address!("0x0000000000000000000000000000000000000000"),
    address!("0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"),
];

const ERC_20_ABI: &str = r#"[{"inputs":[{"name":"_owner","type":"address"}],"name":"balanceOf","outputs":[{"name":"balance","type":"uint256"}],"stateMutability":"view","type":"function"}]"#;

pub struct RPCProvider {
    pub url: Url,
    trace: bool,
}

impl RPCProvider {
    pub fn new(url: String, trace: bool) -> Self {
        let url = url.as_str().parse().unwrap();
        RPCProvider { url, trace }
    }

    pub async fn get_token_balance(
        &self,
        token_address: Address,
        wallet_address: Address,
        block_number: u64,
    ) -> miette::Result<U256> {
        let provider = ProviderBuilder::new().connect_http(self.url.clone());
        let block_id: BlockId = BlockId::from(block_number);

        match NATIVE_ALIASES.contains(&token_address) {
            true => provider
                .get_balance(wallet_address)
                .block_id(block_id)
                .await
                .into_diagnostic()
                .wrap_err("Failed to fetch token balance"),
            false => {
                let abi = serde_json::from_str(ERC_20_ABI)
                    .into_diagnostic()
                    .wrap_err("invalid ABI")?;

                let contract = ContractInstance::new(token_address, provider, Interface::new(abi));

                let wallet_addr = DynSolValue::from(wallet_address);

                let result_value = contract
                    .function("balanceOf", &[wallet_addr])
                    .expect("Failed to build function call")
                    .block(block_id)
                    .call()
                    .await
                    .into_diagnostic()
                    .wrap_err("Failed to fetch ERC-20 Balance")?;
                let result: U256 = result_value
                    .first()
                    .ok_or_else(|| miette::miette!("No value returned from contract call"))?
                    .as_uint()
                    .ok_or_else(|| miette::miette!("Returned value is not a uint"))?
                    .0;
                Ok(result)
            }
        }
    }

    pub async fn get_block_header(&self, block_number: u64) -> miette::Result<Block> {
        let provider = ProviderBuilder::new().connect_http(self.url.clone());
        let block_id: BlockId = BlockId::from(block_number);

        provider
            .get_block(block_id)
            .await
            .into_diagnostic()
            .wrap_err("Failed to fetch block header")
            .and_then(|block_opt| block_opt.ok_or_else(|| miette::miette!("Block not found")))
    }

    /// Helper function to get the contract's storage at the given slot at the latest block.
    pub async fn get_storage_at(
        &self,
        contract_address: Address,
        slot: FixedBytes<32>,
    ) -> miette::Result<FixedBytes<32>> {
        let provider = ProviderBuilder::new().connect_http(self.url.clone());
        let storage_value = provider
            .get_storage_at(contract_address, slot.into())
            .await
            .into_diagnostic()
            .wrap_err("Failed to fetch storage slot")?;

        Ok(storage_value.into())
    }

    pub async fn copy_contract_storage_and_code(
        &self,
        contract_address: Address,
        router_bytecode_json: &str,
    ) -> miette::Result<StateOverride> {
        let json_value: serde_json::Value = serde_json::from_str(router_bytecode_json)
            .into_diagnostic()
            .wrap_err("Failed to parse router JSON")?;

        let bytecode_str = json_value["runtimeBytecode"]
            .as_str()
            .ok_or_else(|| miette::miette!("No runtimeBytecode field found in router JSON"))?;

        // Remove 0x prefix if present
        let bytecode_hex = if let Some(stripped) = bytecode_str.strip_prefix("0x") {
            stripped
        } else {
            bytecode_str
        };

        let router_bytecode = hex::decode(bytecode_hex)
            .into_diagnostic()
            .wrap_err("Failed to decode router bytecode from hex")?;

        // Start with the router bytecode override
        let mut state_override = StateOverride::new().with_code(router_bytecode);

        for (protocol_name, &executor_address) in EXECUTOR_ADDRESSES.iter() {
            let storage_slot = self.calculate_executor_storage_slot(executor_address);

            match self
                .get_storage_at(contract_address, storage_slot)
                .await
            {
                Ok(value) => {
                    state_override = state_override.with_state_diff(
                        alloy::primitives::Bytes::from(storage_slot.to_vec()),
                        alloy::primitives::Bytes::from(value.to_vec()),
                    );
                }
                Err(e) => {
                    info!(
                        "Failed to fetch executor approval for {} ({:?}): {}",
                        protocol_name, executor_address, e
                    );
                }
            }
        }
        Ok(state_override)
    }

    /// Calculate storage slot for Solidity mapping.
    ///
    /// The solidity code:
    /// keccak256(abi.encodePacked(bytes32(key), bytes32(slot)))
    pub fn calculate_executor_storage_slot(&self, key: Address) -> FixedBytes<32> {
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

    fn bytes_to_fixed_32(bytes: &[u8]) -> [u8; 32] {
        let mut arr = [0u8; 32];
        let len = bytes.len().min(32);
        // Right-pad by copying to the end of the array
        arr[32 - len..].copy_from_slice(&bytes[bytes.len() - len..]);
        arr
    }

    pub async fn simulate_transactions_with_tracing(
        &self,
        transaction: TransactionRequest,
        block_number: u64,
        state_overwrites: HashMap<Address, StateOverride>,
    ) -> miette::Result<U256> {
        let provider = ProviderBuilder::new().connect_http(self.url.clone());
        // Convert our StateOverride to alloy's state override format
        let mut alloy_state_overrides = AddressHashMap::default();
        for (address, override_data) in state_overwrites {
            let mut account_override = AccountOverride::default();

            if let Some(code) = override_data.code {
                account_override.code = Some(alloy::primitives::Bytes::from(code));
            }

            if let Some(balance) = override_data.balance {
                account_override.balance = Some(balance);
            }

            if !override_data.state_diff.is_empty() {
                // Convert Bytes to FixedBytes<32> for storage slots
                let mut state_diff = HashMap::default();
                for (slot, value) in override_data.state_diff {
                    let slot_bytes = Self::bytes_to_fixed_32(&slot);
                    let value_bytes = Self::bytes_to_fixed_32(&value);
                    state_diff.insert(FixedBytes(slot_bytes), FixedBytes(value_bytes));
                }
                account_override.state_diff = Some(state_diff);
            }

            alloy_state_overrides.insert(address, account_override);
        }

        // Configure tracing options - use callTracer for better formatted results
        let tracing_options = GethDebugTracingOptions {
            tracer: Some(GethDebugTracerType::BuiltInTracer(
                GethDebugBuiltInTracerType::CallTracer,
            )),
            config: Default::default(),
            tracer_config: Default::default(),
            timeout: None,
        };

        let trace_options = GethDebugTracingCallOptions {
            tracing_options,
            state_overrides: if alloy_state_overrides.is_empty() {
                None
            } else {
                Some(alloy_state_overrides)
            },
            block_overrides: None,
        };

        let result: Value = provider
            .client()
            .request("debug_traceCall", (transaction, BlockId::from(block_number), trace_options))
            .await
            .into_diagnostic()
            .wrap_err("Failed to debug trace call many")?;

        if self.trace {
            print_call_trace(&result, 0).await;
        }
        let has_error = result
            .as_object()
            .and_then(|obj| obj.get("error"))
            .is_some();

        let has_failed = result
            .as_object()
            .and_then(|obj| obj.get("failed"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        if has_error || has_failed {
            if let Some(result_obj) = result.as_object() {
                if let Some(error) = result_obj.get("error") {
                    return Err(miette::miette!("Transaction execution failed: {}", error));
                }
                if let Some(revert_reason) = result_obj.get("revertReason") {
                    return Err(miette::miette!("Transaction reverted: {}", revert_reason));
                }
            }
            return Err(miette::miette!("Transaction failed"));
        } else {
            info!("Transaction successfully simulated.");
        }

        let mut executed_amount_out = U256::ZERO;
        if let Some(result_obj) = result.as_object() {
            if let Some(gas_used) = result_obj
                .get("gasUsed")
                .and_then(|v| v.as_str())
            {
                let gas_used_decoded = U256::from_str_radix(gas_used.trim_start_matches("0x"), 16)
                    .into_diagnostic()?;
                info!("Gas used: {}", gas_used_decoded);
            }
            if let Some(output) = result_obj
                .get("output")
                .and_then(|v| v.as_str())
            {
                executed_amount_out = U256::abi_decode(&Bytes::from_str(output).into_diagnostic()?)
                    .into_diagnostic()?;
            }
        }
        Ok(executed_amount_out)
    }
}

#[cfg(test)]
mod tests {
    use std::{env, str::FromStr};

    use alloy::primitives::address;

    use super::*;

    #[tokio::test]
    async fn get_token_balance_native_token() {
        let eth_rpc_url = env::var("RPC_URL").expect("Missing RPC_URL in environment");

        let rpc_provider = RPCProvider::new(eth_rpc_url, false);
        let token_address = address!("0x0000000000000000000000000000000000000000");
        let wallet_address = address!("0x787B8840100d9BaAdD7463f4a73b5BA73B00C6cA");
        let block_number = 21998530;

        let balance = rpc_provider
            .get_token_balance(token_address, wallet_address, block_number)
            .await
            .unwrap();

        assert_eq!(
            balance,
            U256::from_str("1070041574684539264153").expect("Failed to convert ETH value")
        );
    }

    #[tokio::test]
    async fn get_token_balance_erc20_token() {
        let eth_rpc_url = env::var("RPC_URL").expect("Missing RPC_URL in environment");

        let rpc_provider = RPCProvider::new(eth_rpc_url, false);
        let token_address = address!("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48");
        let wallet_address = address!("0x787B8840100d9BaAdD7463f4a73b5BA73B00C6cA");
        let block_number = 21998530;

        let balance = rpc_provider
            .get_token_balance(token_address, wallet_address, block_number)
            .await
            .unwrap();

        assert_eq!(balance, U256::from(717250938432_u64));
    }

    #[tokio::test]
    async fn get_block_header() {
        let eth_rpc_url = env::var("RPC_URL").expect("Missing RPC_URL in environment");

        let rpc_provider = RPCProvider::new(eth_rpc_url, false);
        let block_number = 21998530;

        let block_header = rpc_provider
            .get_block_header(block_number)
            .await
            .unwrap();

        // Verify that we got a block with the correct number
        assert_eq!(block_number, block_header.header.number);
        assert_eq!(block_header.header.timestamp, 1741393115);
    }
}
