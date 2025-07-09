// This struct already exists, duplicated here for convenience.

use std::collections::HashMap;

use alloy_primitives::U256;
use alloy_sol_types::sol;
use tonic::async_trait;
use tycho_common::{
    keccak256,
    models::{
        blockchain::{Block, EntryPointWithTracingParams},
        protocol::ProtocolComponent,
        Address,
    },
};

use crate::extractor::dynamic_contract_indexer::component_metadata::ComponentTracingMetadata;
type SlotId = U256;

sol! {
    struct PoolKey {
        address currency0;
        address currency1;
        uint24 fee;
        int24 tickSpacing;
        address hooks;
    }

    struct ExactInputSingleParams {
        PoolKey poolKey;
        bool zeroForOne;
        uint128 amountIn;
        uint128 amountOutMinimum;
        bytes hookData;
    }

    struct Plan {
        bytes actions;
        bytes[] params;
    }

    function execute(bytes calldata params) public;
}

pub struct HookEntrypointConfig {
    // Ideal number of entrypoints to generate for each component.
    pub sample_size: Option<usize>,
    // Minimum number of entrypoints to generate for each component.
    pub min_samples: usize,
    // Router address to use for the entrypoints.
    pub router_address: Option<Address>,
    // If not provided, should use a default address. Could be defined by a custom Hook
    // Orchestrator.
    pub sender: Option<Address>,
}
pub struct HookEntrypointData {
    pub hook_address: Address,
    // Component should provide, via static attributes - all the information required for PoolKey.
    // PoolKey is generated from tokens, LPfee, tickSpacing and hooks address.
    // https://github.com/Uniswap/v4-core/blob/main/src/types/PoolKey.sol
    pub component: ProtocolComponent,
    pub component_metadata: ComponentTracingMetadata,
}

pub struct HookTracerContext {
    block: Block,
}

pub enum EntrypointGenerationError {
    AmountsEstimationFailed(String),
    EntrypointGenerationFailed(String),
}

#[async_trait]
pub trait HookEntrypointGenerator {
    fn set_config(&mut self, config: HookEntrypointConfig);

    /// Generate entrypoints for a given component.
    /// First, it should call the SwapAmountEstimator to estimate the swap amounts.
    /// Then, using the ERC6909Overwrites and the custom Router code, we should generate
    /// the Entrypoints for tracing the router's 0x09c5eabe function.
    async fn generate_entrypoints(
        &self,
        data: &HookEntrypointData,
        context: &HookTracerContext,
    ) -> Result<Vec<EntryPointWithTracingParams>, EntrypointGenerationError>;
}

#[async_trait]
pub trait SwapAmountEstimator {
    /// Estimate the swap amounts for a given component.
    /// If limits are available, use different fractions of it; use 1, 10, 50 and 95% of the limits,
    /// to cover different bands. Else, use fractions of balances.
    /// Else, raise a custom Error.
    async fn estimate_swap_amounts(
        &self,
        metadata: &ComponentTracingMetadata,
        pool_key: &PoolKey,
    ) -> Result<HashMap<Address, Vec<U256>>, EntrypointGenerationError>;
}

// Auxiliary code
fn get_storage_slot_index_at_key(
    key: U256,
    mapping_slot: SlotId,
    compiler: ContractCompiler,
) -> SlotId {
    let mut key_bytes = key.to_be_bytes::<32>().to_vec();
    if key_bytes.len() < 32 {
        let padding = vec![0u8; 32 - key_bytes.len()];
        key_bytes.splice(0..0, padding); // Prepend zeros to the start
    }

    let mapping_slot_bytes = mapping_slot.to_be_bytes::<32>();
    compiler.compute_map_slot(&mapping_slot_bytes, &key_bytes)
}

/// Enum representing the type of contract compiler.
#[derive(Debug, PartialEq, Copy, Clone)]
enum ContractCompiler {
    Solidity,
    Vyper,
}

impl ContractCompiler {
    /// Computes the storage slot for a given mapping based on the base storage slot of the map and
    /// the key.
    ///
    /// # Arguments
    ///
    /// * `map_base_slot` - A byte slice representing the base storage slot of the mapping.
    /// * `key` - A byte slice representing the key for which the storage slot is being computed.
    ///
    /// # Returns
    ///
    /// A `SlotId` representing the computed storage slot.
    ///
    /// # Notes
    ///
    /// - For `Solidity`, the slot is computed as `keccak256(key + map_base_slot)`.
    /// - For `Vyper`, the slot is computed as `keccak256(map_base_slot + key)`.
    pub fn compute_map_slot(&self, map_base_slot: &[u8], key: &[u8]) -> SlotId {
        let concatenated = match &self {
            ContractCompiler::Solidity => [key, map_base_slot].concat(),
            ContractCompiler::Vyper => [map_base_slot, key].concat(),
        };

        let slot_bytes = keccak256(&concatenated);

        SlotId::from_be_slice(&slot_bytes)
    }
}
struct ERC6909Overwrites {
    balance_of_slot: SlotId,
    operator_slot: SlotId,
    allowance_slot: SlotId,
}

impl Default for ERC6909Overwrites {
    fn default() -> Self {
        ERC6909Overwrites {
            balance_of_slot: U256::try_from(4).unwrap(),
            operator_slot: U256::try_from(3).unwrap(),
            allowance_slot: U256::try_from(5).unwrap(),
        }
    }
}

impl ERC6909Overwrites {
    fn balance_slot(&self, owner: Address, token: Address) -> SlotId {
        let balance_mapping_slot = get_storage_slot_index_at_key(
            U256::from_be_slice(owner.as_ref()),
            self.balance_of_slot,
            ContractCompiler::Solidity,
        );
        get_storage_slot_index_at_key(
            U256::from_be_slice(token.as_ref()),
            balance_mapping_slot,
            ContractCompiler::Solidity,
        )
    }
}
