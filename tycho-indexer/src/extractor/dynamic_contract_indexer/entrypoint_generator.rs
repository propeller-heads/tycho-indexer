#![allow(dead_code)] // TODO: Remove this

// This struct already exists, duplicated here for convenience.

use std::collections::HashMap;

use alloy_primitives::U256;
use alloy_sol_types::sol;
use num_bigint::BigInt;
use num_traits::Zero;
use tonic::async_trait;
use tycho_common::{
    keccak256,
    models::{
        blockchain::{Block, EntryPointWithTracingParams},
        protocol::ProtocolComponent,
        Address,
    },
    Bytes,
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

#[derive(Debug)]
pub enum EntrypointGenerationError {
    AmountsEstimationFailed(String),
    EntrypointGenerationFailed(String),
    NoDataAvailable(String),
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
    ///
    /// Returns a combination of TokenIn and Token Out and an array of swap amounts, encoded in
    /// bytes
    async fn estimate_swap_amounts(
        &self,
        metadata: &ComponentTracingMetadata,
        tokens: &[Address],
    ) -> Result<HashMap<(Address, Address), Vec<Bytes>>, EntrypointGenerationError>;
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

pub struct DefaultSwapAmountEstimator;

#[async_trait]
impl SwapAmountEstimator for DefaultSwapAmountEstimator {
    async fn estimate_swap_amounts(
        &self,
        metadata: &ComponentTracingMetadata,
        tokens: &[Address],
    ) -> Result<HashMap<(Address, Address), Vec<Bytes>>, EntrypointGenerationError> {
        let mut result = HashMap::new();

        // Try to use limits first (preferred)
        if let Some(Ok((_, limits))) = &metadata.limits {
            if !limits.is_empty() {
                for ((token0, token1), (limit0, _limit1, _)) in limits {
                    let limit_amount =
                        BigInt::from_bytes_be(num_bigint::Sign::Plus, limit0.as_ref());

                    if !limit_amount.is_zero() {
                        let one_hundred = BigInt::from(100);
                        let amounts = vec![
                            Bytes::from(
                                (&limit_amount / &one_hundred)
                                    .to_bytes_be()
                                    .1,
                            ), // 1%
                            Bytes::from(
                                (&limit_amount / BigInt::from(10))
                                    .to_bytes_be()
                                    .1,
                            ), // 10%
                            Bytes::from(
                                (&limit_amount / BigInt::from(2))
                                    .to_bytes_be()
                                    .1,
                            ), // 50%
                            Bytes::from(
                                ((&limit_amount * BigInt::from(95)) / &one_hundred)
                                    .to_bytes_be()
                                    .1,
                            ), // 95%
                        ];
                        result.insert((token0.clone(), token1.clone()), amounts);
                    }
                }
                if !result.is_empty() {
                    return Ok(result);
                }
            }
        }

        // Fallback to using balances if no limits available
        // For each token that has a balance, create amounts for all possible sell->buy pairs
        if let Some(Ok((_, balances))) = &metadata.balances {
            for sell_token in tokens {
                if let Some(balance_bytes) = balances.get(sell_token) {
                    let balance =
                        BigInt::from_bytes_be(num_bigint::Sign::Plus, balance_bytes.as_ref());
                    if !balance.is_zero() {
                        let one_hundred = BigInt::from(100);
                        let amounts = vec![
                            Bytes::from((&balance / &one_hundred).to_bytes_be().1), // 1%
                            Bytes::from(
                                (&balance / BigInt::from(10))
                                    .to_bytes_be()
                                    .1,
                            ), // 10%
                            Bytes::from(
                                (&balance / BigInt::from(2))
                                    .to_bytes_be()
                                    .1,
                            ), // 50%
                            Bytes::from(
                                ((&balance * BigInt::from(95)) / &one_hundred)
                                    .to_bytes_be()
                                    .1,
                            ), // 95%
                        ];
                        // Create entries for each possible buy token
                        for buy_token in tokens {
                            if sell_token != buy_token {
                                result.insert(
                                    (sell_token.clone(), buy_token.clone()),
                                    amounts.clone(),
                                );
                            }
                        }
                    }
                }
            }
            if !result.is_empty() {
                return Ok(result);
            }
        }

        // If neither limits nor balances are available, return error
        Err(EntrypointGenerationError::NoDataAvailable(
            "No limits or balances available for swap amount estimation".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use tycho_common::{models::TxHash, Bytes};

    use super::*;

    fn create_test_tokens() -> Vec<Address> {
        vec![Address::from([1u8; 20]), Address::from([2u8; 20])]
    }

    fn create_metadata_with_limits(
        limits: Vec<((Address, Address), (Bytes, Bytes))>,
    ) -> ComponentTracingMetadata {
        ComponentTracingMetadata {
            balances: None,
            limits: Some(Ok((
                TxHash::from([0u8; 32]),
                limits
                    .into_iter()
                    .map(|(tokens, (l0, l1))| (tokens, (l0, l1, None)))
                    .collect(),
            ))),
            tvl: None,
        }
    }

    fn create_metadata_with_balances(
        balances: HashMap<Address, Bytes>,
    ) -> ComponentTracingMetadata {
        ComponentTracingMetadata {
            balances: Some(Ok((TxHash::from([0u8; 32]), balances))),
            limits: None,
            tvl: None,
        }
    }

    #[tokio::test]
    async fn test_estimate_with_limits() {
        let estimator = DefaultSwapAmountEstimator;
        let tokens = create_test_tokens();

        let limit_value = BigInt::from(1000u64);
        let limits = vec![(
            (tokens[0].clone(), tokens[1].clone()),
            (Bytes::from(limit_value.to_bytes_be().1), Bytes::from(limit_value.to_bytes_be().1)),
        )];
        let metadata = create_metadata_with_limits(limits);

        let result = estimator
            .estimate_swap_amounts(&metadata, &tokens)
            .await
            .unwrap();

        assert_eq!(result.len(), 1);

        let amounts = result
            .get(&(tokens[0].clone(), tokens[1].clone()))
            .unwrap();
        assert_eq!(amounts.len(), 4);
        assert_eq!(amounts[0], Bytes::from(BigInt::from(10u64).to_bytes_be().1)); // 1%
        assert_eq!(amounts[1], Bytes::from(BigInt::from(100u64).to_bytes_be().1)); // 10%
        assert_eq!(amounts[2], Bytes::from(BigInt::from(500u64).to_bytes_be().1)); // 50%
        assert_eq!(amounts[3], Bytes::from(BigInt::from(950u64).to_bytes_be().1)); // 95%
    }

    #[tokio::test]
    async fn test_estimate_with_balances_fallback() {
        let estimator = DefaultSwapAmountEstimator;
        let tokens = create_test_tokens();

        let balance_value = BigInt::from(2000u64);
        let mut balances = HashMap::new();
        balances.insert(tokens[0].clone(), Bytes::from(balance_value.to_bytes_be().1));
        balances.insert(tokens[1].clone(), Bytes::from(balance_value.to_bytes_be().1));

        let metadata = create_metadata_with_balances(balances);

        let result = estimator
            .estimate_swap_amounts(&metadata, &tokens)
            .await
            .unwrap();

        assert_eq!(result.len(), 2); // 2 pairs: token0->token1, token1->token0

        let amounts01 = result
            .get(&(tokens[0].clone(), tokens[1].clone()))
            .unwrap();
        assert_eq!(amounts01.len(), 4);
        assert_eq!(amounts01[0], Bytes::from(BigInt::from(20u64).to_bytes_be().1)); // 1%
        assert_eq!(amounts01[1], Bytes::from(BigInt::from(200u64).to_bytes_be().1)); // 10%
        assert_eq!(amounts01[2], Bytes::from(BigInt::from(1000u64).to_bytes_be().1)); // 50%
        assert_eq!(amounts01[3], Bytes::from(BigInt::from(1900u64).to_bytes_be().1)); // 95%

        let amounts10 = result
            .get(&(tokens[1].clone(), tokens[0].clone()))
            .unwrap();
        assert_eq!(amounts10.len(), 4);
        assert_eq!(amounts10[0], Bytes::from(BigInt::from(20u64).to_bytes_be().1)); // 1%
        assert_eq!(amounts10[1], Bytes::from(BigInt::from(200u64).to_bytes_be().1)); // 10%
        assert_eq!(amounts10[2], Bytes::from(BigInt::from(1000u64).to_bytes_be().1)); // 50%
        assert_eq!(amounts10[3], Bytes::from(BigInt::from(1900u64).to_bytes_be().1)); // 95%
    }

    #[tokio::test]
    async fn test_estimate_with_no_data() {
        let estimator = DefaultSwapAmountEstimator;
        let tokens = create_test_tokens();

        let metadata = ComponentTracingMetadata { balances: None, limits: None, tvl: None };

        let result = estimator
            .estimate_swap_amounts(&metadata, &tokens)
            .await;

        assert!(matches!(result, Err(EntrypointGenerationError::NoDataAvailable(_))));
    }
}
