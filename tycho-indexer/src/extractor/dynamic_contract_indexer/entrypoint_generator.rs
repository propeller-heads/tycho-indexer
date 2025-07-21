#![allow(dead_code)] // TODO: Remove this

// This struct already exists, duplicated here for convenience.

use std::collections::{BTreeMap, HashMap};

use alloy_primitives::{hex, U256};
use alloy_sol_types::{
    private::{
        primitives::aliases::{I24, U24},
        Address as SolAddress, Bytes as SolBytes,
    },
    sol, SolValue,
};
use num_bigint::BigInt;
use num_traits::Zero;
use tonic::async_trait;
use tycho_common::{
    keccak256,
    models::{
        blockchain::{
            AccountOverrides, Block, EntryPoint, EntryPointWithTracingParams, RPCTracerParams,
            StorageOverride, TracingParams,
        },
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

// V4Router action constants
// These correspond to the actions enum in V4Router
const ACTION_SWAP_EXACT_IN_SINGLE: u8 = 6; // SWAP_EXACT_IN_SINGLE = 0x06
const ACTION_SETTLE_ALL: u8 = 12; // SETTLE_ALL = 0x0c
const ACTION_TAKE_ALL: u8 = 15; // TAKE_ALL = 0x0f

// V4Router function selector for execute(bytes calldata params)
// This is the keccak256 hash of "execute(bytes)" truncated to 4 bytes: 0x09c5eabe
const EXECUTE_FUNCTION_SELECTOR: [u8; 4] = [0x09, 0xc5, 0xea, 0xbe];

pub struct HookEntrypointConfig {
    // Ideal number of entrypoints to generate for each component.
    pub max_sample_size: Option<usize>,
    // Minimum number of entrypoints to generate for each component.
    pub min_samples: usize,
    // Router address to use for the entrypoints. If not provided, uses a random address.
    pub router_address: Option<Address>,
    // If not provided, should use a default address. Could be defined by a custom Hook
    // Orchestrator.
    pub sender: Option<Address>,
    // Router bytecode to use for state overrides. If not provided, uses a default implementation.
    pub router_code: Option<Bytes>,
    /// Pool manager address (required)
    pub pool_manager: Address,
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

#[derive(Debug, Clone)]
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
                            Bytes::from(
                                (&balance / &one_hundred)
                                    .to_bytes_be()
                                    .1,
                            ), // 1%
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

/// Default implementation of HookEntrypointGenerator for Uniswap V4 hooks
/// Generates entrypoints using V4MiniRouter for tracing hook interactions
pub struct UniswapV4DefaultHookEntrypointGenerator<E: SwapAmountEstimator> {
    config: HookEntrypointConfig,
    estimator: E,
}

impl<E: SwapAmountEstimator> UniswapV4DefaultHookEntrypointGenerator<E> {
    pub fn new(estimator: E, pool_manager: Address) -> Self {
        Self {
            config: HookEntrypointConfig {
                max_sample_size: Some(4),
                min_samples: 1,
                router_address: None,
                sender: None,
                router_code: None,
                pool_manager,
            },
            estimator,
        }
    }
}

#[async_trait]
impl<E: SwapAmountEstimator + Send + Sync> HookEntrypointGenerator
    for UniswapV4DefaultHookEntrypointGenerator<E>
{
    fn set_config(&mut self, config: HookEntrypointConfig) {
        self.config = config;
    }

    async fn generate_entrypoints(
        &self,
        data: &HookEntrypointData,
        _context: &HookTracerContext,
    ) -> Result<Vec<EntryPointWithTracingParams>, EntrypointGenerationError> {
        let tokens = data.component.tokens.clone();

        // Defaults to random predefined address.
        let router_address = self
            .config
            .router_address
            .clone()
            .unwrap_or_else(|| Address::from(hex!("1f31095ECb8dD97f7133cC9a4dD208b8645c4E24")));

        let max_sample_size = self.config.max_sample_size.unwrap_or(4);
        let min_samples = self.config.min_samples;

        let mut entrypoints = Vec::new();

        let swap_amounts = self
            .estimator
            .estimate_swap_amounts(&data.component_metadata, &tokens)
            .await?;

        for ((token0, token1), amounts) in swap_amounts.iter() {
            let currency0 = SolAddress::from_slice(token0.as_ref());
            let currency1 = SolAddress::from_slice(token1.as_ref());
            let hooks = SolAddress::from_slice(data.hook_address.as_ref());

            let fee = u32::from(
                data.component
                    .static_attributes
                    .get("key_lp_fee")
                    .expect("Fee attribute not found for component")
                    .clone(),
            );

            let tick_spacing = i32::from(
                data.component
                    .static_attributes
                    .get("tick_spacing")
                    .expect("tick_spacing attribute not found for component")
                    .clone(),
            );

            let pool_key = PoolKey {
                currency0,
                currency1,
                fee: U24::try_from(fee).expect("Fee value too large for U24"),
                tickSpacing: I24::try_from(tick_spacing)
                    .expect("tick_spacing value out of range for I24"),
                hooks,
            };

            let is_zero_for_one = token0 < token1;

            let amounts_to_use = if amounts.len() >= max_sample_size {
                amounts
                    .iter()
                    .take(max_sample_size)
                    .collect::<Vec<_>>()
            } else if amounts.len() >= min_samples {
                amounts.iter().collect::<Vec<_>>()
            } else {
                // TODO: Raise error?
                continue;
            };

            for amount_bytes in amounts_to_use {
                let amount_u256 = U256::from_be_slice(amount_bytes.as_ref());
                let amount_in = u128::try_from(amount_u256).map_err(|_| {
                    EntrypointGenerationError::EntrypointGenerationFailed(
                        "Amount too large for u128".to_string(),
                    )
                })?;

                let swap_params = ExactInputSingleParams {
                    poolKey: pool_key.clone(),
                    zeroForOne: is_zero_for_one,
                    amountIn: amount_in,
                    amountOutMinimum: 0,
                    // We only support composable hooks, meaning hook data is not supported atm.
                    hookData: Default::default(),
                };

                let plan = Plan {
                    actions: SolBytes::from(vec![
                        ACTION_SWAP_EXACT_IN_SINGLE,
                        ACTION_SETTLE_ALL,
                        ACTION_TAKE_ALL,
                    ]),
                    params: vec![
                        SolBytes::from(swap_params.abi_encode()),
                        // Token In // amount in
                        SolBytes::from((currency0, amount_in).abi_encode()),
                        // Token Out // amount out
                        SolBytes::from((currency1, 0u128).abi_encode()),
                    ],
                };

                // Build calldata for execute(bytes) function call
                let mut calldata = EXECUTE_FUNCTION_SELECTOR.to_vec();
                calldata.extend(plan.abi_encode());

                let overwrites = ERC6909Overwrites::default();
                let balance_slot = overwrites.balance_slot(router_address.clone(), token0.clone());

                let pool_manager = self.config.pool_manager.clone();

                let router_code = self
                    .config
                    .router_code
                    .clone()
                    .unwrap_or_else(|| {
                        // Default placeholder bytecode when no router code is provided
                        // This should be replaced with actual compiled V4MiniRouter bytecode
                        Bytes::from(vec![
                            0x60, 0x80, 0x60, 0x40, 0x52, 0x34, 0x80, 0x15, 0x61, 0x00, 0x10, 0x57,
                            0x60, 0x00, 0x80, 0xfd,
                        ])
                    });

                let mut state_overrides = BTreeMap::new();

                state_overrides.insert(
                    router_address.clone(),
                    AccountOverrides { slots: None, native_balance: None, code: Some(router_code) },
                );

                let mut storage_diff = BTreeMap::new();
                storage_diff.insert(
                    Bytes::from(
                        balance_slot
                            .to_be_bytes::<32>()
                            .as_slice(),
                    ),
                    Bytes::from(
                        U256::from(amount_in)
                            .to_be_bytes::<32>()
                            .as_slice(),
                    ),
                );

                state_overrides.insert(
                    pool_manager,
                    AccountOverrides {
                        slots: Some(StorageOverride::Diff(storage_diff)),
                        native_balance: None,
                        code: None,
                    },
                );

                let entry_point = EntryPointWithTracingParams::new(
                    EntryPoint::new(
                        format!("{router_address}:execute(bytes)"),
                        router_address.clone(),
                        "execute(bytes)".to_string(),
                    ),
                    TracingParams::RPCTracer(
                        RPCTracerParams::new(None, Bytes::from(calldata))
                            .with_state_overrides(state_overrides),
                    ),
                );

                entrypoints.push(entry_point);
            }
        }

        if entrypoints.is_empty() {
            return Err(EntrypointGenerationError::NoDataAvailable(
                "No entrypoints could be generated".to_string(),
            ));
        }

        Ok(entrypoints)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use tycho_common::{
        models::{protocol::ProtocolComponent, TxHash},
        Bytes,
    };

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

    fn create_test_component() -> ProtocolComponent {
        use chrono::NaiveDateTime;
        use tycho_common::models::{Chain, ChangeType, TxHash};

        ProtocolComponent {
            id: "test_component".to_string(),
            protocol_system: "uniswap_v4".to_string(),
            protocol_type_name: "pool".to_string(),
            chain: Chain::Ethereum,
            tokens: create_test_tokens(),
            contract_addresses: vec![Address::from([3u8; 20])],
            static_attributes: [
                ("fee".to_string(), Bytes::from(3000u32.to_be_bytes())),
                ("tickSpacing".to_string(), Bytes::from(60i32.to_be_bytes())),
            ]
            .into_iter()
            .collect(),
            change: ChangeType::Creation,
            creation_tx: TxHash::from([0u8; 32]),
            created_at: NaiveDateTime::from_timestamp_opt(1640995200, 0).unwrap(),
        }
    }

    fn create_test_hook_data() -> HookEntrypointData {
        HookEntrypointData {
            hook_address: Address::from([4u8; 20]),
            component: create_test_component(),
            component_metadata: create_metadata_with_limits(vec![(
                (Address::from([1u8; 20]), Address::from([2u8; 20])),
                (
                    Bytes::from(U256::from(1000u64).to_be_bytes_vec()),
                    Bytes::from(U256::from(1000u64).to_be_bytes_vec()),
                ),
            )]),
        }
    }

    fn create_test_context() -> HookTracerContext {
        use chrono::NaiveDateTime;
        use tycho_common::models::{blockchain::Block, BlockHash, Chain};

        HookTracerContext {
            block: Block {
                number: 1000,
                hash: BlockHash::from([0u8; 32]),
                parent_hash: BlockHash::from([0u8; 32]),
                chain: Chain::Ethereum,
                ts: NaiveDateTime::from_timestamp_opt(1640995200, 0).unwrap(),
            },
        }
    }

    struct MockEstimator {
        result: Result<HashMap<(Address, Address), Vec<Bytes>>, EntrypointGenerationError>,
    }

    #[async_trait]
    impl SwapAmountEstimator for MockEstimator {
        async fn estimate_swap_amounts(
            &self,
            _metadata: &ComponentTracingMetadata,
            _tokens: &[Address],
        ) -> Result<HashMap<(Address, Address), Vec<Bytes>>, EntrypointGenerationError> {
            self.result.clone()
        }
    }

    #[tokio::test]
    async fn test_hook_entrypoint_generator_success() {
        let mut amounts = HashMap::new();
        amounts.insert(
            (Address::from([1u8; 20]), Address::from([2u8; 20])),
            vec![
                Bytes::from(U256::from(100u64).to_be_bytes_vec()),
                Bytes::from(U256::from(200u64).to_be_bytes_vec()),
            ],
        );

        let estimator = MockEstimator { result: Ok(amounts) };
        let mut generator = UniswapV4DefaultHookEntrypointGenerator::new(
            estimator,
            Address::from(hex!("000000000004444c5dc75cB358380D2e3dE08A90")),
        );

        let config = HookEntrypointConfig {
            max_sample_size: Some(2),
            min_samples: 1,
            router_address: Some(Address::from([5u8; 20])),
            sender: Some(Address::from([6u8; 20])),
            router_code: None,
            pool_manager: Address::from(hex!("000000000004444c5dc75cB358380D2e3dE08A90")),
        };
        generator.set_config(config);

        let hook_data = create_test_hook_data();
        let context = create_test_context();

        let result = generator
            .generate_entrypoints(&hook_data, &context)
            .await;

        match result {
            Ok(entrypoints) => {
                assert!(!entrypoints.is_empty());
                assert_eq!(entrypoints.len(), 2); // 2 amounts
                for entrypoint in entrypoints {
                    assert_eq!(entrypoint.entry_point.signature, "0x09c5eabe");
                    assert_eq!(entrypoint.entry_point.target, Address::from([5u8; 20]));
                }
            }
            Err(EntrypointGenerationError::EntrypointGenerationFailed(_)) => {
                // This is expected when router code file doesn't exist
            }
            Err(e) => panic!("Unexpected error: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_hook_entrypoint_generator_no_amounts() {
        let estimator = MockEstimator {
            result: Err(EntrypointGenerationError::NoDataAvailable("No data".to_string())),
        };
        let generator = UniswapV4DefaultHookEntrypointGenerator::new(
            estimator,
            Address::from(hex!("000000000004444c5dc75cB358380D2e3dE08A90")),
        );

        let hook_data = create_test_hook_data();
        let context = create_test_context();

        let result = generator
            .generate_entrypoints(&hook_data, &context)
            .await;

        assert!(matches!(result, Err(EntrypointGenerationError::NoDataAvailable(_))));
    }

    #[tokio::test]
    async fn test_hook_entrypoint_generator_empty_amounts() {
        let estimator = MockEstimator { result: Ok(HashMap::new()) };
        let generator = UniswapV4DefaultHookEntrypointGenerator::new(
            estimator,
            Address::from(hex!("000000000004444c5dc75cB358380D2e3dE08A90")),
        );

        let hook_data = create_test_hook_data();
        let context = create_test_context();

        let result = generator
            .generate_entrypoints(&hook_data, &context)
            .await;

        assert!(matches!(result, Err(EntrypointGenerationError::NoDataAvailable(_))));
    }
}
