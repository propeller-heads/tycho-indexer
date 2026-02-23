use std::collections::HashMap;

use alloy::primitives::U256;
use tycho_client::feed::{synchronizer::ComponentWithState, BlockHeader};
use tycho_common::{models::token::Token, Bytes};
use tycho_ethereum::BytesCodec;

use super::state::RocketpoolState;
use crate::protocol::{
    errors::InvalidSnapshotError,
    models::{DecoderContext, TryFromWithBlock},
};

impl TryFromWithBlock<ComponentWithState, BlockHeader> for RocketpoolState {
    type Error = InvalidSnapshotError;

    /// Decodes a `ComponentWithState` into a `RocketpoolState`. Errors with a
    /// `InvalidSnapshotError` if any required attribute is missing.
    async fn try_from_with_header(
        snapshot: ComponentWithState,
        _block: BlockHeader,
        _account_balances: &HashMap<Bytes, HashMap<Bytes, Bytes>>,
        _all_tokens: &HashMap<Bytes, Token>,
        _decoder_context: &DecoderContext,
    ) -> Result<Self, Self::Error> {
        let total_eth = snapshot
            .state
            .attributes
            .get("total_eth")
            .map(U256::from_bytes)
            .ok_or_else(|| InvalidSnapshotError::MissingAttribute("total_eth".to_string()))?;
        let reth_supply = snapshot
            .state
            .attributes
            .get("reth_supply")
            .map(U256::from_bytes)
            .ok_or_else(|| InvalidSnapshotError::MissingAttribute("reth_supply".to_string()))?;

        let deposit_contract_balance = snapshot
            .state
            .attributes
            .get("deposit_contract_balance")
            .map(U256::from_bytes)
            .ok_or_else(|| {
                InvalidSnapshotError::MissingAttribute("deposit_contract_balance".to_string())
            })?;

        let reth_contract_liquidity = snapshot
            .state
            .attributes
            .get("reth_contract_liquidity")
            .map(U256::from_bytes)
            .ok_or_else(|| {
                InvalidSnapshotError::MissingAttribute("reth_contract_liquidity".to_string())
            })?;

        let deposits_enabled = snapshot
            .state
            .attributes
            .get("deposits_enabled")
            .map(|val| !U256::from_bytes(val).is_zero())
            .ok_or_else(|| {
                InvalidSnapshotError::MissingAttribute("deposits_enabled".to_string())
            })?;

        let deposit_assigning_enabled = snapshot
            .state
            .attributes
            .get("deposit_assigning_enabled")
            .map(|val| !U256::from_bytes(val).is_zero())
            .ok_or_else(|| {
                InvalidSnapshotError::MissingAttribute("deposit_assigning_enabled".to_string())
            })?;

        let deposit_fee = snapshot
            .state
            .attributes
            .get("deposit_fee")
            .map(U256::from_bytes)
            .ok_or_else(|| InvalidSnapshotError::MissingAttribute("deposit_fee".to_string()))?;

        let min_deposit_amount = snapshot
            .state
            .attributes
            .get("min_deposit_amount")
            .map(U256::from_bytes)
            .ok_or_else(|| {
                InvalidSnapshotError::MissingAttribute("min_deposit_amount".to_string())
            })?;

        let max_deposit_pool_size = snapshot
            .state
            .attributes
            .get("max_deposit_pool_size")
            .map(U256::from_bytes)
            .ok_or_else(|| {
                InvalidSnapshotError::MissingAttribute("max_deposit_pool_size".to_string())
            })?;

        let deposit_assign_maximum = snapshot
            .state
            .attributes
            .get("deposit_assign_maximum")
            .map(U256::from_bytes)
            .ok_or_else(|| {
                InvalidSnapshotError::MissingAttribute("deposit_assign_maximum".to_string())
            })?;

        let deposit_assign_socialised_maximum = snapshot
            .state
            .attributes
            .get("deposit_assign_socialised_maximum")
            .map(U256::from_bytes)
            .ok_or_else(|| {
                InvalidSnapshotError::MissingAttribute(
                    "deposit_assign_socialised_maximum".to_string(),
                )
            })?;

        // Queue fields: try v4 megapool fields first, fall back to pre-Saturn minipool fields.
        // The presence of express_queue_rate distinguishes v4 from pre-Saturn state.
        let megapool_queue_requested_total = snapshot
            .state
            .attributes
            .get("megapool_queue_requested_total")
            .map(U256::from_bytes);
        let megapool_queue_index = snapshot
            .state
            .attributes
            .get("megapool_queue_index")
            .map(U256::from_bytes);
        let express_queue_rate = snapshot
            .state
            .attributes
            .get("express_queue_rate")
            .map(U256::from_bytes);

        let is_saturn = express_queue_rate.is_some();

        if is_saturn {
            Ok(RocketpoolState::new_v4(
                reth_supply,
                total_eth,
                deposit_contract_balance,
                reth_contract_liquidity,
                deposit_fee,
                deposits_enabled,
                min_deposit_amount,
                max_deposit_pool_size,
                deposit_assigning_enabled,
                deposit_assign_maximum,
                deposit_assign_socialised_maximum,
                megapool_queue_requested_total.unwrap_or(U256::ZERO),
                megapool_queue_index.unwrap_or(U256::ZERO),
                express_queue_rate.unwrap_or(U256::ZERO),
            ))
        } else {
            let queue_variable_start = snapshot
                .state
                .attributes
                .get("queue_variable_start")
                .map(U256::from_bytes)
                .ok_or_else(|| {
                    InvalidSnapshotError::MissingAttribute("queue_variable_start".to_string())
                })?;

            let queue_variable_end = snapshot
                .state
                .attributes
                .get("queue_variable_end")
                .map(U256::from_bytes)
                .ok_or_else(|| {
                    InvalidSnapshotError::MissingAttribute("queue_variable_end".to_string())
                })?;

            Ok(RocketpoolState::new(
                reth_supply,
                total_eth,
                deposit_contract_balance,
                reth_contract_liquidity,
                deposit_fee,
                deposits_enabled,
                min_deposit_amount,
                max_deposit_pool_size,
                deposit_assigning_enabled,
                deposit_assign_maximum,
                deposit_assign_socialised_maximum,
                queue_variable_start,
                queue_variable_end,
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use alloy::primitives::U256;
    use rstest::rstest;
    use tycho_client::feed::synchronizer::ComponentWithState;
    use tycho_common::{dto::ResponseProtocolState, Bytes};

    use super::super::state::RocketpoolState;
    use crate::{
        evm::protocol::{test_utils, test_utils::try_decode_snapshot_with_defaults},
        protocol::errors::InvalidSnapshotError,
    };

    fn create_test_snapshot() -> ComponentWithState {
        ComponentWithState {
            state: ResponseProtocolState {
                component_id: "Rocketpool".to_owned(),
                attributes: HashMap::from([
                    (
                        "total_eth".to_string(),
                        Bytes::from(U256::from(100_000_000_000_000_000_000u128).to_be_bytes_vec()),
                    ),
                    (
                        "reth_supply".to_string(),
                        Bytes::from(U256::from(95_000_000_000_000_000_000u128).to_be_bytes_vec()),
                    ),
                    (
                        "deposit_contract_balance".to_string(),
                        Bytes::from(U256::from(50_000_000_000_000_000_000u128).to_be_bytes_vec()),
                    ), // 50 ETH in deposit contract
                    (
                        "reth_contract_liquidity".to_string(),
                        Bytes::from(U256::from(10_000_000_000_000_000_000u128).to_be_bytes_vec()),
                    ), // 10 ETH in rETH contract
                    ("deposits_enabled".to_string(), Bytes::from(vec![0x01])),
                    ("deposit_assigning_enabled".to_string(), Bytes::from(vec![0x01])),
                    (
                        "deposit_fee".to_string(),
                        Bytes::from(U256::from(5_000_000_000_000_000u128).to_be_bytes_vec()),
                    ), // 0.5%
                    (
                        "min_deposit_amount".to_string(),
                        Bytes::from(U256::from(10_000_000_000_000_000u128).to_be_bytes_vec()),
                    ), // 0.01 ETH
                    (
                        "max_deposit_pool_size".to_string(),
                        Bytes::from(
                            U256::from(5_000_000_000_000_000_000_000u128).to_be_bytes_vec(),
                        ),
                    ), // 5000 ETH
                    (
                        "deposit_assign_maximum".to_string(),
                        Bytes::from(U256::from(10u64).to_be_bytes_vec()),
                    ),
                    (
                        "deposit_assign_socialised_maximum".to_string(),
                        Bytes::from(U256::from(2u64).to_be_bytes_vec()),
                    ),
                    (
                        "queue_variable_start".to_string(),
                        Bytes::from(U256::from(100u64).to_be_bytes_vec()),
                    ),
                    (
                        "queue_variable_end".to_string(),
                        Bytes::from(U256::from(105u64).to_be_bytes_vec()),
                    ),
                ]),
                balances: HashMap::new(),
            },
            component: Default::default(),
            component_tvl: None,
            entrypoints: Vec::new(),
        }
    }

    #[tokio::test]
    async fn test_rocketpool_try_from() {
        let snapshot = create_test_snapshot();

        let result =
            test_utils::try_decode_snapshot_with_defaults::<RocketpoolState>(snapshot).await;

        assert!(result.is_ok());
        let state = result.unwrap();
        assert_eq!(state.total_eth, U256::from(100_000_000_000_000_000_000u128));
        assert_eq!(state.reth_supply, U256::from(95_000_000_000_000_000_000u128));
        assert_eq!(state.deposit_contract_balance, U256::from(50_000_000_000_000_000_000u128));
        assert_eq!(state.reth_contract_liquidity, U256::from(10_000_000_000_000_000_000u128));
        assert!(state.deposits_enabled);
        assert!(state.deposit_assigning_enabled);
        assert_eq!(state.min_deposit_amount, U256::from(10_000_000_000_000_000u128));
        assert_eq!(state.max_deposit_pool_size, U256::from(5_000_000_000_000_000_000_000u128));
        assert_eq!(state.queue_variable_start, U256::from(100u64));
        assert_eq!(state.queue_variable_end, U256::from(105u64));
    }

    #[tokio::test]
    async fn test_rocketpool_try_from_deposits_disabled() {
        let eth_address = Bytes::from(vec![0u8; 20]);

        let snapshot = ComponentWithState {
            state: ResponseProtocolState {
                component_id: "Rocketpool".to_owned(),
                attributes: HashMap::from([
                    ("total_eth".to_string(), Bytes::from(U256::from(100u64).to_be_bytes_vec())),
                    ("reth_supply".to_string(), Bytes::from(U256::from(100u64).to_be_bytes_vec())),
                    (
                        "deposit_contract_balance".to_string(),
                        Bytes::from(U256::from(50u64).to_be_bytes_vec()),
                    ),
                    (
                        "reth_contract_liquidity".to_string(),
                        Bytes::from(U256::from(10u64).to_be_bytes_vec()),
                    ),
                    ("deposits_enabled".to_string(), Bytes::from(vec![0x00])), // disabled
                    ("deposit_assigning_enabled".to_string(), Bytes::from(vec![0x00])), // disabled
                    ("deposit_fee".to_string(), Bytes::from(U256::from(0u64).to_be_bytes_vec())),
                    (
                        "min_deposit_amount".to_string(),
                        Bytes::from(U256::from(0u64).to_be_bytes_vec()),
                    ),
                    (
                        "max_deposit_pool_size".to_string(),
                        Bytes::from(U256::from(1000u64).to_be_bytes_vec()),
                    ),
                    (
                        "deposit_assign_maximum".to_string(),
                        Bytes::from(U256::from(0u64).to_be_bytes_vec()),
                    ),
                    (
                        "deposit_assign_socialised_maximum".to_string(),
                        Bytes::from(U256::from(0u64).to_be_bytes_vec()),
                    ),
                    (
                        "queue_full_start".to_string(),
                        Bytes::from(U256::from(0u64).to_be_bytes_vec()),
                    ),
                    ("queue_full_end".to_string(), Bytes::from(U256::from(0u64).to_be_bytes_vec())),
                    (
                        "queue_half_start".to_string(),
                        Bytes::from(U256::from(0u64).to_be_bytes_vec()),
                    ),
                    ("queue_half_end".to_string(), Bytes::from(U256::from(0u64).to_be_bytes_vec())),
                    (
                        "queue_variable_start".to_string(),
                        Bytes::from(U256::from(0u64).to_be_bytes_vec()),
                    ),
                    (
                        "queue_variable_end".to_string(),
                        Bytes::from(U256::from(0u64).to_be_bytes_vec()),
                    ),
                ]),
                balances: HashMap::from([(
                    eth_address,
                    Bytes::from(U256::from(50u64).to_be_bytes_vec()),
                )]),
            },
            component: Default::default(),
            component_tvl: None,
            entrypoints: Vec::new(),
        };

        let result = try_decode_snapshot_with_defaults::<RocketpoolState>(snapshot).await;

        assert!(result.is_ok());
        let state = result.unwrap();
        assert!(!state.deposits_enabled);
        assert!(!state.deposit_assigning_enabled);
    }

    #[tokio::test]
    #[rstest]
    #[case::missing_total_eth("total_eth")]
    #[case::missing_reth_supply("reth_supply")]
    #[case::missing_deposit_contract_balance("deposit_contract_balance")]
    #[case::missing_reth_contract_liquidity("reth_contract_liquidity")]
    #[case::missing_deposits_enabled("deposits_enabled")]
    #[case::missing_deposit_assigning_enabled("deposit_assigning_enabled")]
    #[case::missing_deposit_fee("deposit_fee")]
    #[case::missing_min_deposit_amount("min_deposit_amount")]
    #[case::missing_max_deposit_pool_size("max_deposit_pool_size")]
    #[case::missing_deposit_assign_maximum("deposit_assign_maximum")]
    #[case::missing_deposit_assign_socialised_maximum("deposit_assign_socialised_maximum")]
    #[case::missing_queue_variable_start("queue_variable_start")]
    #[case::missing_queue_variable_end("queue_variable_end")]
    async fn test_rocketpool_try_from_missing_attribute(#[case] missing_attribute: &str) {
        let eth_address = Bytes::from(vec![0u8; 20]);

        let mut attributes = HashMap::from([
            ("total_eth".to_string(), Bytes::from(U256::from(100u64).to_be_bytes_vec())),
            ("reth_supply".to_string(), Bytes::from(U256::from(100u64).to_be_bytes_vec())),
            (
                "deposit_contract_balance".to_string(),
                Bytes::from(U256::from(50u64).to_be_bytes_vec()),
            ),
            (
                "reth_contract_liquidity".to_string(),
                Bytes::from(U256::from(10u64).to_be_bytes_vec()),
            ),
            ("deposits_enabled".to_string(), Bytes::from(vec![0x01])),
            ("deposit_assigning_enabled".to_string(), Bytes::from(vec![0x01])),
            ("deposit_fee".to_string(), Bytes::from(U256::from(0u64).to_be_bytes_vec())),
            ("min_deposit_amount".to_string(), Bytes::from(U256::from(0u64).to_be_bytes_vec())),
            (
                "max_deposit_pool_size".to_string(),
                Bytes::from(U256::from(1000u64).to_be_bytes_vec()),
            ),
            ("deposit_assign_maximum".to_string(), Bytes::from(U256::from(0u64).to_be_bytes_vec())),
            (
                "deposit_assign_socialised_maximum".to_string(),
                Bytes::from(U256::from(0u64).to_be_bytes_vec()),
            ),
            ("queue_full_start".to_string(), Bytes::from(U256::from(0u64).to_be_bytes_vec())),
            ("queue_full_end".to_string(), Bytes::from(U256::from(0u64).to_be_bytes_vec())),
            ("queue_half_start".to_string(), Bytes::from(U256::from(0u64).to_be_bytes_vec())),
            ("queue_half_end".to_string(), Bytes::from(U256::from(0u64).to_be_bytes_vec())),
            ("queue_variable_start".to_string(), Bytes::from(U256::from(0u64).to_be_bytes_vec())),
            ("queue_variable_end".to_string(), Bytes::from(U256::from(0u64).to_be_bytes_vec())),
        ]);
        attributes.remove(missing_attribute);

        let snapshot = ComponentWithState {
            state: ResponseProtocolState {
                component_id: "Rocketpool".to_owned(),
                attributes,
                balances: HashMap::from([(
                    eth_address,
                    Bytes::from(U256::from(50u64).to_be_bytes_vec()),
                )]),
            },
            component: Default::default(),
            component_tvl: None,
            entrypoints: Vec::new(),
        };

        let result = try_decode_snapshot_with_defaults::<RocketpoolState>(snapshot).await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            InvalidSnapshotError::MissingAttribute(ref x) if x == missing_attribute
        ));
    }
}
