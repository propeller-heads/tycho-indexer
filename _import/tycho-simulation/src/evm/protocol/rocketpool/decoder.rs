use std::collections::HashMap;

use alloy::primitives::U256;
use tycho_client::feed::{synchronizer::ComponentWithState, BlockHeader};
use tycho_common::{models::token::Token, Bytes};
use tycho_ethereum::BytesCodec;

use super::state::RocketPoolState;
use crate::protocol::{
    errors::InvalidSnapshotError,
    models::{DecoderContext, TryFromWithBlock},
};

impl TryFromWithBlock<ComponentWithState, BlockHeader> for RocketPoolState {
    type Error = InvalidSnapshotError;

    /// Decodes a `ComponentWithState` into a `RocketPoolState`. Errors with a
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

        let liquidity = snapshot
            .state
            .attributes
            .get("liquidity")
            .map(U256::from_bytes)
            .ok_or_else(|| InvalidSnapshotError::MissingAttribute("liquidity".to_string()))?;

        let deposits_enabled = snapshot
            .state
            .attributes
            .get("deposits_enabled")
            .map(|val| !U256::from_bytes(val).is_zero())
            .ok_or_else(|| {
                InvalidSnapshotError::MissingAttribute("deposits_enabled".to_string())
            })?;

        let assign_deposits_enabled = snapshot
            .state
            .attributes
            .get("assign_deposits_enabled")
            .map(|val| !U256::from_bytes(val).is_zero())
            .ok_or_else(|| {
                InvalidSnapshotError::MissingAttribute("assign_deposits_enabled".to_string())
            })?;

        let deposit_fee = snapshot
            .state
            .attributes
            .get("deposit_fee")
            .map(U256::from_bytes)
            .ok_or_else(|| InvalidSnapshotError::MissingAttribute("deposit_fee".to_string()))?;

        let minimum_deposit = snapshot
            .state
            .attributes
            .get("minimum_deposit")
            .map(U256::from_bytes)
            .ok_or_else(|| InvalidSnapshotError::MissingAttribute("minimum_deposit".to_string()))?;

        let maximum_deposit_pool_size = snapshot
            .state
            .attributes
            .get("maximum_deposit_pool_size")
            .map(U256::from_bytes)
            .ok_or_else(|| {
                InvalidSnapshotError::MissingAttribute("maximum_deposit_pool_size".to_string())
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

        let queue_full_start = snapshot
            .state
            .attributes
            .get("queue_full_start")
            .map(U256::from_bytes)
            .ok_or_else(|| {
                InvalidSnapshotError::MissingAttribute("queue_full_start".to_string())
            })?;

        let queue_full_end = snapshot
            .state
            .attributes
            .get("queue_full_end")
            .map(U256::from_bytes)
            .ok_or_else(|| InvalidSnapshotError::MissingAttribute("queue_full_end".to_string()))?;

        let queue_half_start = snapshot
            .state
            .attributes
            .get("queue_half_start")
            .map(U256::from_bytes)
            .ok_or_else(|| {
                InvalidSnapshotError::MissingAttribute("queue_half_start".to_string())
            })?;

        let queue_half_end = snapshot
            .state
            .attributes
            .get("queue_half_end")
            .map(U256::from_bytes)
            .ok_or_else(|| InvalidSnapshotError::MissingAttribute("queue_half_end".to_string()))?;

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

        Ok(RocketPoolState::new(
            reth_supply,
            total_eth,
            liquidity,
            deposit_fee,
            deposits_enabled,
            minimum_deposit,
            maximum_deposit_pool_size,
            assign_deposits_enabled,
            deposit_assign_maximum,
            deposit_assign_socialised_maximum,
            queue_full_start,
            queue_full_end,
            queue_half_start,
            queue_half_end,
            queue_variable_start,
            queue_variable_end,
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use alloy::primitives::U256;
    use rstest::rstest;
    use tycho_client::feed::{synchronizer::ComponentWithState, BlockHeader};
    use tycho_common::{dto::ResponseProtocolState, Bytes};

    use super::super::state::RocketPoolState;
    use crate::protocol::{
        errors::InvalidSnapshotError,
        models::{DecoderContext, TryFromWithBlock},
    };

    fn header() -> BlockHeader {
        BlockHeader {
            number: 1,
            hash: Bytes::from(vec![0; 32]),
            parent_hash: Bytes::from(vec![0; 32]),
            revert: false,
            timestamp: 1,
        }
    }

    fn create_test_snapshot() -> ComponentWithState {
        ComponentWithState {
            state: ResponseProtocolState {
                component_id: "RocketPool".to_owned(),
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
                        "liquidity".to_string(),
                        Bytes::from(U256::from(50_000_000_000_000_000_000u128).to_be_bytes_vec()),
                    ), // 50 ETH liquidity
                    ("deposits_enabled".to_string(), Bytes::from(vec![0x01])),
                    ("assign_deposits_enabled".to_string(), Bytes::from(vec![0x01])),
                    (
                        "deposit_fee".to_string(),
                        Bytes::from(U256::from(5_000_000_000_000_000u128).to_be_bytes_vec()),
                    ), // 0.5%
                    (
                        "minimum_deposit".to_string(),
                        Bytes::from(U256::from(10_000_000_000_000_000u128).to_be_bytes_vec()),
                    ), // 0.01 ETH
                    (
                        "maximum_deposit_pool_size".to_string(),
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
                        "queue_full_start".to_string(),
                        Bytes::from(U256::from(5u64).to_be_bytes_vec()),
                    ),
                    (
                        "queue_full_end".to_string(),
                        Bytes::from(U256::from(10u64).to_be_bytes_vec()),
                    ),
                    (
                        "queue_half_start".to_string(),
                        Bytes::from(U256::from(0u64).to_be_bytes_vec()),
                    ),
                    ("queue_half_end".to_string(), Bytes::from(U256::from(3u64).to_be_bytes_vec())),
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

        let result = RocketPoolState::try_from_with_header(
            snapshot,
            header(),
            &HashMap::new(),
            &HashMap::new(),
            &DecoderContext::new(),
        )
        .await;

        assert!(result.is_ok());
        let state = result.unwrap();
        assert_eq!(state.total_eth, U256::from(100_000_000_000_000_000_000u128));
        assert_eq!(state.reth_supply, U256::from(95_000_000_000_000_000_000u128));
        assert_eq!(state.liquidity, U256::from(50_000_000_000_000_000_000u128));
        assert!(state.deposits_enabled);
        assert!(state.assign_deposits_enabled);
        assert_eq!(state.minimum_deposit, U256::from(10_000_000_000_000_000u128));
        assert_eq!(state.maximum_deposit_pool_size, U256::from(5_000_000_000_000_000_000_000u128));
        assert_eq!(state.queue_full_start, U256::from(5u64));
        assert_eq!(state.queue_full_end, U256::from(10u64));
        assert_eq!(state.queue_half_start, U256::from(0u64));
        assert_eq!(state.queue_half_end, U256::from(3u64));
        assert_eq!(state.queue_variable_start, U256::from(100u64));
        assert_eq!(state.queue_variable_end, U256::from(105u64));
    }

    #[tokio::test]
    async fn test_rocketpool_try_from_deposits_disabled() {
        let eth_address = Bytes::from(vec![0u8; 20]);

        let snapshot = ComponentWithState {
            state: ResponseProtocolState {
                component_id: "RocketPool".to_owned(),
                attributes: HashMap::from([
                    ("total_eth".to_string(), Bytes::from(U256::from(100u64).to_be_bytes_vec())),
                    ("reth_supply".to_string(), Bytes::from(U256::from(100u64).to_be_bytes_vec())),
                    ("liquidity".to_string(), Bytes::from(U256::from(50u64).to_be_bytes_vec())),
                    ("deposits_enabled".to_string(), Bytes::from(vec![0x00])), // disabled
                    ("assign_deposits_enabled".to_string(), Bytes::from(vec![0x00])), // disabled
                    ("deposit_fee".to_string(), Bytes::from(U256::from(0u64).to_be_bytes_vec())),
                    (
                        "minimum_deposit".to_string(),
                        Bytes::from(U256::from(0u64).to_be_bytes_vec()),
                    ),
                    (
                        "maximum_deposit_pool_size".to_string(),
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

        let result = RocketPoolState::try_from_with_header(
            snapshot,
            header(),
            &HashMap::new(),
            &HashMap::new(),
            &DecoderContext::new(),
        )
        .await;

        assert!(result.is_ok());
        let state = result.unwrap();
        assert!(!state.deposits_enabled);
        assert!(!state.assign_deposits_enabled);
    }

    #[tokio::test]
    #[rstest]
    #[case::missing_total_eth("total_eth")]
    #[case::missing_reth_supply("reth_supply")]
    #[case::missing_liquidity("liquidity")]
    #[case::missing_deposits_enabled("deposits_enabled")]
    #[case::missing_assign_deposits_enabled("assign_deposits_enabled")]
    #[case::missing_deposit_fee("deposit_fee")]
    #[case::missing_minimum_deposit("minimum_deposit")]
    #[case::missing_maximum_deposit_pool_size("maximum_deposit_pool_size")]
    #[case::missing_deposit_assign_maximum("deposit_assign_maximum")]
    #[case::missing_deposit_assign_socialised_maximum("deposit_assign_socialised_maximum")]
    #[case::missing_queue_full_start("queue_full_start")]
    #[case::missing_queue_full_end("queue_full_end")]
    #[case::missing_queue_half_start("queue_half_start")]
    #[case::missing_queue_half_end("queue_half_end")]
    #[case::missing_queue_variable_start("queue_variable_start")]
    #[case::missing_queue_variable_end("queue_variable_end")]
    async fn test_rocketpool_try_from_missing_attribute(#[case] missing_attribute: &str) {
        let eth_address = Bytes::from(vec![0u8; 20]);

        let mut attributes = HashMap::from([
            ("total_eth".to_string(), Bytes::from(U256::from(100u64).to_be_bytes_vec())),
            ("reth_supply".to_string(), Bytes::from(U256::from(100u64).to_be_bytes_vec())),
            ("liquidity".to_string(), Bytes::from(U256::from(50u64).to_be_bytes_vec())),
            ("deposits_enabled".to_string(), Bytes::from(vec![0x01])),
            ("assign_deposits_enabled".to_string(), Bytes::from(vec![0x01])),
            ("deposit_fee".to_string(), Bytes::from(U256::from(0u64).to_be_bytes_vec())),
            ("minimum_deposit".to_string(), Bytes::from(U256::from(0u64).to_be_bytes_vec())),
            (
                "maximum_deposit_pool_size".to_string(),
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
                component_id: "RocketPool".to_owned(),
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

        let result = RocketPoolState::try_from_with_header(
            snapshot,
            header(),
            &HashMap::new(),
            &HashMap::new(),
            &DecoderContext::new(),
        )
        .await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            InvalidSnapshotError::MissingAttribute(ref x) if x == missing_attribute
        ));
    }
}
