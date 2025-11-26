use std::collections::HashMap;

use alloy::primitives::U256;
use tycho_client::feed::{synchronizer::ComponentWithState, BlockHeader};
use tycho_common::{models::token::Token, Bytes};
use tycho_ethereum::BytesCodec;

use super::{state::RocketPoolState, ETH_ADDRESS};
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
            .map(|val| U256::from_bytes(val))
            .ok_or_else(|| InvalidSnapshotError::MissingAttribute("total_eth".to_string()))?;

        let reth_supply = snapshot
            .state
            .attributes
            .get("reth_supply")
            .map(|val| U256::from_bytes(val))
            .ok_or_else(|| InvalidSnapshotError::MissingAttribute("reth_supply".to_string()))?;

        // Liquidity is the ETH balance of the component
        // TODO - check if this is the right way to get liquidity, or if we need account balances
        let liquidity = snapshot
            .state
            .balances
            .get(&Bytes::from(ETH_ADDRESS))
            .map(|val| U256::from_bytes(val))
            .ok_or_else(|| {
                InvalidSnapshotError::MissingAttribute("liquidity (ETH balance)".to_string())
            })?;

        let deposits_enabled = snapshot
            .state
            .attributes
            .get("deposits_enabled")
            .map(|val| !U256::from_bytes(val).is_zero())
            .ok_or_else(|| {
                InvalidSnapshotError::MissingAttribute("deposits_enabled".to_string())
            })?;

        let deposit_fee = snapshot
            .state
            .attributes
            .get("deposit_fee")
            .map(|val| U256::from_bytes(val))
            .ok_or_else(|| InvalidSnapshotError::MissingAttribute("deposit_fee".to_string()))?;

        let minimum_deposit = snapshot
            .state
            .attributes
            .get("minimum_deposit")
            .map(|val| U256::from_bytes(val))
            .ok_or_else(|| InvalidSnapshotError::MissingAttribute("minimum_deposit".to_string()))?;

        let maximum_deposit_pool_size = snapshot
            .state
            .attributes
            .get("maximum_deposit_pool_size")
            .map(|val| U256::from_bytes(val))
            .ok_or_else(|| {
                InvalidSnapshotError::MissingAttribute("maximum_deposit_pool_size".to_string())
            })?;

        Ok(RocketPoolState::new(
            reth_supply,
            total_eth,
            liquidity,
            deposit_fee,
            deposits_enabled,
            minimum_deposit,
            maximum_deposit_pool_size,
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
        let eth_address = Bytes::from(vec![0u8; 20]);

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
                    ("deposits_enabled".to_string(), Bytes::from(vec![0x01])),
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
                ]),
                balances: HashMap::from([
                    (
                        eth_address,
                        Bytes::from(U256::from(50_000_000_000_000_000_000u128).to_be_bytes_vec()),
                    ), // 50 ETH liquidity
                ]),
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
        assert_eq!(state.minimum_deposit, U256::from(10_000_000_000_000_000u128));
        assert_eq!(state.maximum_deposit_pool_size, U256::from(5_000_000_000_000_000_000_000u128));
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
                    ("deposits_enabled".to_string(), Bytes::from(vec![0x00])), // disabled
                    ("deposit_fee".to_string(), Bytes::from(U256::from(0u64).to_be_bytes_vec())),
                    (
                        "minimum_deposit".to_string(),
                        Bytes::from(U256::from(0u64).to_be_bytes_vec()),
                    ),
                    (
                        "maximum_deposit_pool_size".to_string(),
                        Bytes::from(U256::from(1000u64).to_be_bytes_vec()),
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
    }

    #[tokio::test]
    #[rstest]
    #[case::missing_total_eth("total_eth")]
    #[case::missing_reth_supply("reth_supply")]
    #[case::missing_deposits_enabled("deposits_enabled")]
    #[case::missing_deposit_fee("deposit_fee")]
    #[case::missing_minimum_deposit("minimum_deposit")]
    #[case::missing_maximum_deposit_pool_size("maximum_deposit_pool_size")]
    async fn test_rocketpool_try_from_missing_attribute(#[case] missing_attribute: &str) {
        let eth_address = Bytes::from(vec![0u8; 20]);

        let mut attributes = HashMap::from([
            ("total_eth".to_string(), Bytes::from(U256::from(100u64).to_be_bytes_vec())),
            ("reth_supply".to_string(), Bytes::from(U256::from(100u64).to_be_bytes_vec())),
            ("deposits_enabled".to_string(), Bytes::from(vec![0x01])),
            ("deposit_fee".to_string(), Bytes::from(U256::from(0u64).to_be_bytes_vec())),
            ("minimum_deposit".to_string(), Bytes::from(U256::from(0u64).to_be_bytes_vec())),
            (
                "maximum_deposit_pool_size".to_string(),
                Bytes::from(U256::from(1000u64).to_be_bytes_vec()),
            ),
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

    #[tokio::test]
    async fn test_rocketpool_try_from_missing_liquidity() {
        let snapshot = ComponentWithState {
            state: ResponseProtocolState {
                component_id: "RocketPool".to_owned(),
                attributes: HashMap::from([
                    ("total_eth".to_string(), Bytes::from(U256::from(100u64).to_be_bytes_vec())),
                    ("reth_supply".to_string(), Bytes::from(U256::from(100u64).to_be_bytes_vec())),
                    ("deposits_enabled".to_string(), Bytes::from(vec![0x01])),
                    ("deposit_fee".to_string(), Bytes::from(U256::from(0u64).to_be_bytes_vec())),
                    (
                        "minimum_deposit".to_string(),
                        Bytes::from(U256::from(0u64).to_be_bytes_vec()),
                    ),
                    (
                        "maximum_deposit_pool_size".to_string(),
                        Bytes::from(U256::from(1000u64).to_be_bytes_vec()),
                    ),
                ]),
                balances: HashMap::new(), // No ETH balance
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
            InvalidSnapshotError::MissingAttribute(ref x) if x.contains("liquidity")
        ));
    }
}
