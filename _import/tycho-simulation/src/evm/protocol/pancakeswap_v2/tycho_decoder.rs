#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use alloy::primitives::U256;
    use rstest::rstest;
    use tycho_client::feed::{synchronizer::ComponentWithState, Header};
    use tycho_common::{dto::ResponseProtocolState, Bytes};

    use super::super::state::PancakeswapV2State;
    use crate::protocol::{errors::InvalidSnapshotError, models::TryFromWithBlock};

    fn header() -> Header {
        Header {
            number: 1,
            hash: Bytes::from(vec![0; 32]),
            parent_hash: Bytes::from(vec![0; 32]),
            revert: false,
        }
    }

    #[tokio::test]
    async fn test_pancakeswap_v2_try_from() {
        let snapshot = ComponentWithState {
            state: ResponseProtocolState {
                component_id: "State1".to_owned(),
                attributes: HashMap::from([
                    ("reserve0".to_string(), Bytes::from(vec![0; 32])),
                    ("reserve1".to_string(), Bytes::from(vec![0; 32])),
                ]),
                balances: HashMap::new(),
            },
            component: Default::default(),
            component_tvl: None,
        };

        let result = PancakeswapV2State::try_from_with_block(
            snapshot,
            header(),
            &HashMap::new(),
            &HashMap::new(),
        )
        .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), PancakeswapV2State::new(U256::from(0u64), U256::from(0u64)));
    }

    #[tokio::test]
    #[rstest]
    #[case::missing_reserve0("reserve0")]
    #[case::missing_reserve1("reserve1")]
    async fn test_pancakeswap_v2_try_from_missing_attribute(#[case] missing_attribute: &str) {
        let mut attributes = HashMap::from([
            ("reserve0".to_string(), Bytes::from(vec![0; 32])),
            ("reserve1".to_string(), Bytes::from(vec![0; 32])),
        ]);
        attributes.remove(missing_attribute);

        let snapshot = ComponentWithState {
            state: ResponseProtocolState {
                component_id: "State1".to_owned(),
                attributes,
                balances: HashMap::new(),
            },
            component: Default::default(),
            component_tvl: None,
        };

        let result = PancakeswapV2State::try_from_with_block(
            snapshot,
            header(),
            &HashMap::new(),
            &HashMap::new(),
        )
        .await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            InvalidSnapshotError::MissingAttribute(ref x) if x == missing_attribute
        ));
    }
}
