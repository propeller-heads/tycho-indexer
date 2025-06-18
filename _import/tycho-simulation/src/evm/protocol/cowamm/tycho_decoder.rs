#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use alloy_primitives::U256;
    use rstest::rstest;
    use tycho_client::feed::{synchronizer::ComponentWithState, Header};
    use tycho_common::{dto::ResponseProtocolState, Bytes};

    use super::super::state::CowAMMState;
    use crate::protocol::{errors::InvalidSnapshotError, models::TryFromWithBlock};

    fn header() -> Header {
        Header {
            number: 1,
            hash: Bytes::from(vec![0; 32]),
            parent_hash: Bytes::from(vec![0; 32]),
            revert: false,
        }
    }

    impl TryFromWithBlock<ComponentWithState> for CowAMMState {
    type Error = InvalidSnapshotError;

    async fn try_from_with_block(
        snapshot: ComponentWithState,
        _block: Header,
        _account_balances: &HashMap<Bytes, HashMap<Bytes, Bytes>>,
        _all_tokens: &HashMap<Bytes, Token>,
    ) -> Result<Self, Self::Error> {
       
        let token0 = U256::from_big_endian(
            snapshot
                .component
                .static_attributes
                .get("token_a")
                .ok_or_else(|| InvalidSnapshotError::MissingAttribute("token_a".to_string()))?,
        );

        let token1 = U256::from_big_endian(
            snapshot
                .component
                .static_attributes
                .get("token_b")
                .ok_or_else(|| InvalidSnapshotError::MissingAttribute("token_b".to_string()))?,
        );

        let lp_token = U256::from_big_endian(
            snapshot
                .component
                .static_attributes
                .get("lp_token")
                .ok_or_else(|| InvalidSnapshotError::MissingAttribute("lp_token".to_string()))?,
        );

        let fee = u64::from_be_bytes(0);

        let weight_a = U256::from_big_endian(
            snapshot
                .component
                .static_attributes
                .get("normalized_weight_a")
                .ok_or_else(|| InvalidSnapshotError::MissingAttribute("normalized_weight_a".to_string()))?,
        );

        let weight_b = U256::from_big_endian(
            snapshot
                .component
                .static_attributes
                .get("normalized_weight_a")
                .ok_or_else(|| InvalidSnapshotError::MissingAttribute("normalized_weight_a".to_string()))?,
        );

        Ok(Self::new(token0, token1, lp_token, fee, weight_a, weight_b))
    }
}

    #[tokio::test]
    async fn test_cowamm_try_from() {
        let snapshot = ComponentWithState {
            state: ResponseProtocolState {
                component_id: "State1".to_owned(),
                attributes: HashMap::from([
                    ("token_a".to_string(), Bytes::from(vec![0; 32])),
                    ("token_b".to_string(), Bytes::from(vec![0; 32])),
                    ("lp_token".to_string(), Bytes::from(vec![0; 32])),
                    ("fee".to_string(), Bytes::from(vec![0; 32])),
                    ("normalized_weight_a".to_string(), Bytes::from(vec![0; 32])),
                    ("normalized_weight_b".to_string(), Bytes::from(vec![0; 32])),
                    ("normalized_weight_a".to_string(), Bytes::from(vec![0; 32])),
                    ("normalized_weight_b".to_string(), Bytes::from(vec![0; 32])),
                ]),
                balances: HashMap::new(),
            },
            component: Default::default(),
            component_tvl: None,
        };

        let result = CowAMMState::try_from_with_block(
            snapshot,
            header(),
            &HashMap::new(),
            &HashMap::new(),
        )
        .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), CowAMMState::new(U256::from(0u64), U256::from(0u64)));
    }

    #[tokio::test]
    #[rstest]
    #[case::missing_token0("token_a")]
    #[case::missing_token1("token_b")]
    #[case::missing_lp_token("lp_token")]
    #[case::missing_fee("fee")]
    #[case::missing_normalized_weight_a("normalized_weight_a")]
    #[case::missing_normalized_weight_b("normalized_weight_b")]
    async fn test_cowamm_try_from_missing_attribute(#[case] missing_attribute: &str) {
        let mut attributes = HashMap::from([
            ("token_a".to_string(), Bytes::from(vec![0; 32])),
            ("token_b".to_string(), Bytes::from(vec![0; 32])),
            ("lp_token".to_string(), Bytes::from(vec![0; 32])),
            ("fee".to_string(), Bytes::from(vec![0; 32])),
            ("normalized_weight_a".to_string(), Bytes::from(vec![0; 32])),
            ("normalized_weight_b".to_string(), Bytes::from(vec![0; 32])),
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

        let result = CowAMMState::try_from_with_block(
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
