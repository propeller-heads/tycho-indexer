use std::collections::HashMap;

use alloy_primitives::U256;
use rstest::rstest;
use tycho_client::feed::{synchronizer::ComponentWithState, Header};
use tycho_common::{dto::ResponseProtocolState, Bytes};

use crate::{
    evm::protocol::{
        cowamm::{
            state::CowAMMState,
            bmath,
        },
    },
    models::{Balances, Token},
    protocol::{
        errors::{SimulationError, TransitionError, InvalidSnapshotError},
        models::TryFromWithBlock
    },
};

const BYTES: usize = 32;

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
       
        let token_a = snapshot
            .component
            .static_attributes
            .get("token_a")
            .ok_or_else(|| InvalidSnapshotError::MissingAttribute("token_a".to_string()))?
            .clone();

        let token_b = snapshot
            .component
            .static_attributes
            .get("token_b")
            .ok_or_else(|| InvalidSnapshotError::MissingAttribute("token_b".to_string()))?
            .clone();

        let lp_token = snapshot
            .component
            .static_attributes
            .get("lp_token")
            .ok_or_else(|| InvalidSnapshotError::MissingAttribute("lp_token".to_string()))?
            .clone();

        let fee = 0u64;

        //weight_a and weight_b are left padded big endian numbers of 32 bytes
        let weight_a =  U256::from_be_bytes::<BYTES>(
            snapshot
                .component
                .static_attributes
                .get("weight_a")
                .ok_or_else(|| InvalidSnapshotError::MissingAttribute("weight_a".to_string()))?
                .as_ref()
                .try_into()
                .map_err(|err| {
                    InvalidSnapshotError::ValueError(format!("weight_a length mismatch: {err:?}"))
                })?,
        );

        let weight_b = U256::from_be_bytes::<BYTES>(
            snapshot
                .component
                .static_attributes
                .get("weight_b")
                .ok_or_else(|| InvalidSnapshotError::MissingAttribute("weight_b".to_string()))?
                .as_ref()
                .try_into()
                .map_err(|err| {
                    InvalidSnapshotError::ValueError(format!("weight_b length mismatch: {err:?}"))
                })?,
        );

        Ok(Self::new(token_a, token_b, lp_token, weight_a, weight_b, fee))
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
                    ("weight_a".to_string(), Bytes::from(vec![0; 32])),
                    ("weight_b".to_string(), Bytes::from(vec![0; 32])),
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
        assert_eq!(result.unwrap(), CowAMMState::new(Bytes::from(vec![0; 32]), Bytes::from(vec![0; 32]), Bytes::from(vec![0; 32]),U256::from(0), U256::from(0), 0u64));
    }

    #[tokio::test]
    #[rstest]
    #[case::missing_token0("token_a")]
    #[case::missing_token1("token_b")]
    #[case::missing_lp_token("lp_token")]
    #[case::missing_fee("fee")]
    #[case::missing_weight_a("weight_a")]
    #[case::missing_weight_b("weight_b")]
    async fn test_cowamm_try_from_missing_attribute(#[case] missing_attribute: &str) {
        let mut attributes = HashMap::from([
            ("token_a".to_string(), Bytes::from(vec![0; 32])),
            ("token_b".to_string(), Bytes::from(vec![0; 32])),
            ("lp_token".to_string(), Bytes::from(vec![0; 32])),
            ("fee".to_string(), Bytes::from(vec![0; 32])),
            ("weight_a".to_string(), Bytes::from(vec![0; 32])),
            ("weight_b".to_string(), Bytes::from(vec![0; 32])),
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
