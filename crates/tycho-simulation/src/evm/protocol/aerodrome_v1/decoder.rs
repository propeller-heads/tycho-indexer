use std::collections::HashMap;

use alloy::primitives::U256;
use tycho_client::feed::{synchronizer::ComponentWithState, BlockHeader};
use tycho_common::{models::token::Token, Bytes};

use crate::{
    evm::protocol::aerodrome_v1::state::AerodromeV1State,
    protocol::{
        errors::InvalidSnapshotError,
        models::{DecoderContext, TryFromWithBlock},
    },
};

impl TryFromWithBlock<ComponentWithState, BlockHeader> for AerodromeV1State {
    type Error = InvalidSnapshotError;

    /// Decodes a `ComponentWithState` into an `AerodromeV1State`. Errors with an
    /// `InvalidSnapshotError` if any required attribute is missing.
    async fn try_from_with_header(
        snapshot: ComponentWithState,
        _block: BlockHeader,
        _account_balances: &HashMap<Bytes, HashMap<Bytes, Bytes>>,
        _all_tokens: &HashMap<Bytes, Token>,
        _decoder_context: &DecoderContext,
    ) -> Result<Self, Self::Error> {
        let reserve0 = U256::from_be_slice(
            snapshot
                .state
                .attributes
                .get("reserve0")
                .ok_or(InvalidSnapshotError::MissingAttribute("reserve0".to_string()))?,
        );
        let reserve1 = U256::from_be_slice(
            snapshot
                .state
                .attributes
                .get("reserve1")
                .ok_or(InvalidSnapshotError::MissingAttribute("reserve1".to_string()))?,
        );
        let fee_bps = u32::from(
            snapshot
                .state
                .attributes
                .get("fee")
                .ok_or(InvalidSnapshotError::MissingAttribute("fee".to_string()))?
                .clone(),
        );

        if fee_bps > 10_000 {
            return Err(InvalidSnapshotError::ValueError(format!(
                "Invalid fee value {fee_bps}, expected <= 10000 bps"
            )));
        }

        Ok(Self::new(reserve0, reserve1, fee_bps))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use alloy::primitives::U256;
    use rstest::rstest;
    use tycho_client::feed::synchronizer::ComponentWithState;
    use tycho_common::{dto::ResponseProtocolState, Bytes};

    use super::super::state::AerodromeV1State;
    use crate::{
        evm::protocol::test_utils::try_decode_snapshot_with_defaults,
        protocol::errors::InvalidSnapshotError,
    };

    #[tokio::test]
    async fn test_aerodrome_v1_try_from() {
        let snapshot = ComponentWithState {
            state: ResponseProtocolState {
                component_id: "State1".to_owned(),
                attributes: HashMap::from([
                    ("reserve0".to_string(), Bytes::from(vec![0; 32])),
                    ("reserve1".to_string(), Bytes::from(vec![0; 32])),
                    ("fee".to_string(), Bytes::from(30_u32.to_be_bytes().to_vec())),
                ]),
                balances: HashMap::new(),
            },
            component: Default::default(),
            component_tvl: None,
            entrypoints: Vec::new(),
        };

        let result = try_decode_snapshot_with_defaults::<AerodromeV1State>(snapshot).await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), AerodromeV1State::new(U256::from(0u64), U256::from(0u64), 30));
    }

    #[tokio::test]
    #[rstest]
    #[case::missing_reserve0("reserve0")]
    #[case::missing_reserve1("reserve1")]
    #[case::missing_fee("fee")]
    async fn test_aerodrome_v1_try_from_missing_attribute(#[case] missing_attribute: &str) {
        let mut attributes = HashMap::from([
            ("reserve0".to_string(), Bytes::from(vec![0; 32])),
            ("reserve1".to_string(), Bytes::from(vec![0; 32])),
            ("fee".to_string(), Bytes::from(30_u32.to_be_bytes().to_vec())),
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
            entrypoints: Vec::new(),
        };

        let result = try_decode_snapshot_with_defaults::<AerodromeV1State>(snapshot).await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            InvalidSnapshotError::MissingAttribute(ref x) if x == missing_attribute
        ));
    }

    #[tokio::test]
    async fn test_aerodrome_v1_try_from_invalid_fee() {
        let snapshot = ComponentWithState {
            state: ResponseProtocolState {
                component_id: "State1".to_owned(),
                attributes: HashMap::from([
                    ("reserve0".to_string(), Bytes::from(vec![0; 32])),
                    ("reserve1".to_string(), Bytes::from(vec![0; 32])),
                    ("fee".to_string(), Bytes::from(10_001_u32.to_be_bytes().to_vec())),
                ]),
                balances: HashMap::new(),
            },
            component: Default::default(),
            component_tvl: None,
            entrypoints: Vec::new(),
        };

        let result = try_decode_snapshot_with_defaults::<AerodromeV1State>(snapshot).await;
        assert!(matches!(result, Err(InvalidSnapshotError::ValueError(_))));
    }
}
