use alloy_primitives::U256;
use std::collections::HashMap;
use tycho_client::feed::{synchronizer::ComponentWithState, Header};
use tycho_core::Bytes;

use crate::{
    models::Token,
    protocol::{errors::InvalidSnapshotError, models::TryFromWithBlock},
};

use super::state::UniswapV2State;

impl TryFromWithBlock<ComponentWithState> for UniswapV2State {
    type Error = InvalidSnapshotError;

    /// Decodes a `ComponentWithState` into a `UniswapV2State`. Errors with a `InvalidSnapshotError`
    /// if either reserve0 or reserve1 attributes are missing.
    async fn try_from_with_block(
        snapshot: ComponentWithState,
        _block: Header,
        _all_tokens: HashMap<Bytes, Token>,
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

        Ok(UniswapV2State::new(reserve0, reserve1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use chrono::DateTime;
    use std::{collections::HashMap, str::FromStr};

    use tycho_core::{
        dto::{Chain, ChangeType, ProtocolComponent, ResponseProtocolState},
        hex_bytes::Bytes,
    };

    fn usv2_component() -> ProtocolComponent {
        let creation_time = DateTime::from_timestamp(1622526000, 0)
            .unwrap()
            .naive_utc(); //Sample timestamp

        ProtocolComponent {
            id: "State1".to_string(),
            protocol_system: "system1".to_string(),
            protocol_type_name: "typename1".to_string(),
            chain: Chain::Ethereum,
            tokens: Vec::new(),
            contract_ids: Vec::new(),
            static_attributes: HashMap::new(),
            change: ChangeType::Creation,
            creation_tx: Bytes::from_str("0x0000").unwrap(),
            created_at: creation_time,
        }
    }

    fn header() -> Header {
        Header {
            number: 1,
            hash: Bytes::from(vec![0; 32]),
            parent_hash: Bytes::from(vec![0; 32]),
            revert: false,
        }
    }

    #[tokio::test]
    async fn test_usv2_try_from() {
        let attributes: HashMap<String, Bytes> = vec![
            ("reserve0".to_string(), Bytes::from(100_u64.to_be_bytes().to_vec())),
            ("reserve1".to_string(), Bytes::from(200_u64.to_be_bytes().to_vec())),
        ]
        .into_iter()
        .collect();
        let snapshot = ComponentWithState {
            state: ResponseProtocolState {
                component_id: "State1".to_owned(),
                attributes,
                balances: HashMap::new(),
            },
            component: usv2_component(),
        };

        let result = UniswapV2State::try_from_with_block(snapshot, header(), HashMap::new()).await;

        assert!(result.is_ok());
        let res = result.unwrap();
        assert_eq!(res.reserve0, U256::from_str("100").unwrap());
        assert_eq!(res.reserve1, U256::from_str("200").unwrap());
    }

    #[tokio::test]
    async fn test_usv2_try_from_invalid() {
        let attributes: HashMap<String, Bytes> =
            vec![("reserve0".to_string(), Bytes::from(100_u64.to_be_bytes().to_vec()))]
                .into_iter()
                .collect();
        let snapshot = ComponentWithState {
            state: ResponseProtocolState {
                component_id: "State1".to_owned(),
                attributes,
                balances: HashMap::new(),
            },
            component: usv2_component(),
        };

        let result = UniswapV2State::try_from_with_block(snapshot, header(), HashMap::new()).await;

        assert!(result.is_err());

        assert!(matches!(
            result.err().unwrap(),
            InvalidSnapshotError::MissingAttribute(attr) if attr == *"reserve1"
        ));
    }
}
