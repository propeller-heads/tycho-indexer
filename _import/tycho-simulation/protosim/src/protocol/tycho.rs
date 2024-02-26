use ethers::types::U256;
use tycho_client::feed::synchronizer::NativeSnapshot;

use crate::protocol::{
    errors::InvalidSnapshotError,
    uniswap_v2::state::UniswapV2State,
    uniswap_v3::{enums::FeeAmount, state::UniswapV3State},
};

use super::uniswap_v3::tick_list::TickInfo;

impl TryFrom<NativeSnapshot> for UniswapV2State {
    type Error = InvalidSnapshotError;

    /// Decodes a `NativeSnapshot` into a `UniswapV2State`. Errors with a `InvalidSnapshotError`
    /// if either reserve0 or reserve1 attributes are missing.
    fn try_from(snapshot: NativeSnapshot) -> Result<Self, Self::Error> {
        let reserve0 = U256::from(
            snapshot
                .state
                .attributes
                .get("reserve0")
                .ok_or(InvalidSnapshotError::MissingAttribute("reserve0".to_string()))?
                .clone(),
        );

        let reserve1 = U256::from(
            snapshot
                .state
                .attributes
                .get("reserve1")
                .ok_or(InvalidSnapshotError::MissingAttribute("reserve1".to_string()))?
                .clone(),
        );

        Ok(UniswapV2State::new(reserve0, reserve1))
    }
}

impl TryFrom<NativeSnapshot> for UniswapV3State {
    type Error = InvalidSnapshotError;

    /// Decodes a `NativeSnapshot` into a `UniswapV3State`. Errors with a `InvalidSnapshotError`
    /// if the snapshot is missing any required attributes or if the fee amount is not supported.
    fn try_from(snapshot: NativeSnapshot) -> Result<Self, Self::Error> {
        let liquidity = u128::from(
            snapshot
                .state
                .attributes
                .get("liquidity")
                .ok_or_else(|| InvalidSnapshotError::MissingAttribute("liquidity".to_string()))?
                .clone(),
        );

        let sqrt_price = U256::from(
            snapshot
                .state
                .attributes
                .get("sqrt_price_x96")
                .ok_or_else(|| InvalidSnapshotError::MissingAttribute("sqrt_price".to_string()))?
                .clone(),
        );

        let fee_value = i32::from(
            snapshot
                .component
                .static_attributes
                .get("fee")
                .ok_or_else(|| InvalidSnapshotError::MissingAttribute("fee".to_string()))?
                .clone(),
        );
        let fee = FeeAmount::try_from(fee_value)
            .map_err(|_| InvalidSnapshotError::ValueError("Unsupported fee amount".to_string()))?;

        let tick = i32::from(
            snapshot
                .state
                .attributes
                .get("tick")
                .ok_or_else(|| InvalidSnapshotError::MissingAttribute("tick".to_string()))?
                .clone(),
        );

        let ticks: Result<Vec<_>, _> = snapshot
            .state
            .attributes
            .iter()
            .filter_map(|(key, value)| {
                if key.starts_with("ticks/") {
                    Some(
                        key.split('/')
                            .nth(1)?
                            .parse::<i32>()
                            .map(|tick_index| TickInfo::new(tick_index, i128::from(value.clone())))
                            .map_err(|err| InvalidSnapshotError::ValueError(err.to_string())),
                    )
                } else {
                    None
                }
            })
            .collect();

        let mut ticks = match ticks {
            Ok(ticks) if !ticks.is_empty() => ticks,
            _ => return Err(InvalidSnapshotError::MissingAttribute("tick_liquidities".to_string())),
        };

        ticks.sort_by_key(|tick| tick.index);

        Ok(UniswapV3State::new(liquidity, sqrt_price, fee, tick, ticks))
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, str::FromStr};

    use chrono::NaiveDateTime;
    use rstest::rstest;
    use tycho_types::{
        dto::{Chain, ChangeType, ProtocolComponent, ResponseProtocolState},
        hex_bytes::Bytes,
    };

    use super::*;

    fn usv2_component() -> ProtocolComponent {
        let creation_time = NaiveDateTime::from_timestamp_opt(1622526000, 0).unwrap(); //Sample timestamp

        let mut static_attributes: HashMap<String, Bytes> = HashMap::new();
        static_attributes.insert("attr1".to_string(), "0x000012".into());
        static_attributes.insert("attr2".to_string(), "0x000005".into());

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

    #[test]
    fn test_usv2_try_from() {
        let attributes: HashMap<String, Bytes> = vec![
            ("reserve0".to_string(), Bytes::from(100_u64.to_le_bytes().to_vec())),
            ("reserve1".to_string(), Bytes::from(200_u64.to_le_bytes().to_vec())),
        ]
        .into_iter()
        .collect();
        let snapshot = NativeSnapshot {
            state: ResponseProtocolState {
                component_id: "State1".to_owned(),
                attributes,
                modify_tx: Bytes::from_str("0x0000").unwrap(),
            },
            component: usv2_component(),
        };

        let result = UniswapV2State::try_from(snapshot);

        assert!(result.is_ok());
        let res = result.unwrap();
        assert_eq!(res.reserve0, 100.into());
        assert_eq!(res.reserve1, 200.into());
    }

    #[test]
    fn test_usv2_try_from_invalid() {
        let attributes: HashMap<String, Bytes> =
            vec![("reserve0".to_string(), Bytes::from(100_u64.to_le_bytes().to_vec()))]
                .into_iter()
                .collect();
        let snapshot = NativeSnapshot {
            state: ResponseProtocolState {
                component_id: "State1".to_owned(),
                attributes,
                modify_tx: Bytes::from_str("0x0000").unwrap(),
            },
            component: usv2_component(),
        };

        let result = UniswapV2State::try_from(snapshot);

        assert!(result.is_err());
        assert_eq!(
            result.err().unwrap(),
            InvalidSnapshotError::MissingAttribute("reserve1".to_string())
        );
    }

    fn usv3_component() -> ProtocolComponent {
        let creation_time = NaiveDateTime::from_timestamp_opt(1622526000, 0).unwrap(); //Sample timestamp

        // Add a static attribute "fee"
        let mut static_attributes: HashMap<String, Bytes> = HashMap::new();
        static_attributes.insert("fee".to_string(), Bytes::from(3000_i32.to_le_bytes().to_vec()));

        ProtocolComponent {
            id: "State1".to_string(),
            protocol_system: "system1".to_string(),
            protocol_type_name: "typename1".to_string(),
            chain: Chain::Ethereum,
            tokens: Vec::new(),
            contract_ids: Vec::new(),
            static_attributes,
            change: ChangeType::Creation,
            creation_tx: Bytes::from_str("0x0000").unwrap(),
            created_at: creation_time,
        }
    }

    fn usv3_attributes() -> HashMap<String, Bytes> {
        vec![
            ("liquidity".to_string(), Bytes::from(100_u64.to_le_bytes().to_vec())),
            ("sqrt_price_x96".to_string(), Bytes::from(200_u64.to_le_bytes().to_vec())),
            ("tick".to_string(), Bytes::from(300_i32.to_le_bytes().to_vec())),
            ("ticks/60/net_liquidity".to_string(), Bytes::from(400_i128.to_le_bytes().to_vec())),
        ]
        .into_iter()
        .collect::<HashMap<String, Bytes>>()
    }

    #[test]
    fn test_usv3_try_from() {
        let snapshot = NativeSnapshot {
            state: ResponseProtocolState {
                component_id: "State1".to_owned(),
                attributes: usv3_attributes(),
                modify_tx: Bytes::from_str("0x0000").unwrap(),
            },
            component: usv3_component(),
        };

        let result = UniswapV3State::try_from(snapshot);

        assert!(result.is_ok());
        let expected = UniswapV3State::new(
            100,
            U256::from(200),
            FeeAmount::Medium,
            300,
            vec![TickInfo::new(60, 400)],
        );
        assert_eq!(result.unwrap(), expected);
    }

    #[rstest]
    #[case::missing_liquidity("liquidity")]
    #[case::missing_sqrt_price("sqrt_price")]
    #[case::missing_tick("tick")]
    #[case::missing_tick_liquidity("tick_liquidities")]
    #[case::missing_fee("fee")]
    fn test_usv3_try_from_invalid(#[case] missing_attribute: String) {
        // remove missing attribute
        let mut attributes = usv3_attributes();
        attributes.remove(&missing_attribute);

        if missing_attribute == "tick_liquidities" {
            attributes.remove("ticks/60/net_liquidity");
        }

        if missing_attribute == "sqrt_price" {
            attributes.remove("sqrt_price_x96");
        }

        let mut component = usv3_component();
        if missing_attribute == "fee" {
            component
                .static_attributes
                .remove("fee");
        }

        let snapshot = NativeSnapshot {
            state: ResponseProtocolState {
                component_id: "State1".to_owned(),
                attributes,
                modify_tx: Bytes::from_str("0x0000").unwrap(),
            },
            component,
        };

        let result = UniswapV3State::try_from(snapshot);

        assert!(result.is_err());
        assert_eq!(
            result.err().unwrap(),
            InvalidSnapshotError::MissingAttribute(missing_attribute)
        );
    }

    #[test]
    fn test_usv3_try_from_invalid_fee() {
        // set an invalid fee amount (100, 500, 3_000 and 10_000 are the only valid fee amounts)
        let mut component = usv3_component();
        component
            .static_attributes
            .insert("fee".to_string(), Bytes::from(4000_i32.to_le_bytes().to_vec()));

        let snapshot = NativeSnapshot {
            state: ResponseProtocolState {
                component_id: "State1".to_owned(),
                attributes: usv3_attributes(),
                modify_tx: Bytes::from_str("0x0000").unwrap(),
            },
            component,
        };

        let result = UniswapV3State::try_from(snapshot);

        assert!(result.is_err());
        assert_eq!(
            result.err().unwrap(),
            InvalidSnapshotError::ValueError("Unsupported fee amount".to_string())
        );
    }
}
