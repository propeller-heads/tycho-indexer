use std::collections::HashMap;

use alloy_primitives::U256;
use tycho_client::feed::{synchronizer::ComponentWithState, Header};
use tycho_core::Bytes;

use super::{enums::FeeAmount, state::UniswapV3State};
use crate::{
    evm::protocol::utils::{uniswap, uniswap::tick_list::TickInfo},
    models::Token,
    protocol::{errors::InvalidSnapshotError, models::TryFromWithBlock},
};

impl TryFromWithBlock<ComponentWithState> for UniswapV3State {
    type Error = InvalidSnapshotError;

    /// Decodes a `ComponentWithState` into a `UniswapV3State`. Errors with a `InvalidSnapshotError`
    /// if the snapshot is missing any required attributes or if the fee amount is not supported.
    async fn try_from_with_block(
        snapshot: ComponentWithState,
        _block: Header,
        _all_tokens: &HashMap<Bytes, Token>,
    ) -> Result<Self, Self::Error> {
        let liq = snapshot
            .state
            .attributes
            .get("liquidity")
            .ok_or_else(|| InvalidSnapshotError::MissingAttribute("liquidity".to_string()))?
            .clone();

        // This is a hotfix because if the liquidity has never been updated after creation, it's
        // currently encoded as H256::zero(), therefore, we can't decode this as u128.
        // We can remove this once it has been fixed on the tycho side.
        let liq_16_bytes = if liq.len() == 32 {
            // Make sure it only happens for 0 values, otherwise error.
            if liq == Bytes::zero(32) {
                Bytes::from([0; 16])
            } else {
                return Err(InvalidSnapshotError::ValueError(format!(
                    "Liquidity bytes too long for {}, expected 16",
                    liq
                )));
            }
        } else {
            liq
        };

        let liquidity = u128::from(liq_16_bytes);

        let sqrt_price = U256::from_be_slice(
            snapshot
                .state
                .attributes
                .get("sqrt_price_x96")
                .ok_or_else(|| InvalidSnapshotError::MissingAttribute("sqrt_price".to_string()))?,
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

        let tick = snapshot
            .state
            .attributes
            .get("tick")
            .ok_or_else(|| InvalidSnapshotError::MissingAttribute("tick".to_string()))?
            .clone();

        // This is a hotfix because if the tick has never been updated after creation, it's
        // currently encoded as H256::zero(), therefore, we can't decode this as i32. We can
        // remove this this will be fixed on the tycho side.
        let ticks_4_bytes = if tick.len() == 32 {
            // Make sure it only happens for 0 values, otherwise error.
            if tick == Bytes::zero(32) {
                Bytes::from([0; 4])
            } else {
                return Err(InvalidSnapshotError::ValueError(format!(
                    "Tick bytes too long for {}, expected 4",
                    tick
                )));
            }
        } else {
            tick
        };
        let tick = uniswap::i24_be_bytes_to_i32(&ticks_4_bytes);

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
            Ok(ticks) if !ticks.is_empty() => ticks
                .into_iter()
                .filter(|t| t.net_liquidity != 0)
                .collect::<Vec<_>>(),
            _ => return Err(InvalidSnapshotError::MissingAttribute("tick_liquidities".to_string())),
        };

        ticks.sort_by_key(|tick| tick.index);

        Ok(UniswapV3State::new(liquidity, sqrt_price, fee, tick, ticks))
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, str::FromStr};

    use chrono::DateTime;
    use rstest::rstest;
    use tycho_core::{
        dto::{Chain, ChangeType, ProtocolComponent, ResponseProtocolState},
        hex_bytes::Bytes,
    };

    use super::*;
    use crate::evm::protocol::utils::uniswap::i24_be_bytes_to_i32;

    fn usv3_component() -> ProtocolComponent {
        let creation_time = DateTime::from_timestamp(1622526000, 0)
            .unwrap()
            .naive_utc(); //Sample timestamp

        // Add a static attribute "fee"
        let mut static_attributes: HashMap<String, Bytes> = HashMap::new();
        static_attributes.insert("fee".to_string(), Bytes::from(3000_i32.to_be_bytes().to_vec()));

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
            ("liquidity".to_string(), Bytes::from(100_u64.to_be_bytes().to_vec())),
            ("sqrt_price_x96".to_string(), Bytes::from(200_u64.to_be_bytes().to_vec())),
            ("tick".to_string(), Bytes::from(300_i32.to_be_bytes().to_vec())),
            ("ticks/60/net_liquidity".to_string(), Bytes::from(400_i128.to_be_bytes().to_vec())),
        ]
        .into_iter()
        .collect::<HashMap<String, Bytes>>()
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
    async fn test_usv3_try_from() {
        let snapshot = ComponentWithState {
            state: ResponseProtocolState {
                component_id: "State1".to_owned(),
                attributes: usv3_attributes(),
                balances: HashMap::new(),
            },
            component: usv3_component(),
        };

        let result = UniswapV3State::try_from_with_block(snapshot, header(), &HashMap::new()).await;

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

    #[tokio::test]
    #[rstest]
    #[case::missing_liquidity("liquidity")]
    #[case::missing_sqrt_price("sqrt_price")]
    #[case::missing_tick("tick")]
    #[case::missing_tick_liquidity("tick_liquidities")]
    #[case::missing_fee("fee")]
    async fn test_usv3_try_from_invalid(#[case] missing_attribute: String) {
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

        let snapshot = ComponentWithState {
            state: ResponseProtocolState {
                component_id: "State1".to_owned(),
                attributes,
                balances: HashMap::new(),
            },
            component,
        };

        let result = UniswapV3State::try_from_with_block(snapshot, header(), &HashMap::new()).await;

        assert!(result.is_err());
        assert!(matches!(
            result.err().unwrap(),
            InvalidSnapshotError::MissingAttribute(attr) if attr == missing_attribute
        ));
    }

    #[tokio::test]
    async fn test_usv3_try_from_invalid_fee() {
        // set an invalid fee amount (100, 500, 3_000 and 10_000 are the only valid fee amounts)
        let mut component = usv3_component();
        component
            .static_attributes
            .insert("fee".to_string(), Bytes::from(4000_i32.to_be_bytes().to_vec()));

        let snapshot = ComponentWithState {
            state: ResponseProtocolState {
                component_id: "State1".to_owned(),
                attributes: usv3_attributes(),
                balances: HashMap::new(),
            },
            component,
        };

        let result = UniswapV3State::try_from_with_block(snapshot, header(), &HashMap::new()).await;

        assert!(result.is_err());
        assert!(matches!(
            result.err().unwrap(),
            InvalidSnapshotError::ValueError(err) if err == *"Unsupported fee amount"
        ));
    }

    #[test]
    fn test_i24_be_bytes_to_i32() {
        let val = Bytes::from_str("0xfeafc6").unwrap();
        let converted = i24_be_bytes_to_i32(&val);
        assert_eq!(converted, -86074);
        let val = Bytes::from_str("0x02dd").unwrap();
        let converted = i24_be_bytes_to_i32(&val);
        assert_eq!(converted, 733);
        let val = Bytes::from_str("0xe2bb").unwrap();
        let converted = i24_be_bytes_to_i32(&val);
        assert_eq!(converted, -7493);
    }
}
