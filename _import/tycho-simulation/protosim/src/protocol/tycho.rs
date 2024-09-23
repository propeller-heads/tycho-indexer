use ethers::types::U256;
use tycho_client::feed::synchronizer::ComponentWithState;
use tycho_core::Bytes;

use crate::protocol::{
    errors::InvalidSnapshotError,
    uniswap_v2::state::UniswapV2State,
    uniswap_v3::{enums::FeeAmount, state::UniswapV3State},
};

use super::{uniswap_v3::tick_list::TickInfo, BytesConvertible};

impl TryFrom<ComponentWithState> for UniswapV2State {
    type Error = InvalidSnapshotError;

    /// Decodes a `ComponentWithState` into a `UniswapV2State`. Errors with a `InvalidSnapshotError`
    /// if either reserve0 or reserve1 attributes are missing.
    fn try_from(snapshot: ComponentWithState) -> Result<Self, Self::Error> {
        let reserve0 = U256::from_bytes(
            snapshot
                .state
                .attributes
                .get("reserve0")
                .ok_or(InvalidSnapshotError::MissingAttribute("reserve0".to_string()))?,
        );

        let reserve1 = U256::from_bytes(
            snapshot
                .state
                .attributes
                .get("reserve1")
                .ok_or(InvalidSnapshotError::MissingAttribute("reserve1".to_string()))?,
        );

        Ok(UniswapV2State::new(reserve0, reserve1))
    }
}

impl TryFrom<ComponentWithState> for UniswapV3State {
    type Error = InvalidSnapshotError;

    /// Decodes a `ComponentWithState` into a `UniswapV3State`. Errors with a `InvalidSnapshotError`
    /// if the snapshot is missing any required attributes or if the fee amount is not supported.
    fn try_from(snapshot: ComponentWithState) -> Result<Self, Self::Error> {
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

        let sqrt_price = U256::from_bytes(
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
        let tick = i24_le_bytes_to_i32(&ticks_4_bytes);

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
                            .map(|tick_index| {
                                TickInfo::new(tick_index, decode_le_bytes_as_i128(value))
                            })
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

/// Converts a slice of bytes representing a little-endian 24-bit signed integer
/// to a 32-bit signed integer.
///
/// # Arguments
/// * `val` - A reference to a `Bytes` type, which should contain at most three bytes.
///
/// # Returns
/// * The 32-bit signed integer representation of the input bytes.
pub fn i24_le_bytes_to_i32(val: &Bytes) -> i32 {
    let bytes_slice = val.as_ref();
    let bytes_len = bytes_slice.len();
    let mut result = 0i32;

    for (i, &byte) in bytes_slice.iter().enumerate() {
        result |= (byte as i32) << (8 * i);
    }

    // If the last byte is in the input and its most significant bit is set (0x80),
    // perform sign extension. This is for handling negative numbers.
    if bytes_len > 0 && bytes_slice[bytes_len - 1] & 0x80 != 0 {
        result |= -1i32 << (8 * bytes_len);
    }
    result
}

fn decode_le_bytes_as_i128(src: &Bytes) -> i128 {
    let bytes_slice = src.as_ref();
    let bytes_len = bytes_slice.len();
    let msb = bytes_slice[bytes_len - 1] & 0x80 != 0;

    // Create an array with zeros.
    let mut u128_bytes: [u8; 16] = if msb { [0xFF; 16] } else { [0x00; 16] };

    // Copy bytes from bytes_slice to u128_bytes.
    u128_bytes[..bytes_slice.len()].copy_from_slice(bytes_slice);

    // Convert to i128 using little-endian
    i128::from_le_bytes(u128_bytes)
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

    fn usv2_component() -> ProtocolComponent {
        let creation_time = DateTime::from_timestamp(1622526000, 0)
            .unwrap()
            .naive_utc(); //Sample timestamp

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
        let snapshot = ComponentWithState {
            state: ResponseProtocolState {
                component_id: "State1".to_owned(),
                attributes,
                balances: HashMap::new(),
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
        let snapshot = ComponentWithState {
            state: ResponseProtocolState {
                component_id: "State1".to_owned(),
                attributes,
                balances: HashMap::new(),
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
        let creation_time = DateTime::from_timestamp(1622526000, 0)
            .unwrap()
            .naive_utc(); //Sample timestamp

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
        let snapshot = ComponentWithState {
            state: ResponseProtocolState {
                component_id: "State1".to_owned(),
                attributes: usv3_attributes(),
                balances: HashMap::new(),
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

        let snapshot = ComponentWithState {
            state: ResponseProtocolState {
                component_id: "State1".to_owned(),
                attributes,
                balances: HashMap::new(),
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

        let snapshot = ComponentWithState {
            state: ResponseProtocolState {
                component_id: "State1".to_owned(),
                attributes: usv3_attributes(),
                balances: HashMap::new(),
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

    #[test]
    fn test_i24_le_bytes_to_i32() {
        let val = Bytes::from_str("0xc6affe").unwrap();
        let converted = i24_le_bytes_to_i32(&val);
        assert_eq!(converted, -86074);
        let val = Bytes::from_str("0xdd02").unwrap();
        let converted = i24_le_bytes_to_i32(&val);
        assert_eq!(converted, 733);
        let val = Bytes::from_str("0xbbe2").unwrap();
        let converted = i24_le_bytes_to_i32(&val);
        assert_eq!(converted, -7493);
    }

    #[test]
    fn test_i24_le_bytes_to() {
        let val = Bytes::from_str("0xe0629dfd41bec2e5").unwrap();
        let converted = decode_le_bytes_as_i128(&val);
        assert_eq!(converted, -1890739702905085216);
    }
}
