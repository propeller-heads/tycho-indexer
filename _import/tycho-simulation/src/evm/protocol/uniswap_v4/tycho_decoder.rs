use std::collections::HashMap;

use alloy_primitives::U256;
use tycho_client::feed::{synchronizer::ComponentWithState, Header};
use tycho_core::Bytes;

use super::state::UniswapV4State;
use crate::{
    evm::protocol::{
        uniswap_v4::state::UniswapV4Fees,
        utils::uniswap::{i24_be_bytes_to_i32, tick_list::TickInfo},
    },
    models::Token,
    protocol::{errors::InvalidSnapshotError, models::TryFromWithBlock},
};

impl TryFromWithBlock<ComponentWithState> for UniswapV4State {
    type Error = InvalidSnapshotError;

    /// Decodes a `ComponentWithState` into a `UniswapV4State`. Errors with a `InvalidSnapshotError`
    /// if the snapshot is missing any required attributes.
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

        let liquidity = u128::from(liq);

        let sqrt_price = U256::from_be_slice(
            snapshot
                .state
                .attributes
                .get("sqrt_price_x96")
                .ok_or_else(|| InvalidSnapshotError::MissingAttribute("sqrt_price".to_string()))?,
        );

        let lp_fee = u32::from(
            snapshot
                .component
                .static_attributes
                .get("fee")
                .ok_or_else(|| InvalidSnapshotError::MissingAttribute("fee".to_string()))?
                .clone(),
        );

        let zero2one_protocol_fee = u32::from(
            snapshot
                .state
                .attributes
                .get("protocol_fees/zero2one")
                .ok_or_else(|| {
                    InvalidSnapshotError::MissingAttribute("protocol_fees/zero2one".to_string())
                })?
                .clone(),
        );
        let one2zero_protocol_fee = u32::from(
            snapshot
                .state
                .attributes
                .get("protocol_fees/one2zero")
                .ok_or_else(|| {
                    InvalidSnapshotError::MissingAttribute("protocol_fees/one2zero".to_string())
                })?
                .clone(),
        );

        let fees: UniswapV4Fees =
            UniswapV4Fees::new(zero2one_protocol_fee, one2zero_protocol_fee, lp_fee);

        let tick_spacing: i32 = i32::from(
            snapshot
                .component
                .static_attributes
                .get("tick_spacing")
                .ok_or_else(|| InvalidSnapshotError::MissingAttribute("tick_spacing".to_string()))?
                .clone(),
        );

        let tick = i24_be_bytes_to_i32(
            snapshot
                .state
                .attributes
                .get("tick")
                .ok_or_else(|| InvalidSnapshotError::MissingAttribute("tick".to_string()))?,
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
            Ok(ticks) if !ticks.is_empty() => ticks
                .into_iter()
                .filter(|t| t.net_liquidity != 0)
                .collect::<Vec<_>>(),
            _ => return Err(InvalidSnapshotError::MissingAttribute("tick_liquidities".to_string())),
        };

        ticks.sort_by_key(|tick| tick.index);

        Ok(UniswapV4State::new(liquidity, sqrt_price, fees, tick, tick_spacing, ticks))
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, str::FromStr};

    use chrono::DateTime;
    use tycho_core::{
        dto::{Chain, ChangeType, ProtocolComponent, ResponseProtocolState},
        hex_bytes::Bytes,
    };

    use super::*;

    fn usv4_component() -> ProtocolComponent {
        let creation_time = DateTime::from_timestamp(1622526000, 0)
            .unwrap()
            .naive_utc();

        // Add a static attribute "tick_spacing"
        let mut static_attributes: HashMap<String, Bytes> = HashMap::new();
        static_attributes
            .insert("tick_spacing".to_string(), Bytes::from(60_i32.to_be_bytes().to_vec()));

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

    fn usv4_attributes() -> HashMap<String, Bytes> {
        vec![
            ("fee".to_string(), Bytes::from(500_i32.to_be_bytes().to_vec())),
            ("liquidity".to_string(), Bytes::from(100_u64.to_be_bytes().to_vec())),
            ("tick".to_string(), Bytes::from(300_i32.to_be_bytes().to_vec())),
            (
                "sqrt_price_x96".to_string(),
                Bytes::from(
                    79228162514264337593543950336_u128
                        .to_be_bytes()
                        .to_vec(),
                ),
            ),
            ("protocol_fees/zero2one".to_string(), Bytes::from(0_u32.to_be_bytes().to_vec())),
            ("protocol_fees/one2zero".to_string(), Bytes::from(0_u32.to_be_bytes().to_vec())),
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
    async fn test_usv4_try_from() {
        let snapshot = ComponentWithState {
            state: ResponseProtocolState {
                component_id: "State1".to_owned(),
                attributes: usv4_attributes(),
                balances: HashMap::new(),
            },
            component: usv4_component(),
        };

        let result = UniswapV4State::try_from_with_block(snapshot, header(), &HashMap::new()).await;

        assert!(result.is_ok());

        let fees = UniswapV4Fees::new(0, 0, 500);
        let expected =
            UniswapV4State::new(100, U256::from(200), fees, 300, 60, vec![TickInfo::new(60, 400)]);
        assert_eq!(result.unwrap(), expected);
    }
}
