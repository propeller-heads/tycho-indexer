use std::collections::HashMap;

use num_bigint::BigUint;
use tycho_client::feed::{synchronizer::ComponentWithState, BlockHeader};
use tycho_common::{models::token::Token, Bytes};

use crate::{
    evm::protocol::lido::state::{LidoPoolType, LidoState, StakeLimitState, StakingStatus},
    protocol::{
        errors::InvalidSnapshotError,
        models::{DecoderContext, TryFromWithBlock},
    },
};

pub const ETH_ADDRESS: &str = "0x0000000000000000000000000000000000000000";

impl TryFromWithBlock<ComponentWithState, BlockHeader> for LidoState {
    type Error = InvalidSnapshotError;

    /// Decodes a `ComponentWithState` into a `LidoState`. Errors with a `InvalidSnapshotError`
    async fn try_from_with_header(
        snapshot: ComponentWithState,
        _block: BlockHeader,
        _account_balances: &HashMap<Bytes, HashMap<Bytes, Bytes>>,
        _all_tokens: &HashMap<Bytes, Token>,
        _decoder_context: &DecoderContext,
    ) -> Result<Self, Self::Error> {
        let id = snapshot.component.id.as_str();

        let pool_type = match snapshot
            .component
            .static_attributes
            .get("protocol_type_name")
            .and_then(|bytes| std::str::from_utf8(bytes).ok())
            .ok_or(InvalidSnapshotError::MissingAttribute(
                "protocol_type_name is missing".to_owned(),
            ))? {
            "stETH" => LidoPoolType::StEth,
            "wstETH" => LidoPoolType::WStEth,
            _ => {
                return Err(InvalidSnapshotError::ValueError(format!(
                    "Unknown protocol type name: {:?}",
                    snapshot.component.protocol_type_name
                )))
            }
        };

        let token_to_track_total_pooled_eth = snapshot
            .component
            .static_attributes
            .get("token_to_track_total_pooled_eth")
            .ok_or(InvalidSnapshotError::MissingAttribute(
                "token_to_track_total_pooled_eth is missing".to_owned(),
            ))?
            .clone();

        let tokens: [Bytes; 2] =
            [snapshot.component.tokens[0].clone(), snapshot.component.tokens[1].clone()];

        let total_shares = snapshot
            .state
            .attributes
            .get("total_shares")
            .ok_or(InvalidSnapshotError::MissingAttribute(
                "Total shares field is missing".to_owned(),
            ))?;

        let total_pooled_eth = snapshot
            .state
            .balances
            .get(&token_to_track_total_pooled_eth)
            .ok_or(InvalidSnapshotError::MissingAttribute(
                "Total pooled eth field is missing".to_owned(),
            ))?;

        let (staking_status_parsed, staking_limit) = if pool_type == LidoPoolType::StEth {
            let staking_status = snapshot
                .state
                .attributes
                .get("staking_status")
                .ok_or(InvalidSnapshotError::MissingAttribute(
                    "Staking_status field is missing".to_owned(),
                ))?;

            let staking_status_parsed =
                if let Ok(status_as_str) = std::str::from_utf8(staking_status) {
                    match status_as_str {
                        "Limited" => StakingStatus::Limited,
                        "Paused" => StakingStatus::Paused,
                        "Unlimited" => StakingStatus::Unlimited,
                        _ => {
                            return Err(InvalidSnapshotError::ValueError(
                                "status_as_str parsed to invalid status".to_owned(),
                            ))
                        }
                    }
                } else {
                    return Err(InvalidSnapshotError::ValueError(
                        "status_as_str cannot be parsed".to_owned(),
                    ));
                };

            let staking_limit = snapshot
                .state
                .attributes
                .get("staking_limit")
                .ok_or(InvalidSnapshotError::MissingAttribute(
                    "Staking_limit field is missing".to_owned(),
                ))?;
            (staking_status_parsed, staking_limit)
        } else {
            (StakingStatus::Limited, &Bytes::from(vec![0; 32]))
        };

        let total_wrapped_st_eth = if pool_type == LidoPoolType::StEth {
            None
        } else {
            Some(BigUint::from_bytes_be(
                snapshot
                    .state
                    .attributes
                    .get("total_wstETH")
                    .ok_or(InvalidSnapshotError::MissingAttribute(
                        "Total pooled eth field is missing".to_owned(),
                    ))?,
            ))
        };

        Ok(Self {
            pool_type,
            total_shares: BigUint::from_bytes_be(total_shares),
            total_pooled_eth: BigUint::from_bytes_be(total_pooled_eth),
            total_wrapped_st_eth,
            id: id.into(),
            native_address: ETH_ADDRESS.into(),
            stake_limits_state: StakeLimitState {
                staking_status: staking_status_parsed,
                staking_limit: BigUint::from_bytes_be(staking_limit),
            },
            tokens,
            token_to_track_total_pooled_eth,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, str::FromStr};

    use chrono::NaiveDateTime;
    use num_bigint::BigUint;
    use num_traits::Zero;
    use rstest::rstest;
    use tycho_client::feed::synchronizer::ComponentWithState;
    use tycho_common::{
        dto::{Chain, ChangeType, ProtocolComponent, ResponseProtocolState},
        Bytes,
    };

    use crate::{
        evm::protocol::lido::{
            decoder::ETH_ADDRESS,
            state::{LidoPoolType, LidoState, StakeLimitState},
        },
        protocol::{
            errors::InvalidSnapshotError,
            models::{DecoderContext, TryFromWithBlock},
        },
    };

    const ST_ETH_ADDRESS_PROXY: &str = "0xae7ab96520de3a18e5e111b5eaab095312d7fe84";
    const WST_ETH_ADDRESS: &str = "0x7f39c581f595b53c5cb19bd0b3f8da6c935e2ca0";

    #[tokio::test]
    async fn test_lido_steth_try_from() {
        let mut static_attr = HashMap::new();
        static_attr.insert(
            "token_to_track_total_pooled_eth".to_string(),
            "0x0000000000000000000000000000000000000000"
                .as_bytes()
                .to_vec()
                .into(),
        );
        static_attr.insert(
            "token_to_track_total_pooled_eth".to_string(),
            Bytes::from_str(ETH_ADDRESS).unwrap(),
        );
        static_attr.insert("protocol_type_name".to_string(), "stETH".as_bytes().to_vec().into());

        let pc = ProtocolComponent {
            id: ST_ETH_ADDRESS_PROXY.to_string(),
            protocol_system: "protocol_system".to_owned(),
            protocol_type_name: "protocol_type_name".to_owned(),
            chain: Chain::Ethereum,
            tokens: vec![
                Bytes::from("0x0000000000000000000000000000000000000000"),
                Bytes::from("0xae7ab96520de3a18e5e111b5eaab095312d7fe84"),
            ],
            contract_ids: vec![],
            static_attributes: static_attr,
            change: ChangeType::Creation,
            creation_tx: Bytes::from(vec![0; 32]),
            created_at: NaiveDateTime::default(),
        };

        let snapshot = ComponentWithState {
            state: ResponseProtocolState {
                component_id: ST_ETH_ADDRESS_PROXY.to_owned(),
                attributes: HashMap::from([
                    ("total_shares".to_string(), Bytes::from(vec![0; 32])),
                    ("staking_status".to_string(), "Limited".as_bytes().to_vec().into()),
                    ("staking_limit".to_string(), Bytes::from(vec![0; 32])),
                ]),
                balances: HashMap::from([(Bytes::from(ETH_ADDRESS), Bytes::from(vec![0; 32]))]),
            },
            component: pc,
            component_tvl: None,
            entrypoints: Vec::new(),
        };

        let decoder_context = DecoderContext::new();

        let result = LidoState::try_from_with_header(
            snapshot,
            Default::default(),
            &HashMap::new(),
            &HashMap::new(),
            &decoder_context,
        )
        .await;

        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            LidoState {
                pool_type: LidoPoolType::StEth,
                total_shares: BigUint::zero(),
                total_pooled_eth: BigUint::zero(),
                total_wrapped_st_eth: None,
                id: ST_ETH_ADDRESS_PROXY.into(),
                native_address: ETH_ADDRESS.into(),
                stake_limits_state: StakeLimitState {
                    staking_status: crate::evm::protocol::lido::state::StakingStatus::Limited,
                    staking_limit: BigUint::zero(),
                },
                tokens: [
                    Bytes::from("0x0000000000000000000000000000000000000000"),
                    Bytes::from("0xae7ab96520de3a18e5e111b5eaab095312d7fe84"),
                ],
                token_to_track_total_pooled_eth: Bytes::from(ETH_ADDRESS)
            }
        );
    }

    #[tokio::test]
    #[rstest]
    #[case::missing_total_shares("total_shares")]
    #[case::missing_staking_status("staking_status")]
    #[case::missing_staking_limit("staking_limit")]
    async fn test_lido_try_from_missing_attribute(#[case] missing_attribute: &str) {
        let mut static_attr = HashMap::new();
        static_attr.insert(
            "token_to_track_total_pooled_eth".to_string(),
            Bytes::from_str(ETH_ADDRESS).unwrap(),
        );

        let pc = ProtocolComponent {
            id: ST_ETH_ADDRESS_PROXY.to_string(),
            protocol_system: "protocol_system".to_owned(),
            protocol_type_name: "protocol_type_name".to_owned(),
            chain: Chain::Ethereum,
            tokens: vec![
                Bytes::from("0x0000000000000000000000000000000000000000"),
                Bytes::from("0xae7ab96520de3a18e5e111b5eaab095312d7fe84"),
            ],
            contract_ids: vec![],
            static_attributes: static_attr,
            change: ChangeType::Creation,
            creation_tx: Bytes::from(vec![0; 32]),
            created_at: NaiveDateTime::default(),
        };

        let mut snapshot = ComponentWithState {
            state: ResponseProtocolState {
                component_id: ST_ETH_ADDRESS_PROXY.to_owned(),
                attributes: HashMap::from([
                    ("total_shares".to_string(), Bytes::from(vec![0; 32])),
                    ("staking_status".to_string(), "Limited".as_bytes().to_vec().into()),
                    ("staking_limit".to_string(), Bytes::from(vec![0; 32])),
                ]),
                balances: HashMap::from([(
                    Bytes::from_str(ETH_ADDRESS).unwrap(),
                    Bytes::from(vec![0; 32]),
                )]),
            },
            component: pc,
            component_tvl: None,
            entrypoints: Vec::new(),
        };
        snapshot
            .state
            .attributes
            .remove(missing_attribute);

        let decoder_context = DecoderContext::new();

        let result = LidoState::try_from_with_header(
            snapshot,
            Default::default(),
            &HashMap::new(),
            &HashMap::new(),
            &decoder_context,
        )
        .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), InvalidSnapshotError::MissingAttribute(_)));
    }

    #[tokio::test]
    async fn test_lido_wst_eth_try_from() {
        let mut static_attr = HashMap::new();
        static_attr.insert(
            "token_to_track_total_pooled_eth".to_string(),
            "0xae7ab96520de3a18e5e111b5eaab095312d7fe84"
                .as_bytes()
                .to_vec()
                .into(),
        );
        static_attr.insert(
            "token_to_track_total_pooled_eth".to_string(),
            Bytes::from_str(ST_ETH_ADDRESS_PROXY).unwrap(),
        );
        static_attr.insert("protocol_type_name".to_string(), "wstETH".as_bytes().to_vec().into());

        let pc = ProtocolComponent {
            id: WST_ETH_ADDRESS.to_string(),
            protocol_system: "protocol_system".to_owned(),
            protocol_type_name: "protocol_type_name".to_owned(),
            chain: Chain::Ethereum,
            tokens: vec![
                Bytes::from("0x7f39c581f595b53c5cb19bd0b3f8da6c935e2ca0"),
                Bytes::from("0xae7ab96520de3a18e5e111b5eaab095312d7fe84"),
            ],
            contract_ids: vec![],
            static_attributes: static_attr,
            change: ChangeType::Creation,
            creation_tx: Bytes::from(vec![0; 32]),
            created_at: NaiveDateTime::default(),
        };

        let snapshot = ComponentWithState {
            state: ResponseProtocolState {
                component_id: ST_ETH_ADDRESS_PROXY.to_owned(),
                attributes: HashMap::from([
                    ("total_shares".to_string(), Bytes::from(vec![0; 32])),
                    ("total_wstETH".to_string(), Bytes::from(vec![0; 32])),
                ]),
                balances: HashMap::from([(
                    Bytes::from_str(ST_ETH_ADDRESS_PROXY).unwrap(),
                    Bytes::from(vec![0; 32]),
                )]),
            },
            component: pc,
            component_tvl: None,
            entrypoints: Vec::new(),
        };

        let decoder_context = DecoderContext::new();

        let result = LidoState::try_from_with_header(
            snapshot,
            Default::default(),
            &HashMap::new(),
            &HashMap::new(),
            &decoder_context,
        )
        .await;

        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            LidoState {
                pool_type: LidoPoolType::WStEth,
                total_shares: BigUint::zero(),
                total_pooled_eth: BigUint::zero(),
                total_wrapped_st_eth: Some(BigUint::zero()),
                id: WST_ETH_ADDRESS.into(),
                native_address: ETH_ADDRESS.into(),
                stake_limits_state: StakeLimitState {
                    staking_status: crate::evm::protocol::lido::state::StakingStatus::Limited,
                    staking_limit: BigUint::zero(),
                },
                tokens: [
                    Bytes::from("0x7f39c581f595b53c5cb19bd0b3f8da6c935e2ca0"),
                    Bytes::from("0xae7ab96520de3a18e5e111b5eaab095312d7fe84"),
                ],
                token_to_track_total_pooled_eth: Bytes::from(
                    "0xae7ab96520de3a18e5e111b5eaab095312d7fe84"
                )
            }
        );
    }

    #[tokio::test]
    #[rstest]
    #[case::missing_total_shares("total_shares")]
    #[case::missing_total_wst_eth("total_wstETH")]
    async fn test_lido_wst_try_from_missing_attribute(#[case] missing_attribute: &str) {
        let pc = ProtocolComponent {
            id: WST_ETH_ADDRESS.to_string(),
            protocol_system: "protocol_system".to_owned(),
            protocol_type_name: "protocol_type_name".to_owned(),
            chain: Chain::Ethereum,
            tokens: vec![
                Bytes::from("0x7f39c581f595b53c5cb19bd0b3f8da6c935e2ca0"),
                Bytes::from("0xae7ab96520de3a18e5e111b5eaab095312d7fe84"),
            ],
            contract_ids: vec![],
            static_attributes: HashMap::new(),
            change: ChangeType::Creation,
            creation_tx: Bytes::from(vec![0; 32]),
            created_at: NaiveDateTime::default(),
        };

        let mut snapshot = ComponentWithState {
            state: ResponseProtocolState {
                component_id: ST_ETH_ADDRESS_PROXY.to_owned(),
                attributes: HashMap::from([
                    ("total_shares".to_string(), Bytes::from(vec![0; 32])),
                    ("total_wstETH".to_string(), Bytes::from(vec![0; 32])),
                ]),
                balances: HashMap::from([(
                    Bytes::from(ST_ETH_ADDRESS_PROXY),
                    Bytes::from(vec![0; 32]),
                )]),
            },
            component: pc,
            component_tvl: None,
            entrypoints: Vec::new(),
        };
        snapshot
            .state
            .attributes
            .remove(missing_attribute);

        let decoder_context = DecoderContext::new();

        let result = LidoState::try_from_with_header(
            snapshot,
            Default::default(),
            &HashMap::new(),
            &HashMap::new(),
            &decoder_context,
        )
        .await;

        assert!(result.is_err());
    }
}
