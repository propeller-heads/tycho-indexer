use std::collections::HashMap;

use evm_ekubo_sdk::{
    math::uint::U256,
    quoting::{
        base_pool::BasePoolState,
        full_range_pool::FullRangePoolState,
        oracle_pool::OraclePoolState,
        types::{Config, NodeKey},
        util::find_nearest_initialized_tick_index,
    },
};
use num_traits::Zero;
use tycho_client::feed::{synchronizer::ComponentWithState, Header};
use tycho_common::Bytes;

use super::{
    pool::{base::BasePool, full_range::FullRangePool, oracle::OraclePool},
    state::EkuboState,
    tick::{ticks_from_attributes, Ticks},
};
use crate::{
    models::Token,
    protocol::{errors::InvalidSnapshotError, models::TryFromWithBlock},
};

enum EkuboExtension {
    Base,
    Oracle,
}

impl TryFrom<Bytes> for EkuboExtension {
    type Error = InvalidSnapshotError;

    fn try_from(value: Bytes) -> Result<Self, Self::Error> {
        // See extension ID encoding in tycho-protocol-sdk
        match i32::from(value) {
            0 => Err(InvalidSnapshotError::ValueError("unknown extension".to_string())),
            1 => Ok(Self::Base),
            2 => Ok(Self::Oracle),
            discriminant => Err(InvalidSnapshotError::ValueError(format!(
                "unknown discriminant {discriminant}"
            ))),
        }
    }
}

impl TryFromWithBlock<ComponentWithState> for EkuboState {
    type Error = InvalidSnapshotError;

    async fn try_from_with_block(
        snapshot: ComponentWithState,
        _block: Header,
        _account_balances: &HashMap<Bytes, HashMap<Bytes, Bytes>>,
        _all_tokens: &HashMap<Bytes, Token>,
    ) -> Result<Self, Self::Error> {
        let extension_id = snapshot
            .component
            .static_attributes
            .get("extension_id")
            .ok_or_else(|| InvalidSnapshotError::MissingAttribute("extension_id".to_string()))?
            .clone()
            .try_into()?;

        let token0 = U256::from_big_endian(
            snapshot
                .component
                .static_attributes
                .get("token0")
                .ok_or_else(|| InvalidSnapshotError::MissingAttribute("token0".to_string()))?,
        );

        let token1 = U256::from_big_endian(
            snapshot
                .component
                .static_attributes
                .get("token1")
                .ok_or_else(|| InvalidSnapshotError::MissingAttribute("token1".to_string()))?,
        );

        let fee = u64::from_be_bytes(
            snapshot
                .component
                .static_attributes
                .get("fee")
                .ok_or_else(|| InvalidSnapshotError::MissingAttribute("fee".to_string()))?
                .as_ref()
                .try_into()
                .map_err(|err| {
                    InvalidSnapshotError::ValueError(format!("fee length mismatch: {err:?}"))
                })?,
        );

        let tick_spacing = u32::from_be_bytes(
            snapshot
                .component
                .static_attributes
                .get("tick_spacing")
                .ok_or_else(|| InvalidSnapshotError::MissingAttribute("tick_spacing".to_string()))?
                .as_ref()
                .try_into()
                .map_err(|err| {
                    InvalidSnapshotError::ValueError(format!(
                        "tick_spacing length mismatch: {err:?}"
                    ))
                })?,
        );

        let extension = U256::from_big_endian(
            snapshot
                .component
                .static_attributes
                .get("extension")
                .ok_or_else(|| InvalidSnapshotError::MissingAttribute("extension".to_string()))?,
        );

        let config = Config { fee, tick_spacing, extension };

        let liquidity = snapshot
            .state
            .attributes
            .get("liquidity")
            .ok_or_else(|| InvalidSnapshotError::MissingAttribute("liquidity".to_string()))?
            .clone()
            .into();

        let sqrt_ratio = U256::from_big_endian(
            snapshot
                .state
                .attributes
                .get("sqrt_ratio")
                .ok_or_else(|| InvalidSnapshotError::MissingAttribute("sqrt_ratio".to_string()))?,
        );

        let tick = snapshot
            .state
            .attributes
            .get("tick")
            .ok_or_else(|| InvalidSnapshotError::MissingAttribute("tick".to_string()))?
            .clone()
            .into();

        let mut ticks = ticks_from_attributes(snapshot.state.attributes)
            .map_err(InvalidSnapshotError::ValueError)?;

        ticks.sort_by_key(|tick| tick.index);

        let key = NodeKey { token0, token1, config };

        Ok(match extension_id {
            EkuboExtension::Base => {
                if tick_spacing.is_zero() {
                    Self::FullRange(FullRangePool::new(
                        key,
                        FullRangePoolState { sqrt_ratio, liquidity },
                    )?)
                } else {
                    Self::Base(BasePool::new(
                        key,
                        BasePoolState {
                            sqrt_ratio,
                            liquidity,
                            active_tick_index: find_nearest_initialized_tick_index(&ticks, tick),
                        },
                        Ticks::new(ticks),
                        tick,
                    )?)
                }
            }
            EkuboExtension::Oracle => Self::Oracle(OraclePool::new(
                &key,
                OraclePoolState {
                    full_range_pool_state: FullRangePoolState { liquidity, sqrt_ratio },
                    last_snapshot_time: 0, /* TODO Fill with real value when timestamps are
                                            * supported */
                },
            )?),
        })
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;
    use tycho_common::dto::ResponseProtocolState;

    use super::*;
    use crate::evm::protocol::ekubo::test_pool::{attributes, component, state};

    #[tokio::test]
    async fn test_try_from_with_block() {
        let snapshot = ComponentWithState {
            state: ResponseProtocolState { attributes: attributes(), ..Default::default() },
            component: component(),
            component_tvl: None,
        };

        let result = EkuboState::try_from_with_block(
            snapshot,
            Header::default(),
            &HashMap::new(),
            &HashMap::new(),
        )
        .await
        .unwrap();

        assert_eq!(state(), result);
    }

    #[tokio::test]
    #[rstest]
    #[case::missing_extension_id("extension_id")]
    #[case::missing_token0("token0")]
    #[case::missing_token1("token1")]
    #[case::missing_fee("fee")]
    #[case::missing_tick_spacing("tick_spacing")]
    #[case::missing_extension("extension")]
    #[case::missing_liquidity("liquidity")]
    #[case::missing_sqrt_ratio("sqrt_ratio")]
    #[case::missing_tick("tick")]
    async fn test_try_from_invalid(#[case] missing_attribute: String) {
        let mut component = component();
        let mut attributes = attributes();

        component
            .static_attributes
            .remove(&missing_attribute);
        attributes.remove(&missing_attribute);

        let snapshot = ComponentWithState {
            state: ResponseProtocolState {
                component_id: "State1".to_owned(),
                attributes,
                balances: HashMap::new(),
            },
            component,
            component_tvl: None,
        };

        let result = EkuboState::try_from_with_block(
            snapshot,
            Header::default(),
            &HashMap::default(),
            &HashMap::default(),
        )
        .await;

        let err = result.unwrap_err();

        assert!(matches!(
            err,
            InvalidSnapshotError::MissingAttribute(attr) if attr == missing_attribute
        ));
    }
}
