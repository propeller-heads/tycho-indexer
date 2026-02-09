use std::collections::HashMap;

use alloy::primitives::aliases::B32;
use ekubo_sdk::{
    chain::evm::{EvmBasePoolKey, EvmOraclePoolKey, EvmPoolTypeConfig, EvmTwammPoolKey},
    quoting::{
        pools::{
            full_range::{FullRangePoolKey, FullRangePoolState, FullRangePoolTypeConfig},
            mev_capture::MevCapturePoolKey,
            oracle::OraclePoolState,
            stableswap::{StableswapPoolKey, StableswapPoolState},
            twamm::TwammPoolState,
        },
        types::PoolConfig,
    },
    U256,
};
use itertools::Itertools;
use revm::primitives::Address;
use tycho_client::feed::{synchronizer::ComponentWithState, BlockHeader};
use tycho_common::{models::token::Token, Bytes};

use super::{
    attributes::{sale_rate_deltas_from_attributes, ticks_from_attributes},
    pool::{base::BasePool, full_range::FullRangePool, oracle::OraclePool, twamm::TwammPool},
    state::EkuboV3State,
};
use crate::{
    evm::protocol::ekubo_v3::pool::{mev_capture::MevCapturePool, stableswap::StableswapPool},
    protocol::{
        errors::InvalidSnapshotError,
        models::{DecoderContext, TryFromWithBlock},
    },
};

enum EkuboExtension {
    Base,
    Oracle,
    Twamm,
    MevCapture,
}

impl TryFrom<Bytes> for EkuboExtension {
    type Error = InvalidSnapshotError;

    fn try_from(value: Bytes) -> Result<Self, Self::Error> {
        // See extension ID encoding in tycho-protocol-sdk
        match i32::from(value) {
            0 => Err(InvalidSnapshotError::ValueError("Unknown Ekubo extension".to_string())),
            1 => Ok(Self::Base),
            2 => Ok(Self::Oracle),
            3 => Ok(Self::Twamm),
            4 => Ok(Self::MevCapture),
            discriminant => Err(InvalidSnapshotError::ValueError(format!(
                "Unknown Ekubo extension discriminant {discriminant}"
            ))),
        }
    }
}

impl TryFromWithBlock<ComponentWithState, BlockHeader> for EkuboV3State {
    type Error = InvalidSnapshotError;

    async fn try_from_with_header(
        snapshot: ComponentWithState,
        _block: BlockHeader,
        _account_balances: &HashMap<Bytes, HashMap<Bytes, Bytes>>,
        _all_tokens: &HashMap<Bytes, Token>,
        _decoder_context: &DecoderContext,
    ) -> Result<Self, Self::Error> {
        let static_attrs = snapshot.component.static_attributes;
        let state_attrs = snapshot.state.attributes;

        let extension_id = attribute(&static_attrs, "extension_id")?
            .clone()
            .try_into()?;

        let (token0, token1) = (
            parse_address(attribute(&static_attrs, "token0")?, "token0")?,
            parse_address(attribute(&static_attrs, "token1")?, "token1")?,
        );

        let fee = u64::from_be_bytes(
            attribute(&static_attrs, "fee")?
                .as_ref()
                .try_into()
                .map_err(|err| {
                    InvalidSnapshotError::ValueError(format!("fee length mismatch: {err:?}"))
                })?,
        );

        let pool_type_config = EvmPoolTypeConfig::try_from(
            B32::try_from(attribute(&static_attrs, "pool_type_config")?.as_ref()).map_err(
                |err| {
                    InvalidSnapshotError::ValueError(format!(
                        "pool_type_config length mismatch: {err:?}"
                    ))
                },
            )?,
        )
        .map_err(|err| {
            InvalidSnapshotError::ValueError(format!("parsing pool_type_config: {err}"))
        })?;

        let extension = parse_address(attribute(&static_attrs, "extension")?, "extension")?;

        let liquidity = attribute(&state_attrs, "liquidity")?
            .clone()
            .into();

        let sqrt_ratio = U256::try_from_be_slice(&attribute(&state_attrs, "sqrt_ratio")?[..])
            .ok_or_else(|| InvalidSnapshotError::ValueError("invalid pool price".to_string()))?;

        Ok(match extension_id {
            EkuboExtension::Base => match pool_type_config {
                EvmPoolTypeConfig::FullRange(pool_type_config) => {
                    Self::FullRange(FullRangePool::new(
                        FullRangePoolKey {
                            token0,
                            token1,
                            config: PoolConfig { extension, fee, pool_type_config },
                        },
                        FullRangePoolState { sqrt_ratio, liquidity },
                    )?)
                }
                EvmPoolTypeConfig::Stableswap(pool_type_config) => {
                    Self::Stableswap(StableswapPool::new(
                        StableswapPoolKey {
                            token0,
                            token1,
                            config: PoolConfig { extension, fee, pool_type_config },
                        },
                        StableswapPoolState { sqrt_ratio, liquidity },
                    )?)
                }
                EvmPoolTypeConfig::Concentrated(pool_type_config) => {
                    let tick = attribute(&state_attrs, "tick")?
                        .clone()
                        .into();

                    let mut ticks = ticks_from_attributes(state_attrs)
                        .map_err(InvalidSnapshotError::ValueError)?;

                    ticks.sort_unstable_by_key(|tick| tick.index);

                    Self::Base(BasePool::new(
                        EvmBasePoolKey {
                            token0,
                            token1,
                            config: PoolConfig { extension, fee, pool_type_config },
                        },
                        ticks,
                        sqrt_ratio,
                        liquidity,
                        tick,
                    )?)
                }
            },
            EkuboExtension::Oracle => Self::Oracle(OraclePool::new(
                EvmOraclePoolKey {
                    token0,
                    token1,
                    config: PoolConfig {
                        extension,
                        fee,
                        pool_type_config: FullRangePoolTypeConfig,
                    },
                },
                OraclePoolState {
                    full_range_pool_state: FullRangePoolState { sqrt_ratio, liquidity },
                    last_snapshot_time: 0, /* For the purpose of quote computation it isn't
                                            * required to track actual timestamps */
                },
            )?),
            EkuboExtension::Twamm => {
                let (token0_sale_rate, token1_sale_rate) = (
                    attribute(&state_attrs, "token0_sale_rate")?
                        .clone()
                        .into(),
                    attribute(&state_attrs, "token1_sale_rate")?
                        .clone()
                        .into(),
                );

                let last_execution_time = attribute(&state_attrs, "last_execution_time")?
                    .clone()
                    .into();

                let mut virtual_order_deltas =
                    sale_rate_deltas_from_attributes(state_attrs, last_execution_time)
                        .map_err(InvalidSnapshotError::ValueError)?
                        .collect_vec();

                virtual_order_deltas.sort_unstable_by_key(|delta| delta.time);

                Self::Twamm(TwammPool::new(
                    EvmTwammPoolKey {
                        token0,
                        token1,
                        config: PoolConfig {
                            extension,
                            fee,
                            pool_type_config: FullRangePoolTypeConfig,
                        },
                    },
                    TwammPoolState {
                        full_range_pool_state: FullRangePoolState { sqrt_ratio, liquidity },
                        token0_sale_rate,
                        token1_sale_rate,
                        last_execution_time,
                    },
                    virtual_order_deltas,
                )?)
            }
            EkuboExtension::MevCapture => {
                let tick = attribute(&state_attrs, "tick")?
                    .clone()
                    .into();

                let mut ticks =
                    ticks_from_attributes(state_attrs).map_err(InvalidSnapshotError::ValueError)?;

                ticks.sort_unstable_by_key(|tick| tick.index);

                let EvmPoolTypeConfig::Concentrated(pool_type_config) = pool_type_config else {
                    return Err(InvalidSnapshotError::ValueError(
                        "expected concentrated pool config for MEV-capture pool".to_string(),
                    ));
                };

                Self::MevCapture(MevCapturePool::new(
                    MevCapturePoolKey {
                        token0,
                        token1,
                        config: PoolConfig { extension, fee, pool_type_config },
                    },
                    ticks,
                    sqrt_ratio,
                    liquidity,
                    tick,
                )?)
            }
        })
    }
}

fn attribute<'a>(
    map: &'a HashMap<String, Bytes>,
    key: &str,
) -> Result<&'a Bytes, InvalidSnapshotError> {
    map.get(key)
        .ok_or_else(|| InvalidSnapshotError::MissingAttribute(key.to_string()))
}

fn parse_address(bytes: &Bytes, attr_name: &str) -> Result<Address, InvalidSnapshotError> {
    Address::try_from(&bytes[..])
        .map_err(|err| InvalidSnapshotError::ValueError(format!("parsing {attr_name}: {err}")))
}

#[cfg(test)]
mod tests {
    use rstest::*;
    use rstest_reuse::apply;
    use tycho_common::dto::ResponseProtocolState;

    use super::*;
    use crate::evm::protocol::{
        ekubo_v3::test_cases::*, test_utils::try_decode_snapshot_with_defaults,
    };

    #[apply(all_cases)]
    #[tokio::test]
    async fn test_try_from_with_header(case: TestCase) {
        let snapshot = ComponentWithState {
            state: ResponseProtocolState {
                attributes: case.state_attributes,
                ..Default::default()
            },
            component: case.component,
            component_tvl: None,
            entrypoints: Vec::new(),
        };

        let result = try_decode_snapshot_with_defaults::<EkuboV3State>(snapshot)
            .await
            .expect("reconstructing state");

        assert_eq!(result, case.state_before_transition);
    }

    #[apply(all_cases)]
    #[tokio::test]
    async fn test_try_from_invalid(case: TestCase) {
        for missing_attribute in case.required_attributes {
            let mut component = case.component.clone();
            let mut attributes = case.state_attributes.clone();

            component
                .static_attributes
                .remove(&missing_attribute);
            attributes.remove(&missing_attribute);

            let snapshot = ComponentWithState {
                state: ResponseProtocolState {
                    attributes,
                    component_id: Default::default(),
                    balances: Default::default(),
                },
                component,
                component_tvl: None,
                entrypoints: Vec::new(),
            };

            EkuboV3State::try_from_with_header(
                snapshot,
                BlockHeader::default(),
                &HashMap::default(),
                &HashMap::default(),
                &DecoderContext::new(),
            )
            .await
            .unwrap_err();
        }
    }
}
