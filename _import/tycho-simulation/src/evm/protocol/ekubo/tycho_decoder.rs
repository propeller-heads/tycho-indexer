use std::collections::HashMap;

use evm_ekubo_sdk::{
    math::uint::U256,
    quoting::{
        base_pool::BasePoolState, oracle_pool::OraclePoolState, types::{Config, NodeKey}, util::find_nearest_initialized_tick_index
    },
};
use thiserror::Error;
use tycho_client::feed::{synchronizer::ComponentWithState, Header};
use tycho_core::Bytes;

use super::{pool::{base::BasePool, oracle::OraclePool}, state::EkuboState, tick::{ticks_from_attributes, Ticks}};
use crate::{
    models::Token,
    protocol::{errors::InvalidSnapshotError, models::TryFromWithBlock},
};

enum EkuboExtension {
    Base,
    Oracle,
}

#[derive(Error, Debug)]
pub enum StateDecodingError {
    #[error(transparent)]
    InvalidSnapshot(#[from] InvalidSnapshotError),
    #[error("unsupported extension")]
    UnsupportedExtension,
}

impl TryFrom<Bytes> for EkuboExtension {
    type Error = StateDecodingError;

    fn try_from(value: Bytes) -> Result<Self, Self::Error> {
        // See extension ID encoding in tycho-protocol-sdk
        match i32::from(value) {
            0 => Err(StateDecodingError::UnsupportedExtension),
            1 => Ok(Self::Base),
            2 => Ok(Self::Oracle),
            discriminant => Err(InvalidSnapshotError::ValueError(format!("unknown discriminant {discriminant}")).into()),
        }
    }
}

impl TryFromWithBlock<ComponentWithState> for EkuboState {
    type Error = StateDecodingError;

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
            &snapshot
                .component
                .static_attributes
                .get("token0")
                .ok_or_else(|| InvalidSnapshotError::MissingAttribute("token0".to_string()))?,
        );

        let token1 = U256::from_big_endian(
            &snapshot
                .component
                .static_attributes
                .get("token1")
                .ok_or_else(|| InvalidSnapshotError::MissingAttribute("token1".to_string()))?,
        );

        let fee = u64::from_be_bytes(snapshot
            .component
            .static_attributes
            .get("fee")
            .ok_or_else(|| InvalidSnapshotError::MissingAttribute("fee".to_string()))?
            .as_ref()
            .try_into()
            .map_err(|err| InvalidSnapshotError::ValueError(format!("fee length mismatch: {err:?}")))?
        );

        let tick_spacing = u32::from_be_bytes(snapshot
            .component
            .static_attributes
            .get("tick_spacing")
            .ok_or_else(|| InvalidSnapshotError::MissingAttribute("tick_spacing".to_string()))?
            .as_ref()
            .try_into()
            .map_err(|err| InvalidSnapshotError::ValueError(format!("tick_spacing length mismatch: {err:?}")))?
        );

        let extension = U256::from_big_endian(snapshot
            .component
            .static_attributes
            .get("extension")
            .ok_or_else(|| InvalidSnapshotError::MissingAttribute("extension".to_string()))?
        );

        let config = Config {
            fee,
            tick_spacing,
            extension,
        };

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
            .map_err(|err| InvalidSnapshotError::ValueError(err))?;

        ticks.sort();

        let key = NodeKey { token0, token1, config };

        let state = BasePoolState {
            sqrt_ratio,
            liquidity,
            active_tick_index: find_nearest_initialized_tick_index(&ticks, tick),
        };

        Ok(match extension_id {
            EkuboExtension::Base => Self::Base(BasePool::new(key, state, Ticks::new(ticks), tick)),
            EkuboExtension::Oracle => Self::Oracle(OraclePool::new(
                &key,
                OraclePoolState {
                    base_pool_state: state,
                    last_snapshot_time: 0, // TODO Fill with real value when timestamps are supported
                },
            )),
        })
    }
}
