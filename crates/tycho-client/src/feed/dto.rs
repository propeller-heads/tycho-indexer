//! Serializable wrappers for the client feed pipeline types.
//!
//! [`FeedMessageDto`], [`StateSyncMessageDto`], etc. mirror the structures of their
//! model-based counterparts but use [`tycho_common::dto`] types that carry full
//! `Serialize` / `Deserialize` support. The JSON format produced here matches the
//! wire format (dto field names such as `contract_ids` and `state_updates`), which
//! keeps the CLI output backwards-compatible with existing tooling and preserves the
//! existing test fixture files.
//!
//! Conversion to and from the model-based pipeline types is provided via `From` impls.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use tycho_common::{
    dto::{
        BlockChanges, EntryPointWithTracingParams as DtoEntryPointWithTracingParams,
        ProtocolComponent as DtoProtocolComponent, ResponseAccount, ResponseProtocolState,
        TracingResult as DtoTracingResult,
    },
    Bytes,
};

use crate::feed::{
    synchronizer::{ComponentWithState, Snapshot, StateSyncMessage},
    BlockHeader, FeedMessage, HeaderLike, SynchronizerState,
};

/// Serializable counterpart of [`ComponentWithState`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentWithStateDto {
    pub state: ResponseProtocolState,
    pub component: DtoProtocolComponent,
    pub component_tvl: Option<f64>,
    pub entrypoints: Vec<(DtoEntryPointWithTracingParams, DtoTracingResult)>,
}

/// Serializable counterpart of [`Snapshot`].
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SnapshotDto {
    pub states: HashMap<String, ComponentWithStateDto>,
    #[serde(with = "tycho_common::serde_primitives::hex_hashmap_key")]
    pub vm_storage: HashMap<Bytes, ResponseAccount>,
}

/// Serializable counterpart of [`StateSyncMessage`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateSyncMessageDto<H = BlockHeader> {
    pub header: H,
    pub snapshots: SnapshotDto,
    pub deltas: Option<BlockChanges>,
    pub removed_components: HashMap<String, DtoProtocolComponent>,
}

/// Serializable counterpart of [`FeedMessage`].
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FeedMessageDto<H = BlockHeader> {
    pub state_msgs: HashMap<String, StateSyncMessageDto<H>>,
    pub sync_states: HashMap<String, SynchronizerState>,
}

// ── FeedMessageDto → model types ──────────────────────────────────────────────

impl From<ComponentWithStateDto> for ComponentWithState {
    fn from(value: ComponentWithStateDto) -> Self {
        Self {
            state: value.state.into(),
            component: value.component.into(),
            component_tvl: value.component_tvl,
            entrypoints: value
                .entrypoints
                .into_iter()
                .map(|(ep, tr)| (ep.into(), tr.into()))
                .collect(),
        }
    }
}

impl From<SnapshotDto> for Snapshot {
    fn from(value: SnapshotDto) -> Self {
        Self {
            states: value
                .states
                .into_iter()
                .map(|(k, v)| (k, v.into()))
                .collect(),
            vm_storage: value
                .vm_storage
                .into_iter()
                .map(|(k, v)| (k, v.into()))
                .collect(),
        }
    }
}

impl<H: HeaderLike> From<StateSyncMessageDto<H>> for StateSyncMessage<H> {
    fn from(value: StateSyncMessageDto<H>) -> Self {
        Self {
            header: value.header,
            snapshots: value.snapshots.into(),
            deltas: value.deltas.map(Into::into),
            removed_components: value
                .removed_components
                .into_iter()
                .map(|(k, v)| (k, v.into()))
                .collect(),
        }
    }
}

impl<H: HeaderLike> From<FeedMessageDto<H>> for FeedMessage<H> {
    fn from(value: FeedMessageDto<H>) -> Self {
        Self {
            state_msgs: value
                .state_msgs
                .into_iter()
                .map(|(k, v)| (k, v.into()))
                .collect(),
            sync_states: value.sync_states,
        }
    }
}

// ── model types → FeedMessageDto ──────────────────────────────────────────────

impl From<ComponentWithState> for ComponentWithStateDto {
    fn from(value: ComponentWithState) -> Self {
        Self {
            state: value.state.into(),
            component: value.component.into(),
            component_tvl: value.component_tvl,
            entrypoints: value
                .entrypoints
                .into_iter()
                .map(|(ep, tr)| (ep.into(), tr.into()))
                .collect(),
        }
    }
}

impl From<Snapshot> for SnapshotDto {
    fn from(value: Snapshot) -> Self {
        Self {
            states: value
                .states
                .into_iter()
                .map(|(k, v)| (k, v.into()))
                .collect(),
            vm_storage: value
                .vm_storage
                .into_iter()
                .map(|(k, v)| (k, v.into()))
                .collect(),
        }
    }
}

impl<H: HeaderLike> From<StateSyncMessage<H>> for StateSyncMessageDto<H> {
    fn from(value: StateSyncMessage<H>) -> Self {
        Self {
            header: value.header,
            snapshots: value.snapshots.into(),
            deltas: value.deltas.map(Into::into),
            removed_components: value
                .removed_components
                .into_iter()
                .map(|(k, v)| (k, v.into()))
                .collect(),
        }
    }
}

impl<H: HeaderLike> From<FeedMessage<H>> for FeedMessageDto<H> {
    fn from(value: FeedMessage<H>) -> Self {
        Self {
            state_msgs: value
                .state_msgs
                .into_iter()
                .map(|(k, v)| (k, v.into()))
                .collect(),
            sync_states: value.sync_states,
        }
    }
}
