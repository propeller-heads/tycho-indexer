//! Serializable wrappers for the client feed pipeline types.
//!
//! [`FeedMessage`], [`StateSyncMessage`], etc. mirror the structures of their
//! model-based counterparts but use [`tycho_common::dto`] types that carry full
//! `Serialize` / `Deserialize` support. The JSON format produced here matches the
//! wire format (dto field names such as `contract_ids` and `state_updates`), which
//! keeps the CLI output backwards-compatible with existing tooling and preserves the
//! existing test fixture files.
//!
//! Conversion to and from the model-based pipeline types is provided via `From` impls.
//! When both names are in scope use the module path to disambiguate, e.g.
//! `feed::dto::ComponentWithState` vs `feed::synchronizer::ComponentWithState`.

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
    synchronizer::{
        ComponentWithState as ModelComponentWithState, Snapshot as ModelSnapshot,
        StateSyncMessage as ModelStateSyncMessage,
    },
    BlockHeader, FeedMessage as ModelFeedMessage, HeaderLike, SynchronizerState,
};

/// Serializable counterpart of [`crate::feed::synchronizer::ComponentWithState`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentWithState {
    pub state: ResponseProtocolState,
    pub component: DtoProtocolComponent,
    pub component_tvl: Option<f64>,
    pub entrypoints: Vec<(DtoEntryPointWithTracingParams, DtoTracingResult)>,
}

/// Serializable counterpart of [`crate::feed::synchronizer::Snapshot`].
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Snapshot {
    pub states: HashMap<String, ComponentWithState>,
    #[serde(with = "tycho_common::serde_primitives::hex_hashmap_key")]
    pub vm_storage: HashMap<Bytes, ResponseAccount>,
}

/// Serializable counterpart of [`crate::feed::synchronizer::StateSyncMessage`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateSyncMessage<H = BlockHeader> {
    pub header: H,
    pub snapshots: Snapshot,
    pub deltas: Option<BlockChanges>,
    pub removed_components: HashMap<String, DtoProtocolComponent>,
}

/// Serializable counterpart of [`crate::feed::FeedMessage`].
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FeedMessage<H = BlockHeader> {
    pub state_msgs: HashMap<String, StateSyncMessage<H>>,
    pub sync_states: HashMap<String, SynchronizerState>,
}

// ── dto types → model types ───────────────────────────────────────────────────

impl From<ComponentWithState> for ModelComponentWithState {
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

impl From<Snapshot> for ModelSnapshot {
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

impl<H: HeaderLike> From<StateSyncMessage<H>> for ModelStateSyncMessage<H> {
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

impl<H: HeaderLike> From<FeedMessage<H>> for ModelFeedMessage<H> {
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

// ── model types → dto types ───────────────────────────────────────────────────

impl From<ModelComponentWithState> for ComponentWithState {
    fn from(value: ModelComponentWithState) -> Self {
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

impl From<ModelSnapshot> for Snapshot {
    fn from(value: ModelSnapshot) -> Self {
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

impl<H: HeaderLike> From<ModelStateSyncMessage<H>> for StateSyncMessage<H> {
    fn from(value: ModelStateSyncMessage<H>) -> Self {
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

impl<H: HeaderLike> From<ModelFeedMessage<H>> for FeedMessage<H> {
    fn from(value: ModelFeedMessage<H>) -> Self {
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
