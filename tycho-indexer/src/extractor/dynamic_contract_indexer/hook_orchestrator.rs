use std::collections::HashMap;

use tonic::async_trait;
use tycho_common::{
    dto::ProtocolComponentId,
    models::{
        blockchain::{TracingParams, Transaction},
        protocol::ProtocolComponent,
        Address, EntryPointId,
    },
};

use crate::extractor::{
    dynamic_contract_indexer::component_metadata::ComponentTracingMetadata, models::BlockChanges,
};

// Implementation reference only - the custom errors will be defined during the implementation.
pub enum HookOrchestratorError {
    PrepareComponentsFailed(String),
    GenerateEntrypointParamsFailed(String),
}

/// Trait for hook orchestration operations
pub trait HookOrchestrator: Send + Sync {
    /// Update components with the collected metadata (e.g., inject balances)
    fn prepare_components(
        &self,
        block_changes: &mut BlockChanges,
        metadata: &HashMap<ProtocolComponentId, ComponentTracingMetadata>,
    ) -> Result<(), HookOrchestratorError>;

    /// Generate entrypoint tracing parameters using the metadata
    fn generate_entrypoint_params(
        &self,
        components: &[ProtocolComponent],
        metadata: &HashMap<ProtocolComponentId, ComponentTracingMetadata>,
    ) -> Result<HashMap<EntryPointId, Vec<(Transaction, TracingParams)>>, HookOrchestratorError>;

    fn prune_components(
        &self,
        block_changes: &mut BlockChanges,

    ) -> Result<(), HookOrchestratorError>;
}

pub struct HookOrchestratorRegistry {
    pub hooks: HashMap<Address, Box<dyn HookOrchestrator>>,
}
