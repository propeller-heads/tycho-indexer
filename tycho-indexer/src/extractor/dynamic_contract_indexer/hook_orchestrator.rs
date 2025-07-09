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
    /// Main Entrypoint for the orchestrator.
    ///
    /// This method is called for each block and is responsible for
    /// 1. Generating the Entrypoints with TracingParams
    /// 2. Updating the components with the collected metadata 2.1 Inject Balances to the
    ///    ProtocolComponents 2.2 Inject the Limits to the ProtocolComponents (if they are RPC
    ///    calls) 2.3 Inject Entrypoints to the ProtocolComponents
    fn update_components(
        &self,
        block_changes: &mut BlockChanges,
        metadata: &HashMap<ProtocolComponentId, ComponentTracingMetadata>,
    ) -> Result<(), HookOrchestratorError>;

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
}

pub struct HookOrchestratorRegistry {
    pub hooks: HashMap<Address, Box<dyn HookOrchestrator>>,
}
