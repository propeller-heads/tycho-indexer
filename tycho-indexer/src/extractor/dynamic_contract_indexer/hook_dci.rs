#![allow(unused_variables)] // TODO: Remove this
#![allow(dead_code)] // TODO: Remove this

use tonic::async_trait;
use tycho_common::{
    models::{protocol::ProtocolComponent, BlockHash, ComponentId, TxHash},
    storage::EntryPointGateway,
    traits::{AccountExtractor, EntryPointTracer},
};

use crate::extractor::{
    dynamic_contract_indexer::{
        cache::VersionedCache, dci::DynamicContractIndexer,
        hook_orchestrator::HookOrchestratorRegistry,
        // hook_permissions_detector::HookPermissionsDetector, // TODO: Uncomment when used
        metadata_orchestrator::BlockMetadataOrchestrator,
    },
    models::BlockChanges,
    ExtractionError, ExtractorExtension,
};

pub struct UniswapV4HookDCI<AE, T, G>
where
    AE: AccountExtractor + Send + Sync,
    T: EntryPointTracer + Send + Sync,
    G: EntryPointGateway + Send + Sync,
{
    inner_dci: DynamicContractIndexer<AE, T, G>,
    metadata_orchestrator: BlockMetadataOrchestrator,
    hook_orchestrator_registry: HookOrchestratorRegistry,
    // Component processing state tracking
    component_states: VersionedCache<ComponentId, ComponentProcessingState>,
    entrypoint_gw: G, // Direct access for querying existing entrypoints
    // Maximum number of retries for processing a component.
    max_retries: u32,
    // Pause after a certain number of retries to avoid failed simulations.
    pause_after_retries: u32,
}

type ComponentWithTxHash = (TxHash, ProtocolComponent); // TODO: See if it makes sens to make this a struct

impl<AE, T, G> UniswapV4HookDCI<AE, T, G>
where
    AE: AccountExtractor + Send + Sync,
    T: EntryPointTracer + Send + Sync,
    G: EntryPointGateway + Send + Sync,
{
    fn handle_component_success(&self, component: ComponentId, block_changes: &mut BlockChanges) {
        todo!()
    }

    fn extract_components_with_swap_hooks(
        &self,
        block_changes: &mut BlockChanges,
    ) -> Vec<ProtocolComponent> {
        todo!()
    }

    fn categorize_components(
        &self,
        components: &[ProtocolComponent],
        block_changes: &mut BlockChanges,
    ) -> Result<(Vec<ComponentWithTxHash>, Vec<ComponentWithTxHash>), ExtractionError> {
        todo!()
    }

    fn update_component_balances(
        &self,
        component: &ProtocolComponent,
        block_changes: &mut BlockChanges,
    ) -> Result<(), ExtractionError> {
        todo!()
    }
}

// Component state tracking
pub struct ComponentProcessingState {
    pub status: ProcessingStatus,
    pub retry_count: u32,
    pub last_error: Option<ProcessingError>,
}

pub enum ProcessingStatus {
    Unprocessed,     // Never processed or needs full processing
    TracingComplete, // Has entrypoints generated, only needs balance updates
    Failed,          // Processing failed, can retry
}

pub enum ProcessingError {
    MetadataError(String), // Before entrypoint generation
    TracingError(String),  // During/after entrypoint generation
}

#[async_trait]
impl<AE, T, G> ExtractorExtension for UniswapV4HookDCI<AE, T, G>
where
    AE: AccountExtractor + Send + Sync,
    T: EntryPointTracer + Send + Sync,
    G: EntryPointGateway + Send + Sync,
{
    async fn process_block_update(
        &mut self,
        block_changes: &mut BlockChanges,
    ) -> Result<(), ExtractionError> {
        // 1. Filter components with swap hooks (beforeSwap/afterSwap only)
        // TODO: How can I get the components that were created in the previous blocks?
        // Do we need to fetch them on startup and store them in the cache?

        // TODO: Need to keep track of the link between component and the transaction that updated
        // it.
        let swap_hook_components = self.extract_components_with_swap_hooks(block_changes);

        if swap_hook_components.is_empty() {
            return self
                .inner_dci
                .process_block_update(block_changes)
                .await;
        }

        // 2. Categorize components based on processing state
        let (components_needing_full_processing, components_needing_balance_only) =
            self.categorize_components(&swap_hook_components, block_changes)?;

        // 3. Process the components.
        let component_results = self
            .metadata_orchestrator
            .collect_metadata_for_block(
                &components_needing_balance_only,
                &components_needing_full_processing,
                &block_changes.block,
            )
            .await
            .expect("Failed to collect metadata for block");

        // 4. Handle results per component
        for (component, result) in component_results.iter() {
            // If it's a balance-only component, we need to update the component's balances.
        }
        //
        // Here, we need to group components per-orchestrator. Then, we call
        // orchestrator.update_components
        // 5. Call HookOrchestrator to generate entrypoints.

        // 6. Delegate to standard DCI (handles tracing + pruning)
        self.inner_dci
            .process_block_update(block_changes)
            .await
            .expect("Failed to process block update");

        // 7. Prune components
        // self.hook_orchestrator_registry
        //     .prune_components(block_changes)
        //     .expect("Failed to prune components");

        Ok(())
    }

    /// Handles revert by reverting the state of the component_states cache and calling the
    /// inner_dci's process_revert.
    async fn process_revert(&mut self, target_block: &BlockHash) -> Result<(), ExtractionError> {
        todo!();
    }
}
