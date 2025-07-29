#![allow(unused_variables)] // TODO: Remove this
#![allow(dead_code)] // TODO: Remove this

use std::collections::HashMap;

use tonic::async_trait;
use tracing::{debug, error};
use tycho_common::{
    models::{protocol::ProtocolComponent, Address, BlockHash, Chain, ComponentId, TxHash},
    storage::{EntryPointFilter, EntryPointGateway, ProtocolGateway},
    traits::{AccountExtractor, EntryPointTracer},
};

use crate::extractor::{
    dynamic_contract_indexer::{
        cache::HooksDCICache, component_metadata::ComponentTracingMetadata,
        dci::DynamicContractIndexer, hook_orchestrator::HookOrchestratorRegistry,
        hook_permissions_detector::HookPermissionsDetector,
        metadata_orchestrator::BlockMetadataOrchestrator,
    },
    models::BlockChanges,
    ExtractionError, ExtractorExtension,
};

pub struct UniswapV4HookDCI<AE, T, G>
where
    AE: AccountExtractor + Send + Sync,
    T: EntryPointTracer + Send + Sync,
    G: EntryPointGateway + ProtocolGateway + Send + Sync,
{
    inner_dci: DynamicContractIndexer<AE, T, G>,
    metadata_orchestrator: BlockMetadataOrchestrator,
    hook_orchestrator_registry: HookOrchestratorRegistry,
    // Centralized cache for component states and protocol components
    cache: HooksDCICache,
    db_gateway: G, // Direct access for querying existing entrypoints & protocol components
    chain: Chain,  // Chain information for loading components
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
    G: EntryPointGateway + ProtocolGateway + Send + Sync,
{
    pub fn new(
        inner_dci: DynamicContractIndexer<AE, T, G>,
        metadata_orchestrator: BlockMetadataOrchestrator,
        hook_orchestrator_registry: HookOrchestratorRegistry,
        db_gateway: G,
        chain: Chain,
        max_retries: u32,
        pause_after_retries: u32,
    ) -> Self {
        Self {
            inner_dci,
            metadata_orchestrator,
            hook_orchestrator_registry,
            cache: HooksDCICache::new(),
            db_gateway,
            chain,
            max_retries,
            pause_after_retries,
        }
    }

    pub async fn initialize(&mut self) -> Result<(), ExtractionError> {
        // Initialize the inner DCI
        self.inner_dci.initialize().await?;

        // Load all UniswapV4 protocol components from storage
        let protocol_components = self
            .db_gateway
            .get_protocol_components(
                &self.chain,
                Some("uniswap_v4".to_string()),
                None, // ids - load all
                None, // min_tvl - no filter
                None, // pagination - load all
            )
            .await
            .map_err(|e| {
                error!("Failed to load UniswapV4 protocol components: {e:?}");
                ExtractionError::Unknown(format!("Failed to load protocol components: {e:?}"))
            })?;

        debug!(
            "Loaded {} UniswapV4 protocol components from storage",
            protocol_components.entity.len()
        );

        // First pass: Filter components with swap hooks and collect their IDs
        let mut valid_components = Vec::new();
        let mut component_ids_for_batch = Vec::new();

        for component in protocol_components.entity {
            if let Some(hook_address) = component.static_attributes.get("hook") {
                if HookPermissionsDetector::has_swap_hooks(hook_address) {
                    // Add component to cache
                    self.cache
                        .protocol_components
                        .insert_permanent(component.id.clone(), component.clone());

                    // Collect for batch processing
                    component_ids_for_batch.push(component.id.clone());
                    valid_components.push(component);
                } else {
                    debug!(
                        "Skipping UniswapV4 component {} - no swap hook permissions for hook {}",
                        component.id, hook_address
                    );
                }
            } else {
                debug!("Skipping UniswapV4 component {} - no hook attribute found", component.id);
            }
        }

        // Second pass: Batch request for all component entrypoints
        if !component_ids_for_batch.is_empty() {
            let filter = EntryPointFilter::new("uniswap_v4".to_string())
                .with_component_ids(component_ids_for_batch.clone());

            let all_entrypoints = self
                .db_gateway
                .get_entry_points_tracing_params(filter, None)
                .await
                .map_err(|e| {
                    error!("Failed to batch load entrypoints for components: {e:?}");
                    ExtractionError::Unknown(format!("Failed to load entrypoints: {e:?}"))
                })?;

            debug!("Loaded entrypoints for {} components in batch", all_entrypoints.entity.len());

            // Third pass: Process each component and determine its state
            for component in valid_components {
                let component_has_entrypoints = all_entrypoints
                    .entity
                    .contains_key(&component.id);

                let component_state = if component_has_entrypoints {
                    // Has entrypoints = TracingComplete
                    ComponentProcessingState {
                        status: ProcessingStatus::TracingComplete,
                        retry_count: 0,
                        last_error: None,
                    }
                } else {
                    // No entrypoints = Unprocessed
                    ComponentProcessingState {
                        status: ProcessingStatus::Unprocessed,
                        retry_count: 0,
                        last_error: None,
                    }
                };

                self.cache
                    .component_states
                    .insert_permanent(component.id.clone(), component_state.clone());

                debug!(
                    "Initialized component {} with state {:?}",
                    component.id, component_state.status
                );
            }
        }

        Ok(())
    }

    /// Handles component failures by updating the state and logging errors
    fn handle_component_failure(
        &mut self,
        component_id: ComponentId,
        error_msg: String,
        block: &tycho_common::models::blockchain::Block,
    ) -> Result<(), ExtractionError> {
        error!("Component {} failed processing: {}", component_id, error_msg);

        // Update component state
        let mut retry_count = 0;
        if let Some(current_state) = self
            .cache
            .component_states
            .get(&component_id)
        {
            retry_count = current_state.retry_count + 1;
        }

        let new_state = ComponentProcessingState {
            status: ProcessingStatus::Failed,
            retry_count,
            last_error: Some(ProcessingError::MetadataError(error_msg)),
        };

        self.cache
            .component_states
            .insert_pending(block.clone(), component_id, new_state)
            .map_err(|e| {
                ExtractionError::Unknown(format!("Failed to update component state: {e}"))
            })?;

        Ok(())
    }

    /// Checks ComponentTracingMetadata for errors and updates component states accordingly
    fn process_metadata_errors(
        &mut self,
        component_metadata: &[(ProtocolComponent, ComponentTracingMetadata)],
        block: &tycho_common::models::blockchain::Block,
    ) -> Result<(), ExtractionError> {
        for (component, metadata) in component_metadata {
            let mut errors = Vec::new();

            // Check for balance errors
            if let Some(Err(balance_error)) = &metadata.balances {
                errors.push(format!("Balance error: {balance_error:?}"));
            }

            // Check for limits errors
            if let Some(Err(limits_error)) = &metadata.limits {
                errors.push(format!("Limits error: {limits_error:?}"));
            }

            // Check for TVL errors
            if let Some(Err(tvl_error)) = &metadata.tvl {
                errors.push(format!("TVL error: {tvl_error:?}"));
            }

            // If there are errors, mark component as failed
            if !errors.is_empty() {
                let error_msg = errors.join("; ");
                self.handle_component_failure(component.id.clone(), error_msg, block)?;
            }
        }

        Ok(())
    }

    fn handle_component_success(
        &mut self,
        component: ComponentId,
        block: &tycho_common::models::blockchain::Block,
    ) -> Result<(), ExtractionError> {
        // Update the component state to indicate successful processing
        let new_state = ComponentProcessingState {
            status: ProcessingStatus::TracingComplete,
            retry_count: 0,
            last_error: None,
        };

        self.cache
            .component_states
            .insert_pending(block.clone(), component, new_state)
            .map_err(|e| {
                ExtractionError::Unknown(format!("Failed to update component state: {e}"))
            })?;

        Ok(())
    }

    fn extract_components_with_swap_hooks(
        &mut self,
        block_changes: &mut BlockChanges,
    ) -> Result<HashMap<ComponentId, ComponentWithTxHash>, ExtractionError> {
        let mut components_with_hooks = HashMap::new();

        // Create a map of component ID to latest transaction hash in the block
        // This ensures we use the latest transaction that affected each component
        let mut component_to_latest_tx = HashMap::new();

        // First pass: collect all affected components and their transaction hashes
        // Process transactions in order to ensure we get the latest transaction hash
        for tx_with_changes in &block_changes.txs_with_update {
            let tx_hash = tx_with_changes.tx.hash.clone();

            // Track newly created components
            for component_id in tx_with_changes
                .protocol_components
                .keys()
            {
                component_to_latest_tx.insert(component_id.clone(), tx_hash.clone());
            }

            // Track mutated components from state_updates
            for component_id in tx_with_changes.state_updates.keys() {
                component_to_latest_tx.insert(component_id.clone(), tx_hash.clone());
            }

            // Track mutated components from balance_changes
            for component_id in tx_with_changes.balance_changes.keys() {
                component_to_latest_tx.insert(component_id.clone(), tx_hash.clone());
            }
        }

        // Second pass: extract components with swap hooks
        for tx_with_changes in &block_changes.txs_with_update {
            // Process newly created components
            for component in tx_with_changes
                .protocol_components
                .values()
            {
                if let Some(hook_address) = component.static_attributes.get("hook") {
                    if HookPermissionsDetector::has_swap_hooks(hook_address) {
                        let latest_tx_hash = component_to_latest_tx
                            .get(&component.id)
                            .cloned()
                            .unwrap_or_else(|| tx_with_changes.tx.hash.clone());

                        components_with_hooks
                            .insert(component.id.clone(), (latest_tx_hash, component.clone()));

                        // Add new components to the cache
                        self.cache
                            .protocol_components
                            .insert_pending(
                                block_changes.block.clone(),
                                component.id.clone(),
                                component.clone(),
                            )
                            .map_err(|e| {
                                ExtractionError::Unknown(format!(
                                    "Failed to cache new component: {e:?}"
                                ))
                            })?;
                    }
                }
            }
        }

        // Process mutated components (from state_updates and balance_changes)
        for component_id in component_to_latest_tx.keys() {
            // Skip if we already processed this as a new component
            if components_with_hooks.contains_key(component_id) {
                continue;
            }

            if let Some(component) = self
                .cache
                .protocol_components
                .get(component_id)
            {
                if let Some(hook_address) = component.static_attributes.get("hook") {
                    if HookPermissionsDetector::has_swap_hooks(hook_address) {
                        let latest_tx_hash = component_to_latest_tx
                            .get(component_id)
                            .cloned()
                            .unwrap_or_default();

                        components_with_hooks
                            .insert(component_id.clone(), (latest_tx_hash, component.clone()));
                    }
                }
            } else {
                // Note: It's possible for components to be mutated that aren't in our cache
                // (e.g., non-swap hook Uniswap V4 components). This is expected and we ignore them.
                debug!("Skipping component with no swap hook permissions for {}", component_id);
            }
        }

        Ok(components_with_hooks)
    }

    fn categorize_components(
        &self,
        components: &HashMap<ComponentId, ComponentWithTxHash>,
    ) -> Result<(Vec<ComponentWithTxHash>, Vec<ComponentWithTxHash>), ExtractionError> {
        let mut components_needing_full_processing = Vec::new();
        let mut components_needing_balance_only = Vec::new();

        for (component_id, (tx_hash, component)) in components {
            // Check the component's processing state from cache
            match self
                .cache
                .component_states
                .get(component_id)
            {
                Some(state) => {
                    match state.status {
                        ProcessingStatus::Unprocessed => {
                            // Never processed, needs full processing
                            components_needing_full_processing
                                .push((tx_hash.clone(), component.clone()));
                        }
                        ProcessingStatus::TracingComplete => {
                            // Already traced, only needs balance updates
                            components_needing_balance_only
                                .push((tx_hash.clone(), component.clone()));
                        }
                        ProcessingStatus::Failed => {
                            // Check retry count
                            if state.retry_count < self.max_retries &&
                                state.retry_count < self.pause_after_retries
                            {
                                components_needing_full_processing
                                    .push((tx_hash.clone(), component.clone()));
                            }
                            // else: pause processing for this component or max retries reached
                        }
                    }
                }
                None => {
                    // Not in cache, needs full processing
                    components_needing_full_processing.push((tx_hash.clone(), component.clone()));
                }
            }
        }

        Ok((components_needing_full_processing, components_needing_balance_only))
    }

    fn update_component_balances(
        &self,
        component: &ProtocolComponent,
        block_changes: &mut BlockChanges,
    ) -> Result<(), ExtractionError> {
        // This method should not be needed anymore as the HookOrchestrator
        // already handles balance updates in prepare_components method.
        // The balances are injected into block_changes.txs_with_update by the orchestrator.
        Ok(())
    }
}

// Component state tracking
#[derive(Clone)]
pub struct ComponentProcessingState {
    pub status: ProcessingStatus,
    pub retry_count: u32,
    pub last_error: Option<ProcessingError>,
}

#[derive(Clone, Debug)]
pub enum ProcessingStatus {
    Unprocessed,     // Never processed or needs full processing
    TracingComplete, // Has entrypoints generated, only needs balance updates
    Failed,          // Processing failed, can retry
}

// TODO: Use anyhow error
#[derive(Clone)]
pub enum ProcessingError {
    MetadataError(String), // Before entrypoint generation
    TracingError(String),  // During/after entrypoint generation
}

#[async_trait]
impl<AE, T, G> ExtractorExtension for UniswapV4HookDCI<AE, T, G>
where
    AE: AccountExtractor + Send + Sync,
    T: EntryPointTracer + Send + Sync,
    G: EntryPointGateway + ProtocolGateway + Send + Sync,
{
    async fn process_block_update(
        &mut self,
        block_changes: &mut BlockChanges,
    ) -> Result<(), ExtractionError> {
        // Ensure the block layer exists in the cache
        self.cache
            .try_insert_block_layer(&block_changes.block)
            .map_err(|e| {
                ExtractionError::Unknown(format!("Failed to ensure block layer: {e:?}"))
            })?;

        // 1. Filter components with swap hooks (beforeSwap/afterSwap only)
        let swap_hook_components = self.extract_components_with_swap_hooks(block_changes)?;

        // Early stop if no hook-components are affected
        if swap_hook_components.is_empty() {
            return self
                .inner_dci
                .process_block_update(block_changes)
                .await;
        }

        // 2. Categorize components based on processing state
        let (components_needing_full_processing, components_needing_balance_only) =
            self.categorize_components(&swap_hook_components)?;

        // 3. Process the components - collect metadata
        let component_metadata = self
            .metadata_orchestrator
            .collect_metadata_for_block(
                &components_needing_balance_only,
                &components_needing_full_processing,
                &block_changes.block,
            )
            .await
            .map_err(|e| {
                error!(
                    "Failed to collect metadata for block {}: {e:?}",
                    block_changes.block.number
                );
                ExtractionError::Unknown(format!("Failed to collect metadata: {e:?}"))
            })?;

        // 3a. Process metadata errors and update component states
        self.process_metadata_errors(&component_metadata, &block_changes.block)?;

        // 4. Group components by hook address for orchestrator processing
        let mut components_by_hook: HashMap<Address, Vec<ProtocolComponent>> = HashMap::new();
        let mut metadata_by_component_id: HashMap<ComponentId, _> = HashMap::new();

        for (component, metadata) in component_metadata {
            metadata_by_component_id.insert(component.id.clone(), metadata);

            if let Some(hook_address) = component.static_attributes.get("hook") {
                components_by_hook
                    .entry(hook_address.clone())
                    .or_default()
                    .push(component);
            }
        }

        // 5. Call appropriate hook orchestrator for each group
        for (hook_address, components) in &components_by_hook {
            if let Some(orchestrator) = self
                .hook_orchestrator_registry
                .hooks
                .get(hook_address)
            {
                let component_metadata_map: HashMap<String, _> = components
                    .iter()
                    .filter_map(|comp| {
                        metadata_by_component_id
                            .get(&comp.id)
                            .map(|meta| (comp.id.clone(), meta.clone()))
                    })
                    .collect();

                match orchestrator.update_components(
                    block_changes,
                    components,
                    &component_metadata_map,
                ) {
                    Ok(()) => {
                        // Update component states for successful processing
                        for component in components {
                            self.handle_component_success(
                                component.id.clone(),
                                &block_changes.block,
                            )?;
                        }
                    }
                    Err(e) => {
                        error!("Hook orchestrator failed for hook {}: {e:?}", hook_address);

                        // Mark all components in this group as failed
                        for component in components {
                            self.handle_component_failure(
                                component.id.clone(),
                                format!("Hook orchestrator error: {e:?}"),
                                &block_changes.block,
                            )?;
                        }
                    }
                }
            } else {
                debug!("No hook orchestrator found for hook address: {}", hook_address);

                // Mark components as failed since we can't process them
                for component in components {
                    self.handle_component_failure(
                        component.id.clone(),
                        format!("No hook orchestrator available for hook {hook_address}"),
                        &block_changes.block,
                    )?;
                }
            }
        }

        // TODO: Is pruning implemented already?
        // 6. Delegate to standard DCI (handles tracing + pruning)
        self.inner_dci
            .process_block_update(block_changes)
            .await?;

        // 7. Handle finality for the cache
        self.cache
            .handle_finality(block_changes.finalized_block_height)
            .map_err(|e| {
                ExtractionError::Unknown(format!("Failed to handle finality for cache: {e:?}"))
            })?;

        Ok(())
    }

    /// Handles revert by reverting the cache and calling the inner_dci's process_revert.
    async fn process_revert(&mut self, target_block: &BlockHash) -> Result<(), ExtractionError> {
        // Revert the cache
        self.cache
            .revert_to(target_block)
            .map_err(|e| ExtractionError::Unknown(format!("Failed to revert cache: {e:?}")))?;

        // Delegate to inner DCI
        self.inner_dci
            .process_revert(target_block)
            .await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use tycho_common::{
        models::{
            blockchain::{Block, Transaction, TxWithChanges},
            protocol::{ProtocolComponent, ProtocolComponentStateDelta},
            Chain, ChangeType, TxHash,
        },
        storage::WithTotal,
        traits::{MockAccountExtractor, MockEntryPointTracer},
        Bytes,
    };

    use super::*;
    use crate::{
        extractor::{
            dynamic_contract_indexer::component_metadata::{
                MetadataGeneratorRegistry, MetadataResponseParserRegistry, ProviderRegistry,
            },
            models::BlockChanges,
        },
        testing::{self, MockGateway},
    };

    fn get_test_block(version: u8) -> Block {
        testing::block(version.into())
    }

    fn get_test_transaction(version: u8) -> Transaction {
        Transaction::new(
            Bytes::from(version).lpad(32, 0),
            Bytes::from(version).lpad(32, 0),
            Bytes::from(version).lpad(20, 0),
            Some(Bytes::from(version).lpad(20, 0)),
            version as u64,
        )
    }

    fn create_hook_component(id: &str, hook_address: Address) -> ProtocolComponent {
        let mut static_attributes = HashMap::new();
        static_attributes.insert("hook".to_string(), hook_address.clone());
        static_attributes.insert("key_lp_fee".to_string(), Bytes::from(vec![0, 0, 100])); // 100 basis points
        static_attributes.insert("tick_spacing".to_string(), Bytes::from(vec![0, 0, 0, 10])); // tick spacing 10

        ProtocolComponent {
            id: id.to_string(),
            protocol_system: "uniswap_v4".to_string(),
            protocol_type_name: "pool".to_string(),
            chain: Chain::Ethereum,
            tokens: vec![Address::from([2u8; 20]), Address::from([3u8; 20])],
            contract_addresses: vec![hook_address],
            static_attributes,
            change: ChangeType::Creation,
            creation_tx: TxHash::from([0u8; 32]),
            created_at: chrono::NaiveDateTime::from_timestamp_opt(1234567890, 0).unwrap(),
        }
    }

    fn create_hook_address_with_swap_permissions() -> Address {
        // Address with beforeSwap (bit 7) and afterSwap (bit 6) enabled
        // 0x00000000000000000000000000000000000000C0 = 0b11000000
        Address::from("0x00000000000000000000000000000000000000C0")
    }

    fn create_hook_address_without_swap_permissions() -> Address {
        // Address with no swap hooks
        Address::from("0x0000000000000000000000000000000000000000")
    }

    fn get_mock_gateway() -> MockGateway {
        let mut gateway = MockGateway::new();

        // Mock for inner DCI initialization
        gateway
            .expect_get_entry_points_tracing_params()
            .return_once(move |_, _| {
                Box::pin(async move { Ok(WithTotal { entity: HashMap::new(), total: None }) })
            });

        gateway
            .expect_get_traced_entry_points()
            .return_once(move |_| Box::pin(async move { Ok(HashMap::new()) }));

        gateway
    }

    #[tokio::test]
    async fn test_initialize() {
        let gateway = get_mock_gateway();
        let account_extractor = MockAccountExtractor::new();
        let entrypoint_tracer = MockEntryPointTracer::new();

        let inner_dci = DynamicContractIndexer::new(
            Chain::Ethereum,
            "test".to_string(),
            gateway,
            account_extractor,
            entrypoint_tracer,
        );

        let metadata_orchestrator = BlockMetadataOrchestrator::new(
            MetadataGeneratorRegistry::new(),
            MetadataResponseParserRegistry::new(),
            ProviderRegistry::new(),
        );

        let hook_orchestrator_registry = HookOrchestratorRegistry { hooks: HashMap::new() };

        let mut gateway2 = MockGateway::new();
        gateway2
            .expect_get_protocol_components()
            .return_once(move |_, _, _, _, _| {
                Box::pin(async move { Ok(WithTotal { entity: vec![], total: Some(0) }) })
            });

        let mut hook_dci = UniswapV4HookDCI::new(
            inner_dci,
            metadata_orchestrator,
            hook_orchestrator_registry,
            gateway2,
            Chain::Ethereum,
            2, // pause_after_retries
            3, // max_retries
        );

        // Should initialize successfully
        hook_dci.initialize().await.unwrap();
    }

    #[tokio::test]
    async fn test_process_block_update_no_hook_components() {
        let gateway = get_mock_gateway();
        let account_extractor = MockAccountExtractor::new();
        let entrypoint_tracer = MockEntryPointTracer::new();

        let inner_dci = DynamicContractIndexer::new(
            Chain::Ethereum,
            "test".to_string(),
            gateway,
            account_extractor,
            entrypoint_tracer,
        );

        let metadata_orchestrator = BlockMetadataOrchestrator::new(
            MetadataGeneratorRegistry::new(),
            MetadataResponseParserRegistry::new(),
            ProviderRegistry::new(),
        );

        let hook_orchestrator_registry = HookOrchestratorRegistry { hooks: HashMap::new() };

        let mut gateway2 = MockGateway::new();
        gateway2
            .expect_get_protocol_components()
            .return_once(move |_, _, _, _, _| {
                Box::pin(async move { Ok(WithTotal { entity: vec![], total: Some(0) }) })
            });

        let mut hook_dci = UniswapV4HookDCI::new(
            inner_dci,
            metadata_orchestrator,
            hook_orchestrator_registry,
            gateway2,
            Chain::Ethereum,
            2,
            3,
        );

        hook_dci.initialize().await.unwrap();

        // Create block changes with no hook components
        let mut block_changes = BlockChanges::new(
            "test".to_string(),
            Chain::Ethereum,
            get_test_block(1),
            1,
            false,
            vec![TxWithChanges { tx: get_test_transaction(1), ..Default::default() }],
            Vec::new(),
        );

        // Should delegate directly to inner DCI
        hook_dci
            .process_block_update(&mut block_changes)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_extract_components_with_swap_hooks() {
        let gateway = MockGateway::new();
        let account_extractor = MockAccountExtractor::new();
        let entrypoint_tracer = MockEntryPointTracer::new();

        let inner_dci = DynamicContractIndexer::new(
            Chain::Ethereum,
            "test".to_string(),
            gateway,
            account_extractor,
            entrypoint_tracer,
        );

        let metadata_orchestrator = BlockMetadataOrchestrator::new(
            MetadataGeneratorRegistry::new(),
            MetadataResponseParserRegistry::new(),
            ProviderRegistry::new(),
        );

        let hook_orchestrator_registry = HookOrchestratorRegistry { hooks: HashMap::new() };

        let gateway2 = MockGateway::new();
        let mut hook_dci = UniswapV4HookDCI::new(
            inner_dci,
            metadata_orchestrator,
            hook_orchestrator_registry,
            gateway2,
            Chain::Ethereum,
            2,
            3,
        );

        // Create components with and without swap hooks
        let hook_with_swap = create_hook_address_with_swap_permissions();
        let hook_without_swap = create_hook_address_without_swap_permissions();

        let component1 = create_hook_component("comp1", hook_with_swap);
        let component2 = create_hook_component("comp2", hook_without_swap);

        let mut block_changes = BlockChanges::new(
            "test".to_string(),
            Chain::Ethereum,
            get_test_block(1),
            1,
            false,
            vec![TxWithChanges {
                tx: get_test_transaction(1),
                protocol_components: HashMap::from([
                    ("comp1".to_string(), component1.clone()),
                    ("comp2".to_string(), component2.clone()),
                ]),
                ..Default::default()
            }],
            Vec::new(),
        );

        // Initialize the block layer in the cache
        hook_dci
            .cache
            .protocol_components
            .validate_and_ensure_block_layer_test(&block_changes.block)
            .unwrap();

        let components = hook_dci
            .extract_components_with_swap_hooks(&mut block_changes)
            .unwrap();

        // Should only extract component with swap hooks
        assert_eq!(components.len(), 1);
        assert!(components.contains_key("comp1"));
        let (tx_hash, component) = components.get("comp1").unwrap();
        assert_eq!(component.id, "comp1");
    }

    #[tokio::test]
    async fn test_extract_components_with_mutated_components() {
        let gateway = MockGateway::new();
        let account_extractor = MockAccountExtractor::new();
        let entrypoint_tracer = MockEntryPointTracer::new();

        let inner_dci = DynamicContractIndexer::new(
            Chain::Ethereum,
            "test".to_string(),
            gateway,
            account_extractor,
            entrypoint_tracer,
        );

        let metadata_orchestrator = BlockMetadataOrchestrator::new(
            MetadataGeneratorRegistry::new(),
            MetadataResponseParserRegistry::new(),
            ProviderRegistry::new(),
        );

        let hook_orchestrator_registry = HookOrchestratorRegistry { hooks: HashMap::new() };

        let gateway2 = MockGateway::new();
        let mut hook_dci = UniswapV4HookDCI::new(
            inner_dci,
            metadata_orchestrator,
            hook_orchestrator_registry,
            gateway2,
            Chain::Ethereum,
            2,
            3,
        );

        // Pre-populate the cache with an existing component
        let hook_address = create_hook_address_with_swap_permissions();
        let existing_component = create_hook_component("existing_comp", hook_address);
        hook_dci
            .cache
            .protocol_components
            .insert_permanent("existing_comp".to_string(), existing_component.clone());

        // Create block changes with only state_updates (no new components)
        let mut state_updates = HashMap::new();
        let state_delta = ProtocolComponentStateDelta::new(
            "existing_comp",
            HashMap::new(),                   // No updated attributes
            std::collections::HashSet::new(), // No deleted attributes
        );
        state_updates.insert("existing_comp".to_string(), state_delta);

        let mut block_changes = BlockChanges::new(
            "test".to_string(),
            Chain::Ethereum,
            get_test_block(1),
            1,
            false,
            vec![TxWithChanges {
                tx: get_test_transaction(1),
                protocol_components: HashMap::new(), // No new components
                state_updates,
                ..Default::default()
            }],
            Vec::new(),
        );

        // Initialize the block layer in the cache
        hook_dci
            .cache
            .protocol_components
            .validate_and_ensure_block_layer_test(&block_changes.block)
            .unwrap();

        let components = hook_dci
            .extract_components_with_swap_hooks(&mut block_changes)
            .unwrap();

        // Should extract the mutated component with swap hooks
        assert_eq!(components.len(), 1);
        assert!(components.contains_key("existing_comp"));
        let (tx_hash, component) = components.get("existing_comp").unwrap();
        assert_eq!(component.id, "existing_comp");
    }

    #[tokio::test]
    async fn test_extract_components_with_balance_changes() {
        let gateway = MockGateway::new();
        let account_extractor = MockAccountExtractor::new();
        let entrypoint_tracer = MockEntryPointTracer::new();

        let inner_dci = DynamicContractIndexer::new(
            Chain::Ethereum,
            "test".to_string(),
            gateway,
            account_extractor,
            entrypoint_tracer,
        );

        let metadata_orchestrator = BlockMetadataOrchestrator::new(
            MetadataGeneratorRegistry::new(),
            MetadataResponseParserRegistry::new(),
            ProviderRegistry::new(),
        );

        let hook_orchestrator_registry = HookOrchestratorRegistry { hooks: HashMap::new() };

        let gateway2 = MockGateway::new();
        let mut hook_dci = UniswapV4HookDCI::new(
            inner_dci,
            metadata_orchestrator,
            hook_orchestrator_registry,
            gateway2,
            Chain::Ethereum,
            2,
            3,
        );

        // Pre-populate the cache with an existing component
        let hook_address = create_hook_address_with_swap_permissions();
        let existing_component = create_hook_component("balance_comp", hook_address);
        hook_dci
            .cache
            .protocol_components
            .insert_permanent("balance_comp".to_string(), existing_component.clone());

        // Create block changes with only balance_changes (no new components)
        let mut balance_changes = HashMap::new();
        balance_changes.insert("balance_comp".to_string(), HashMap::new()); // Dummy balance update

        let mut block_changes = BlockChanges::new(
            "test".to_string(),
            Chain::Ethereum,
            get_test_block(1),
            1,
            false,
            vec![TxWithChanges {
                tx: get_test_transaction(1),
                protocol_components: HashMap::new(), // No new components
                balance_changes,
                ..Default::default()
            }],
            Vec::new(),
        );

        // Initialize the block layer in the cache
        hook_dci
            .cache
            .protocol_components
            .validate_and_ensure_block_layer_test(&block_changes.block)
            .unwrap();

        let components = hook_dci
            .extract_components_with_swap_hooks(&mut block_changes)
            .unwrap();

        // Should extract the component with balance changes that has swap hooks
        assert_eq!(components.len(), 1);
        assert!(components.contains_key("balance_comp"));
        let (tx_hash, component) = components.get("balance_comp").unwrap();
        assert_eq!(component.id, "balance_comp");
    }

    #[tokio::test]
    async fn test_categorize_components() {
        let gateway = MockGateway::new();
        let account_extractor = MockAccountExtractor::new();
        let entrypoint_tracer = MockEntryPointTracer::new();

        let inner_dci = DynamicContractIndexer::new(
            Chain::Ethereum,
            "test".to_string(),
            gateway,
            account_extractor,
            entrypoint_tracer,
        );

        let metadata_orchestrator = BlockMetadataOrchestrator::new(
            MetadataGeneratorRegistry::new(),
            MetadataResponseParserRegistry::new(),
            ProviderRegistry::new(),
        );

        let hook_orchestrator_registry = HookOrchestratorRegistry { hooks: HashMap::new() };

        let gateway2 = MockGateway::new();
        let mut hook_dci = UniswapV4HookDCI::new(
            inner_dci,
            metadata_orchestrator,
            hook_orchestrator_registry,
            gateway2,
            Chain::Ethereum,
            2,
            3,
        );

        let hook_address = create_hook_address_with_swap_permissions();
        let component = create_hook_component("comp1", hook_address);
        let tx_hash = TxHash::from([1u8; 32]);

        let block_changes = BlockChanges::new(
            "test".to_string(),
            Chain::Ethereum,
            get_test_block(1),
            1,
            false,
            vec![TxWithChanges {
                tx: get_test_transaction(1),
                protocol_components: HashMap::from([("comp1".to_string(), component.clone())]),
                ..Default::default()
            }],
            Vec::new(),
        );

        // Test component not in cache (needs full processing)
        let mut components_map = HashMap::new();
        components_map.insert("comp1".to_string(), (tx_hash.clone(), component.clone()));

        let (full_processing, balance_only) = hook_dci
            .categorize_components(&components_map)
            .unwrap();

        assert_eq!(full_processing.len(), 1);
        assert_eq!(balance_only.len(), 0);
        assert_eq!(full_processing[0].1.id, "comp1");

        // Add component to cache as TracingComplete
        let state = ComponentProcessingState {
            status: ProcessingStatus::TracingComplete,
            retry_count: 0,
            last_error: None,
        };
        hook_dci
            .cache
            .component_states
            .insert_permanent("comp1".to_string(), state);

        // Test component in cache with TracingComplete (needs balance only)
        let (full_processing, balance_only) = hook_dci
            .categorize_components(&components_map)
            .unwrap();

        assert_eq!(full_processing.len(), 0);
        assert_eq!(balance_only.len(), 1);
        assert_eq!(balance_only[0].1.id, "comp1");
    }

    #[tokio::test]
    async fn test_handle_component_success() {
        let gateway = MockGateway::new();
        let account_extractor = MockAccountExtractor::new();
        let entrypoint_tracer = MockEntryPointTracer::new();

        let inner_dci = DynamicContractIndexer::new(
            Chain::Ethereum,
            "test".to_string(),
            gateway,
            account_extractor,
            entrypoint_tracer,
        );

        let metadata_orchestrator = BlockMetadataOrchestrator::new(
            MetadataGeneratorRegistry::new(),
            MetadataResponseParserRegistry::new(),
            ProviderRegistry::new(),
        );

        let hook_orchestrator_registry = HookOrchestratorRegistry { hooks: HashMap::new() };

        let gateway2 = MockGateway::new();
        let mut hook_dci = UniswapV4HookDCI::new(
            inner_dci,
            metadata_orchestrator,
            hook_orchestrator_registry,
            gateway2,
            Chain::Ethereum,
            2,
            3,
        );

        let block = get_test_block(1);
        let component_id = "comp1".to_string();

        // Initialize the block layer in the cache first
        hook_dci
            .cache
            .component_states
            .validate_and_ensure_block_layer_test(&block)
            .unwrap();

        // Handle success
        hook_dci
            .handle_component_success(component_id.clone(), &block)
            .unwrap();

        // Check that component state was updated
        let state = hook_dci
            .cache
            .component_states
            .get(&component_id)
            .unwrap();
        assert!(matches!(state.status, ProcessingStatus::TracingComplete));
        assert_eq!(state.retry_count, 0);
        assert!(state.last_error.is_none());
    }

    #[tokio::test]
    async fn test_process_revert() {
        let gateway = MockGateway::new();
        let account_extractor = MockAccountExtractor::new();
        let entrypoint_tracer = MockEntryPointTracer::new();

        let inner_dci = DynamicContractIndexer::new(
            Chain::Ethereum,
            "test".to_string(),
            gateway,
            account_extractor,
            entrypoint_tracer,
        );

        let metadata_orchestrator = BlockMetadataOrchestrator::new(
            MetadataGeneratorRegistry::new(),
            MetadataResponseParserRegistry::new(),
            ProviderRegistry::new(),
        );

        let hook_orchestrator_registry = HookOrchestratorRegistry { hooks: HashMap::new() };

        let gateway2 = MockGateway::new();
        let mut hook_dci = UniswapV4HookDCI::new(
            inner_dci,
            metadata_orchestrator,
            hook_orchestrator_registry,
            gateway2,
            Chain::Ethereum,
            2,
            3,
        );

        let block_hash = Bytes::from([1u8; 32]);

        // Should process revert without error
        hook_dci
            .process_revert(&block_hash)
            .await
            .unwrap();
    }
}
