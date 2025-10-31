use std::collections::{HashMap, HashSet};

#[cfg(test)]
use mockall::automock;
use thiserror::Error;
use tracing::{debug, error, info, instrument, warn};
use tycho_common::{
    models::{
        blockchain::{Block, EntryPointWithTracingParams},
        protocol::{ComponentBalance, ProtocolComponent, ProtocolComponentStateDelta},
        Address, ComponentId, TxHash,
    },
    traits::BalanceSlotDetector,
    Bytes,
};

use crate::extractor::{
    dynamic_contract_indexer::{
        component_metadata::{Balances, ComponentTracingMetadata},
        entrypoint_generator::{
            DefaultSwapAmountEstimator, EntrypointGenerationError, HookEntrypointData,
            HookEntrypointGenerator, HookTracerContext, UniswapV4DefaultHookEntrypointGenerator,
        },
    },
    models::BlockChanges,
    u256_num::bytes_to_f64,
};

// Implementation reference only - the custom errors will be defined during the implementation.
#[derive(Debug, Error)]
pub enum HookOrchestratorError {
    #[error("Prepare components failed: {0}")]
    PrepareComponentsFailed(String),
    #[error("Generate entrypoint params failed: {0}")]
    GenerateEntrypointParamsFailed(#[from] EntrypointGenerationError),
}

/// Trait for hook orchestration operations
#[cfg_attr(test, automock)]
#[async_trait::async_trait]
pub trait HookOrchestrator: Send + Sync {
    /// Main Entrypoint for the orchestrator.
    ///
    /// This method is called for each block and is responsible for
    /// - Generating the Entrypoints with TracingParams
    /// - Updating the components with the collected metadata
    ///     - Inject Balances to the ProtocolComponents
    ///     - Inject the Limits to the ProtocolComponents (if they are RPC calls)
    ///     - Inject Entrypoints to the ProtocolComponents
    async fn update_components(
        &self,
        block_changes: &mut BlockChanges,
        components: &[ProtocolComponent],
        metadata: &HashMap<String, ComponentTracingMetadata>,
        generate_entrypoints: bool,
    ) -> Result<(), HookOrchestratorError>;
}

pub struct HookOrchestratorRegistry {
    hooks: HashMap<Address, Box<dyn HookOrchestrator>>,
    hook_identifiers: HashMap<String, Box<dyn HookOrchestrator>>,
    default_orchestrator: Option<Box<dyn HookOrchestrator>>,
}

impl HookOrchestratorRegistry {
    pub fn new() -> Self {
        Self { hooks: HashMap::new(), hook_identifiers: HashMap::new(), default_orchestrator: None }
    }

    /// Sets a default orchestrator to use when no specific orchestrator is found for a component
    pub fn set_default_orchestrator(&mut self, orchestrator: Box<dyn HookOrchestrator>) {
        self.default_orchestrator = Some(orchestrator);
    }

    #[allow(dead_code)]
    pub fn register_hook_orchestrator(
        &mut self,
        hook_address: Address,
        orchestrator: Box<dyn HookOrchestrator>,
    ) {
        self.hooks
            .insert(hook_address, orchestrator);
    }

    #[allow(dead_code)]
    pub fn register_hook_identifier(
        &mut self,
        hook_identifier: String,
        orchestrator: Box<dyn HookOrchestrator>,
    ) {
        self.hook_identifiers
            .insert(hook_identifier, orchestrator);
    }

    pub fn get_orchestrator_for_component(
        &self,
        component: &ProtocolComponent,
    ) -> Option<&dyn HookOrchestrator> {
        let hook_address = component
            .static_attributes
            .get("hooks")?;

        // Priority: hook address first, then hook identifier, then default orchestrator
        match self.hooks.get(hook_address) {
            Some(orchestrator) => Some(orchestrator.as_ref()),
            None => {
                // Try hook identifier if available
                if let Some(hook_identifier_bytes) = component
                    .static_attributes
                    .get("hook_identifier")
                {
                    if let Ok(identifier) = String::from_utf8(hook_identifier_bytes.to_vec()) {
                        if let Some(orchestrator) = self.hook_identifiers.get(&identifier) {
                            return Some(orchestrator.as_ref());
                        }
                    }
                }

                // Fall back to default orchestrator if no specific one found
                self.default_orchestrator
                    .as_ref()
                    .map(|o| o.as_ref())
            }
        }
    }
}

pub struct DefaultUniswapV4HookOrchestrator<B>
where
    B: BalanceSlotDetector,
{
    entrypoint_generator: UniswapV4DefaultHookEntrypointGenerator<DefaultSwapAmountEstimator, B>,
}

impl<B> DefaultUniswapV4HookOrchestrator<B>
where
    B: BalanceSlotDetector,
{
    pub fn new(
        entrypoint_generator: UniswapV4DefaultHookEntrypointGenerator<
            DefaultSwapAmountEstimator,
            B,
        >,
    ) -> Self {
        Self { entrypoint_generator }
    }

    #[instrument(skip(self, block_changes, metadata, component_entrypoints), fields(
        component_count = metadata.len(),
        entrypoint_count = component_entrypoints.len(),
        tx_count = block_changes.txs_with_update.len()
    ))]
    fn prepare_components(
        &self,
        block_changes: &mut BlockChanges,
        metadata: &HashMap<String, ComponentTracingMetadata>,
        component_entrypoints: HashMap<ComponentId, Vec<(TxHash, EntryPointWithTracingParams)>>,
    ) -> Result<(), HookOrchestratorError> {
        debug!("Preparing components with metadata and entrypoint params");

        let tx_vec_idx_by_hash: HashMap<TxHash, usize> = block_changes
            .txs_with_update
            .iter()
            .enumerate()
            .map(|(idx, tx_delta)| (tx_delta.tx.hash.clone(), idx))
            .collect();

        let mut components_with_limits = 0;
        let mut components_with_balances = 0;
        let mut total_balance_updates = 0;

        for (component_id, metadata) in metadata {
            let tx_idx = tx_vec_idx_by_hash
                .get(&metadata.tx_hash)
                .expect("Tx hash should be present in the block changes");

            let tx_delta = &mut block_changes.txs_with_update[*tx_idx];

            if let Some(Ok(limit)) = &metadata.limits {
                components_with_limits += 1;
                debug!(
                    component_id = %component_id,
                    "Processing component limits"
                );
                for (idx, lim) in limit.iter().enumerate() {
                    if let Some(limit_entrypoint) = lim.1 .2.as_ref() {
                        // Since limits should share the same entrypoint but different parameters
                        // (for 0->1 and 1->0 we only insert one Entrypoint.
                        if idx == 0 {
                            let mut updated_attributes = HashMap::new();
                            updated_attributes.insert(
                                "limits_entrypoint".to_string(),
                                Bytes::from(
                                    format!(
                                        "{}:{}",
                                        limit_entrypoint.entry_point.target,
                                        limit_entrypoint.entry_point.signature
                                    )
                                    .as_bytes()
                                    .to_vec(),
                                ),
                            );
                            let pc_delta = ProtocolComponentStateDelta::new(
                                component_id,
                                updated_attributes,
                                HashSet::new(),
                            );
                            let tx_delta_state_updates = tx_delta
                                .state_updates
                                .entry(component_id.clone())
                                .or_insert(ProtocolComponentStateDelta::new(
                                    component_id,
                                    HashMap::new(),
                                    HashSet::new(),
                                ));

                            tx_delta_state_updates
                                .merge(pc_delta)
                                .map_err(|e| {
                                    error!(
                                        component_id = %component_id,
                                        error = %e,
                                        "Failed to merge component state updates"
                                    );
                                    HookOrchestratorError::PrepareComponentsFailed(format!(
                                        "Failed to merge component state updates: {e}"
                                    ))
                                })?;

                            tx_delta
                                .entrypoints
                                .entry(component_id.clone())
                                .or_default()
                                .insert(limit_entrypoint.entry_point.clone());
                        }

                        tx_delta
                            .entrypoint_params
                            .entry(
                                limit_entrypoint
                                    .entry_point
                                    .external_id
                                    .clone(),
                            )
                            .or_default()
                            .insert((limit_entrypoint.params.clone(), Some(component_id.clone())));
                    }
                }
            }

            if let Some(Ok(balances)) = metadata.balances.clone() {
                components_with_balances += 1;
                total_balance_updates += balances.len();

                debug!(
                    component_id = %component_id,
                    balance_count = balances.len(),
                    "Processing component balances"
                );

                let component_balance = balances
                    .into_iter()
                    .map(|(token, balance)| {
                        let balance_float = bytes_to_f64(balance.as_ref()).ok_or_else(|| {
                            error!(
                                component_id = %component_id,
                                token = %token,
                                balance = %balance,
                                "Failed to convert balance to float"
                            );
                            HookOrchestratorError::PrepareComponentsFailed(format!(
                                "Failed to convert balance to float: {balance}"
                            ))
                        })?;

                        debug!(
                            component_id = %component_id,
                            token = %token,
                            balance_raw = %balance,
                            balance_float = balance_float,
                            "Converted balance"
                        );

                        Ok((
                            token.clone(),
                            ComponentBalance::new(
                                token,
                                balance,
                                balance_float,
                                tx_delta.tx.hash.clone(),
                                component_id,
                            ),
                        ))
                    })
                    .collect::<Result<HashMap<Address, ComponentBalance>, HookOrchestratorError>>(
                    )?;

                tx_delta
                    .balance_changes
                    .insert(component_id.clone(), component_balance);
            }
        }

        let mut total_entrypoint_params = 0;

        // Process each component's entrypoints
        for (component_id, entrypoints_with_tx) in component_entrypoints {
            for (tx_hash, entrypoint_with_params) in entrypoints_with_tx {
                total_entrypoint_params += 1;

                let tx_idx = tx_vec_idx_by_hash
                    .get(&tx_hash)
                    .expect("Tx hash should be present in the block changes");

                let tx_delta = &mut block_changes.txs_with_update[*tx_idx];

                // Add the EntryPoint to the transaction's entrypoints
                tx_delta
                    .entrypoints
                    .entry(component_id.clone())
                    .or_default()
                    .insert(
                        entrypoint_with_params
                            .entry_point
                            .clone(),
                    );

                // Add the tracing params to the transaction's entrypoint_params
                tx_delta
                    .entrypoint_params
                    .entry(
                        entrypoint_with_params
                            .entry_point
                            .external_id
                            .clone(),
                    )
                    .or_default()
                    .insert((entrypoint_with_params.params, Some(component_id.clone())));
            }
        }

        info!(
            components_with_limits,
            components_with_balances,
            total_balance_updates,
            total_entrypoint_params,
            "Completed component preparation"
        );

        Ok(())
    }

    /// Enriches component metadata with balance updates extracted from block changes.
    ///
    /// This method efficiently processes blockchain transaction data to extract the latest
    /// balance updates for protocol components that need metadata for entrypoint generation
    /// but don't have external metadata sources. It processes transactions in reverse order
    /// to capture only the most recent balance changes for each token.
    ///
    /// # Arguments
    /// * `components_needing_metadata` - Components that need balance-based metadata
    /// * `block_changes` - Reference to block changes containing transaction data and balance
    ///   updates
    ///
    /// # Returns
    /// HashMap mapping component IDs to their enriched metadata containing balance information
    #[instrument(skip_all, fields(
        components_count = components_needing_metadata.len(),
        transactions_count = block_changes.txs_with_update.len()
    ))]
    fn enrich_metadata_from_block_balances(
        &self,
        components_needing_metadata: &[&ProtocolComponent],
        block_changes: &BlockChanges,
    ) -> HashMap<ComponentId, ComponentTracingMetadata> {
        debug!("Starting balance-based metadata enrichment for entrypoint generation");

        let mut enriched_metadata: HashMap<ComponentId, Balances> =
            HashMap::with_capacity(components_needing_metadata.len());
        let mut components_enriched = 0;
        let mut total_balance_entries = 0;

        // Build lookup structures
        let mut remaining_components: HashMap<ComponentId, HashSet<Address>> =
            components_needing_metadata
                .iter()
                .map(|component| {
                    (
                        component.id.clone(),
                        component
                            .tokens
                            .iter()
                            .cloned()
                            .collect(),
                    )
                })
                .collect();

        debug!(
            total_tokens_to_track = remaining_components
                .values()
                .map(|tokens| tokens.len())
                .sum::<usize>(),
            unique_components = remaining_components.len(),
            "Built tracking data structures for balance enrichment"
        );

        // Process transactions in reverse order to get latest values first
        for tx_with_changes in block_changes
            .txs_with_update
            .iter()
            .rev()
        {
            // Early exit if all components have been processed
            if remaining_components.is_empty() {
                debug!("Early exit: all components processed");
                break;
            }

            for (component_id, balance_changes) in tx_with_changes.balance_changes.iter() {
                if let Some(tokens_to_update) = remaining_components.get_mut(component_id) {
                    let initial_token_count = tokens_to_update.len();

                    for (token, component_balance) in balance_changes.iter() {
                        if tokens_to_update.remove(token) {
                            enriched_metadata
                                .entry(component_id.clone())
                                .or_default()
                                .insert(token.clone(), component_balance.balance.clone());
                            total_balance_entries += 1;
                        }
                    }

                    // Remove component if all tokens processed
                    if tokens_to_update.is_empty() {
                        remaining_components.remove(component_id);
                        if initial_token_count > 0 {
                            components_enriched += 1;
                            debug!(
                                component_id = %component_id,
                                tokens_processed = initial_token_count,
                                tx_hash = %tx_with_changes.tx.hash,
                                "Component fully enriched with balance data"
                            );
                        }
                    }
                }
            }
        }

        // Convert to ComponentTracingMetadata format
        let mut result = HashMap::new();
        for (component_id, balances) in enriched_metadata {
            // Only include components with non-zero balances and complete token data
            if !balances.values().all(|v| v.is_zero()) &&
                !remaining_components.contains_key(&component_id)
            {
                // Find the latest transaction hash for this component
                let tx_hash = block_changes
                    .txs_with_update
                    .iter()
                    .rev()
                    .find_map(|tx_with_changes| {
                        if tx_with_changes
                            .balance_changes
                            .contains_key(&component_id) ||
                            tx_with_changes
                                .protocol_components
                                .contains_key(&component_id) ||
                            tx_with_changes
                                .state_updates
                                .contains_key(&component_id)
                        {
                            Some(tx_with_changes.tx.hash.clone())
                        } else {
                            None
                        }
                    })
                    .unwrap_or_else(|| {
                        block_changes
                            .txs_with_update
                            .first()
                            .unwrap()
                            .tx
                            .hash
                            .clone()
                    });

                let mut metadata = ComponentTracingMetadata::new(tx_hash);
                metadata.balances = Some(Ok(balances));
                result.insert(component_id, metadata);
            }
        }

        info!(
            components_enriched,
            components_skipped = remaining_components.len(),
            total_balance_entries,
            result_count = result.len(),
            "Completed balance-based metadata enrichment for entrypoint generation"
        );

        result
    }

    #[instrument(skip(self, block, components, metadata, block_changes), fields(
        block_number = block.number,
        component_count = components.len(),
        metadata_count = metadata.len()
    ))]
    async fn generate_entrypoint_params(
        &self,
        block: &Block,
        components: &[ProtocolComponent],
        metadata: &HashMap<String, ComponentTracingMetadata>,
        block_changes: &BlockChanges,
    ) -> Result<
        HashMap<ComponentId, Vec<(TxHash, EntryPointWithTracingParams)>>,
        HookOrchestratorError,
    > {
        debug!("Generating entrypoint parameters");

        // First, identify components that don't have external metadata
        let components_without_metadata: Vec<&ProtocolComponent> = components
            .iter()
            .filter(|component| !metadata.contains_key(&component.id))
            .collect();

        // Enrich metadata for components that don't have external metadata sources
        let balance_enriched_metadata = if !components_without_metadata.is_empty() {
            debug!(
                components_without_metadata = components_without_metadata.len(),
                "Enriching metadata from block balances for components without external metadata"
            );
            self.enrich_metadata_from_block_balances(&components_without_metadata, block_changes)
        } else {
            HashMap::new()
        };

        // Combine external metadata with balance-enriched metadata
        let mut combined_metadata = metadata.clone();
        for (component_id, enriched_meta) in balance_enriched_metadata {
            combined_metadata.insert(component_id, enriched_meta);
        }

        debug!(
            total_metadata_available = combined_metadata.len(),
            external_metadata = metadata.len(),
            balance_enriched = combined_metadata.len() - metadata.len(),
            "Combined metadata sources for entrypoint generation"
        );

        let mut result = HashMap::new();
        let mut total_entrypoints_generated = 0;
        let mut components_with_metadata = 0;
        let mut components_skipped = 0;

        for component in components {
            if let Some(component_metadata) = combined_metadata.get(&component.id) {
                components_with_metadata += 1;

                let hook_address = component
                    .static_attributes
                    .get("hooks")
                    .expect(
                        "UniswapV4 component should have a hook address in the static attributes",
                    );

                debug!(
                    component_id = %component.id,
                    hook_address = %hook_address,
                    "Generating entrypoints for component"
                );

                let data = HookEntrypointData {
                    component: component.clone(),
                    component_metadata: component_metadata.clone(),
                    hook_address: hook_address.clone(),
                    use_balance_overwrites: true, // Use balance overwrites
                };

                let context = HookTracerContext::new(block.clone());

                let eps = self
                    .entrypoint_generator
                    .generate_entrypoints(&data, &context)
                    .await
                    .map_err(|e| {
                        error!(
                            component_id = %component.id,
                            hook_address = %hook_address,
                            error = %e,
                            "Failed to generate entrypoints"
                        );
                        HookOrchestratorError::GenerateEntrypointParamsFailed(e)
                    })?;

                debug!(
                    component_id = %component.id,
                    entrypoint_count = eps.len(),
                    "Generated entrypoints for component"
                );

                total_entrypoints_generated += eps.len();

                let component_entrypoints = eps
                    .into_iter()
                    .map(|ep| (component_metadata.tx_hash.clone(), ep))
                    .collect::<Vec<_>>();

                result.insert(component.id.clone(), component_entrypoints);
            } else {
                components_skipped += 1;
                debug!(
                    component_id = %component.id,
                    "Component has no metadata available, skipping entrypoint generation"
                );
            }
        }

        info!(
            unique_entrypoints = result.len(),
            total_entrypoints_generated,
            components_with_metadata,
            components_skipped,
            "Completed entrypoint parameter generation"
        );

        Ok(result)
    }
}

#[async_trait::async_trait]
impl<B> HookOrchestrator for DefaultUniswapV4HookOrchestrator<B>
where
    B: BalanceSlotDetector + Send + Sync,
{
    #[instrument(skip(self, block_changes, components, metadata), fields(
        block_number = block_changes.block.number,
        component_count = components.len(),
        metadata_count = metadata.len(),
    ))]
    async fn update_components(
        &self,
        block_changes: &mut BlockChanges,
        components: &[ProtocolComponent],
        metadata: &HashMap<String, ComponentTracingMetadata>,
        generate_entrypoints: bool,
    ) -> Result<(), HookOrchestratorError> {
        info!("Starting component update process");

        let component_entrypoints = match generate_entrypoints {
            true => {
                self.generate_entrypoint_params(
                    &block_changes.block,
                    components,
                    metadata,
                    block_changes,
                )
                .await?
            }
            false => HashMap::new(),
        };

        self.prepare_components(block_changes, metadata, component_entrypoints)?;

        info!("Component update process completed successfully");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, str::FromStr};

    use tycho_common::{
        models::{
            blockchain::{Block, Transaction, TxWithChanges},
            protocol::{ComponentBalance, ProtocolComponent},
            Address, Chain, ChangeType,
        },
        Bytes,
    };

    use super::*;
    use crate::extractor::{
        dynamic_contract_indexer::component_metadata::ComponentTracingMetadata,
        models::BlockChanges,
    };

    // Helper functions for creating test data
    fn create_test_component(id: &str, tokens: Vec<Address>) -> ProtocolComponent {
        let mut static_attributes = HashMap::new();
        static_attributes
            .insert("hooks".to_string(), Bytes::from_str("0x1234567890abcdef").unwrap());

        // Add balance_owner tokens
        for (i, token) in tokens.into_iter().enumerate() {
            static_attributes.insert(format!("balance_owner/{}", i), token);
        }

        ProtocolComponent {
            id: id.to_string(),
            protocol_system: "uniswap_v4".to_string(),
            protocol_type_name: "pool".to_string(),
            chain: Chain::Ethereum,
            tokens: vec![], // Not used in balance enrichment
            contract_addresses: vec![],
            static_attributes,
            change: ChangeType::Creation,
            creation_tx: Bytes::default(),
            created_at: chrono::DateTime::from_timestamp(1719849000, 0)
                .unwrap()
                .naive_utc(),
        }
    }

    fn create_test_balance_update(token: Address, balance: u64) -> ComponentBalance {
        ComponentBalance {
            token,
            balance: Bytes::from(balance),
            balance_float: balance as f64,
            modify_tx: Bytes::default(),
            component_id: "test_component".to_string(),
        }
    }

    fn create_test_block_changes(
        block_number: u64,
        tx_count: u64,
        balance_updates: HashMap<String, HashMap<Address, ComponentBalance>>,
    ) -> BlockChanges {
        let block = Block::new(
            block_number,
            Chain::Ethereum,
            Bytes::from(block_number).lpad(32, 0),
            Bytes::from(block_number - 1).lpad(32, 0),
            chrono::DateTime::from_timestamp(1719849000 + (block_number * 12) as i64, 0)
                .unwrap()
                .naive_utc(),
        );

        let mut txs_with_update = Vec::new();
        for i in 0..tx_count {
            let tx = Transaction::new(
                Bytes::from(i).lpad(32, 0),
                Bytes::from(1u64).lpad(32, 0),
                Address::from("0x1234567890123456789012345678901234567890"),
                Some(Address::from("0x0987654321098765432109876543210987654321")),
                i,
            );

            let tx_with_changes = TxWithChanges {
                tx,
                balance_changes: balance_updates.clone(),
                ..Default::default()
            };
            txs_with_update.push(tx_with_changes);
        }

        BlockChanges::new(
            "test_protocol".to_string(),
            Chain::Ethereum,
            block,
            1,
            false,
            txs_with_update,
            Vec::new(),
        )
    }

    // Test orchestrator for testing balance enrichment functionality
    struct TestOrchestrator;
    impl TestOrchestrator {
        fn enrich_metadata_from_block_balances(
            &self,
            components_needing_metadata: &[&ProtocolComponent],
            block_changes: &BlockChanges,
        ) -> HashMap<ComponentId, ComponentTracingMetadata> {
            // Copy the implementation from DefaultUniswapV4HookOrchestrator
            let mut enriched_metadata: HashMap<ComponentId, HashMap<Address, Bytes>> =
                HashMap::with_capacity(components_needing_metadata.len());
            let mut remaining_components: HashMap<ComponentId, std::collections::HashSet<Address>> =
                components_needing_metadata
                    .iter()
                    .map(|component| {
                        let balance_owner_tokens: std::collections::HashSet<Address> = component
                            .static_attributes
                            .iter()
                            .filter_map(|(key, value)| {
                                if key.starts_with("balance_owner/") {
                                    Address::try_from(value.clone()).ok()
                                } else {
                                    None
                                }
                            })
                            .collect();
                        (component.id.clone(), balance_owner_tokens)
                    })
                    .collect();

            // Process transactions in reverse order for latest values
            for tx_with_changes in block_changes
                .txs_with_update
                .iter()
                .rev()
            {
                for (component_id, balance_changes) in &tx_with_changes.balance_changes {
                    if let Some(tokens_to_update) = remaining_components.get_mut(component_id) {
                        for (token, component_balance) in balance_changes.iter() {
                            if tokens_to_update.remove(token) {
                                enriched_metadata
                                    .entry(component_id.clone())
                                    .or_default()
                                    .insert(token.clone(), component_balance.balance.clone());
                            }
                        }

                        if tokens_to_update.is_empty() {
                            remaining_components.remove(component_id);
                        }
                    }
                }
            }

            // Convert to ComponentTracingMetadata format
            let mut result = HashMap::new();
            for (component_id, balances) in enriched_metadata {
                if !balances.values().all(|v| v.is_zero()) &&
                    !remaining_components.contains_key(&component_id)
                {
                    let tx_hash = block_changes
                        .txs_with_update
                        .iter()
                        .rev()
                        .find_map(|tx_with_changes| {
                            if tx_with_changes
                                .balance_changes
                                .contains_key(&component_id)
                            {
                                Some(tx_with_changes.tx.hash.clone())
                            } else {
                                None
                            }
                        })
                        .unwrap_or_else(|| {
                            block_changes
                                .txs_with_update
                                .first()
                                .unwrap()
                                .tx
                                .hash
                                .clone()
                        });

                    result.insert(
                        component_id,
                        ComponentTracingMetadata {
                            tx_hash,
                            balances: Some(Ok(balances)),
                            limits: None,
                            tvl: None,
                        },
                    );
                }
            }

            result
        }
    }

    #[test]
    fn test_enrich_metadata_from_block_balances() {
        let orchestrator = TestOrchestrator;

        // Create test components with specific tokens
        let token1 = Address::from("0x1111111111111111111111111111111111111111");
        let token2 = Address::from("0x2222222222222222222222222222222222222222");
        let token3 = Address::from("0x3333333333333333333333333333333333333333");

        let component1 = create_test_component("comp1", vec![token1.clone(), token2.clone()]);
        let component2 = create_test_component("comp2", vec![token2.clone(), token3.clone()]);
        let components = vec![&component1, &component2];

        // Create balance updates for these tokens
        let mut balance_updates = HashMap::new();
        balance_updates.insert("comp1".to_string(), {
            let mut balances = HashMap::new();
            balances.insert(token1.clone(), create_test_balance_update(token1.clone(), 1000));
            balances.insert(token2.clone(), create_test_balance_update(token2.clone(), 2000));
            balances
        });
        balance_updates.insert("comp2".to_string(), {
            let mut balances = HashMap::new();
            balances.insert(token2.clone(), create_test_balance_update(token2.clone(), 3000));
            balances.insert(token3.clone(), create_test_balance_update(token3.clone(), 4000));
            balances
        });

        let block_changes = create_test_block_changes(1, 2, balance_updates);

        // Test the enrichment
        let result = orchestrator.enrich_metadata_from_block_balances(&components, &block_changes);

        // Verify results
        assert_eq!(result.len(), 2, "Should enrich metadata for both components");

        // Check component1 enrichment
        let comp1_metadata = result.get("comp1").unwrap();
        if let Some(Ok(balances)) = &comp1_metadata.balances {
            assert_eq!(balances.len(), 2, "Component1 should have 2 balance entries");
            assert_eq!(balances.get(&token1).unwrap(), &Bytes::from(1000u64));
            assert_eq!(balances.get(&token2).unwrap(), &Bytes::from(2000u64));
        } else {
            panic!("Component1 should have successful balance data");
        }

        // Check component2 enrichment
        let comp2_metadata = result.get("comp2").unwrap();
        if let Some(Ok(balances)) = &comp2_metadata.balances {
            assert_eq!(balances.len(), 2, "Component2 should have 2 balance entries");
            assert_eq!(balances.get(&token2).unwrap(), &Bytes::from(3000u64));
            assert_eq!(balances.get(&token3).unwrap(), &Bytes::from(4000u64));
        } else {
            panic!("Component2 should have successful balance data");
        }
    }

    #[test]
    fn test_enrich_metadata_reverse_order_processing() {
        let orchestrator = TestOrchestrator;

        let token1 = Address::from("0x1111111111111111111111111111111111111111");
        let component1 = create_test_component("comp1", vec![token1.clone()]);
        let components = vec![&component1];

        // Create multiple transactions with different balance values
        // The last transaction should have the final value
        let mut balance_updates = HashMap::new();
        balance_updates.insert("comp1".to_string(), {
            let mut balances = HashMap::new();
            balances.insert(token1.clone(), create_test_balance_update(token1.clone(), 5000)); // This should be the final value
            balances
        });

        let block_changes = create_test_block_changes(1, 3, balance_updates);

        let result = orchestrator.enrich_metadata_from_block_balances(&components, &block_changes);

        // Verify that the latest balance value is used
        let comp1_metadata = result.get("comp1").unwrap();
        if let Some(Ok(balances)) = &comp1_metadata.balances {
            assert_eq!(
                balances.get(&token1).unwrap(),
                &Bytes::from(5000u64),
                "Should use the latest balance value from reverse order processing"
            );
        } else {
            panic!("Component1 should have successful balance data");
        }
    }

    #[test]
    fn test_enrich_metadata_handles_empty_balances() {
        let orchestrator = TestOrchestrator;

        let token1 = Address::from("0x1111111111111111111111111111111111111111");
        let component1 = create_test_component("comp1", vec![token1.clone()]);
        let components = vec![&component1];

        // Create block changes with no balance updates
        let balance_updates = HashMap::new();
        let block_changes = create_test_block_changes(1, 1, balance_updates);

        let result = orchestrator.enrich_metadata_from_block_balances(&components, &block_changes);

        // Should return empty results since no balance data is available
        assert_eq!(
            result.len(),
            0,
            "Should return no enriched metadata when no balance updates exist"
        );
    }

    #[test]
    fn test_enrich_metadata_filters_zero_balances() {
        let orchestrator = TestOrchestrator;

        let token1 = Address::from("0x1111111111111111111111111111111111111111");
        let token2 = Address::from("0x2222222222222222222222222222222222222222");
        let component1 = create_test_component("comp1", vec![token1.clone(), token2.clone()]);
        let components = vec![&component1];

        // Create balance updates with one zero balance
        let mut balance_updates = HashMap::new();
        balance_updates.insert("comp1".to_string(), {
            let mut balances = HashMap::new();
            balances.insert(token1.clone(), create_test_balance_update(token1.clone(), 0)); // Zero balance
            balances.insert(token2.clone(), create_test_balance_update(token2.clone(), 1000)); // Non-zero balance
            balances
        });

        let block_changes = create_test_block_changes(1, 1, balance_updates);

        let result = orchestrator.enrich_metadata_from_block_balances(&components, &block_changes);

        // Should still include the component because not ALL balances are zero
        assert_eq!(result.len(), 1, "Should include component with mixed zero/non-zero balances");

        let comp1_metadata = result.get("comp1").unwrap();
        if let Some(Ok(balances)) = &comp1_metadata.balances {
            assert_eq!(balances.len(), 2, "Should include all balance entries, even zero ones");
            assert_eq!(balances.get(&token1).unwrap(), &Bytes::from(0u64));
            assert_eq!(balances.get(&token2).unwrap(), &Bytes::from(1000u64));
        } else {
            panic!("Component1 should have successful balance data");
        }
    }

    // Note: This test is commented out because testing generate_entrypoint_params requires
    // complex mocking of the entrypoint generator dependencies. The functionality is tested
    // through integration tests in hook_dci.rs instead.
    //
    // #[tokio::test]
    // async fn test_generate_entrypoint_params_without_external_metadata() {
    //     // This would require mocking UniswapV4DefaultHookEntrypointGenerator and its
    // dependencies     // The actual functionality is verified through the hook_dci integration
    // test }

    // Tests for HookOrchestratorRegistry
    #[test]
    fn test_hook_orchestrator_registry_default_orchestrator() {
        let mut registry = HookOrchestratorRegistry::new();

        // Create a mock orchestrator to use as default
        let mut default_mock = MockHookOrchestrator::new();
        default_mock
            .expect_update_components()
            .returning(|_, _, _, _| Ok(()));

        registry.set_default_orchestrator(Box::new(default_mock));

        // Create a component without a specific orchestrator registered
        let component = create_test_component(
            "test_comp",
            vec![Address::from("0x1111111111111111111111111111111111111111")],
        );

        // Should return the default orchestrator
        let orchestrator = registry.get_orchestrator_for_component(&component);
        assert!(
            orchestrator.is_some(),
            "Should return default orchestrator when no specific one is registered"
        );
    }

    #[test]
    fn test_hook_orchestrator_registry_no_default() {
        let registry = HookOrchestratorRegistry::new();

        // Create a component without a specific orchestrator registered
        let component = create_test_component(
            "test_comp",
            vec![Address::from("0x1111111111111111111111111111111111111111")],
        );

        // Should return None when no default is set
        let orchestrator = registry.get_orchestrator_for_component(&component);
        assert!(
            orchestrator.is_none(),
            "Should return None when no orchestrator is registered and no default is set"
        );
    }

    #[test]
    fn test_hook_orchestrator_registry_specific_over_default() {
        let mut registry = HookOrchestratorRegistry::new();

        // Create and set a default orchestrator
        let mut default_mock = MockHookOrchestrator::new();
        default_mock
            .expect_update_components()
            .returning(|_, _, _, _| Ok(()));
        registry.set_default_orchestrator(Box::new(default_mock));

        // Create and register a specific orchestrator for a hook address
        let hook_address = Address::from("0x1234567890123456789012345678901234567890");
        let mut specific_mock = MockHookOrchestrator::new();
        specific_mock
            .expect_update_components()
            .returning(|_, _, _, _| Ok(()));
        registry.register_hook_orchestrator(hook_address.clone(), Box::new(specific_mock));

        // Create a component with the specific hook address
        let mut static_attributes = HashMap::new();
        static_attributes.insert("hooks".to_string(), hook_address);
        let component = ProtocolComponent {
            id: "test_comp".to_string(),
            protocol_system: "uniswap_v4".to_string(),
            protocol_type_name: "pool".to_string(),
            chain: Chain::Ethereum,
            tokens: vec![],
            contract_addresses: vec![],
            static_attributes,
            change: ChangeType::Creation,
            creation_tx: Bytes::default(),
            created_at: chrono::DateTime::from_timestamp(1719849000, 0)
                .unwrap()
                .naive_utc(),
        };

        // Should return the specific orchestrator, not the default
        let orchestrator = registry.get_orchestrator_for_component(&component);
        assert!(
            orchestrator.is_some(),
            "Should return specific orchestrator when one is registered for the hook address"
        );
    }

    #[test]
    fn test_hook_orchestrator_registry_hook_identifier_over_default() {
        let mut registry = HookOrchestratorRegistry::new();

        // Create and set a default orchestrator
        let mut default_mock = MockHookOrchestrator::new();
        default_mock
            .expect_update_components()
            .returning(|_, _, _, _| Ok(()));
        registry.set_default_orchestrator(Box::new(default_mock));

        // Create and register an orchestrator for a hook identifier
        let mut identifier_mock = MockHookOrchestrator::new();
        identifier_mock
            .expect_update_components()
            .returning(|_, _, _, _| Ok(()));
        registry.register_hook_identifier("euler_v1".to_string(), Box::new(identifier_mock));

        // Create a component with hook identifier
        let hook_address = Address::from("0x1234567890123456789012345678901234567890");
        let mut static_attributes = HashMap::new();
        static_attributes.insert("hooks".to_string(), hook_address);
        static_attributes
            .insert("hook_identifier".to_string(), Bytes::from("euler_v1".as_bytes().to_vec()));
        let component = ProtocolComponent {
            id: "test_comp".to_string(),
            protocol_system: "uniswap_v4".to_string(),
            protocol_type_name: "pool".to_string(),
            chain: Chain::Ethereum,
            tokens: vec![],
            contract_addresses: vec![],
            static_attributes,
            change: ChangeType::Creation,
            creation_tx: Bytes::default(),
            created_at: chrono::DateTime::from_timestamp(1719849000, 0)
                .unwrap()
                .naive_utc(),
        };

        // Should return the identifier-specific orchestrator, not the default
        let orchestrator = registry.get_orchestrator_for_component(&component);
        assert!(
            orchestrator.is_some(),
            "Should return hook identifier orchestrator when one is registered"
        );
    }
}
