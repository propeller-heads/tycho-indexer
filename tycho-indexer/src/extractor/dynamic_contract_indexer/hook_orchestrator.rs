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
    Bytes,
};

use crate::extractor::{
    dynamic_contract_indexer::{
        component_metadata::ComponentTracingMetadata,
        entrypoint_generator::{
            DefaultSwapAmountEstimator, EntrypointGenerationError,
            HookEntrypointData, HookEntrypointGenerator, HookTracerContext,
            UniswapV4DefaultHookEntrypointGenerator,
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
pub trait HookOrchestrator: Send + Sync {
    /// Main Entrypoint for the orchestrator.
    ///
    /// This method is called for each block and is responsible for
    /// - Generating the Entrypoints with TracingParams
    /// - Updating the components with the collected metadata
    ///     - Inject Balances to the ProtocolComponents
    ///     - Inject the Limits to the ProtocolComponents (if they are RPC calls)
    ///     - Inject Entrypoints to the ProtocolComponents
    fn update_components(
        &self,
        block_changes: &mut BlockChanges,
        components: &[ProtocolComponent],
        metadata: &HashMap<String, ComponentTracingMetadata>,
    ) -> Result<(), HookOrchestratorError>;
}

pub struct HookOrchestratorRegistry {
    pub hooks: HashMap<Address, Box<dyn HookOrchestrator>>,
}

pub struct DefaultUniswapV4HookOrchestrator {
    entrypoint_generator: UniswapV4DefaultHookEntrypointGenerator<DefaultSwapAmountEstimator>,
}

impl DefaultUniswapV4HookOrchestrator {
    pub fn new(
        entrypoint_generator: UniswapV4DefaultHookEntrypointGenerator<DefaultSwapAmountEstimator>,
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
                if let Some(limit_entrypoint) = limit
                    .first()
                    .expect("Limit should be present")
                    .1
                     .2
                    .as_ref()
                {
                    debug!(
                        component_id = %component_id,
                        entrypoint_target = %limit_entrypoint.entry_point.target,
                        entrypoint_signature = %limit_entrypoint.entry_point.signature,
                        "Processing component limits"
                    );

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
                    tx_delta
                        .state_updates
                        .insert(component_id.clone(), pc_delta);

                    tx_delta.entrypoints.insert(
                        component_id.clone(),
                        HashSet::from([limit_entrypoint.entry_point.clone()]),
                    );
                    tx_delta.entrypoint_params.insert(
                        limit_entrypoint
                            .entry_point
                            .external_id
                            .clone(),
                        HashSet::from([(
                            limit_entrypoint.params.clone(),
                            Some(component_id.clone()),
                        )]),
                    );
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
                    .insert(entrypoint_with_params.entry_point.clone());
                
                // Add the tracing params to the transaction's entrypoint_params
                tx_delta
                    .entrypoint_params
                    .entry(entrypoint_with_params.entry_point.external_id.clone())
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

    #[instrument(skip(self, block, components, metadata), fields(
        block_number = block.number,
        component_count = components.len(),
        metadata_count = metadata.len()
    ))]
    fn generate_entrypoint_params(
        &self,
        block: &Block,
        components: &[ProtocolComponent],
        metadata: &HashMap<String, ComponentTracingMetadata>,
    ) -> Result<HashMap<ComponentId, Vec<(TxHash, EntryPointWithTracingParams)>>, HookOrchestratorError> {
        debug!("Generating entrypoint parameters");

        let mut result = HashMap::new();
        let mut total_entrypoints_generated = 0;
        let mut components_with_metadata = 0;

        for component in components {
            if let Some(metadata) = metadata.get(&component.id) {
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
                    component_metadata: metadata.clone(),
                    hook_address: hook_address.clone(),
                };

                let context = HookTracerContext::new(block.clone());

                let eps = self
                    .entrypoint_generator
                    .generate_entrypoints(&data, &context)
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
                    .map(|ep| (metadata.tx_hash.clone(), ep))
                    .collect::<Vec<_>>();
                
                result.insert(component.id.clone(), component_entrypoints);
            } else {
                warn!(
                    component_id = %component.id,
                    "Component has no metadata, skipping entrypoint generation"
                );
            }
        }

        info!(
            unique_entrypoints = result.len(),
            total_entrypoints_generated,
            components_with_metadata,
            "Completed entrypoint parameter generation"
        );

        Ok(result)
    }
}

impl HookOrchestrator for DefaultUniswapV4HookOrchestrator {
    #[instrument(skip(self, block_changes, components, metadata), fields(
        block_number = block_changes.block.number,
        component_count = components.len(),
        metadata_count = metadata.len(),
    ))]
    fn update_components(
        &self,
        block_changes: &mut BlockChanges,
        components: &[ProtocolComponent],
        metadata: &HashMap<String, ComponentTracingMetadata>,
    ) -> Result<(), HookOrchestratorError> {
        info!("Starting component update process");

        let component_entrypoints =
            self.generate_entrypoint_params(&block_changes.block, components, metadata)?;
        self.prepare_components(block_changes, metadata, component_entrypoints)?;

        info!("Component update process completed successfully");
        Ok(())
    }
}
