#![allow(dead_code)] // TODO: Remove this

use std::collections::{HashMap, HashSet};

#[cfg(test)]
use mockall::automock;
use thiserror::Error;
use tycho_common::{
    models::{
        blockchain::{Block, TracingParams},
        protocol::{ComponentBalance, ProtocolComponent, ProtocolComponentStateDelta},
        Address, EntryPointId, TxHash,
    },
    Bytes,
};

use crate::extractor::{
    dynamic_contract_indexer::{
        component_metadata::ComponentTracingMetadata,
        entrypoint_generator::{
            DefaultSwapAmountEstimator, EntrypointGenerationError, HookEntrypointConfig,
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
    router_address: Address,
    config: HookEntrypointConfig,
    entrypoint_generator: UniswapV4DefaultHookEntrypointGenerator<DefaultSwapAmountEstimator>,
}

impl DefaultUniswapV4HookOrchestrator {
    fn prepare_components(
        &self,
        block_changes: &mut BlockChanges,
        metadata: &HashMap<String, ComponentTracingMetadata>,
        entrypoint_params: HashMap<EntryPointId, Vec<(TxHash, TracingParams)>>,
    ) -> Result<(), HookOrchestratorError> {
        let tx_vec_idx_by_hash: HashMap<TxHash, usize> = block_changes
            .txs_with_update
            .iter()
            .enumerate()
            .map(|(idx, tx_delta)| (tx_delta.tx.hash.clone(), idx))
            .collect();

        for (component_id, metadata) in metadata {
            let tx_idx = tx_vec_idx_by_hash
                .get(&metadata.tx_hash)
                .expect("Tx hash should be present in the block changes");

            let tx_delta = &mut block_changes.txs_with_update[*tx_idx];

            if let Some(Ok(limit)) = &metadata.limits {
                if let Some(limit_entrypoint) = limit
                    .first()
                    .expect("Limit should be present")
                    .1
                     .2
                    .as_ref()
                {
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
                let component_balance = balances
                    .into_iter()
                    .map(|(token, balance)| {
                        let balance_float = bytes_to_f64(balance.as_ref()).ok_or_else(|| {
                            HookOrchestratorError::PrepareComponentsFailed(format!(
                                "Failed to convert balance to float: {balance}"
                            ))
                        })?;
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

        for (entrypoint_id, entrypoint_params) in entrypoint_params {
            for (tx_hash, entrypoint_params) in entrypoint_params {
                let tx_idx = tx_vec_idx_by_hash
                    .get(&tx_hash)
                    .expect("Tx hash should be present in the block changes");

                let tx_delta = &mut block_changes.txs_with_update[*tx_idx];

                tx_delta
                    .entrypoint_params
                    .insert(entrypoint_id.clone(), HashSet::from([(entrypoint_params, None)]));
            }
        }

        Ok(())
    }

    fn generate_entrypoint_params(
        &self,
        block: &Block,
        components: &[ProtocolComponent],
        metadata: &HashMap<String, ComponentTracingMetadata>,
    ) -> Result<HashMap<EntryPointId, Vec<(TxHash, TracingParams)>>, HookOrchestratorError> {
        let mut result = HashMap::new();
        for component in components {
            if let Some(metadata) = metadata.get(&component.id) {
                let data = HookEntrypointData {
                    component: component.clone(),
                    component_metadata: metadata.clone(),
                    hook_address: component
                        .static_attributes
                        .get("hook")
                        .expect(
                            "UniswapV4 component should have a hook address in the static attributes",
                        )
                        .clone(),
                };

                let context = HookTracerContext::new(block.clone());

                let eps = self
                    .entrypoint_generator
                    .generate_entrypoints(&data, &context)
                    .map_err(HookOrchestratorError::GenerateEntrypointParamsFailed)?;

                for ep in eps {
                    result
                        .entry(ep.entry_point.external_id)
                        .or_insert_with(Vec::new)
                        .push((metadata.tx_hash.clone(), ep.params));
                }
            }
        }

        Ok(result)
    }
}

impl HookOrchestrator for DefaultUniswapV4HookOrchestrator {
    fn update_components(
        &self,
        block_changes: &mut BlockChanges,
        components: &[ProtocolComponent],
        metadata: &HashMap<String, ComponentTracingMetadata>,
    ) -> Result<(), HookOrchestratorError> {
        let entrypoint_params =
            self.generate_entrypoint_params(&block_changes.block, components, metadata)?;
        self.prepare_components(block_changes, metadata, entrypoint_params)?;

        Ok(())
    }
}
