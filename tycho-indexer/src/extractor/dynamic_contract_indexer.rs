use std::collections::{hash_map::Entry, HashMap, HashSet};

use tracing::{debug, instrument, trace};
use tycho_common::{
    models::{
        blockchain::{
            EntryPoint, EntryPointWithTracingParams, TracedEntryPoint, TracingParams,
            TracingResult, TxWithChanges,
        },
        contract::AccountDelta,
        Address, Chain, ChangeType, ContractStoreDeltas, EntryPointId, StoreKey, TxHash,
    },
    storage::{EntryPointFilter, EntryPointGateway, StorageError},
    traits::{AccountExtractor, EntryPointTracer, StorageSnapshotRequest},
};

use super::{
    models::{BlockChanges, TxWithStorageChanges},
    ExtractionError,
};

/// A unique identifier for a storage location, consisting of an address and a storage key.
type StorageLocation = (Address, StoreKey);

/// The index of a transaction in the transaction vector
#[allow(dead_code)] // Clippy thinks this is dead code, but it's used below for clarity
type TxVecIndex = usize;

#[allow(unused)]
struct DynamicContractIndexer<AE, T, G>
where
    AE: AccountExtractor,
    T: EntryPointTracer,
    G: EntryPointGateway,
{
    chain: Chain,
    protocol: String,
    entrypoint_gw: G,
    storage_source: AE,
    tracer: T,
    cache: DCICache,
}

#[allow(unused)]
struct DCICache {
    ep_id_to_entrypoint: HashMap<EntryPointId, EntryPoint>,
    entrypoint_results: HashMap<(EntryPointId, TracingParams), TracingResult>,
    retriggers: HashMap<StorageLocation, HashSet<EntryPointWithTracingParams>>,
    tracked_contracts: HashMap<Address, Option<HashSet<StoreKey>>>,
}

impl DCICache {
    #[allow(unused)]
    fn new_empty() -> Self {
        Self {
            ep_id_to_entrypoint: HashMap::new(),
            entrypoint_results: HashMap::new(),
            retriggers: HashMap::new(),
            tracked_contracts: HashMap::new(),
        }
    }
}

impl<AE, T, G> DynamicContractIndexer<AE, T, G>
where
    AE: AccountExtractor,
    T: EntryPointTracer,
    G: EntryPointGateway,
{
    pub fn new(
        chain: Chain,
        protocol: String,
        entrypoint_gw: G,
        storage_source: AE,
        tracer: T,
    ) -> Self {
        Self {
            chain,
            protocol,
            entrypoint_gw,
            storage_source,
            tracer,
            cache: DCICache::new_empty(),
        }
    }

    /// Initialize the DynamicContractIndexer. Loads all the entrypoints and their respective
    /// trace results from the gateway.
    #[instrument(skip_all, fields(chain = % self.chain, protocol = % self.protocol))]
    pub async fn initialize(&mut self) -> Result<(), ExtractionError> {
        let entrypoint_filter = EntryPointFilter::new(self.protocol.clone());

        let entrypoints_with_params = self
            .entrypoint_gw
            .get_entry_points_tracing_params(entrypoint_filter, None)
            .await
            .map_err(ExtractionError::from)?
            .entity;

        let entrypoint_results: HashMap<EntryPointId, HashMap<TracingParams, TracingResult>> = self
            .entrypoint_gw
            .get_traced_entry_points(
                &entrypoints_with_params
                    .values()
                    .flat_map(|e| {
                        e.iter()
                            .map(|ep| ep.entry_point.external_id.clone())
                    })
                    .collect(),
            )
            .await
            .map_err(ExtractionError::from)?;

        self.cache.ep_id_to_entrypoint.extend(
            entrypoints_with_params
                .values()
                .flat_map(|e| {
                    e.iter()
                        .map(|ep| (ep.entry_point.external_id.clone(), ep.entry_point.clone()))
                }),
        );

        for (entrypoint_id, params_results_map) in entrypoint_results.into_iter() {
            for (param, result) in params_results_map.into_iter() {
                for location in result.retriggers.clone() {
                    let entrypoint_with_params = EntryPointWithTracingParams::new(
                        self.cache
                            .ep_id_to_entrypoint
                            .get(&entrypoint_id)
                            .ok_or(ExtractionError::Setup(format!(
                                "Got a tracing result for a unknown entrypoint: {entrypoint_id:?}"
                            )))?
                            .clone(),
                        param.clone(),
                    );

                    self.cache
                        .retriggers
                        .entry(location)
                        .or_default()
                        .insert(entrypoint_with_params);
                }

                for address in result.called_addresses.iter() {
                    self.cache
                        .tracked_contracts
                        .entry(address.clone())
                        .or_default(); //TODO: Add the tracked slots when tracer returns them
                }

                self.cache
                    .entrypoint_results
                    .insert((entrypoint_id.clone(), param), result);
            }
        }

        Ok(())
    }

    #[instrument(skip_all, fields(chain = % self.chain, protocol = % self.protocol, block_number = % block_changes.block.number))]
    pub(super) async fn process_block_update(
        &mut self,
        block_changes: &mut BlockChanges,
    ) -> Result<(), ExtractionError> {
        // Note: in the end we need to link DCI indexed accounts to a transaction, therefore we need
        // to keep track of the transaction index in the txs_with_update vector related to any
        // possible newly indexed accounts. This index will be represented by the TxVecIndex type.

        let mut new_entrypoint_params: HashMap<String, Vec<(TxVecIndex, TracingParams)>> =
            HashMap::new();
        for (tx_vec_idx, tx) in block_changes
            .txs_with_update
            .iter()
            .enumerate()
        {
            for (entrypoint_id, params) in tx.entrypoint_params.iter() {
                for (p, _) in params.iter() {
                    new_entrypoint_params
                        .entry(entrypoint_id.clone())
                        .or_default()
                        .push((tx_vec_idx, p.clone()));
                }
            }
        }

        // Select for analysis the newly detected EntryPointsWithData that haven't been analyzed
        // yet. This filter prevents us from re-analyzing entrypoints that have already been
        // analyzed, which can be a case if all the components have the same entrypoint.
        let mut entrypoints_to_analyze: HashMap<EntryPointWithTracingParams, TxVecIndex> =
            HashMap::new();
        for (entrypoint_id, tracing_params) in new_entrypoint_params.iter() {
            for (tx_vec_idx, param) in tracing_params.iter() {
                // Skip if we already have results for this entrypoint and param combination
                if self
                    .cache
                    .entrypoint_results
                    .contains_key(&(entrypoint_id.clone(), param.clone()))
                {
                    continue;
                }

                let entrypoint = self
                    .cache
                    .ep_id_to_entrypoint
                    .get(entrypoint_id)
                    .ok_or(ExtractionError::Storage(StorageError::NotFound(
                        "Entrypoint".to_string(),
                        entrypoint_id.to_string(),
                    )))?;

                let entrypoint_with_params =
                    EntryPointWithTracingParams::new(entrypoint.clone(), param.clone());

                entrypoints_to_analyze.insert(entrypoint_with_params, *tx_vec_idx);
            }
        }

        // Use block storage changes to detect retriggered entrypoints
        let retriggered_entrypoints: HashMap<EntryPointWithTracingParams, TxVecIndex> =
            self.detect_retriggers(&block_changes.block_storage_changes);

        // Update the entrypoint results with the retriggered entrypoints
        entrypoints_to_analyze.extend(retriggered_entrypoints);
        debug!("DCI: Will analyze {:?} entrypoints", entrypoints_to_analyze.len());
        trace!("DCI: Entrypoints to analyze: {:?}", entrypoints_to_analyze);

        let traced_entry_points = self
            .tracer
            .trace(
                block_changes.block.hash.clone(),
                entrypoints_to_analyze
                    .keys()
                    .map(Clone::clone)
                    .collect(),
            )
            .await
            .map_err(|e| ExtractionError::TracingError(format!("{e:?}")))?;

        let tx_to_traced_entry_point: HashMap<&TxVecIndex, &TracedEntryPoint> =
            entrypoints_to_analyze
                .values()
                .zip(traced_entry_points.iter())
                .collect();

        let mut account_to_tx_idx: HashMap<Address, &TxVecIndex> = HashMap::new();
        for (tx_vec_idx, traced_entry_point) in tx_to_traced_entry_point {
            for account in traced_entry_point
                .tracing_result
                .called_addresses
                .clone()
            {
                account_to_tx_idx
                    .entry(account)
                    .and_modify(|existing_idx| {
                        if tx_vec_idx < *existing_idx {
                            *existing_idx = tx_vec_idx;
                        }
                    })
                    .or_insert(tx_vec_idx);
            }
        }

        // Get from the storage source (Node) the code, balance and storage changes for the new
        // results
        let storage_request: Vec<StorageSnapshotRequest> = traced_entry_points
            .iter()
            .flat_map(|traced_entry_point| {
                traced_entry_point
                    .tracing_result
                    .called_addresses
                    .iter()
                    .map(|address| {
                        StorageSnapshotRequest {
                            address: address.clone(),
                            // TODO: Set the slots once it's available from the Tracer
                            slots: None,
                        }
                    })
            })
            .collect();

        let mut new_accounts = self
            .storage_source
            .get_accounts_at_block(&block_changes.block, &storage_request)
            .await
            .map_err(|e| ExtractionError::AccountExtractionError(format!("{e:?}")))?;

        // Update the cache with new entrypoints and tracing results
        self.update_cache(block_changes, &traced_entry_points);

        // Update the block changes
        for (account, tx_idx) in account_to_tx_idx.into_iter() {
            block_changes
                .txs_with_update
                .get_mut(*tx_idx)
                .expect("Transaction index should be valid in the txs_with_update vector")
                .account_deltas
                .entry(account.clone())
                .or_insert_with(|| new_accounts.remove(&account).unwrap());
        }

        let tracked_updates = self.extract_tracked_updates(block_changes);

        let mut tx_with_changes = block_changes
            .txs_with_update
            .iter_mut()
            .map(|t| (t.tx.hash.clone(), t))
            .collect::<HashMap<_, _>>();

        // Update the tx_with_changes with DCI updates and collect new transactions updates, then
        // add them to the block changes
        let mut new_transactions = Vec::new();
        for (_, tx) in tracked_updates {
            if let Some(existing_tx) = tx_with_changes.get_mut(&tx.tx.hash) {
                existing_tx.merge(tx).unwrap();
            } else {
                new_transactions.push(tx);
            }
        }

        block_changes
            .txs_with_update
            .extend(new_transactions);

        block_changes.trace_results = traced_entry_points;

        Ok(())
    }

    /// Scans the storage changes of the block and detects entrypoints that need to be re-traced
    /// due to detected storage changes.
    ///
    /// # Returns
    /// A map of entrypoints that need to be re-traced and the index of the transaction that first
    /// detected the retriggered entrypoint.
    fn detect_retriggers(
        &self,
        tx_with_changes: &[TxWithStorageChanges],
    ) -> HashMap<EntryPointWithTracingParams, TxVecIndex> {
        // Create a map of storage locations that have been updated in the block and the index of
        // the transaction that first detected the update.
        // Note: tracing results are block scoped, this means if the same storage location is
        // updated in different transactions, we will link the results of the retriggered
        // entrypoint with the first transaction that updated the storage location in the
        // block.
        let mut updated_storage: HashMap<StorageLocation, usize> = HashMap::new();
        for (tx_vec_idx, tx) in tx_with_changes.iter().enumerate() {
            for (account, contract_store) in tx.storage_changes.iter() {
                for key in contract_store.keys() {
                    updated_storage
                        .entry((account.clone(), key.clone()))
                        .or_insert(tx_vec_idx);
                }
            }
        }

        let mut retriggered_entrypoints: HashMap<EntryPointWithTracingParams, usize> =
            HashMap::new();

        for (location, tx_vec_idx) in updated_storage.iter() {
            if let Some(entrypoints) = self.cache.retriggers.get(location) {
                for entrypoint in entrypoints {
                    retriggered_entrypoints.insert(entrypoint.clone(), *tx_vec_idx);
                }
            }
        }

        retriggered_entrypoints
    }

    /// Update the DCI cache with the new entrypoints and tracing results
    fn update_cache(
        &mut self,
        block_changes: &BlockChanges,
        new_tracing_results: &[TracedEntryPoint],
    ) {
        // Update entrypoint cache from block changes
        for tx in block_changes.txs_with_update.iter() {
            for entrypoint in tx.entrypoints.values().flatten() {
                self.cache
                    .ep_id_to_entrypoint
                    .insert(entrypoint.external_id.clone(), entrypoint.clone());
            }
        }

        // Update the cache with the traced entrypoints
        for traced_entry_point in new_tracing_results.iter() {
            for location in traced_entry_point
                .tracing_result
                .retriggers
                .iter()
            {
                self.cache
                    .retriggers
                    .entry(location.clone())
                    .or_default()
                    .insert(
                        traced_entry_point
                            .entry_point_with_params
                            .clone(),
                    );
            }

            for address in traced_entry_point
                .tracing_result
                .called_addresses
                .iter()
            {
                self.cache
                    .tracked_contracts
                    .entry(address.clone())
                    .or_default(); //TODO: Add the tracked slots when tracer returns them
            }

            self.cache.entrypoint_results.insert(
                (
                    traced_entry_point
                        .entry_point_with_params
                        .entry_point
                        .external_id
                        .clone(),
                    traced_entry_point
                        .entry_point_with_params
                        .params
                        .clone(),
                ),
                traced_entry_point
                    .tracing_result
                    .clone(),
            );
        }
    }

    fn extract_tracked_updates(
        &self,
        block_changes: &BlockChanges,
    ) -> HashMap<TxHash, TxWithChanges> {
        let mut tracked_updates: HashMap<TxHash, TxWithChanges> = HashMap::new();

        for tx in block_changes
            .block_storage_changes
            .iter()
        {
            for (account, contract_store) in tx.storage_changes.iter() {
                // Early skip if the contract is not tracked
                if !self
                    .cache
                    .tracked_contracts
                    .contains_key(account)
                {
                    continue;
                }

                let mut slot_updates = contract_store
                    .iter()
                    .map(|(slot, value)| {
                        if value.is_zero() {
                            (slot.clone(), None)
                        } else {
                            (slot.clone(), Some(value.clone()))
                        }
                    })
                    .collect::<ContractStoreDeltas>();

                if let Some(tracked_keys) = self
                    .cache
                    .tracked_contracts
                    .get(account)
                    .unwrap()
                {
                    slot_updates.retain(|slot, _| tracked_keys.contains(slot));
                }

                let account_delta = HashMap::from([(
                    account.clone(),
                    AccountDelta::new(
                        self.chain,
                        account.clone(),
                        slot_updates,
                        None,
                        None,
                        ChangeType::Update,
                    ),
                )]);

                let tx_with_changes = TxWithChanges::new(
                    tx.tx.clone(),
                    Default::default(),
                    account_delta,
                    Default::default(),
                    Default::default(),
                    Default::default(),
                    Default::default(),
                    Default::default(),
                );

                match tracked_updates.entry(tx.tx.hash.clone()) {
                    Entry::Occupied(mut entry) => {
                        entry
                            .get_mut()
                            .merge(tx_with_changes)
                            .unwrap();
                    }
                    Entry::Vacant(entry) => {
                        entry.insert(tx_with_changes);
                    }
                }
            }
        }

        tracked_updates
    }

    // TODO: Handle reverts, need to cleanup reverted internal state
    #[allow(unused)]
    pub(super) fn process_revert(&mut self, target_block: u64) -> Result<(), ExtractionError> {
        todo!()
    }
}
