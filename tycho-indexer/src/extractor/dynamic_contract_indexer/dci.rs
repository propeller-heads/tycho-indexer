use std::{
    collections::{hash_map::Entry, HashMap, HashSet},
    str::FromStr,
    sync::LazyLock,
};

use async_trait::async_trait;
use tracing::{debug, info, instrument, span, trace, warn, Instrument, Level};
use tycho_common::{
    models::{
        blockchain::{
            Block, EntryPoint, EntryPointWithTracingParams, TracedEntryPoint, TracingParams,
            TracingResult, Transaction, TxWithChanges,
        },
        contract::AccountDelta,
        protocol::QualityRange,
        Address, BlockHash, Chain, ChangeType, ContractStoreDeltas, EntryPointId, StoreKey, TxHash,
    },
    storage::{EntryPointFilter, EntryPointGateway, ProtocolGateway, StorageError},
    traits::{AccountExtractor, EntryPointTracer, StorageSnapshotRequest},
};

use super::cache::DCICache;
use crate::extractor::{
    models::{BlockChanges, TxWithStorageChanges},
    ExtractionError, ExtractorExtension,
};

pub(crate) struct DynamicContractIndexer<AE, T, G>
where
    AE: AccountExtractor + Send + Sync,
    T: EntryPointTracer + Send + Sync,
    G: EntryPointGateway + ProtocolGateway + Send + Sync,
{
    chain: Chain,
    protocol: String,
    entrypoint_gw: G,
    storage_source: AE,
    tracer: T,
    cache: DCICache,
}

static MANUAL_BLACKLIST: LazyLock<Vec<Address>> = LazyLock::new(|| {
    vec![
        // UniswapV4 Pool Manager - cannot be fully tracked
        Address::from_str("0x000000000004444c5dc75cB358380D2e3dE08A90").unwrap(),
        // UniswapV2 Permit2
        Address::from_str("0x000000000022D473030F116dDEE9F6B43aC78BA3").unwrap(),
    ]
});

#[async_trait]
impl<AE, T, G> ExtractorExtension for DynamicContractIndexer<AE, T, G>
where
    AE: AccountExtractor + Send + Sync,
    T: EntryPointTracer + Send + Sync,
    G: EntryPointGateway + ProtocolGateway + Send + Sync,
{
    #[instrument(skip(self, block_changes), fields(
        chain = % self.chain,
        protocol = % self.protocol,
        block_number = % block_changes.block.number,
        tx_count = block_changes.txs_with_update.len()
    ))]
    async fn process_block_update(
        &mut self,
        block_changes: &mut BlockChanges,
    ) -> Result<(), ExtractionError> {
        self.cache
            .try_insert_block_layer(&block_changes.block)?;

        // Process new tokens from BlockChanges
        for (address, _token) in block_changes.new_tokens.iter() {
            // Add new tokens to the ERC-20 cache
            self.cache
                .erc20_addresses
                .pending_entry(&block_changes.block, address)?
                .or_insert(true);

            debug!("Added new ERC-20 token to skip list: {}", address);
        }

        let new_entrypoints: HashMap<EntryPointId, EntryPoint> = block_changes
            .txs_with_update
            .iter()
            .flat_map(|tx| {
                tx.entrypoints
                    .values()
                    .flatten()
                    .map(|ep| (ep.external_id.clone(), ep.clone()))
            })
            .collect::<HashMap<_, _>>();

        // Note: in the end we need to link DCI indexed accounts to a transaction, therefore we need
        // to keep track of the transaction related to any possible updates.

        // Get the new tracing params from the block changes
        let mut new_entrypoint_params: HashMap<EntryPointId, Vec<(Transaction, TracingParams)>> =
            HashMap::new();
        for tx in block_changes.txs_with_update.iter() {
            for (entrypoint_id, params) in tx.entrypoint_params.iter() {
                for (p, _) in params.iter() {
                    new_entrypoint_params
                        .entry(entrypoint_id.clone())
                        .or_default()
                        .push((tx.tx.clone(), p.clone()));
                }
            }
        }

        if !new_entrypoints.is_empty() {
            tracing::debug!(entrypoints = ?new_entrypoints, "DCI: Entrypoints");
        }

        if !new_entrypoint_params.is_empty() {
            tracing::debug!(entrypoints_params = ?new_entrypoint_params, "DCI: Entrypoints params");
        }

        // Select for analysis the newly detected EntryPointsWithData that haven't been analyzed
        // yet. This filter prevents us from re-analyzing entrypoints that have already been
        // analyzed, which can be a case if all the components have the same entrypoint. This is
        // for performance reasons, we don't want to re-analyze the same entrypoint many times.
        let mut entrypoints_to_analyze: HashMap<EntryPointWithTracingParams, &Transaction> =
            HashMap::new();
        for (entrypoint_id, tracing_params) in new_entrypoint_params.iter() {
            for (tx, param) in tracing_params.iter() {
                // Skip if we already have a trace for this entrypoint + params pair.
                if self
                    .cache
                    .entrypoint_results
                    .contains_key(&(entrypoint_id.clone(), param.clone()))
                {
                    continue;
                }

                let entrypoint = new_entrypoints
                    .get(entrypoint_id)
                    .or_else(|| {
                        self.cache
                            .ep_id_to_entrypoint
                            .get(entrypoint_id)
                    })
                    .ok_or_else(|| {
                        ExtractionError::Storage(StorageError::NotFound(
                            "Entrypoint".to_string(),
                            entrypoint_id.to_string(),
                        ))
                    })?;

                let entrypoint_with_params =
                    EntryPointWithTracingParams::new(entrypoint.clone(), param.clone());

                // If the same params appear twice in the block, we link them to the first
                // transaction.
                entrypoints_to_analyze
                    .entry(entrypoint_with_params)
                    .and_modify(|entry_tx| {
                        if entry_tx.index > tx.index {
                            *entry_tx = tx;
                        }
                    })
                    .or_insert(tx);
            }
        }

        // Use block storage changes to detect retriggered entrypoints
        let retriggered_entrypoints: HashMap<EntryPointWithTracingParams, &Transaction> =
            self.detect_retriggers(&block_changes.block_storage_changes);

        // Update the entrypoint results with the retriggered entrypoints
        entrypoints_to_analyze.extend(retriggered_entrypoints);

        if !entrypoints_to_analyze.is_empty() {
            debug!("DCI: Will analyze {:?} entrypoints", entrypoints_to_analyze.len());
            trace!("DCI: Entrypoints to analyze: {:?}", entrypoints_to_analyze);
            tracing::debug!(entrypoints_to_analyze = ?entrypoints_to_analyze, "DCI: Entrypoints to analyze");

            let traced_entry_points = self
                .tracer
                .trace(
                    block_changes.block.hash.clone(),
                    entrypoints_to_analyze
                        .keys()
                        .cloned()
                        .collect(),
                )
                .instrument(span!(
                    Level::INFO,
                    "dci_rpc_tracing",
                    entrypoint_count = entrypoints_to_analyze.len(),
                    block_hash = %block_changes.block.hash
                ))
                .await
                .map_err(|e| ExtractionError::TracingError(format!("{e:?}")))?;

            tracing::debug!(traced_entry_points = ?traced_entry_points, "DCI: Traced entrypoints");

            let mut tx_to_traced_entry_point: HashMap<&Transaction, Vec<&TracedEntryPoint>> =
                HashMap::new();
            for traced_entry_point in traced_entry_points.iter() {
                let tx = entrypoints_to_analyze
                    .get(&traced_entry_point.entry_point_with_params)
                    .ok_or_else(|| {
                        ExtractionError::Unknown(format!(
                            "Traced entrypoint {traced_entry_point:?} not found in the entrypoints_to_analyze map. \
                            Every traced entrypoint should be in the entrypoints_to_analyze map"
                        ))
                    })?;
                tx_to_traced_entry_point
                    .entry(tx)
                    .or_default()
                    .push(traced_entry_point);
            }

            let mut new_account_addr_to_slots: HashMap<Address, HashSet<StoreKey>> = HashMap::new();
            let mut new_account_addr_to_tx: HashMap<Address, &Transaction> = HashMap::new();

            for (tx, traced_entry_points) in tx_to_traced_entry_point {
                for traced_entry_point in traced_entry_points.iter() {
                    for (account, slots) in traced_entry_point
                        .tracing_result
                        .accessed_slots
                        .iter()
                    {
                        // Update slots for all accounts
                        new_account_addr_to_slots
                            .entry(account.clone())
                            .or_default()
                            .extend(slots.iter().cloned());

                        // Update transaction mapping only for untracked accounts
                        if !self
                            .cache
                            .tracked_contracts
                            .contains_key(account)
                        {
                            // Keep track of the first transaction that pushed the entrypoint that
                            // calls this account.
                            new_account_addr_to_tx
                                .entry(account.clone())
                                .and_modify(|existing_tx| {
                                    if existing_tx.index > tx.index {
                                        *existing_tx = tx;
                                    }
                                })
                                .or_insert(tx);
                        }
                    }
                }
            }

            // Get the code, balance and storage changes for the new traced entrypoints.
            // This can contain duplicates, but the AccountExtractor implementation should ignore
            // them.
            let storage_request: Vec<StorageSnapshotRequest> = new_account_addr_to_tx
                .keys()
                .map(|address| {
                    if !self.should_skip_full_indexing(address) {
                        // Process all slots for non-token or non-blacklisted contracts
                        tracing::trace!("Skipping full storage indexing for address: {}", address);
                        Ok(StorageSnapshotRequest { address: address.clone(), slots: None })
                    } else {
                        // Skip full storage indexing for tokens and blacklisted addresses
                        let slots = new_account_addr_to_slots
                            .get(address)
                            .cloned()
                            .ok_or_else(|| {
                                ExtractionError::Unknown(format!(
                                    "Account {address} not found in the address to slots map"
                                ))
                            })?
                            .into_iter()
                            .collect();

                        Ok(StorageSnapshotRequest { address: address.clone(), slots: Some(slots) })
                    }
                })
                .collect::<Result<Vec<_>, ExtractionError>>()?;

            debug!(storage_request = ?storage_request, "DCI: Storage request");

            let mut new_accounts = self
                .storage_source
                .get_accounts_at_block(&block_changes.block, &storage_request)
                .instrument(span!(
                    Level::INFO,
                    "dci_account_extraction",
                    account_count = storage_request.len(),
                    block_number = block_changes.block.number
                ))
                .await
                .map_err(|e| ExtractionError::AccountExtractionError(format!("{e:?}")))?;

            // Update the block changes
            for (account, tx) in new_account_addr_to_tx.into_iter() {
                let account_delta = new_accounts
                    .remove(&account)
                    .ok_or_else(|| {
                        ExtractionError::Unknown(format!(
                            "Account {account} not found in the result. All accounts in request should have a result"
                        ))
                    })?;

                match block_changes
                    .txs_with_update
                    .iter_mut()
                    .find(|tx_with_changes| tx_with_changes.tx.hash == tx.hash)
                {
                    Some(tx_with_changes) => {
                        match tx_with_changes
                            .account_deltas
                            .entry(account.clone())
                        {
                            Entry::Occupied(mut entry) => {
                                entry.get_mut().merge(account_delta)?;
                            }
                            Entry::Vacant(entry) => {
                                entry.insert(account_delta);
                            }
                        }
                    }
                    None => {
                        let tx_with_changes = TxWithChanges {
                            tx: tx.clone(),
                            account_deltas: HashMap::from([(account.clone(), account_delta)]),
                            ..Default::default()
                        };
                        block_changes
                            .txs_with_update
                            .push(tx_with_changes);
                    }
                }
            }

            // Update the cache with new traced entrypoints
            let _span = span!(
                Level::INFO,
                "dci_cache_update",
                traced_entrypoints = traced_entry_points.len(),
                block_number = block_changes.block.number
            )
            .entered();
            self.update_cache(&block_changes.block, &traced_entry_points)?;
            drop(_span);

            // Update the block changes with the traced entrypoints
            block_changes.trace_results = traced_entry_points;
        }

        // Update the entrypoint cache from the block changes
        // Perf: when syncing we can completely bypass the reorgs handling logic and push directly
        // to the permanent cache
        self.cache
            .ep_id_to_entrypoint
            .extend_pending(
                block_changes.block.clone(),
                new_entrypoints
                    .into_values()
                    .map(|ep| (ep.external_id.clone(), ep)),
            )?;

        let _span = span!(
            Level::INFO,
            "dci_extract_tracked_updates",
            block_storage_changes = block_changes
                .block_storage_changes
                .len()
        )
        .entered();
        let tracked_updates = self.extract_tracked_updates(block_changes)?;
        drop(_span);

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
                existing_tx.merge(tx)?;
            } else {
                new_transactions.push(tx);
            }
        }

        block_changes
            .txs_with_update
            .extend(new_transactions);

        block_changes
            .txs_with_update
            .sort_by_key(|tx| tx.tx.index);

        // Handle finality for the cache
        self.cache
            .handle_finality(block_changes.finalized_block_height)?;

        Ok(())
    }

    async fn process_revert(&mut self, target_block: &BlockHash) -> Result<(), ExtractionError> {
        self.cache.revert_to(target_block)?;
        Ok(())
    }
}

impl<AE, T, G> DynamicContractIndexer<AE, T, G>
where
    AE: AccountExtractor + Send + Sync,
    T: EntryPointTracer + Send + Sync,
    G: EntryPointGateway + ProtocolGateway + Send + Sync,
{
    pub fn new(
        chain: Chain,
        protocol: String,
        entrypoint_gw: G,
        storage_source: AE,
        tracer: T,
    ) -> Self {
        Self { chain, protocol, entrypoint_gw, storage_source, tracer, cache: DCICache::new() }
    }

    /// Initialize the DynamicContractIndexer. Loads all the entrypoints and their respective
    /// trace results from the gateway.
    #[instrument(skip_all, fields(chain = % self.chain, protocol = % self.protocol))]
    pub async fn initialize(&mut self) -> Result<(), ExtractionError> {
        let entrypoint_filter = EntryPointFilter::new(self.protocol.clone());

        // We need to call the gateway twice, once to get the entrypoints and their tracing params,
        // and once to get the tracing results.
        // Perf: There is room for optimization here if we make a single custom function on the
        // gateway that returns both.
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

        self.cache
            .ep_id_to_entrypoint
            .extend_permanent(
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
                                "Got a tracing result for a unknown entrypoint: {entrypoint_id}"
                            )))?
                            .clone(),
                        param.clone(),
                    );

                    self.cache
                        .retriggers
                        .permanent_entry(&location)
                        .or_default()
                        .insert(entrypoint_with_params);
                }

                for (address, slots) in result.accessed_slots.iter() {
                    let slots_to_insert =
                        if slots.is_empty() { None } else { Some(slots.iter().cloned().collect()) };

                    self.cache
                        .tracked_contracts
                        .permanent_entry(address)
                        .and_modify(|existing_slots| {
                            if let Some(existing) = existing_slots {
                                existing.extend(slots.iter().cloned());
                            } else {
                                *existing_slots = slots_to_insert.clone();
                            }
                        })
                        .or_insert(slots_to_insert);
                }

                self.cache
                    .entrypoint_results
                    .insert_permanent((entrypoint_id.clone(), param), result);
            }
        }

        // Load manual blacklist into cache
        for address in MANUAL_BLACKLIST.iter() {
            self.cache
                .blacklisted_addresses
                .insert_permanent(address.clone(), true);
        }

        // Load known tokens from database
        let quality_range = QualityRange::min_only(0);
        match self
            .entrypoint_gw
            .get_tokens(self.chain, None, quality_range, None, None)
            .await
        {
            Ok(tokens_result) => {
                let token_count = tokens_result.entity.len();
                for token in tokens_result.entity {
                    self.cache
                        .erc20_addresses
                        .insert_permanent(token.address, true);
                }
                info!("Loaded {} known tokens from database", token_count);
            }
            Err(e) => {
                warn!("Failed to load tokens from database: {:?}", e);
                // Continue initialization even if token loading fails
            }
        }

        Ok(())
    }

    /// Check if an address should skip full storage indexing
    fn should_skip_full_indexing(&self, address: &Address) -> bool {
        // Check if it's a known ERC-20 token
        if let Some(is_token) = self.cache.erc20_addresses.get(address) {
            if *is_token {
                return true;
            }
        }

        // Check if it's manually blacklisted
        if let Some(is_blacklisted) = self
            .cache
            .blacklisted_addresses
            .get(address)
        {
            if *is_blacklisted {
                return true;
            }
        }

        false
    }

    /// Scans the storage changes of the block and detects entrypoints that need to be re-traced
    /// due to detected storage changes.
    ///
    /// # Returns
    /// A map of entrypoints that need to be re-traced and the transaction that first detected the
    /// retriggered entrypoint.
    #[instrument(skip(self, tx_with_changes), fields(
        protocol = % self.protocol,
        storage_changes_count = tx_with_changes.len()
    ))]
    fn detect_retriggers<'a>(
        &self,
        tx_with_changes: &'a [TxWithStorageChanges],
    ) -> HashMap<EntryPointWithTracingParams, &'a Transaction> {
        let _span = span!(Level::INFO, "dci_retrigger_detection", tx_count = tx_with_changes.len())
            .entered();

        // Create a map of storage locations that have been updated in the block and the transaction
        // that last detected the update.
        // Note: tracing results are block scoped, this means if the same storage location is
        // updated in different transactions, we will link the results of the retriggered
        // entrypoint with the last transaction that updated the storage location in the
        // block.

        let mut retriggered_entrypoints: HashMap<EntryPointWithTracingParams, &Transaction> =
            HashMap::new();
        let mut storage_locations_scanned = 0u64;

        for tx_with_changes in tx_with_changes.iter() {
            for (account, contract_store) in tx_with_changes.storage_changes.iter() {
                for key in contract_store.keys() {
                    storage_locations_scanned += 1;
                    let location = (account.clone(), key.clone());
                    // Check if this storage location triggers any entrypoints
                    if let Some(entrypoints) = self.cache.retriggers.get(&location) {
                        for entrypoint in entrypoints {
                            // Only insert if we haven't seen this entrypoint before or if this tx
                            // is later
                            retriggered_entrypoints
                                .entry(entrypoint.clone())
                                .and_modify(|entry_tx| {
                                    if entry_tx.index > tx_with_changes.tx.index {
                                        *entry_tx = &tx_with_changes.tx;
                                    }
                                })
                                .or_insert(&tx_with_changes.tx);
                        }
                    }
                }
            }
        }

        span!(Level::INFO, "retrigger_scan_complete")
            .in_scope(|| {
                tracing::info!(
                    retriggered_count = retriggered_entrypoints.len(),
                    storage_locations_scanned = storage_locations_scanned,
                    "DCI: Retrigger detection completed"
                );
            });

        if !retriggered_entrypoints.is_empty() {
            let retrigger_log: Vec<String> = retriggered_entrypoints
                .keys()
                .map(|e| e.entry_point.external_id.clone())
                .collect();
            tracing::info!("DCI: Retriggered entrypoints: {:?}", retrigger_log);
        }

        retriggered_entrypoints
    }

    /// Update the DCI cache with the new entrypoints and tracing results
    fn update_cache(
        &mut self,
        block: &Block,
        new_tracing_results: &[TracedEntryPoint],
    ) -> Result<(), ExtractionError> {
        // Update the cache with the traced entrypoints
        // Perf: when syncing we can completely bypass the reorgs handling logic and push directly
        // to the permanent cache
        for traced_entry_point in new_tracing_results.iter() {
            for location in traced_entry_point
                .tracing_result
                .retriggers
                .iter()
            {
                self.cache
                    .retriggers
                    .pending_entry(block, location)?
                    .or_default()
                    .insert(
                        traced_entry_point
                            .entry_point_with_params
                            .clone(),
                    );
            }

            for (address, slots) in traced_entry_point
                .tracing_result
                .accessed_slots
                .iter()
            {
                let slots_to_insert =
                    if slots.is_empty() { None } else { Some(slots.iter().cloned().collect()) };

                self.cache
                    .tracked_contracts
                    .pending_entry(block, address)?
                    .and_modify(|existing_slots| {
                        if let Some(existing) = existing_slots {
                            existing.extend(slots.iter().cloned());
                        } else {
                            *existing_slots = slots_to_insert.clone();
                        }
                    })
                    .or_insert(slots_to_insert);
            }

            self.cache
                .entrypoint_results
                .insert_pending(
                    block.clone(),
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
                )?;
        }

        Ok(())
    }

    /// Scans the block storage changes and extracts the updates for the tracked contracts.
    ///
    /// # Returns
    /// A map of tx_hash to tx_with_changes, where the tx_with_changes contains the account deltas
    /// for the tracked contracts.
    ///
    /// Note: the tx_with_changes are only contain the account deltas for the tracked contracts;
    /// they need to be merged with the `txs_with_update` vector from the block changes.
    fn extract_tracked_updates(
        &self,
        block_changes: &BlockChanges,
    ) -> Result<HashMap<TxHash, TxWithChanges>, ExtractionError> {
        let mut tracked_updates: HashMap<TxHash, TxWithChanges> = HashMap::new();

        for tx in block_changes
            .block_storage_changes
            .iter()
        {
            for (account, contract_store) in tx.storage_changes.iter() {
                let tracked_keys = match self
                    .cache
                    .tracked_contracts
                    .get(account)
                {
                    None => continue, // Early skip if the contract is not tracked
                    Some(keys) => keys,
                };

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

                // Only filter slots if skipping full indexing
                if self.should_skip_full_indexing(account) {
                    if let Some(tracked_keys) = tracked_keys {
                        slot_updates.retain(|slot, _| tracked_keys.contains(slot));
                    }
                }

                if !slot_updates.is_empty() {
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

                    let tx_with_changes = TxWithChanges {
                        tx: tx.tx.clone(),
                        account_deltas: account_delta,
                        ..Default::default()
                    };

                    match tracked_updates.entry(tx.tx.hash.clone()) {
                        Entry::Occupied(mut entry) => {
                            entry.get_mut().merge(tx_with_changes)?;
                        }
                        Entry::Vacant(entry) => {
                            entry.insert(tx_with_changes);
                        }
                    }
                }
            }
        }

        if !tracked_updates.is_empty() {
            tracing::trace!("DCI: Tracked updates: {:?}", tracked_updates);
        }

        Ok(tracked_updates)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};

    use mockall::predicate::{self, *};
    use tycho_common::{
        models::{
            blockchain::{
                EntryPoint, EntryPointWithTracingParams, RPCTracerParams, TracingParams,
                Transaction, TxWithChanges,
            },
            contract::AccountDelta,
            Chain, ChangeType, EntryPointId,
        },
        storage::WithTotal,
        traits::{MockAccountExtractor, MockEntryPointTracer},
        Bytes,
    };

    use super::*;
    use crate::{
        extractor::models::BlockChanges,
        testing::{self, MockGateway},
    };

    fn get_transaction(version: u8) -> Transaction {
        Transaction::new(
            Bytes::from(version).lpad(32, 0),
            Bytes::from(version).lpad(32, 0),
            Bytes::from(version).lpad(20, 0),
            Some(Bytes::from(version).lpad(20, 0)),
            version as u64,
        )
    }

    fn get_block_changes(version: u8) -> BlockChanges {
        match version {
            // A classic block with no DCI related changes, shouldn't be affected by DCI at all
            1 => {
                let tx = get_transaction(1);
                BlockChanges::new(
                    "test".to_string(),
                    Chain::Ethereum,
                    testing::block(1),
                    1,
                    false,
                    vec![TxWithChanges { tx, ..Default::default() }],
                    Vec::new(),
                )
            }
            // A block containing a new entrypoint to be traced, should be used by DCI to trace the
            // entrypoint, update the cache and add the related changes to the BlockChanges
            2 => {
                let tx = get_transaction(2);

                BlockChanges::new(
                    "test".to_string(),
                    Chain::Ethereum,
                    testing::block(2),
                    2,
                    false,
                    vec![TxWithChanges {
                        tx,
                        entrypoints: HashMap::from([(
                            "component_1".to_string(),
                            HashSet::from([get_entrypoint(9)]),
                        )]),
                        entrypoint_params: HashMap::from([(
                            "entrypoint_9".to_string(),
                            HashSet::from([(get_tracing_params(9), None)]),
                        )]),
                        ..Default::default()
                    }],
                    Vec::new(),
                )
            }
            // A block containing no new entrypoints, but an update to a tracked contract
            3 => {
                let tx = get_transaction(1);

                BlockChanges::new(
                    "test".to_string(),
                    Chain::Ethereum,
                    testing::block(3),
                    3,
                    false,
                    vec![],
                    vec![TxWithStorageChanges {
                        tx,
                        storage_changes: HashMap::from([
                            (
                                Bytes::from("0x02"),
                                HashMap::from([
                                    (Bytes::from("0x01"), Bytes::from("0x01")),
                                    (Bytes::from("0x22"), Bytes::from("0x22")),
                                ]),
                            ),
                            (
                                Bytes::from("0x22"),
                                HashMap::from([(Bytes::from("0x22"), Bytes::from("0x01"))]),
                            ),
                            // These should be ignored because they are not tracked
                            (
                                Bytes::from("0x9999"),
                                HashMap::from([(Bytes::from("0x01"), Bytes::from("0x01"))]),
                            ),
                        ]),
                    }],
                )
            }
            // A block containing an update for a retrigger
            4 => {
                let tx = get_transaction(1);

                BlockChanges::new(
                    "test".to_string(),
                    Chain::Ethereum,
                    testing::block(4),
                    4,
                    false,
                    vec![],
                    vec![TxWithStorageChanges {
                        tx,
                        storage_changes: HashMap::from([
                            // This should trigger the retrigger
                            (
                                Bytes::from("0x01"),
                                HashMap::from([(Bytes::from("0x01"), Bytes::from("0xabcd"))]),
                            ),
                        ]),
                    }],
                )
            }
            _ => panic!("block entity version not implemented"),
        }
    }

    fn get_entrypoint(version: u8) -> EntryPoint {
        EntryPoint::new(
            format!("entrypoint_{version}"),
            Bytes::from(version),
            format!("test_entrypoint_{version}"),
        )
    }

    fn get_tracing_params(version: u8) -> TracingParams {
        TracingParams::RPCTracer(RPCTracerParams::new(None, Bytes::from(version)))
    }

    fn get_tracing_result(version: u8) -> TracingResult {
        TracingResult::new(
            HashSet::from([(Bytes::from(version), Bytes::from(version))]),
            HashMap::from([
                (Bytes::from(version), HashSet::from([Bytes::from(version + version * 16)])),
                (
                    Bytes::from(version + version * 16),
                    HashSet::from([Bytes::from(version + version * 16)]),
                ),
            ]),
        )
    }

    fn get_mock_gateway() -> MockGateway {
        let mut gateway = MockGateway::new();
        let entrypoints_map = HashMap::from([
            (
                "entrypoint_1".to_string(),
                HashSet::from([
                    EntryPointWithTracingParams::new(get_entrypoint(1), get_tracing_params(1)),
                    EntryPointWithTracingParams::new(get_entrypoint(1), get_tracing_params(2)),
                ]),
            ),
            (
                "entrypoint_2".to_string(),
                HashSet::from([EntryPointWithTracingParams::new(
                    get_entrypoint(2),
                    get_tracing_params(3),
                )]),
            ),
            (
                "entrypoint_4".to_string(),
                HashSet::from([EntryPointWithTracingParams::new(
                    get_entrypoint(4),
                    get_tracing_params(1),
                )]),
            ),
        ]);

        gateway
            .expect_get_entry_points_tracing_params()
            .return_once(move |_, _| {
                Box::pin(async move { Ok(WithTotal { entity: entrypoints_map, total: None }) })
            });

        let tracing_results: HashMap<EntryPointId, HashMap<TracingParams, TracingResult>> =
            HashMap::from([
                (
                    "entrypoint_1".to_string(),
                    HashMap::from([(get_tracing_params(1), get_tracing_result(1))]),
                ),
                (
                    "entrypoint_2".to_string(),
                    HashMap::from([(get_tracing_params(3), get_tracing_result(2))]),
                ),
                (
                    "entrypoint_4".to_string(),
                    HashMap::from([(get_tracing_params(1), get_tracing_result(1))]),
                ),
            ]);

        gateway
            .expect_get_traced_entry_points()
            .return_once(move |_| Box::pin(async move { Ok(tracing_results) }));

        // Mock get_tokens to return empty result
        gateway
            .expect_get_tokens()
            .return_once(move |_, _, _, _, _| {
                Box::pin(async move {
                    Ok(tycho_common::storage::WithTotal { entity: Vec::new(), total: Some(0) })
                })
            });

        gateway
    }

    #[tokio::test]
    async fn test_initialize() {
        let gateway = get_mock_gateway();
        let account_extractor = MockAccountExtractor::new();
        let entrypoint_tracer = MockEntryPointTracer::new();

        let mut dci = DynamicContractIndexer::new(
            Chain::Ethereum,
            "test".to_string(),
            gateway,
            account_extractor,
            entrypoint_tracer,
        );

        dci.initialize().await.unwrap();

        assert_eq!(
            dci.cache
                .ep_id_to_entrypoint
                .get_full_permanent_state(),
            &HashMap::from([
                ("entrypoint_1".to_string(), get_entrypoint(1)),
                ("entrypoint_4".to_string(), get_entrypoint(4)),
                ("entrypoint_2".to_string(), get_entrypoint(2)),
            ])
        );
        assert_eq!(
            dci.cache
                .entrypoint_results
                .get_full_permanent_state(),
            &HashMap::from([
                (("entrypoint_1".to_string(), get_tracing_params(1)), get_tracing_result(1)),
                (("entrypoint_2".to_string(), get_tracing_params(3)), get_tracing_result(2)),
                (("entrypoint_4".to_string(), get_tracing_params(1)), get_tracing_result(1)),
            ])
        );
        assert_eq!(
            dci.cache
                .retriggers
                .get_full_permanent_state(),
            &HashMap::from([
                (
                    (Bytes::from(1_u8), Bytes::from(1_u8)),
                    HashSet::from([
                        EntryPointWithTracingParams::new(get_entrypoint(1), get_tracing_params(1)),
                        EntryPointWithTracingParams::new(get_entrypoint(4), get_tracing_params(1)),
                    ]),
                ),
                (
                    (Bytes::from(2_u8), Bytes::from(2_u8)),
                    HashSet::from([EntryPointWithTracingParams::new(
                        get_entrypoint(2),
                        get_tracing_params(3)
                    )])
                )
            ])
        );
        assert_eq!(
            dci.cache
                .tracked_contracts
                .get_full_permanent_state(),
            &HashMap::from([
                (Bytes::from("0x01"), Some(HashSet::from([Bytes::from("0x11")]))),
                (Bytes::from("0x11"), Some(HashSet::from([Bytes::from("0x11")]))),
                (Bytes::from("0x02"), Some(HashSet::from([Bytes::from("0x22")]))),
                (Bytes::from("0x22"), Some(HashSet::from([Bytes::from("0x22")]))),
            ])
        );
    }

    #[tokio::test]
    async fn test_process_block_update_no_changes() {
        let gateway = get_mock_gateway();
        let account_extractor = MockAccountExtractor::new();
        let entrypoint_tracer = MockEntryPointTracer::new();

        let mut dci = DynamicContractIndexer::new(
            Chain::Ethereum,
            "test".to_string(),
            gateway,
            account_extractor,
            entrypoint_tracer,
        );

        dci.initialize().await.unwrap();

        let mut block_changes = get_block_changes(1);
        dci.process_block_update(&mut block_changes)
            .await
            .unwrap();

        assert_eq!(block_changes, get_block_changes(1));
    }

    #[tokio::test]
    async fn test_process_block_update_new_entrypoints() {
        let gateway = get_mock_gateway();
        let mut account_extractor = MockAccountExtractor::new();
        let mut entrypoint_tracer = MockEntryPointTracer::new();

        entrypoint_tracer
            .expect_trace()
            .with(
                eq(Bytes::from(2_u8).lpad(32, 0)),
                eq(vec![EntryPointWithTracingParams::new(
                    get_entrypoint(9),
                    get_tracing_params(9),
                )]),
            )
            .return_once(move |_, _| {
                Ok(vec![TracedEntryPoint::new(
                    EntryPointWithTracingParams::new(get_entrypoint(9), get_tracing_params(9)),
                    Bytes::zero(32),
                    get_tracing_result(9),
                )])
            });

        account_extractor
            .expect_get_accounts_at_block()
            .with(
                eq(testing::block(2)),
                predicate::function(|requests: &[StorageSnapshotRequest]| {
                    requests.len() == 2 &&
                        requests
                            .iter()
                            .any(|r| r.address == Bytes::from("0x09")) &&
                        requests
                            .iter()
                            .any(|r| r.address == Bytes::from("0x99"))
                }),
            )
            .return_once(move |_, _| {
                Ok(HashMap::from([
                    (
                        Bytes::from("0x09"),
                        AccountDelta::new(
                            Chain::Ethereum,
                            Bytes::from("0x09"),
                            HashMap::new(),
                            None,
                            None,
                            ChangeType::Update,
                        ),
                    ),
                    (
                        Bytes::from("0x99"),
                        AccountDelta::new(
                            Chain::Ethereum,
                            Bytes::from("0x99"),
                            HashMap::new(),
                            None,
                            None,
                            ChangeType::Update,
                        ),
                    ),
                ]))
            });

        let mut dci = DynamicContractIndexer::new(
            Chain::Ethereum,
            "test".to_string(),
            gateway,
            account_extractor,
            entrypoint_tracer,
        );

        dci.initialize().await.unwrap();

        let mut block_changes = get_block_changes(2);
        dci.process_block_update(&mut block_changes)
            .await
            .unwrap();

        let mut expected_block_changes = get_block_changes(2);
        expected_block_changes.txs_with_update[0]
            .account_deltas
            .extend([
                (
                    Bytes::from("0x99"),
                    AccountDelta::new(
                        Chain::Ethereum,
                        Bytes::from("0x99"),
                        HashMap::new(),
                        None,
                        None,
                        ChangeType::Update,
                    ),
                ),
                (
                    Bytes::from("0x09"),
                    AccountDelta::new(
                        Chain::Ethereum,
                        Bytes::from("0x09"),
                        HashMap::new(),
                        None,
                        None,
                        ChangeType::Update,
                    ),
                ),
            ]);

        expected_block_changes.trace_results = vec![TracedEntryPoint::new(
            EntryPointWithTracingParams::new(get_entrypoint(9), get_tracing_params(9)),
            Bytes::zero(32),
            get_tracing_result(9),
        )];
        assert_eq!(block_changes, expected_block_changes);
    }

    #[tokio::test]
    async fn test_process_block_update_old_entrypoints_updates() {
        let gateway = get_mock_gateway();
        let account_extractor = MockAccountExtractor::new();
        let entrypoint_tracer = MockEntryPointTracer::new();

        let mut dci = DynamicContractIndexer::new(
            Chain::Ethereum,
            "test".to_string(),
            gateway,
            account_extractor,
            entrypoint_tracer,
        );

        dci.initialize().await.unwrap();

        let mut block_changes = get_block_changes(3);
        dci.process_block_update(&mut block_changes)
            .await
            .unwrap();

        let mut expected_block_changes = get_block_changes(3);

        expected_block_changes
            .txs_with_update
            .extend([TxWithChanges {
                tx: get_transaction(1),
                account_deltas: HashMap::from([
                    (
                        Bytes::from("0x02"),
                        AccountDelta::new(
                            Chain::Ethereum,
                            Bytes::from("0x02"),
                            HashMap::from([
                                (Bytes::from("0x01"), Some(Bytes::from("0x01"))),
                                (Bytes::from("0x22"), Some(Bytes::from("0x22"))),
                            ]),
                            None,
                            None,
                            ChangeType::Update,
                        ),
                    ),
                    (
                        Bytes::from("0x22"),
                        AccountDelta::new(
                            Chain::Ethereum,
                            Bytes::from("0x22"),
                            HashMap::from([(Bytes::from("0x22"), Some(Bytes::from("0x01")))]),
                            None,
                            None,
                            ChangeType::Update,
                        ),
                    ),
                ]),
                ..Default::default()
            }]);

        assert_eq!(block_changes, expected_block_changes);
    }

    #[tokio::test]
    async fn test_process_block_update_retriggers() {
        let gateway = get_mock_gateway();
        let mut account_extractor = MockAccountExtractor::new();
        let mut entrypoint_tracer = MockEntryPointTracer::new();

        entrypoint_tracer
            .expect_trace()
            .with(
                // Block 4 hash
                eq(Bytes::from(4_u8).lpad(32, 0)),
                // Entrypoints to trace
                predicate::function(|ep_with_params: &Vec<EntryPointWithTracingParams>| {
                    ep_with_params.len() == 2 &&
                        ep_with_params.iter().any(|ep| {
                            ep == &EntryPointWithTracingParams::new(
                                get_entrypoint(1),
                                get_tracing_params(1),
                            )
                        }) &&
                        ep_with_params.iter().any(|ep| {
                            ep == &EntryPointWithTracingParams::new(
                                get_entrypoint(4),
                                get_tracing_params(1),
                            )
                        })
                }),
            )
            .return_once(move |_, _| {
                Ok(vec![
                    TracedEntryPoint::new(
                        EntryPointWithTracingParams::new(get_entrypoint(1), get_tracing_params(1)),
                        Bytes::zero(32),
                        get_tracing_result(1),
                    ),
                    TracedEntryPoint::new(
                        EntryPointWithTracingParams::new(get_entrypoint(4), get_tracing_params(1)),
                        Bytes::zero(32),
                        get_tracing_result(5),
                    ),
                ])
            });

        // Should only be called for new accounts, so account 0x01 and 0x11 are ignored because
        // already indexed. Both 0x05 and 0x55 are accessed by the traced entrypoints.
        account_extractor
            .expect_get_accounts_at_block()
            .with(
                eq(testing::block(4)),
                predicate::function(|requests: &[StorageSnapshotRequest]| {
                    requests.len() == 2 &&
                        requests
                            .iter()
                            .any(|r| r.address == Bytes::from("0x05")) &&
                        requests
                            .iter()
                            .any(|r| r.address == Bytes::from("0x55"))
                }),
            )
            .return_once(move |_, _| {
                Ok(HashMap::from([
                    (
                        Bytes::from("0x05"),
                        AccountDelta::new(
                            Chain::Ethereum,
                            Bytes::from("0x05"),
                            HashMap::new(),
                            None,
                            None,
                            ChangeType::Update,
                        ),
                    ),
                    (
                        Bytes::from("0x55"),
                        AccountDelta::new(
                            Chain::Ethereum,
                            Bytes::from("0x55"),
                            HashMap::new(),
                            None,
                            None,
                            ChangeType::Update,
                        ),
                    ),
                ]))
            });

        let mut dci = DynamicContractIndexer::new(
            Chain::Ethereum,
            "test".to_string(),
            gateway,
            account_extractor,
            entrypoint_tracer,
        );

        dci.initialize().await.unwrap();

        let mut block_changes = get_block_changes(4);
        dci.process_block_update(&mut block_changes)
            .await
            .unwrap();

        let mut expected_block_changes = get_block_changes(4);
        expected_block_changes.txs_with_update = vec![TxWithChanges {
            tx: get_transaction(1),
            account_deltas: HashMap::from([
                // Account 0x01 has the storage update that triggered the retrigger
                (
                    Bytes::from("0x01"),
                    AccountDelta::new(
                        Chain::Ethereum,
                        Bytes::from("0x01"),
                        HashMap::from([(Bytes::from("0x01"), Some(Bytes::from("0xabcd")))]),
                        None,
                        None,
                        ChangeType::Update,
                    ),
                ),
                // Two new accounts are detected in the re-tracing
                (
                    Bytes::from("0x05"),
                    AccountDelta::new(
                        Chain::Ethereum,
                        Bytes::from("0x05"),
                        HashMap::new(),
                        None,
                        None,
                        ChangeType::Update,
                    ),
                ),
                (
                    Bytes::from("0x55"),
                    AccountDelta::new(
                        Chain::Ethereum,
                        Bytes::from("0x55"),
                        HashMap::new(),
                        None,
                        None,
                        ChangeType::Update,
                    ),
                ),
            ]),
            ..Default::default()
        }];
        expected_block_changes.trace_results = vec![
            TracedEntryPoint::new(
                EntryPointWithTracingParams::new(get_entrypoint(1), get_tracing_params(1)),
                Bytes::zero(32),
                get_tracing_result(1),
            ),
            TracedEntryPoint::new(
                EntryPointWithTracingParams::new(get_entrypoint(4), get_tracing_params(1)),
                Bytes::zero(32),
                get_tracing_result(5),
            ),
        ];

        assert_eq!(block_changes, expected_block_changes);
    }

    #[tokio::test]
    async fn test_storage_request_logic_for_tokens() {
        let gateway = get_mock_gateway();
        let mut account_extractor = MockAccountExtractor::new();
        let mut entrypoint_tracer = MockEntryPointTracer::new();

        // Set up a token address for testing
        let token_address = Bytes::from("0xA0b86991c6218a36c1d19D4a2e9Eb0cE3606eB48"); // USDC

        entrypoint_tracer
            .expect_trace()
            .with(
                eq(Bytes::from(2_u8).lpad(32, 0)),
                eq(vec![EntryPointWithTracingParams::new(
                    get_entrypoint(9),
                    get_tracing_params(9),
                )]),
            )
            .return_once({
                let token_address = token_address.clone();
                move |_, _| {
                    Ok(vec![TracedEntryPoint::new(
                        EntryPointWithTracingParams::new(get_entrypoint(9), get_tracing_params(9)),
                        Bytes::zero(32),
                        get_tracing_result_with_address(&token_address),
                    )])
                }
            });

        // Expect specific slots to be requested for the token
        account_extractor
            .expect_get_accounts_at_block()
            .with(
                eq(testing::block(2)),
                predicate::function({
                    let token_address = token_address.clone();
                    move |requests: &[StorageSnapshotRequest]| {
                        requests.len() == 1 &&
                            requests[0].address == token_address &&
                            requests[0].slots.is_some() &&
                            requests[0]
                                .slots
                                .as_ref()
                                .unwrap()
                                .len() ==
                                1 &&
                            requests[0]
                                .slots
                                .as_ref()
                                .unwrap()
                                .contains(&Bytes::from(0x99_u8).lpad(32, 0))
                    }
                }),
            )
            .return_once({
                let token_address = token_address.clone();
                move |_, _| {
                    Ok(HashMap::from([(
                        token_address.clone(),
                        AccountDelta::new(
                            Chain::Ethereum,
                            token_address.clone(),
                            HashMap::new(),
                            None,
                            None,
                            ChangeType::Update,
                        ),
                    )]))
                }
            });

        let mut dci = DynamicContractIndexer::new(
            Chain::Ethereum,
            "test".to_string(),
            gateway,
            account_extractor,
            entrypoint_tracer,
        );

        dci.initialize().await.unwrap();

        // Add the token to the cache
        dci.cache
            .erc20_addresses
            .insert_permanent(token_address.clone(), true);

        let mut block_changes = get_block_changes_with_token(token_address.clone());
        dci.process_block_update(&mut block_changes)
            .await
            .unwrap();

        // Verify the token was processed with specific slots only
        assert!(!block_changes.txs_with_update.is_empty());
    }

    #[tokio::test]
    async fn test_storage_request_logic_for_blacklisted_addresses() {
        let gateway = get_mock_gateway();
        let mut account_extractor = MockAccountExtractor::new();
        let mut entrypoint_tracer = MockEntryPointTracer::new();

        // Use the UniswapV4 pool manager (blacklisted address)
        let blacklisted_address =
            Bytes::from_str("0x000000000004444c5dc75cB358380D2e3dE08A90").unwrap();

        // Clone addresses for use in different closures
        let blacklisted_address_for_trace = blacklisted_address.clone();
        let blacklisted_address_for_predicate = blacklisted_address.clone();
        let blacklisted_address_for_return1 = blacklisted_address.clone();
        let blacklisted_address_for_return2 = blacklisted_address.clone();
        let blacklisted_address_for_block_changes = blacklisted_address.clone();

        entrypoint_tracer
            .expect_trace()
            .with(
                eq(Bytes::from(2_u8).lpad(32, 0)),
                eq(vec![EntryPointWithTracingParams::new(
                    get_entrypoint(9),
                    get_tracing_params(9),
                )]),
            )
            .return_once(move |_, _| {
                Ok(vec![TracedEntryPoint::new(
                    EntryPointWithTracingParams::new(get_entrypoint(9), get_tracing_params(9)),
                    Bytes::zero(32),
                    get_tracing_result_with_address(&blacklisted_address_for_trace),
                )])
            });

        // Expect specific slots to be requested for the blacklisted address
        account_extractor
            .expect_get_accounts_at_block()
            .with(
                eq(testing::block(2)),
                predicate::function(move |requests: &[StorageSnapshotRequest]| {
                    requests.len() == 1 &&
                        requests[0].address == blacklisted_address_for_predicate &&
                        requests[0].slots.is_some() &&
                        requests[0]
                            .slots
                            .as_ref()
                            .unwrap()
                            .len() ==
                            1 &&
                        requests[0]
                            .slots
                            .as_ref()
                            .unwrap()
                            .contains(&Bytes::from(0x99_u8).lpad(32, 0))
                }),
            )
            .return_once(move |_, _| {
                Ok(HashMap::from([(
                    blacklisted_address_for_return1.clone(),
                    AccountDelta::new(
                        Chain::Ethereum,
                        blacklisted_address_for_return2,
                        HashMap::new(),
                        None,
                        None,
                        ChangeType::Update,
                    ),
                )]))
            });

        let mut dci = DynamicContractIndexer::new(
            Chain::Ethereum,
            "test".to_string(),
            gateway,
            account_extractor,
            entrypoint_tracer,
        );

        dci.initialize().await.unwrap();

        let mut block_changes = get_block_changes_with_token(blacklisted_address_for_block_changes);
        dci.process_block_update(&mut block_changes)
            .await
            .unwrap();

        // Verify the blacklisted address was processed with specific slots only
        assert!(!block_changes.txs_with_update.is_empty());
    }

    #[tokio::test]
    async fn test_storage_request_logic_for_normal_contracts() {
        let gateway = get_mock_gateway();
        let mut account_extractor = MockAccountExtractor::new();
        let mut entrypoint_tracer = MockEntryPointTracer::new();

        // Use a normal contract address (not token or blacklisted)
        let normal_address = Bytes::from("0x1234567890123456789012345678901234567890");

        // Clone addresses for use in different closures
        let normal_address_for_trace = normal_address.clone();
        let normal_address_for_predicate = normal_address.clone();
        let normal_address_for_return1 = normal_address.clone();
        let normal_address_for_return2 = normal_address.clone();
        let normal_address_for_block_changes = normal_address.clone();

        entrypoint_tracer
            .expect_trace()
            .with(
                eq(Bytes::from(2_u8).lpad(32, 0)),
                eq(vec![EntryPointWithTracingParams::new(
                    get_entrypoint(9),
                    get_tracing_params(9),
                )]),
            )
            .return_once(move |_, _| {
                Ok(vec![TracedEntryPoint::new(
                    EntryPointWithTracingParams::new(get_entrypoint(9), get_tracing_params(9)),
                    Bytes::zero(32),
                    get_tracing_result_with_address(&normal_address_for_trace),
                )])
            });

        // Expect all slots (None) to be requested for normal contracts
        account_extractor
            .expect_get_accounts_at_block()
            .with(
                eq(testing::block(2)),
                predicate::function(move |requests: &[StorageSnapshotRequest]| {
                    requests.len() == 1 &&
                        requests[0].address == normal_address_for_predicate &&
                        requests[0].slots.is_none()
                }),
            )
            .return_once(move |_, _| {
                Ok(HashMap::from([(
                    normal_address_for_return1.clone(),
                    AccountDelta::new(
                        Chain::Ethereum,
                        normal_address_for_return2,
                        HashMap::new(),
                        None,
                        None,
                        ChangeType::Update,
                    ),
                )]))
            });

        let mut dci = DynamicContractIndexer::new(
            Chain::Ethereum,
            "test".to_string(),
            gateway,
            account_extractor,
            entrypoint_tracer,
        );

        dci.initialize().await.unwrap();

        let mut block_changes = get_block_changes_with_token(normal_address_for_block_changes);
        dci.process_block_update(&mut block_changes)
            .await
            .unwrap();

        // Verify the normal contract was processed with all slots (None)
        assert!(!block_changes.txs_with_update.is_empty());
    }

    #[tokio::test]
    async fn test_extract_tracked_updates_slots_filtering() {
        let gateway = get_mock_gateway();
        let account_extractor = MockAccountExtractor::new();
        let entrypoint_tracer = MockEntryPointTracer::new();

        let mut dci = DynamicContractIndexer::new(
            Chain::Ethereum,
            "test".to_string(),
            gateway,
            account_extractor,
            entrypoint_tracer,
        );

        dci.initialize().await.unwrap();

        // Set up addresses in different categories
        let token_address = Bytes::from("0xA0b86991c6218a36c1d19D4a2e9Eb0cE3606eB48"); // USDC
        let normal_address = Bytes::from("0x1234567890123456789012345678901234567890");

        // Add token to cache
        dci.cache
            .erc20_addresses
            .insert_permanent(token_address.clone(), true);

        // Add tracked contracts with specific slots
        let tracked_slots =
            HashSet::from([Bytes::from(0x01_u8).lpad(32, 0), Bytes::from(0x02_u8).lpad(32, 0)]);
        dci.cache
            .tracked_contracts
            .insert_permanent(token_address.clone(), Some(tracked_slots.clone()));
        dci.cache
            .tracked_contracts
            .insert_permanent(normal_address.clone(), Some(tracked_slots.clone()));

        // Create block changes with storage updates
        let block_changes = BlockChanges::new(
            "test".to_string(),
            Chain::Ethereum,
            testing::block(3),
            3,
            false,
            vec![],
            vec![TxWithStorageChanges {
                tx: get_transaction(1),
                storage_changes: HashMap::from([
                    // Token address - should have slots filtered
                    (
                        token_address.clone(),
                        HashMap::from([
                            (Bytes::from(0x01_u8).lpad(32, 0), Bytes::from(0x100_u16).lpad(32, 0)), /* Should be kept */
                            (Bytes::from(0x03_u8).lpad(32, 0), Bytes::from(0x300_u16).lpad(32, 0)), /* Should be filtered out */
                        ]),
                    ),
                    // Normal address - should not have slots filtered
                    (
                        normal_address.clone(),
                        HashMap::from([
                            (Bytes::from(0x01_u8).lpad(32, 0), Bytes::from(0x100_u16).lpad(32, 0)), /* Should be kept */
                            (Bytes::from(0x03_u8).lpad(32, 0), Bytes::from(0x300_u16).lpad(32, 0)), /* Should be kept */
                        ]),
                    ),
                ]),
            }],
        );

        let tracked_updates = dci
            .extract_tracked_updates(&block_changes)
            .unwrap();

        // Verify token address has filtered slots (only slot 0x01 should remain)
        if let Some(token_tx) = tracked_updates.get(&get_transaction(1).hash) {
            if let Some(token_delta) = token_tx
                .account_deltas
                .get(&token_address)
            {
                assert_eq!(token_delta.slots.len(), 1);
                assert!(token_delta
                    .slots
                    .contains_key(&Bytes::from(0x01_u8).lpad(32, 0)));
                assert!(!token_delta
                    .slots
                    .contains_key(&Bytes::from(0x03_u8).lpad(32, 0)));
            } else {
                panic!("Token delta not found");
            }
        } else {
            panic!("Token transaction not found");
        }

        // Verify normal address has all slots (both 0x01 and 0x03 should remain)
        if let Some(normal_tx) = tracked_updates.get(&get_transaction(1).hash) {
            if let Some(normal_delta) = normal_tx
                .account_deltas
                .get(&normal_address)
            {
                assert_eq!(normal_delta.slots.len(), 2);
                assert!(normal_delta
                    .slots
                    .contains_key(&Bytes::from(0x01_u8).lpad(32, 0)));
                assert!(normal_delta
                    .slots
                    .contains_key(&Bytes::from(0x03_u8).lpad(32, 0)));
            } else {
                panic!("Normal delta not found");
            }
        } else {
            panic!("Normal transaction not found");
        }
    }

    // Helper function to create a tracing result with a specific address
    fn get_tracing_result_with_address(address: &Address) -> TracingResult {
        TracingResult::new(
            HashSet::new(),
            HashMap::from([(address.clone(), HashSet::from([Bytes::from(0x99_u8).lpad(32, 0)]))]),
        )
    }

    // Helper function to create block changes with a specific token
    fn get_block_changes_with_token(_address: Address) -> BlockChanges {
        let tx = get_transaction(2);

        BlockChanges::new(
            "test".to_string(),
            Chain::Ethereum,
            testing::block(2),
            2,
            false,
            vec![TxWithChanges {
                tx,
                entrypoints: HashMap::from([(
                    "component_1".to_string(),
                    HashSet::from([get_entrypoint(9)]),
                )]),
                entrypoint_params: HashMap::from([(
                    "entrypoint_9".to_string(),
                    HashSet::from([(get_tracing_params(9), None)]),
                )]),
                ..Default::default()
            }],
            Vec::new(),
        )
    }
}
