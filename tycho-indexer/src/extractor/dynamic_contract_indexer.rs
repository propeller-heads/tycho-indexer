use std::collections::{hash_map::Entry, HashMap, HashSet};

use async_trait::async_trait;
use tracing::{debug, instrument, trace};
use tycho_common::{
    models::{
        blockchain::{
            EntryPoint, EntryPointWithTracingParams, TracedEntryPoint, TracingParams,
            TracingResult, Transaction, TxWithChanges,
        },
        contract::AccountDelta,
        Address, Chain, ChangeType, ContractStoreDeltas, EntryPointId, StoreKey, TxHash,
    },
    storage::{EntryPointFilter, EntryPointGateway, StorageError},
    traits::{AccountExtractor, EntryPointTracer, StorageSnapshotRequest},
};

use super::{
    models::{BlockChanges, TxWithStorageChanges},
    ExtractionError, ExtractorExtension,
};

/// A unique identifier for a storage location, consisting of an address and a storage key.
type StorageLocation = (Address, StoreKey);

#[allow(unused)]
pub(super) struct DynamicContractIndexer<AE, T, G>
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

#[async_trait]
impl<AE, T, G> ExtractorExtension for DynamicContractIndexer<AE, T, G>
where
    AE: AccountExtractor + Send + Sync,
    T: EntryPointTracer + Send + Sync,
    G: EntryPointGateway + Send + Sync,
{
    #[instrument(skip_all, fields(chain = % self.chain, protocol = % self.protocol, block_number = % block_changes.block.number))]
    async fn process_block_update(
        &mut self,
        block_changes: &mut BlockChanges,
    ) -> Result<(), ExtractionError> {
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
        debug!("DCI: Will analyze {:?} entrypoints", entrypoints_to_analyze.len());
        trace!("DCI: Entrypoints to analyze: {:?}", entrypoints_to_analyze);

        if !entrypoints_to_analyze.is_empty() {
            let traced_entry_points = self
                .tracer
                .trace(
                    block_changes.block.hash.clone(),
                    entrypoints_to_analyze
                        .keys()
                        .cloned()
                        .collect(),
                )
                .await
                .map_err(|e| ExtractionError::TracingError(format!("{e:?}")))?;

            let mut tx_to_traced_entry_point: HashMap<&Transaction, &TracedEntryPoint> =
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
                tx_to_traced_entry_point.insert(tx, traced_entry_point);
            }

            let mut new_account_addr_to_tx: HashMap<Address, &Transaction> = HashMap::new();
            for (tx, traced_entry_point) in tx_to_traced_entry_point {
                for account in traced_entry_point
                    .tracing_result
                    .called_addresses
                    .iter()
                    .filter(|account| {
                        !self
                            .cache
                            .tracked_contracts
                            .contains_key(*account)
                    })
                    .cloned()
                {
                    // Keep track of the first transaction that pushed the entrypoint that calls
                    // this account.
                    new_account_addr_to_tx
                        .entry(account)
                        .and_modify(|existing_tx| {
                            if existing_tx.index > tx.index {
                                *existing_tx = tx;
                            }
                        })
                        .or_insert(tx);
                }
            }

            // Get the code, balance and storage changes for the new traced entrypoints.
            // This can contain duplicates, but the AccountExtractor implementation should ignore
            // them.
            let storage_request: Vec<StorageSnapshotRequest> = new_account_addr_to_tx
                .keys()
                .map(|address| {
                    StorageSnapshotRequest {
                        address: address.clone(),
                        // TODO: Set the slots once it's available from the Tracer
                        slots: None,
                    }
                })
                .collect();

            let mut new_accounts = self
                .storage_source
                .get_accounts_at_block(&block_changes.block, &storage_request)
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
            self.update_cache(&traced_entry_points);

            // Update the block changes with the traced entrypoints
            block_changes.trace_results = traced_entry_points;
        }

        // Update the entrypoint cache from the block changes
        self.cache.ep_id_to_entrypoint.extend(
            new_entrypoints
                .into_values()
                .map(|ep| (ep.external_id.clone(), ep)),
        );

        let tracked_updates = self.extract_tracked_updates(block_changes)?;

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

        Ok(())
    }

    #[allow(unused)]
    async fn process_revert(&mut self, target_block: u64) -> Result<(), ExtractionError> {
        // TODO: Handle reverts, need to cleanup reverted internal state
        todo!()
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

    /// Scans the storage changes of the block and detects entrypoints that need to be re-traced
    /// due to detected storage changes.
    ///
    /// # Returns
    /// A map of entrypoints that need to be re-traced and the transaction that first detected the
    /// retriggered entrypoint.
    fn detect_retriggers<'a>(
        &self,
        tx_with_changes: &'a [TxWithStorageChanges],
    ) -> HashMap<EntryPointWithTracingParams, &'a Transaction> {
        // Create a map of storage locations that have been updated in the block and the transaction
        // that last detected the update.
        // Note: tracing results are block scoped, this means if the same storage location is
        // updated in different transactions, we will link the results of the retriggered
        // entrypoint with the last transaction that updated the storage location in the
        // block.

        let mut retriggered_entrypoints: HashMap<EntryPointWithTracingParams, &Transaction> =
            HashMap::new();
        for tx_with_changes in tx_with_changes.iter() {
            for (account, contract_store) in tx_with_changes.storage_changes.iter() {
                for key in contract_store.keys() {
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

        retriggered_entrypoints
    }

    /// Update the DCI cache with the new entrypoints and tracing results
    fn update_cache(&mut self, new_tracing_results: &[TracedEntryPoint]) {
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

                if let Some(tracked_keys) = tracked_keys {
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

        Ok(tracked_updates)
    }

    // TODO: Handle reverts, need to cleanup reverted internal state
    #[allow(unused)]
    pub(super) fn process_revert(&mut self, target_block: u64) -> Result<(), ExtractionError> {
        todo!()
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
                    0,
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
                    0,
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
                    0,
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
                                HashMap::from([(Bytes::from("0x01"), Bytes::from("0x01"))]),
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
                    0,
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
            HashSet::from([Bytes::from(version), Bytes::from(version + version * 16)]),
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
            dci.cache.ep_id_to_entrypoint,
            HashMap::from([
                ("entrypoint_1".to_string(), get_entrypoint(1)),
                ("entrypoint_4".to_string(), get_entrypoint(4)),
                ("entrypoint_2".to_string(), get_entrypoint(2)),
            ])
        );
        assert_eq!(
            dci.cache.entrypoint_results,
            HashMap::from([
                (("entrypoint_1".to_string(), get_tracing_params(1)), get_tracing_result(1)),
                (("entrypoint_2".to_string(), get_tracing_params(3)), get_tracing_result(2)),
                (("entrypoint_4".to_string(), get_tracing_params(1)), get_tracing_result(1)),
            ])
        );
        assert_eq!(
            dci.cache.retriggers,
            HashMap::from([
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
            dci.cache.tracked_contracts,
            HashMap::from([
                (Bytes::from(1_u8), None),
                (Bytes::from(2_u8), None),
                (Bytes::from(1_u8 + 16_u8), None),
                (Bytes::from(2_u8 + 2_u8 * 16_u8), None),
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
                    requests.len() == 2
                        && requests
                            .iter()
                            .any(|r| r.address == Bytes::from("0x09"))
                        && requests
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
                            HashMap::from([(Bytes::from("0x01"), Some(Bytes::from("0x01")))]),
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
                    ep_with_params.len() == 2
                        && ep_with_params.iter().any(|ep| {
                            ep == &EntryPointWithTracingParams::new(
                                get_entrypoint(1),
                                get_tracing_params(1),
                            )
                        })
                        && ep_with_params.iter().any(|ep| {
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
        // already indexed.
        account_extractor
            .expect_get_accounts_at_block()
            .with(
                eq(testing::block(4)),
                predicate::function(|requests: &[StorageSnapshotRequest]| {
                    requests.len() == 2
                        && requests
                            .iter()
                            .any(|r| r.address == Bytes::from("0x55"))
                        && requests
                            .iter()
                            .any(|r| r.address == Bytes::from("0x05"))
                }),
            )
            .return_once(move |_, _| {
                Ok(HashMap::from([
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
                // This account is already tracked
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
}
