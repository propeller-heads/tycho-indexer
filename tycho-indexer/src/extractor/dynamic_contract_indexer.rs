use std::{
    collections::{HashMap, HashSet},
    iter::zip,
    sync::Arc,
};

use actix_web::web::trace;
use tokio::sync::mpsc::{Receiver, Sender};
use tracing::debug;
use tycho_common::{
    dto::{Block, Transaction},
    models::{
        blockchain::{EntryPoint, EntryPointWithData, TracedEntryPoint},
        contract::AccountDelta,
        Address, Chain, ChangeType, ComponentId, StoreKey, StoreVal,
    },
    storage::{EntryPointFilter, EntryPointGateway},
    traits::{AccountExtractor, EntryPointTracer, StorageSnapshotRequest},
    Bytes,
};

struct TransactionAccountUpdates {
    tx: Transaction,
    changes: Vec<ContractChanges>,
}

struct DCIBlockUpdate {
    // A Hashmap mapping Transactions to the relevant AccountDeltas (either Create or Update)
    // detected on the block.
    result_deltas: HashMap<Transaction, Vec<AccountDelta>>,
    // A Hashmap mapping component IDs to the new Accounts that were detected by the DCI on the
    // block
    result_components: HashMap<ComponentId, Vec<Address>>,
}

// TODO: Remove this once it's defined and implemented by the extractor
struct ContractChanges {
    address: Bytes,
    key: Bytes,
    old_value: Bytes,
    new_value: Bytes,
    ordinal: u64,
}
// Entrypoint hash
type EntrypointId = Bytes;

// These are the message types that the DynamicContractIndexer can receive
enum DCIMessage<E> {
    // Update received from the extractor consisting of new entrypoints or block updates, and a
    // sender to receive the result of the block
    BlockUpdate(Block, Vec<EntryPointWithData>, ContractChanges, Sender<Result<(), E>>),
}
struct DynamicContractIndexer<E> {
    protocol: String,
    entrypoint_gw: Arc<dyn EntryPointGateway>,
    storage_source: Arc<dyn AccountExtractor<Error = ()>>,
    tracer: Arc<dyn EntryPointTracer<Error = ()>>,
    protocol_entrypoints: HashMap<ComponentId, Vec<EntryPointWithData>>,
    entrypoint_results: HashMap<EntryPointWithData, TracedEntryPoint>,
}

// TODO: Things to check:
// If I emit an AccountDelta of type Update without code or balance, will it overwrite the existing
// value?
impl DynamicContractIndexer<()> {
    pub fn new(
        protocol: String,
        entrypoint_gw: Arc<dyn EntryPointGateway>,
        storage_source: Arc<dyn AccountExtractor<Error = ()>>,
        tracer: Arc<dyn EntryPointTracer<Error = ()>>,
    ) -> Self {
        Self {
            protocol,
            entrypoint_gw,
            storage_source,
            tracer,
            protocol_entrypoints: HashMap::new(),
            entrypoint_results: HashMap::new(),
        }
    }

    /// This function will initialize the DynamicContractIndexer
    /// It will load from the gateway all the entrypoints + entrypoint for the protocols and the
    /// respective trace results.
    pub async fn initialize(&mut self) {
        let entrypoint_filter = EntryPointFilter::new(Some(self.protocol.clone()));

        let entrypoints = self
            .entrypoint_gw
            .get_entry_points_with_data(entrypoint_filter)
            .await
            .unwrap();

        for entrypoint in entrypoints {
            self.protocol_entrypoints
                .insert(entrypoint.clone());

            let traced_entrypoints = self
                .entrypoint_gw
                .get_traced_entry_point(entrypoint)
                .await
                .unwrap();
            if let Some(traced_entrypoint) = traced_entrypoints {
                self.entrypoint_results
                    .insert(entrypoint, traced_entrypoint);
            }
        }
    }

    pub async fn process_block_update(
        &mut self,
        new_entrypoints: &HashMap<ComponentId, Vec<EntryPointWithData>>,
        changes: &Vec<TransactionAccountUpdates>,
        block: &Block,
    ) -> DCIBlockUpdate {
        let mut result_deltas: HashMap<Transaction, Vec<AccountDelta>> = HashMap::new();
        let mut result_components: HashMap<ComponentId, Vec<Address>> = HashMap::new();

        // Registers new Entrypoints sent by the extractor to the map of Component -> Entrypoints
        for (component_id, entrypoints) in new_entrypoints {
            for entrypoint in entrypoints {
                self.protocol_entrypoints
                    .get(&component_id)
                    .get_or_insert_default()
                    .push(entrypoint.clone());
            }
        }

        // Select for analysis the newly detected EntryPointsWithData that haven't been analyzed
        // yet. This filter prevents us from re-analyzing entrypoints that have already been
        // analyzed, which can be a case if all the components have the same entrypoint.
        let mut entrypoints_to_analyze = self
            .protocol_entrypoints
            .values()
            .flatten()
            .filter(|entrypoint| {
                !self
                    .entrypoint_results
                    .contains_key(entrypoint)
            })
            .cloned()
            .collect::<HashSet<_>>();

        // Use block storage changes to detect retriggered entrypoints
        let retriggered_entrypoints = self.detect_retriggers(&changes);

        // Update the entrypoint results with the retriggered entrypoints
        entrypoints_to_analyze.extend(retriggered_entrypoints);
        debug!("Will analyze {:?} entrypoints", entrypoints_to_analyze.len());

        // Trace analyze all the entrypoints
        let entrypoints_to_analyze: Vec<EntryPointWithData> = entrypoints_to_analyze.into();

        let traced_entry_points = self
            .tracer
            .trace(block.hash.clone(), entrypoints_to_analyze)
            .await
            .expect("Failed to trace entrypoints");

        // Save the traced entrypoints to the DB
        self.entrypoint_gw
            .upsert_traced_entry_points(&traced_entry_points)
            .await
            .expect("Failed to upsert traced entrypoints");

        // Update our in-memory cache of traced entry points with the latest tracing results
        // This ensures we always have the most recent analysis results after entrypoints are
        // discovered or retriggered
        for (trace, entry_point) in zip(traced_entry_points.iter(), entrypoints_to_analyze.iter()) {
            self.entrypoint_results
                .insert(entry_point.clone(), trace.clone());
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

        let new_accounts = self
            .storage_source
            .get_accounts_at_block(block.into(), &storage_request)
            .await
            .expect("Failed to get accounts");

        // Create auxiliary map to prevent looping repeatedely through the data.
        let mut entrypoint_to_component: HashMap<EntryPointWithData, Vec<ComponentId>> =
            HashMap::new();
        for (component_id, entrypoints) in self.protocol_entrypoints.iter() {
            for entrypoint in entrypoints {
                entrypoint_to_component
                    .entry(entrypoint.clone())
                    .or_insert_with(Vec::new)
                    .push(component_id.clone());
            }
        }
        for trace in traced_entry_points.iter() {
            let component_ids = entrypoint_to_component
                .get(&trace.entry_point)
                .expect("Failed to get component ID");
            for account in trace
                .tracing_result
                .called_addresses
                .iter()
            {
                if new_accounts.contains(account) {
                    for component in component_ids {
                        result_components
                            .entry(component.clone())
                            .or_insert_with(Vec::new)
                            .push(account.clone());
                    }
                }
            }
        }

        // TODO: Update this to match the specific storage slots. Set (Address, StoreKey) as the key
        let mut aux_struct: HashMap<Address, Vec<EntryPoint>> = HashMap::new();
        for (entrypoint_with_data, trace) in self.entrypoint_results {
            for address in trace.tracing_result.called_addresses {
                let entrypoint = entrypoint_with_data.entry_point.clone();
                aux_struct
                    .entry(address.clone())
                    .or_insert_with(Vec::new)
                    .push(entrypoint);
            }
        }

        for tx in changes {
            let mut account_deltas: HashMap<Address, HashMap<StoreKey, Option<StoreVal>>> =
                HashMap::new();
            for change in tx.changes {
                // Address matches a entrypoint
                if aux_struct.contains_key(&change.address) {
                    let account_delta = account_deltas
                        .entry(&change.address)
                        .or_default()
                        .insert(change.key, Some(change.new_value));
                }
            }
            if !account_deltas.is_empty() {
                let deltas = account_deltas
                    .iter()
                    .flat_map(|(address, changes)| {
                        changes
                            .iter()
                            .map(|(key, value)| AccountDelta {
                                // TODO: Ofc get this from constructor
                                chain: Chain::Ethereum,
                                address: address.clone(),
                                slots: changes,
                                // TODO: We need to track balance?
                                balance: None,
                                code: None,
                                change: ChangeType::Update,
                            })
                    })
                    .collect::<Vec<_>>();
                result_deltas.insert(tx.clone(), deltas);
            }
        }

        DCIBlockUpdate { result_deltas, result_components }

        // // Update with all the storage changes that match any ContractChanges
        // // TODO: By hashing EntryPointWithData we can reduce considerably memory usage
        // let mut account_to_entrypoint: HashMap<(Address, Option<StoreKey>), EntryPointWithData> =
        //     HashMap::new();
        // for (entrypoint, trace) in self.entrypoint_results.iter() {
        //     for address in trace.tracing_result.called_addresses {
        //         account_to_entrypoint.insert((address.clone(), None), entrypoint.clone());
        //         // TODO, make it slot specific once we have this available on the TracingResult
        //         // for slot in trace.tracing_result.retriggers {
        //         //     account_to_entrypoint.insert((address.clone(), slot), entrypoint.clone());
        //         // }
        //     }
        // }
        //
        // for change in changes {
        //     let entrypoint = account_to_entrypoint.get(&(change.address,
        // Some(change.key.clone())));     if entrypoint.is_some() {
        //         // TODO: Brain fog, finish this
        //     }
        // }
    }

    /// Detects entrypoints that need to be reanalyzed due to detected storage changes.
    /// Entrypoints can specify "retrigger" conditions - specific (address, storage slot)
    /// combinations that, when modified in a block, require the entrypoint to be traced again.
    fn detect_retriggers(
        &mut self,
        tx_with_changes: &Vec<TransactionAccountUpdates>,
    ) -> HashSet<EntryPointWithData> {
        let possible_retriggers: HashSet<(Address, StoreKey)> = tx_with_changes
            .iter()
            .flat_map(|tx| {
                tx.changes
                    .iter()
                    .map(|change| (change.address.clone(), change.key.clone()))
            })
            .collect();

        self.entrypoint_results
            .iter()
            .filter_map(|(entrypoint, trace)| {
                trace
                    .tracing_result
                    .retriggers
                    .iter()
                    .any(|retrigger| possible_retriggers.contains(retrigger))
                    .then(|| entrypoint.clone())
            })
            .collect()
    }

    // pub async fn run(&mut self) -> Result<(), Self::Error> {
    //     // This function will run the main loop of the DynamicContractIndexer
    //     // It will listen for messages on the message_rx channel and process them accordingly
    //     loop {
    //         match self.message_rx.recv().await {
    //             Some(DCIMessage::BlockUpdate(block, entrypoints, changes, sender)) => {
    //                 // Process the block update
    //                 self.process_block_update(entrypoints, changes);
    //                 // Send the result back to the sender
    //                 let _ = sender.send(Ok(()));
    //             }
    //             Some(DCIMessage::RefreshEntrypoints(entrypoint_ids, sender)) => {
    //                 // Refresh the entrypoints for the specified contract
    //                 let _ = sender.send(self.refresh_entrypoints(entrypoint_ids));
    //             }
    //             None => break,
    //         }
    //     }
    // }
}
