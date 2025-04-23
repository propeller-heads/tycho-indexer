use std::{
    collections::{HashMap, HashSet},
    iter::zip,
    sync::Arc,
};

use actix_web::web::trace;
use tokio::sync::mpsc::{Receiver, Sender};
use tracing::debug;
use tycho_common::{
    dto::Block,
    models::{
        blockchain::{EntryPointWithData, TracedEntryPoint},
        contract::AccountDelta,
        Address, StoreKey,
    },
    storage::{EntryPointFilter, EntryPointGateway},
    traits::{AccountExtractor, EntryPointTracer, StorageSnapshotRequest},
    Bytes,
};

use crate::extractor::models::fixtures::slots;

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
    storage_source: Arc<dyn AccountExtractor<Error=()>>,
    tracer: Arc<dyn EntryPointTracer<Error=()>>,
    // TOOO: Is this necessary?
    protocol_entrypoints: HashSet<EntryPointWithData>,
    entrypoint_results: HashMap<EntryPointWithData, TracedEntryPoint>,
    message_rx: Receiver<DCIMessage<E>>,
}

// TODO: Things to check:
// If I emit an AccountDelta of type Update without code or balance, will it overwrite the existing
// value?
impl DynamicContractIndexer<()> {
    pub fn new(
        protocol: String,
        entrypoint_gw: Arc<dyn EntryPointGateway>,
        storage_source: Arc<dyn AccountExtractor<Error=()>>,
        tracer: Arc<dyn EntryPointTracer<Error=()>>,
        message_rx: Receiver<DCIMessage<()>>,
    ) -> Self {
        Self {
            protocol,
            entrypoint_gw,
            storage_source,
            tracer,
            protocol_entrypoints: HashSet::new(),
            entrypoint_results: HashMap::new(),
            message_rx,
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
        entrypoints: Vec<EntryPointWithData>,
        changes: Vec<ContractChanges>,
        block: Block,
    ) {
        let result: HashMap<EntryPointWithData, Vec<AccountDelta>> = HashMap::new();
        // Process the changes

        for entrypoint in entrypoints {
            self.register_entrypoint(entrypoint);
        }

        // Get entrypoints that are on hashset but not on the hashmap
        let mut entrypoints_to_analyze = HashSet::new();

        for entrypoint in self.protocol_entrypoints.iter() {
            if !self
                .entrypoint_results
                .contains_key(entrypoint)
            {
                entrypoints_to_analyze.insert(entrypoint.clone());
            }
        }

        // Find the retriggers
        let retriggered_entrypoints = self.analyze_retriggers(&changes);
        // Update the entrypoint results with the retriggered entrypoints
        entrypoints_to_analyze.extend(retriggered_entrypoints);

        debug!("Will analyze {:?} entrypoints", entrypoints_to_analyze.len());

        let entrypoints_to_analyze: Vec<EntryPointWithData> = entrypoints_to_analyze.into();

        // Trace analyze all the entrypoints
        let traced_entry_points = self
            .tracer
            .trace(block.hash, entrypoints_to_analyze)
            .await
            .expect("Failed to trace entrypoints");

        // TODO: Add TracedEntryPoints to DB

        for (trace, entry_point) in zip(traced_entry_points.iter(), entrypoints_to_analyze.iter()) {
            self.entrypoint_results
                .insert(entry_point.clone(), trace.clone());
        }

        // Fetch the storage slots of all the new entrypoints
        // let storage_request: Vec<StorageSnapshotRequest> =
        //     // TODO: Add storage slots
        //     traced_entry_points
        //         .iter()
        //         .map(|traced_entry_point: TracedEntryPoint| {
        //             StorageSnapshotRequest {
        //                 address: traced_entry_point.tracing_result.called_addresses,
        //                 slots,
        //             }
        //         }
        //         )
        //         .collect();

        let mut storage_request: Vec<StorageSnapshotRequest> = Vec::new();

        for traced_entry_point in traced_entry_points.iter() {
            for address in traced_entry_point
                .tracing_result
                .called_addresses
            {
                storage_request
                    .push(StorageSnapshotRequest { address: address.clone(), slots: None })
            }
        }

        let new_accounts = self
            .storage_source
            .get_accounts_at_block(block.into(), &storage_request)
            .await
            .expect("Failed to get accounts");

        // Update with all the storage changes that match any ContractChanges
        // TODO: By hashing EntryPointWithData we can reduce considerably memory usage
        let mut account_to_entrypoint: HashMap<(Address, Option<StoreKey>), EntryPointWithData> = HashMap::new();
        for (entrypoint, trace) in self.entrypoint_results.iter() {
            for address in trace.tracing_result.called_addresses {
                account_to_entrypoint.insert((address.clone(), None), entrypoint.clone());
                // TODO, make it slot specific once we have this available on the TracingResult
                // for slot in trace.tracing_result.retriggers {
                //     account_to_entrypoint.insert((address.clone(), slot), entrypoint.clone());
                // }
            }
        }

        for change in changes {
            let entrypoint = account_to_entrypoint.get(&(change.address, Some(change.key.clone())));
            if entrypoint.is_some() {
                // TODO: Brain fog, finish this
            }

        }
    }

    /// Register the entrypoint in the protocol_entrypoints map
    fn register_entrypoint(&mut self, entrypoint: EntryPointWithData) {
        self.protocol_entrypoints
            .insert(entrypoint);
    }

    fn analyze_retriggers(
        &mut self,
        changes: &Vec<ContractChanges>,
    ) -> HashSet<EntryPointWithData> {
        // Analyze the changes and return a list of entrypoints that need to be retriggered
        let mut retriggered_entrypoints = HashSet::new();

        let possible_retriggers: HashSet<(Address, StoreKey)> = changes
            .iter()
            .map(|change| (change.address.clone(), change.key.clone()))
            .collect();

        for (entrypoint, trace) in self.entrypoint_results.iter() {
            for retrigger in trace.tracing_result.retriggers {
                if possible_retriggers.contains(&retrigger) {
                    retriggered_entrypoints.insert(entrypoint.clone());
                    break;
                }
            }
        }
        retriggered_entrypoints
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
