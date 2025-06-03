use std::collections::{HashMap, HashSet};

use tycho_common::models::{
    blockchain::{EntryPoint, EntryPointWithTracingParams, TracingParams, TracingResult},
    Address, EntryPointId, StoreKey,
};

/// A unique identifier for a storage location, consisting of an address and a storage key.
type StorageLocation = (Address, StoreKey);

pub(super) struct DCICache {
    pub(super) ep_id_to_entrypoint: HashMap<EntryPointId, EntryPoint>,
    pub(super) entrypoint_results: HashMap<(EntryPointId, TracingParams), TracingResult>,
    pub(super) retriggers: HashMap<StorageLocation, HashSet<EntryPointWithTracingParams>>,
    pub(super) tracked_contracts: HashMap<Address, Option<HashSet<StoreKey>>>,
}

impl DCICache {
    pub(super) fn new_empty() -> Self {
        Self {
            ep_id_to_entrypoint: HashMap::new(),
            entrypoint_results: HashMap::new(),
            retriggers: HashMap::new(),
            tracked_contracts: HashMap::new(),
        }
    }
}
