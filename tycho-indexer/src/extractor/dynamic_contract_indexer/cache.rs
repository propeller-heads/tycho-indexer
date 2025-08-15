use std::{
    collections::{hash_map::Entry, HashMap, HashSet, VecDeque},
    hash::Hash,
};

use thiserror::Error;
use tracing::{debug, trace};
use tycho_common::models::{
    blockchain::{Block, EntryPoint, EntryPointWithTracingParams, TracingParams, TracingResult},
    protocol::ProtocolComponent,
    Address, BlockHash, ComponentId, EntryPointId, StoreKey,
};

use super::hook_dci::ComponentProcessingState;

/// A unique identifier for a storage location, consisting of an address and a storage key.
type StorageLocation = (Address, StoreKey);

/// Central data cache used by the Dynamic Contract Indexer (DCI).
pub(super) struct DCICache {
    /// Maps entry point IDs to entry point definitions.
    pub(super) ep_id_to_entrypoint: VersionedCache<EntryPointId, EntryPoint>,
    /// Stores tracing results for entry points paired with specific tracing parameters.
    pub(super) entrypoint_results: VersionedCache<(EntryPointId, TracingParams), TracingResult>,
    /// Maps a storage location to entry points that should be retriggered when that location
    /// changes.
    pub(super) retriggers: VersionedCache<StorageLocation, HashSet<EntryPointWithTracingParams>>,
    /// Stores tracked contract addresses and their associated storage keys.
    pub(super) tracked_contracts: VersionedCache<Address, Option<HashSet<StoreKey>>>,
    /// Stores addresses identified as ERC-20 tokens to skip full indexing.
    /// perf: implement a versioned wrapper around HashSet, similar to VersionedCache for HashMap
    pub(super) erc20_addresses: VersionedCache<Address, bool>,
    /// Stores manually blacklisted addresses that should skip full indexing
    /// but are not tokens (e.g., UniswapV4 pool manager).
    pub(super) blacklisted_addresses: VersionedCache<Address, bool>,
}

impl DCICache {
    pub(super) fn new() -> Self {
        Self {
            ep_id_to_entrypoint: VersionedCache::new(),
            entrypoint_results: VersionedCache::new(),
            retriggers: VersionedCache::new(),
            tracked_contracts: VersionedCache::new(),
            erc20_addresses: VersionedCache::new(),
            blacklisted_addresses: VersionedCache::new(),
        }
    }

    /// Reverts the cache to the state at a specific block hash.
    ///
    /// This operation will discard all changes made in blocks after the specified block.
    /// Errors if the block is not found and is not the parent of the latest pending block.
    ///
    /// # Arguments
    /// * `block` - The block to revert to.
    ///
    /// # Returns
    /// * `Ok(())` - On successful reversion
    /// * `Err(DCICacheError::RevertToBlockNotFound)` - If the block is not found in one of the
    ///   pending layers
    pub(super) fn revert_to(&mut self, block: &BlockHash) -> Result<(), DCICacheError> {
        self.ep_id_to_entrypoint
            .revert_to(block)?;
        self.entrypoint_results
            .revert_to(block)?;
        self.retriggers.revert_to(block)?;
        self.tracked_contracts
            .revert_to(block)?;
        self.erc20_addresses.revert_to(block)?;
        self.blacklisted_addresses
            .revert_to(block)?;

        Ok(())
    }

    /// Move new finalized blocks state to the permanent layer.
    ///
    /// # Arguments
    /// * `finalized_block_height` - The height of the finalized block.
    pub(super) fn handle_finality(
        &mut self,
        finalized_block_height: u64,
    ) -> Result<(), DCICacheError> {
        self.ep_id_to_entrypoint
            .handle_finality(finalized_block_height)?;
        self.entrypoint_results
            .handle_finality(finalized_block_height)?;
        self.retriggers
            .handle_finality(finalized_block_height)?;
        self.tracked_contracts
            .handle_finality(finalized_block_height)?;
        self.erc20_addresses
            .handle_finality(finalized_block_height)?;
        self.blacklisted_addresses
            .handle_finality(finalized_block_height)?;

        Ok(())
    }

    /// Tries to insert a block layer for the given block.
    /// If the block already exists, no-op.
    /// If the block does not exist, we check if it's the next block in the chain. If it's not it
    /// returns an error.
    ///
    /// # Arguments
    /// * `block` - The block to validate and ensure the layer for.
    ///
    /// # Returns
    /// * `Ok(())` - On successful layer creation
    /// * `Err(DCICacheError::UnexpectedBlockOrder)` - If the inserted block is not the correct
    ///   order
    pub(super) fn try_insert_block_layer(&mut self, block: &Block) -> Result<(), DCICacheError> {
        self.ep_id_to_entrypoint
            .validate_and_ensure_block_layer_internal(block)?;
        self.entrypoint_results
            .validate_and_ensure_block_layer_internal(block)?;
        self.retriggers
            .validate_and_ensure_block_layer_internal(block)?;
        self.tracked_contracts
            .validate_and_ensure_block_layer_internal(block)?;

        Ok(())
    }
}

/// Central data cache used by the Hooks Dynamic Contract Indexer (HooksDCI).
pub(super) struct HooksDCICache {
    /// Maps component IDs to their processing state.
    pub(super) component_states: VersionedCache<ComponentId, ComponentProcessingState>,
    /// Stores ProtocolComponent data for both newly created and mutated components.
    pub(super) protocol_components: VersionedCache<ComponentId, ProtocolComponent>,
}

impl HooksDCICache {
    pub(super) fn new() -> Self {
        Self { component_states: VersionedCache::new(), protocol_components: VersionedCache::new() }
    }

    /// Reverts the cache to the state at a specific block hash.
    ///
    /// This operation will discard all changes made in blocks after the specified block.
    /// Errors if the block is not found and is not the parent of the latest pending block.
    ///
    /// # Arguments
    /// * `block` - The block to revert to.
    ///
    /// # Returns
    /// * `Ok(())` - On successful reversion
    /// * `Err(DCICacheError::RevertToBlockNotFound)` - If the block is not found in one of the
    ///   pending layers
    pub(super) fn revert_to(&mut self, block: &BlockHash) -> Result<(), DCICacheError> {
        self.component_states.revert_to(block)?;
        self.protocol_components
            .revert_to(block)?;
        Ok(())
    }

    /// Move new finalized blocks state to the permanent layer.
    ///
    /// # Arguments
    /// * `finalized_block_height` - The height of the finalized block.
    pub(super) fn handle_finality(
        &mut self,
        finalized_block_height: u64,
    ) -> Result<(), DCICacheError> {
        self.component_states
            .handle_finality(finalized_block_height)?;
        self.protocol_components
            .handle_finality(finalized_block_height)?;
        Ok(())
    }

    /// Tries to insert a block layer for the given block.
    /// If the block already exists, no-op.
    /// If the block does not exist, we check if it's the next block in the chain. If it's not it
    /// returns an error.
    ///
    /// # Arguments
    /// * `block` - The block to validate and ensure the layer for.
    ///
    /// # Returns
    /// * `Ok(())` - On successful layer creation
    /// * `Err(DCICacheError::UnexpectedBlockOrder)` - If the inserted block is not the correct
    ///   order
    pub(super) fn try_insert_block_layer(&mut self, block: &Block) -> Result<(), DCICacheError> {
        self.component_states
            .validate_and_ensure_block_layer_internal(block)?;
        self.protocol_components
            .validate_and_ensure_block_layer_internal(block)?;
        Ok(())
    }
}

#[derive(Error, Debug, PartialEq)]
pub enum DCICacheError {
    #[error("Unexpected block order: new block number {0} is not a child of {1}")]
    UnexpectedBlockOrder(u64, u64),
    #[error("Block {0} not found in pending cache in context: {1}")]
    BlockNotFound(String, String),
}

/// A versioned data container scoped to a specific block.
///
/// Stores key-value pairs for a block, used in the pending portion of a cache.
#[derive(Clone)]
struct BlockScopedMap<K, V> {
    /// Block metadata for this layer.
    block: Block,
    /// Key-value store scoped to the block.
    data: HashMap<K, V>,
}

/// A cache structure that supports versioned storage by block.
///
/// It contains:
/// - Permanent data that is not revertable.
/// - Pending data organized in layers per block, supporting reverts.
pub(super) struct VersionedCache<K, V> {
    /// Entries that are permanent and not affected by block reverts.
    permanent: HashMap<K, V>,
    /// Stack of pending block-scoped layers. These can be reverted.
    pending: VecDeque<BlockScopedMap<K, V>>,
}
impl<K, V> VersionedCache<K, V>
where
    K: Eq + Hash + Clone,
    V: Clone,
{
    pub(super) fn new() -> Self {
        Self { permanent: HashMap::new(), pending: VecDeque::new() }
    }

    /// Inserts a key-value pair into the permanent layer.
    pub(super) fn insert_permanent(&mut self, k: K, v: V) {
        self.permanent.insert(k, v);
    }

    /// Inserts a key-value pair into the pending layer for the specified block.
    ///
    /// An error is returned if the layer for the block is not found.
    pub(super) fn insert_pending(&mut self, block: Block, k: K, v: V) -> Result<(), DCICacheError> {
        let layer = self.get_layer_mut(&block)?;
        layer.data.insert(k, v);
        Ok(())
    }

    /// Adds multiple key-value pairs to the permanent layer.
    pub(super) fn extend_permanent(&mut self, entries: impl IntoIterator<Item = (K, V)>) {
        self.permanent.extend(entries);
    }

    /// Adds multiple key-value pairs to the pending layer for the given block.
    ///
    /// An error is returned if the layer for the block is not found.
    pub(super) fn extend_pending(
        &mut self,
        block: Block,
        entries: impl IntoIterator<Item = (K, V)>,
    ) -> Result<(), DCICacheError> {
        let layer = self.get_layer_mut(&block)?;
        layer.data.extend(entries);
        Ok(())
    }

    /// Gets a mutable entry to a value in the permanent layer.
    pub(super) fn permanent_entry<'a>(&'a mut self, k: &K) -> Entry<'a, K, V> {
        self.permanent.entry(k.clone())
    }

    /// Gets a mutable entry to a value in the pending layer for the specified block.
    ///
    /// An error is returned if the layer for the block is not found.
    pub(super) fn pending_entry<'a>(
        &'a mut self,
        block: &Block,
        k: &K,
    ) -> Result<Entry<'a, K, V>, DCICacheError> {
        let layer = self.get_layer_mut(block)?;
        Ok(layer.data.entry(k.clone()))
    }

    /// Retrieves a value for a key, checking latest pending block first, then permanent.
    pub(super) fn get(&self, k: &K) -> Option<&V> {
        for layer in self.pending.iter().rev() {
            if let Some(v) = layer.data.get(k) {
                return Some(v);
            }
        }
        self.permanent.get(k)
    }

    /// Checks if the given key exists in either the pending or permanent layer.
    pub(super) fn contains_key(&self, key: &K) -> bool {
        for layer in self.pending.iter().rev() {
            if layer.data.contains_key(key) {
                return true;
            }
        }
        self.permanent.contains_key(key)
    }

    /// Process block finality by moving all finalized layers from pending to permanent storage.
    ///
    /// # Arguments
    /// * `finalized_block_height` - The block number of the finalized block
    ///
    /// # Returns
    /// * `Ok(())` - On successful processing
    /// * `Err(DCICacheError::FinalityNotFound)` - If the finalized block is not found in pending
    ///   layers
    ///
    /// Note: to make sure the finalized height is always found, we keep the finalized block in the
    /// pending layers. For example:
    /// If pending layers contain blocks [100, 101, 102, 103] and block 102 is finalized:
    /// - Blocks 100 and 101 are moved to permanent storage
    /// - Block 102 and 103 remain in pending storage
    pub(super) fn handle_finality(
        &mut self,
        finalized_block_height: u64,
    ) -> Result<(), DCICacheError> {
        if self.pending.is_empty() {
            return Ok(());
        }

        trace!(
            "Handling finality for block {}, pending layers: {:?}",
            finalized_block_height,
            self.pending
                .iter()
                .map(|layer| layer.block.number)
                .collect::<Vec<_>>()
        );

        let finalized_index = self
            .pending
            .iter()
            .position(|layer| layer.block.number == finalized_block_height)
            .ok_or_else(|| {
                DCICacheError::BlockNotFound(
                    finalized_block_height.to_string(),
                    "finality".to_string(),
                )
            })?;

        // Move all finalized layers but the last one to permanent storage
        let finalized_layers: Vec<_> = self
            .pending
            .drain(..finalized_index)
            .collect();

        for layer in finalized_layers {
            self.permanent.extend(layer.data);
        }

        Ok(())
    }

    /// Reverts the pending layers to the state of a specific block.
    ///
    /// This will remove all block layers added after the specified block.
    ///
    /// Errors if the block is not found and is not the parent of the latest pending block.
    ///
    /// # Arguments
    /// * `block` - The block to revert to.
    ///
    /// # Returns
    /// * `Ok(())` - On successful reversion
    /// * `Err(DCICacheError::RevertToBlockNotFound)` - If the block is not found in the pending
    ///   layers
    pub(super) fn revert_to(&mut self, block: &BlockHash) -> Result<(), DCICacheError> {
        // If there are no pending layers, do nothing
        if self.pending.is_empty() {
            return Ok(());
        }

        debug!("Purging DCI cache... Target hash {}", block.to_string());

        let mut found = false;
        for (index, layer) in self.pending.iter().enumerate().rev() {
            if layer.block.hash == *block {
                let _ = self.pending.split_off(index + 1); // +1 to keep the target block
                found = true;
                break;
            }
        }

        if !found {
            // On startup, the pending cache could not contain the latest finalized block but only
            // its child. In this case, we clear the pending cache and return.
            if self
                .pending
                .front()
                .unwrap()
                .block
                .parent_hash ==
                *block
            {
                self.pending.clear();
                return Ok(());
            }

            // Otherwise, we're in an erroneous state.
            return Err(DCICacheError::BlockNotFound(block.to_string(), "revert to".to_string()));
        }

        Ok(())
    }

    /// Validates block order and ensures the corresponding block layer exists.
    ///
    /// A valid block must:
    /// - Be the same block as the most recent pending layer;
    /// - Or be the child of the current pending block.
    ///
    /// Fails if blocks arrive out of order.
    ///
    /// # Arguments
    /// * `block` - The block used to determine or create the layer.
    ///
    /// # Returns
    /// * `Ok(())` - On successful validation and layer creation
    /// * `Err(DCICacheError::UnexpectedBlockOrder)` - On invalid chain progression
    fn validate_and_ensure_block_layer_internal(
        &mut self,
        block: &Block,
    ) -> Result<(), DCICacheError> {
        match self.pending.back() {
            None => {
                self.pending
                    .push_back(BlockScopedMap { block: block.clone(), data: HashMap::new() });
            }
            Some(last_layer) if last_layer.block == *block => {
                // no-op, already exists
            }
            Some(last_layer) if last_layer.block.hash == block.parent_hash => {
                self.pending
                    .push_back(BlockScopedMap { block: block.clone(), data: HashMap::new() });
            }
            Some(last_layer) => {
                return Err(DCICacheError::UnexpectedBlockOrder(
                    block.number,
                    last_layer.block.number,
                ));
            }
        }

        Ok(())
    }

    /// Gets a mutable reference to the layer for the given block.
    ///
    /// # Arguments
    /// * `block` - The block to get the layer for.
    ///
    /// # Returns
    /// * `Ok(&mut BlockScopedMap<K, V>)` - Layer for the block
    /// * `Err(DCICacheError::BlockNotFound)` - If the block is not found in the pending layers
    fn get_layer_mut(&mut self, block: &Block) -> Result<&mut BlockScopedMap<K, V>, DCICacheError> {
        self.pending
            .iter_mut()
            .find(|layer| layer.block == *block)
            .ok_or_else(|| {
                DCICacheError::BlockNotFound(block.number.to_string(), "get layer".to_string())
            })
    }

    /// Returns full permanent state (only available in tests).
    #[cfg(test)]
    pub fn get_full_permanent_state(&self) -> &HashMap<K, V> {
        &self.permanent
    }

    /// Validates block order and ensures the corresponding block layer exists (only available in
    /// tests).
    #[cfg(test)]
    pub fn validate_and_ensure_block_layer_test(
        &mut self,
        block: &Block,
    ) -> Result<(), DCICacheError> {
        self.validate_and_ensure_block_layer_internal(block)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use chrono::NaiveDateTime;
    use tycho_common::{
        models::{
            blockchain::{
                Block, EntryPoint, EntryPointWithTracingParams, RPCTracerParams, TracingParams,
                TracingResult,
            },
            Address, BlockHash, Chain, StoreKey,
        },
        Bytes,
    };

    use super::*;

    fn create_test_block(number: u64, hash: &str, parent_hash: &str) -> Block {
        Block {
            number,
            hash: BlockHash::from(hash),
            parent_hash: BlockHash::from(parent_hash),
            ts: NaiveDateTime::from_timestamp_opt(0, 0).unwrap(),
            chain: Chain::Ethereum,
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

    fn get_entrypoint_with_tracing_params(version: u8) -> EntryPointWithTracingParams {
        EntryPointWithTracingParams::new(get_entrypoint(version), get_tracing_params(version))
    }

    #[test]
    fn test_versioned_cache_permanent_operations() {
        let mut cache: VersionedCache<String, u32> = VersionedCache::new();

        // Test permanent operations
        cache.insert_permanent("key1".to_string(), 1);
        assert_eq!(cache.get(&"key1".to_string()), Some(&1));
        assert!(cache.contains_key(&"key1".to_string()));

        // Test permanent entry
        cache
            .permanent_entry(&"key2".to_string())
            .or_insert(2);
        assert_eq!(cache.get(&"key2".to_string()), Some(&2));

        // Test permanent update
        cache.extend_permanent(vec![("key3".to_string(), 3), ("key4".to_string(), 4)]);
        assert_eq!(cache.get(&"key3".to_string()), Some(&3));
        assert_eq!(cache.get(&"key4".to_string()), Some(&4));
    }

    #[test]
    fn test_versioned_cache_pending_operations() {
        let mut cache: VersionedCache<String, u32> = VersionedCache::new();
        let block1 = create_test_block(1, "0x01", "0x00");
        let block2 = create_test_block(2, "0x02", "0x01");
        cache
            .validate_and_ensure_block_layer_test(&block1)
            .unwrap();
        cache
            .validate_and_ensure_block_layer_test(&block2)
            .unwrap();

        // Test pending insert
        cache
            .insert_pending(block1.clone(), "key1".to_string(), 1)
            .unwrap();
        assert_eq!(cache.get(&"key1".to_string()), Some(&1));

        // Test pending entry
        cache
            .pending_entry(&block1, &"key2".to_string())
            .unwrap()
            .or_insert(2);
        assert_eq!(cache.get(&"key2".to_string()), Some(&2));

        // Test pending update
        cache
            .extend_pending(block1.clone(), vec![("key3".to_string(), 3), ("key4".to_string(), 4)])
            .unwrap();
        assert_eq!(cache.get(&"key3".to_string()), Some(&3));
        assert_eq!(cache.get(&"key4".to_string()), Some(&4));

        // Test block ordering
        cache
            .insert_pending(block2.clone(), "key5".to_string(), 5)
            .unwrap();
        assert_eq!(cache.get(&"key5".to_string()), Some(&5));

        // Test invalid block order
        let invalid_block = create_test_block(3, "0x03", "0x00"); // Wrong parent hash
        assert!(cache
            .insert_pending(invalid_block, "key6".to_string(), 6)
            .is_err());
    }

    #[test]
    fn test_versioned_cache_revert() {
        let mut cache: VersionedCache<String, u32> = VersionedCache::new();
        let block1 = create_test_block(1, "0x01", "0x00");
        let block2 = create_test_block(2, "0x02", "0x01");
        let block3 = create_test_block(3, "0x03", "0x02");
        let block4 = create_test_block(4, "0x04", "0x03");
        cache
            .validate_and_ensure_block_layer_test(&block1)
            .unwrap();
        cache
            .validate_and_ensure_block_layer_test(&block2)
            .unwrap();
        cache
            .validate_and_ensure_block_layer_test(&block3)
            .unwrap();
        cache
            .validate_and_ensure_block_layer_test(&block4)
            .unwrap();

        // Insert data in both blocks
        cache.insert_permanent("perm".to_string(), 0);
        cache
            .insert_pending(block1.clone(), "key1".to_string(), 1)
            .unwrap();
        cache
            .insert_pending(block2.clone(), "key2".to_string(), 2)
            .unwrap();

        // Verify initial state
        assert_eq!(cache.get(&"perm".to_string()), Some(&0));
        assert_eq!(cache.get(&"key1".to_string()), Some(&1));
        assert_eq!(cache.get(&"key2".to_string()), Some(&2));

        // Revert to block1
        cache.revert_to(&block1.hash).unwrap();
        assert_eq!(cache.get(&"perm".to_string()), Some(&0));
        assert_eq!(cache.get(&"key1".to_string()), Some(&1));
        assert_eq!(cache.get(&"key2".to_string()), None);

        // Make sure we can insert correct new layers after reverting
        cache
            .validate_and_ensure_block_layer_test(&block2)
            .unwrap();
        cache
            .validate_and_ensure_block_layer_test(&block3)
            .unwrap();
    }

    #[test]
    fn test_dci_cache_revert() {
        let mut cache = DCICache::new();
        let block1 = create_test_block(1, "0x01", "0x00");
        let block2 = create_test_block(2, "0x02", "0x01");
        cache
            .try_insert_block_layer(&block1)
            .unwrap();
        cache
            .try_insert_block_layer(&block2)
            .unwrap();

        // Setup test data
        let entrypoint = get_entrypoint(1);
        let tracing_params = get_tracing_params(1);
        let tracing_result = get_tracing_result(1);
        let address = Address::from("0x1234");
        let store_key = StoreKey::from("0x5678");
        let entrypoint_with_params = get_entrypoint_with_tracing_params(1);
        let mut retrigger_set = HashSet::new();
        retrigger_set.insert(entrypoint_with_params);

        // Insert data in block1
        cache
            .ep_id_to_entrypoint
            .insert_pending(block1.clone(), entrypoint.external_id.clone(), entrypoint.clone())
            .unwrap();
        cache
            .entrypoint_results
            .insert_pending(
                block1.clone(),
                (entrypoint.external_id.clone(), tracing_params.clone()),
                tracing_result.clone(),
            )
            .unwrap();
        cache
            .retriggers
            .insert_pending(
                block1.clone(),
                (address.clone(), store_key.clone()),
                retrigger_set.clone(),
            )
            .unwrap();

        // Insert different data in block2
        let entrypoint2 = get_entrypoint(2);
        cache
            .ep_id_to_entrypoint
            .insert_pending(block2.clone(), entrypoint2.external_id.clone(), entrypoint2.clone())
            .unwrap();

        // Verify initial state
        assert_eq!(
            cache
                .ep_id_to_entrypoint
                .get(&entrypoint.external_id),
            Some(&entrypoint)
        );
        assert_eq!(
            cache
                .ep_id_to_entrypoint
                .get(&entrypoint2.external_id),
            Some(&entrypoint2)
        );

        // Revert to block1
        cache.revert_to(&block1.hash).unwrap();

        // Verify state after revert
        assert_eq!(
            cache
                .ep_id_to_entrypoint
                .get(&entrypoint.external_id),
            Some(&entrypoint)
        );
        assert_eq!(
            cache
                .ep_id_to_entrypoint
                .get(&entrypoint2.external_id),
            None
        );

        // Revert to the latest finalized block (parent of block1)
        cache
            .revert_to(&block1.parent_hash)
            .unwrap();

        assert_eq!(
            cache
                .ep_id_to_entrypoint
                .get_full_permanent_state()
                .len(),
            0
        );
    }

    #[test]
    fn test_versioned_cache_handle_finality() {
        let mut cache = VersionedCache::new();
        let block1 = create_test_block(1, "0x01", "0x00");
        let block2 = create_test_block(2, "0x02", "0x01");
        let block3 = create_test_block(3, "0x03", "0x02");
        cache
            .validate_and_ensure_block_layer_test(&block1)
            .unwrap();
        cache
            .validate_and_ensure_block_layer_test(&block2)
            .unwrap();
        cache
            .validate_and_ensure_block_layer_test(&block3)
            .unwrap();

        // Insert data in block1
        cache
            .insert_pending(block1.clone(), "key1".to_string(), 1)
            .unwrap();

        // Insert data in block2
        cache
            .insert_pending(block2.clone(), "key2".to_string(), 2)
            .unwrap();

        // Insert data in block3
        cache
            .insert_pending(block3.clone(), "key3".to_string(), 3)
            .unwrap();

        assert_eq!(cache.get_full_permanent_state(), &HashMap::new());

        // Handle finality of block2
        cache
            .handle_finality(block2.number)
            .unwrap();

        assert_eq!(cache.get_full_permanent_state(), &HashMap::from([("key1".to_string(), 1)]));

        // block2 should still be in pending
        assert_eq!(cache.pending.len(), 2);
    }

    #[test]
    fn test_versioned_cache_get_latest_version() {
        let mut cache: VersionedCache<String, u32> = VersionedCache::new();
        let block1 = create_test_block(1, "0x01", "0x00");
        let block2 = create_test_block(2, "0x02", "0x01");
        cache
            .validate_and_ensure_block_layer_test(&block1)
            .unwrap();
        cache
            .validate_and_ensure_block_layer_test(&block2)
            .unwrap();

        // Insert same key with different values in different blocks
        cache.insert_permanent("key".to_string(), 1);
        cache.insert_permanent("key2".to_string(), 2);
        cache
            .insert_pending(block1.clone(), "key".to_string(), 2)
            .unwrap();
        cache
            .insert_pending(block2.clone(), "key".to_string(), 3)
            .unwrap();
        cache
            .insert_pending(block2.clone(), "key2".to_string(), 3)
            .unwrap();

        // get() should return the latest version (from block2)
        assert_eq!(cache.get(&"key".to_string()), Some(&3));

        // Revert to block1
        cache.revert_to(&block1.hash).unwrap();

        // Should return version from block1
        assert_eq!(cache.get(&"key".to_string()), Some(&2));
        // Should return permanent version
        assert_eq!(cache.get(&"key2".to_string()), Some(&2));
    }

    #[test]
    fn test_versioned_cache_pending_entry_latest_version() {
        let mut cache: VersionedCache<String, u32> = VersionedCache::new();
        let block1 = create_test_block(1, "0x01", "0x00");
        let block2 = create_test_block(2, "0x02", "0x01");
        cache
            .validate_and_ensure_block_layer_test(&block1)
            .unwrap();
        cache
            .validate_and_ensure_block_layer_test(&block2)
            .unwrap();

        // Insert same key with different values in different blocks
        cache.insert_permanent("key".to_string(), 1);
        cache
            .insert_pending(block1.clone(), "key".to_string(), 2)
            .unwrap();
        cache
            .insert_pending(block2.clone(), "key".to_string(), 3)
            .unwrap();

        // pending_entry() should return the latest version for block2
        let entry = cache
            .pending_entry(&block2, &"key".to_string())
            .unwrap();
        assert_eq!(entry.or_insert(4), &3);

        // Test that pending_entry() creates a new entry if key doesn't exist in that block
        let entry = cache
            .pending_entry(&block2, &"new_key".to_string())
            .unwrap();
        entry.or_insert(5);
        assert_eq!(cache.get(&"new_key".to_string()), Some(&5));
    }

    #[test]
    fn test_versioned_cache_update_overwrites_latest() {
        let mut cache: VersionedCache<String, u32> = VersionedCache::new();
        let block1 = create_test_block(1, "0x01", "0x00");
        let block2 = create_test_block(2, "0x02", "0x01");
        cache
            .validate_and_ensure_block_layer_test(&block1)
            .unwrap();
        cache
            .validate_and_ensure_block_layer_test(&block2)
            .unwrap();

        // Insert initial values
        cache.insert_permanent("key1".to_string(), 1);
        cache.extend_permanent(vec![("key1".to_string(), 10), ("key2".to_string(), 20)]);

        cache
            .insert_pending(block1.clone(), "key2".to_string(), 2)
            .unwrap();
        cache
            .extend_pending(
                block1.clone(),
                vec![("key2".to_string(), 21), ("key3".to_string(), 31)],
            )
            .unwrap();

        cache
            .insert_pending(block2.clone(), "key3".to_string(), 3)
            .unwrap();
        cache
            .extend_pending(block2.clone(), vec![("key4".to_string(), 40)])
            .unwrap();

        // Verify latest versions
        assert_eq!(cache.get(&"key1".to_string()), Some(&10)); // permanent
        assert_eq!(cache.get(&"key2".to_string()), Some(&21)); // block1
        assert_eq!(cache.get(&"key3".to_string()), Some(&3)); // block2
        assert_eq!(cache.get(&"key4".to_string()), Some(&40)); // block2
    }
}
