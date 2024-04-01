use std::collections::{HashMap, HashSet, VecDeque};

use tracing::{debug, trace};
use tycho_core::{
    models::{blockchain::BlockScoped, protocol::ComponentBalance, ComponentId},
    storage::StorageError,
    Bytes,
};

/// This buffer temporarily stores blockchain blocks that are not yet finalized. It allows for
/// efficient handling of block reverts without requiring database rollbacks.
///
/// Everytime a new block is received by an extractor, it's pushed here. Then the extractor should
/// check if the revert buffer contains newly finalized blocks, and send them to the db if there are
/// some.
///
/// In case of revert, we can just purge this buffer.
pub(crate) struct RevertBuffer<B: BlockScoped> {
    block_messages: VecDeque<B>,
}

impl<B> RevertBuffer<B>
where
    B: BlockScoped + std::fmt::Debug,
{
    pub(crate) fn new() -> Self {
        Self { block_messages: VecDeque::new() }
    }

    /// Inserts a new block into the buffer. Ensures the new block is the expected next block,
    /// otherwise panics.
    pub fn insert_block(&mut self, new: B) -> Result<(), StorageError> {
        // Make sure the new block matches the one we expect, panic if not.
        if let Some(last_message) = self.block_messages.back() {
            if last_message.block().hash != new.block().parent_hash {
                return Err(StorageError::Unexpected(format!(
                    "Unexpected block sequence. Expected parent hash {} received {}",
                    last_message.block().hash,
                    new.block().parent_hash
                )));
            };
        }

        self.block_messages.push_back(new);

        Ok(())
    }

    /// Drains blocks up to the specified finalized block height. The last finalized block is kept
    /// in the buffer. Returns the drained blocks ordered by ascending number or an error if the
    /// specified block is not found.
    pub fn drain_new_finalized_blocks(
        &mut self,
        final_block_height: u64,
    ) -> Result<Vec<B>, StorageError> {
        debug!(
            "Draining new finalized blocks from RevertBuffer... New chain height {}",
            final_block_height.to_string()
        );

        let mut target_index = None;

        for (index, block_message) in self.block_messages.iter().enumerate() {
            if block_message.block().number == final_block_height {
                target_index = Some(index);
            }
        }

        if let Some(idx) = target_index {
            // Drain and return every block before the target index.
            let mut temp = self.block_messages.split_off(idx);
            std::mem::swap(&mut self.block_messages, &mut temp);
            trace!(?temp, "RevertBuffer drained blocks");
            Ok(temp.into())
        } else {
            Err(StorageError::NotFound("block".into(), final_block_height.to_string()))
        }
    }

    /// Purges all blocks following the specified block hash from the buffer. Returns the purged
    /// blocks ordered by ascending number or an error if the target hash is not found.
    pub fn purge(&mut self, target_hash: Bytes) -> Result<Vec<B>, StorageError> {
        debug!("Purging revert buffer... Target hash {}", target_hash.to_string());
        let mut target_index = None;

        for (index, block_message) in self
            .block_messages
            .iter()
            .rev()
            .enumerate()
        {
            if block_message.block().hash == target_hash {
                target_index = Some(self.block_messages.len() - index);
            }
        }

        if let Some(idx) = target_index {
            let purged = self
                .block_messages
                .split_off(idx)
                .into();
            trace!(?purged, "RevertBuffer purged blocks");
            Ok(purged)
        } else {
            Err(StorageError::NotFound("block".into(), target_hash.to_string()))
        }
    }

    /// Returns an `Option` containing the most recent block in the buffer or `None` if the buffer
    /// is empty
    pub fn get_most_recent_block(&self) -> Option<tycho_core::models::blockchain::Block> {
        if let Some(block_message) = self.block_messages.back() {
            return Some(block_message.block());
        }
        None
    }
}

/// A RevertBuffer entry containing state updates.
///
/// Enables additional state lookuop methods within the buffer.
pub(crate) trait StateUpdateBufferEntry: std::fmt::Debug {
    type IdType: std::hash::Hash + std::cmp::Eq + Clone;
    type KeyType: std::hash::Hash + std::cmp::Eq + Clone;
    type ValueType;

    fn get_filtered_state_update(
        &self,
        keys: Vec<(&Self::IdType, &Self::KeyType)>,
    ) -> HashMap<(Self::IdType, Self::KeyType), Self::ValueType>;

    #[allow(clippy::mutable_key_type)] // Clippy thinks that tuple with Bytes are a mutable type.
    fn get_filtered_balance_update(
        &self,
        keys: Vec<(&String, &Bytes)>,
    ) -> HashMap<(String, Bytes), ComponentBalance>;
}

impl<B> RevertBuffer<B>
where
    B: BlockScoped + StateUpdateBufferEntry,
{
    /// Looks up buffered state updates for the provided keys. Returns a map of updates and a list
    /// of keys for which updates were not found in the buffered blocks.
    #[allow(clippy::type_complexity)] //TODO: use type aliases
    pub fn lookup_state(
        &self,
        keys: &[(&B::IdType, &B::KeyType)],
    ) -> (HashMap<(B::IdType, B::KeyType), B::ValueType>, Vec<(B::IdType, B::KeyType)>) {
        let mut res = HashMap::new();
        let mut remaining_keys: HashSet<(B::IdType, B::KeyType)> = HashSet::from_iter(
            keys.iter()
                .map(|&(c_id, attr)| (c_id.clone(), attr.clone())),
        );

        for block_message in self.block_messages.iter().rev() {
            if remaining_keys.is_empty() {
                break;
            }

            for (key, val) in block_message.get_filtered_state_update(
                remaining_keys
                    .iter()
                    .map(|k| (&k.0, &k.1))
                    .collect(),
            ) {
                if remaining_keys.remove(&(key.0.clone(), key.1.clone())) {
                    res.insert(key, val);
                }
            }
        }

        (res, remaining_keys.into_iter().collect())
    }

    /// Looks up buffered balance updates for the provided component and token keys. Returns a map
    /// where each key is a component ID associated with its token balances, and a list of
    /// component-token pairs for which no updates were found.
    #[allow(clippy::mutable_key_type)] // Clippy thinks that tuple with Bytes are a mutable type.
    #[allow(clippy::type_complexity)]
    pub fn lookup_balances(
        &self,
        keys: &[(&ComponentId, &Bytes)],
    ) -> (HashMap<String, HashMap<Bytes, ComponentBalance>>, Vec<(ComponentId, Bytes)>) {
        let mut res = HashMap::new();
        let mut remaning_keys: HashSet<_> = keys
            .iter()
            .map(|(c_id, token)| (c_id.to_string(), token.to_owned().to_owned()))
            .collect();

        for block_message in self.block_messages.iter().rev() {
            if remaning_keys.is_empty() {
                break;
            }
            for (key, val) in block_message.get_filtered_balance_update(keys.to_vec().clone()) {
                if remaning_keys.remove(&key) {
                    res.entry(key).or_insert(val);
                }
            }
        }

        let mut results: HashMap<String, HashMap<Bytes, ComponentBalance>> = HashMap::new();
        for ((component_id, address), val) in res {
            results
                .entry(component_id)
                .or_default()
                .insert(address, val);
        }

        (results, remaning_keys.into_iter().collect())
    }
}

#[cfg(test)]
mod test {
    use std::{
        collections::{HashMap, HashSet},
        str::FromStr,
    };

    use chrono::NaiveDateTime;
    use ethers::types::{H160, H256};
    use tycho_core::{models::Chain, Bytes};

    use crate::extractor::evm::{
        Block, BlockEntityChanges, ComponentBalance, ProtocolChangesWithTx, ProtocolStateDelta,
        Transaction,
    };

    use super::RevertBuffer;

    fn transaction() -> Transaction {
        Transaction::new(H256::zero(), H256::zero(), H160::zero(), Some(H160::zero()), 10)
    }

    pub fn blocks(version: u64) -> Block {
        if version == 0 {
            panic!("Block version 0 doesn't exist. Smallest version is 1");
        }

        Block {
            number: version,
            hash: H256::from_low_u64_be(version),
            parent_hash: H256::from_low_u64_be(version - 1),
            chain: Chain::Ethereum,
            ts: NaiveDateTime::from_timestamp_opt((version as i64) * 1000, 0).unwrap(),
        }
    }

    fn get_block_entity(version: u8) -> BlockEntityChanges {
        match version {
            1 => {
                let tx = transaction();
                let attr = HashMap::from([
                    ("new".to_owned(), Bytes::from(1_u64.to_be_bytes().to_vec())),
                    ("reserve".to_owned(), Bytes::from(10_u64.to_be_bytes().to_vec())),
                ]);
                let state_updates = HashMap::from([(
                    "State1".to_owned(),
                    ProtocolStateDelta {
                        component_id: "State1".to_owned(),
                        updated_attributes: attr,
                        deleted_attributes: HashSet::new(),
                    },
                )]);
                let new_balances = HashMap::from([
                    (
                        "Balance1".to_string(),
                        [(
                            H160::from_str("0x6B175474E89094C44Da98b954EedeAC495271d0F").unwrap(),
                            ComponentBalance {
                                token: H160::from_str("0x6B175474E89094C44Da98b954EedeAC495271d0F")
                                    .unwrap(),
                                balance: Bytes::from(1_i32.to_le_bytes()),
                                modify_tx: tx.hash,
                                component_id: "Balance1".to_string(),
                                balance_float: 1.0,
                            },
                        )]
                        .into_iter()
                        .collect(),
                    ),
                    (
                        "Balance2".to_string(),
                        [(
                            H160::from_str("0x6B175474E89094C44Da98b954EedeAC495271d0F").unwrap(),
                            ComponentBalance {
                                token: H160::from_str("0x6B175474E89094C44Da98b954EedeAC495271d0F")
                                    .unwrap(),
                                balance: Bytes::from(30_i32.to_le_bytes()),
                                modify_tx: tx.hash,
                                component_id: "Balance2".to_string(),
                                balance_float: 30.0,
                            },
                        )]
                        .into_iter()
                        .collect(),
                    ),
                ]);

                BlockEntityChanges::new(
                    "test".to_string(),
                    Chain::Ethereum,
                    blocks(1),
                    false,
                    vec![ProtocolChangesWithTx {
                        protocol_states: state_updates,
                        tx,
                        balance_changes: new_balances,
                        ..Default::default()
                    }],
                )
            }
            2 => {
                let tx = transaction();
                let state_updates = HashMap::from([
                    (
                        "State1".to_owned(),
                        ProtocolStateDelta {
                            component_id: "State1".to_owned(),
                            updated_attributes: HashMap::from([(
                                "new".to_owned(),
                                Bytes::from(2_u64.to_be_bytes().to_vec()),
                            )]),
                            deleted_attributes: HashSet::new(),
                        },
                    ),
                    (
                        "State2".to_owned(),
                        ProtocolStateDelta {
                            component_id: "State2".to_owned(),
                            updated_attributes: HashMap::from([
                                ("new".to_owned(), Bytes::from(3_u64.to_be_bytes().to_vec())),
                                ("reserve".to_owned(), Bytes::from(30_u64.to_be_bytes().to_vec())),
                            ]),
                            deleted_attributes: HashSet::new(),
                        },
                    ),
                ]);

                BlockEntityChanges::new(
                    "test".to_string(),
                    Chain::Ethereum,
                    blocks(2),
                    false,
                    vec![ProtocolChangesWithTx {
                        protocol_states: state_updates,
                        tx,
                        ..Default::default()
                    }],
                )
            }
            3 => {
                let tx = transaction();

                let balance_changes = HashMap::from([(
                    "Balance1".to_string(),
                    [(
                        H160::from_str("0x6B175474E89094C44Da98b954EedeAC495271d0F").unwrap(),
                        ComponentBalance {
                            token: H160::from_str("0x6B175474E89094C44Da98b954EedeAC495271d0F")
                                .unwrap(),
                            balance: Bytes::from(3_i32.to_le_bytes()),
                            modify_tx: tx.hash,
                            component_id: "Balance1".to_string(),
                            balance_float: 3.0,
                        },
                    )]
                    .into_iter()
                    .collect(),
                )]);

                BlockEntityChanges::new(
                    "test".to_string(),
                    Chain::Ethereum,
                    blocks(3),
                    false,
                    vec![ProtocolChangesWithTx { tx, balance_changes, ..Default::default() }],
                )
            }
            _ => panic!("block entity version not implemented"),
        }
    }
    #[test]
    fn test_revert_buffer_state_lookup() {
        let mut revert_buffer = RevertBuffer::new();
        revert_buffer
            .insert_block(get_block_entity(1))
            .unwrap();
        revert_buffer
            .insert_block(get_block_entity(2))
            .unwrap();

        let c_ids = ["State1".to_string(), "State2".to_string()];
        let new = "new".to_string();
        let reserve = "reserve".to_string();
        let missing = "missing".to_string();

        let keys = vec![
            (&c_ids[0], &new),
            (&c_ids[0], &reserve),
            (&c_ids[1], &reserve),
            (&missing, &new),
            (&c_ids[0], &missing),
        ];

        let (res, mut missing_keys) = revert_buffer.lookup_state(&keys);

        // Need to sort because collecting a HashSet is unstable.
        missing_keys.sort();
        assert_eq!(
            missing_keys,
            vec![(c_ids[0].clone(), missing.clone()), (missing.clone(), new.clone())]
        );
        assert_eq!(
            res,
            HashMap::from([
                ((c_ids[0].clone(), new.clone()), Bytes::from(2_u64.to_be_bytes().to_vec())),
                ((c_ids[0].clone(), reserve.clone()), Bytes::from(10_u64.to_be_bytes().to_vec())),
                ((c_ids[1].clone(), reserve.clone()), Bytes::from(30_u64.to_be_bytes().to_vec()))
            ])
        );
    }

    #[test]
    fn test_revert_buffer_balance_lookup() {
        let mut revert_buffer = RevertBuffer::new();
        revert_buffer
            .insert_block(get_block_entity(1))
            .unwrap();
        revert_buffer
            .insert_block(get_block_entity(2))
            .unwrap();
        revert_buffer
            .insert_block(get_block_entity(3))
            .unwrap();

        let c_ids = ["Balance1".to_string(), "Balance2".to_string()];
        let token_key =
            Bytes::from(H160::from_str("0x6B175474E89094C44Da98b954EedeAC495271d0F").unwrap());
        let missing_token =
            Bytes::from(H160::from_str("0x0000000000000000000000000000000000000000").unwrap());
        let missing_component = "missing".to_string();

        let keys = vec![
            (&c_ids[0], &token_key),
            (&c_ids[1], &token_key),
            (&c_ids[1], &missing_token),
            (&missing_component, &token_key),
        ];

        let (res, mut missing_keys) = revert_buffer.lookup_balances(&keys);

        // Need to sort because collecting a HashSet is unstable.
        missing_keys.sort();
        assert_eq!(
            missing_keys,
            vec![
                (c_ids[1].clone(), missing_token.clone()),
                (missing_component.clone(), token_key.clone())
            ]
        );
        assert_eq!(
            res,
            HashMap::from([
                (
                    c_ids[0].clone(),
                    HashMap::from([(
                        token_key.clone(),
                        tycho_core::models::protocol::ComponentBalance {
                            token: token_key.clone(),
                            new_balance: Bytes::from(3_i32.to_le_bytes()),
                            modify_tx: transaction().hash.into(),
                            component_id: c_ids[0].clone(),
                            balance_float: 3.0,
                        }
                    )])
                ),
                (
                    c_ids[1].clone(),
                    HashMap::from([(
                        token_key.clone(),
                        tycho_core::models::protocol::ComponentBalance {
                            token: token_key.clone(),
                            new_balance: Bytes::from(30_i32.to_le_bytes()),
                            modify_tx: transaction().hash.into(),
                            component_id: c_ids[1].clone(),
                            balance_float: 30.0,
                        }
                    )])
                )
            ])
        );
    }

    #[test]
    fn test_drain_finalized_blocks() {
        let mut revert_buffer = RevertBuffer::new();
        revert_buffer
            .insert_block(get_block_entity(1))
            .unwrap();
        revert_buffer
            .insert_block(get_block_entity(2))
            .unwrap();
        revert_buffer
            .insert_block(get_block_entity(3))
            .unwrap();

        let finalized = revert_buffer
            .drain_new_finalized_blocks(3)
            .unwrap();

        assert_eq!(revert_buffer.block_messages.len(), 1);
        assert_eq!(finalized, vec![get_block_entity(1), get_block_entity(2)]);

        let unknown = revert_buffer.drain_new_finalized_blocks(999);

        assert!(unknown.is_err());
    }

    #[test]
    fn test_purge() {
        let mut revert_buffer = RevertBuffer::new();
        revert_buffer
            .insert_block(get_block_entity(1))
            .unwrap();
        revert_buffer
            .insert_block(get_block_entity(2))
            .unwrap();
        revert_buffer
            .insert_block(get_block_entity(3))
            .unwrap();

        let purged = revert_buffer
            .purge(
                H256::from_low_u64_be(
                    0x0000000000000000000000000000000000000000000000000000000000000001,
                )
                .into(),
            )
            .unwrap();

        assert_eq!(revert_buffer.block_messages.len(), 1);

        assert_eq!(purged, vec![get_block_entity(2), get_block_entity(3)]);

        let unknown = revert_buffer.purge(
            H256::from_low_u64_be(
                0x0000000000000000000000000000000000000000000000000000000000000999,
            )
            .into(),
        );

        assert!(unknown.is_err());
    }

    #[test]
    #[should_panic]
    fn test_insert_wrong_block() {
        let mut revert_buffer = RevertBuffer::new();
        revert_buffer
            .insert_block(get_block_entity(1))
            .unwrap();
        revert_buffer
            .insert_block(get_block_entity(3))
            .unwrap();
    }
}
