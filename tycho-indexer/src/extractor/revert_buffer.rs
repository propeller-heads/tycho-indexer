use chrono::NaiveDateTime;
use std::collections::{HashMap, HashSet, VecDeque};

use tracing::{debug, trace, warn};
use tycho_core::{
    models::{
        blockchain::{Block, BlockScoped},
        protocol::ComponentBalance,
        ComponentId,
    },
    storage::{BlockIdentifier, BlockOrTimestamp, StorageError},
    Bytes,
};

#[derive(Clone, Debug, Copy)]
pub enum BlockNumberOrTimestamp {
    Number(u64),
    Timestamp(NaiveDateTime),
}

impl BlockNumberOrTimestamp {
    fn greater_than(&self, other: &Block) -> bool {
        match self {
            BlockNumberOrTimestamp::Number(n) => n > &other.number,
            BlockNumberOrTimestamp::Timestamp(ts) => ts > &other.ts,
        }
    }
}

impl TryFrom<BlockOrTimestamp> for BlockNumberOrTimestamp {
    type Error = StorageError;

    fn try_from(value: BlockOrTimestamp) -> Result<Self, Self::Error> {
        Ok(match value {
            BlockOrTimestamp::Block(bid) => match bid {
                BlockIdentifier::Number((_, no)) => BlockNumberOrTimestamp::Number(no as u64),
                BlockIdentifier::Hash(_) => {
                    return Err(StorageError::Unexpected("BlockHash unsupported!".to_string()))
                }
                BlockIdentifier::Latest(_) => {
                    return Err(StorageError::Unexpected("Latest marker unsupported!".to_string()))
                }
            },
            BlockOrTimestamp::Timestamp(ts) => BlockNumberOrTimestamp::Timestamp(ts),
        })
    }
}

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
    strict: bool,
}

/// The finality status of a block or block-scoped data.
#[derive(PartialEq, Clone, Debug, Copy)]
pub enum FinalityStatus {
    /// Versions at this status should have been committed to the db.
    Finalized,
    /// Versions with this status should be in the revert buffer.
    Unfinalized,
    /// We have not seen this version yet.
    Unseen,
}

impl<B> RevertBuffer<B>
where
    B: BlockScoped + std::fmt::Debug,
{
    pub(crate) fn new() -> Self {
        Self { block_messages: VecDeque::new(), strict: false }
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
        let target_index = self.find_index(|b| b.block().number == final_block_height);
        let first = self
            .get_block_range(None, None)?
            .next()
            .map(|e| e.block().number);

        if let Some(idx) = target_index {
            // Drain and return every block before the target index.
            let mut temp = self.block_messages.split_off(idx);
            std::mem::swap(&mut self.block_messages, &mut temp);
            trace!(?temp, "RevertBuffer drained blocks");
            Ok(temp.into())
        } else if !self.strict && first.unwrap_or(0) < final_block_height {
            warn!(?first, ?final_block_height, "Finalized block not found in RevertBuffer");
            Ok(Vec::new())
        } else {
            Err(StorageError::NotFound("block".into(), final_block_height.to_string()))
        }
    }

    fn find_index<F: Fn(&B) -> bool>(&self, predicate: F) -> Option<usize> {
        for (index, block_message) in self.block_messages.iter().enumerate() {
            if predicate(block_message) {
                return Some(index);
            }
        }
        None
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

    /// Retrieves a range of blocks from the buffer.
    ///
    /// The retrieved iterator will include both the start and end block of specified range. In case
    /// either start or end block are None, the iterator will start the range at the oldest / end
    /// the range at the latest block.
    pub fn get_block_range(
        &self,
        start_version: Option<BlockNumberOrTimestamp>,
        end_version: Option<BlockNumberOrTimestamp>,
    ) -> Result<impl Iterator<Item = &B>, StorageError> {
        let start_index = if let Some(version) = start_version {
            self.find_index(|b| !version.greater_than(&b.block()))
                .ok_or_else(|| {
                    StorageError::NotFound("Block".to_string(), format!("{:?}", version))
                })?
        } else {
            0
        };

        let end_index = if let Some(version) = end_version {
            let end_idx = self
                .find_index(|b| !version.greater_than(&b.block()))
                .ok_or_else(|| {
                    StorageError::NotFound("Block".to_string(), format!("{:?}", version))
                })?;

            if end_idx < start_index {
                return Err(StorageError::Unexpected(
                    "RevertBuffer: Invalid block range".to_string(),
                ));
            }
            end_idx + 1
        } else {
            self.block_messages.len()
        };

        Ok(self
            .block_messages
            .range(start_index..end_index))
    }

    // Retrieves FinalityStatus for a block, returns None if the buffer is empty.
    pub fn get_finality_status(&self, version: BlockNumberOrTimestamp) -> Option<FinalityStatus> {
        let first_block = self.block_messages.front();
        let last_block = self.block_messages.back();
        match (first_block, last_block) {
            (Some(first), Some(last)) => {
                let first_block = first.block();
                let last_block = last.block();

                if !version.greater_than(&first_block) {
                    Some(FinalityStatus::Finalized)
                } else if (version.greater_than(&first_block)) &
                    (!version.greater_than(&last_block))
                {
                    Some(FinalityStatus::Unfinalized)
                } else {
                    Some(FinalityStatus::Unseen)
                }
            }
            _ => None,
        }
    }
}

/// A RevertBuffer entry containing state updates.
///
/// Enables additional state lookup methods within the buffer.
pub(crate) trait StateUpdateBufferEntry: std::fmt::Debug {
    type ProtocolStateIdType: std::hash::Hash + std::cmp::Eq + Clone;
    type ProtocolStateKeyType: std::hash::Hash + std::cmp::Eq + Clone;
    type ProtocolStateValueType;
    type AccountStateIdType: std::hash::Hash + std::cmp::Eq + Clone;
    type AccountStateKeyType: std::hash::Hash + std::cmp::Eq + Clone;
    type AccountStateValueType;

    fn get_filtered_protocol_state_update(
        &self,
        keys: Vec<(&Self::ProtocolStateIdType, &Self::ProtocolStateKeyType)>,
    ) -> HashMap<
        (Self::ProtocolStateIdType, Self::ProtocolStateKeyType),
        Self::ProtocolStateValueType,
    >;

    fn get_filtered_account_state_update(
        &self,
        keys: Vec<(&Self::AccountStateIdType, &Self::AccountStateKeyType)>,
    ) -> HashMap<(Self::AccountStateIdType, Self::AccountStateKeyType), Self::AccountStateValueType>;

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
    /// Looks up buffered protocol state updates for the provided keys. Returns a map of updates and
    /// a list of keys for which updates were not found in the buffered blocks.
    pub fn lookup_protocol_state(
        &self,
        keys: &[(&B::ProtocolStateIdType, &B::ProtocolStateKeyType)],
    ) -> (
        HashMap<(B::ProtocolStateIdType, B::ProtocolStateKeyType), B::ProtocolStateValueType>,
        Vec<(B::ProtocolStateIdType, B::ProtocolStateKeyType)>,
    ) {
        let mut res = HashMap::new();
        let mut remaining_keys: HashSet<(B::IdType, B::KeyType)> = HashSet::from_iter(
            keys.iter()
                .map(|&(c_id, attr)| (c_id.clone(), attr.clone())),
        );

        for block_message in self.block_messages.iter().rev() {
            if remaining_keys.is_empty() {
                break;
            }

            for (key, val) in block_message.get_filtered_protocol_state_update(
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

    /// Looks up buffered account state updates for the provided keys. Returns a map of updates and
    /// a list of keys for which updates were not found in the buffered blocks.
    pub fn lookup_account_state(
        &self,
        keys: &[(&B::AccountStateIdType, &B::AccountStateKeyType)],
    ) -> (
        HashMap<(B::AccountStateIdType, B::AccountStateKeyType), B::AccountStateValueType>,
        Vec<(B::AccountStateIdType, B::AccountStateKeyType)>,
    ) {
        let mut res = HashMap::new();
        let mut remaining_keys: HashSet<(B::IdType, B::KeyType)> = HashSet::from_iter(
            keys.iter()
                .map(|&(c_id, attr)| (c_id.clone(), attr.clone())),
        );

        for block_message in self.block_messages.iter().rev() {
            if remaining_keys.is_empty() {
                break;
            }

            for (key, val) in block_message.get_filtered_account_state_update(
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
    use rstest::rstest;
    use tycho_core::{models::Chain, storage::StorageError, Bytes};

    use crate::{
        extractor::evm::{
            BlockEntityChanges, ComponentBalance, ProtocolChangesWithTx, ProtocolStateDelta,
            Transaction,
        },
        testing,
    };

    use super::{BlockNumberOrTimestamp, FinalityStatus, RevertBuffer};

    fn transaction() -> Transaction {
        Transaction::new(H256::zero(), H256::zero(), H160::zero(), Some(H160::zero()), 10)
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
                    testing::evm_block(1),
                    0,
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
                    testing::evm_block(2),
                    0,
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
                    testing::evm_block(3),
                    0,
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
        revert_buffer.strict = true;
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

    #[rstest]
    #[case::complete_range(None, None, vec![1, 2, 3])]
    #[case::range(Some("2020-01-01T00:00:12".parse::<NaiveDateTime>().unwrap()), Some("2020-01-01T00:00:24".parse::<NaiveDateTime>().unwrap()), vec![1, 2])]
    #[case::from_start(None, Some("2020-01-01T00:00:24".parse::<NaiveDateTime>().unwrap()), vec![1, 2])]
    #[case::until_end(Some("2020-01-01T00:00:24".parse::<NaiveDateTime>().unwrap()), None, vec![2, 3])]
    fn test_get_block_range(
        #[case] start: Option<NaiveDateTime>,
        #[case] end: Option<NaiveDateTime>,
        #[case] exp: Vec<u64>,
    ) {
        let start = start.map(BlockNumberOrTimestamp::Timestamp);
        let end = end.map(BlockNumberOrTimestamp::Timestamp);
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

        let blocks = revert_buffer
            .get_block_range(start, end)
            .unwrap()
            .map(|e| e.block.number)
            .collect::<Vec<_>>();

        assert_eq!(blocks, exp);
    }

    #[test]
    fn test_get_block_range_empty() {
        let revert_buffer = RevertBuffer::<BlockEntityChanges>::new();

        let res = revert_buffer
            .get_block_range(None, None)
            .unwrap()
            .collect::<Vec<_>>();

        assert_eq!(res, Vec::<&BlockEntityChanges>::new());
    }

    #[rstest]
    #[case::not_found(Some("2020-01-01T00:00:12".parse::<NaiveDateTime>().unwrap()), Some("2020-01-01T00:00:36".parse::<NaiveDateTime>().unwrap()), StorageError::NotFound("Block".to_string(), "Timestamp(2020-01-01T00:00:36)".to_string()))]
    #[case::invalid(Some("2020-01-01T00:00:24".parse::<NaiveDateTime>().unwrap()), Some("2020-01-01T00:00:12".parse::<NaiveDateTime>().unwrap()), StorageError::Unexpected("RevertBuffer: Invalid block range".to_string()))]
    fn test_get_block_range_invalid_range(
        #[case] start: Option<NaiveDateTime>,
        #[case] end: Option<NaiveDateTime>,
        #[case] exp: StorageError,
    ) {
        let start = start.map(BlockNumberOrTimestamp::Timestamp);
        let end = end.map(BlockNumberOrTimestamp::Timestamp);
        let mut revert_buffer = RevertBuffer::new();
        revert_buffer
            .insert_block(get_block_entity(1))
            .unwrap();
        revert_buffer
            .insert_block(get_block_entity(2))
            .unwrap();

        let res = revert_buffer
            .get_block_range(start, end)
            .err()
            .unwrap();

        assert_eq!(res, exp);
    }

    #[rstest]
    #[case::finalized_no(BlockNumberOrTimestamp::Number(0), FinalityStatus::Finalized)]
    #[case::finalized_ts(
        BlockNumberOrTimestamp::Timestamp("2020-01-01T00:00:00".parse().unwrap()),
        FinalityStatus::Finalized
    )]
    #[case::unfinalized_no(BlockNumberOrTimestamp::Number(2), FinalityStatus::Unfinalized)]
    #[case::unfinalized_ts(
        BlockNumberOrTimestamp::Timestamp("2020-01-01T00:00:15".parse().unwrap()), 
        FinalityStatus::Unfinalized
    )]
    #[case::unseen_no(BlockNumberOrTimestamp::Number(5), FinalityStatus::Unseen)]
    #[case::unseen_ts(
        BlockNumberOrTimestamp::Timestamp("2020-01-01T01:00:00".parse().unwrap()),
        FinalityStatus::Unseen
    )]
    fn test_get_finality_status(
        #[case] version: BlockNumberOrTimestamp,
        #[case] exp: FinalityStatus,
    ) {
        let mut buffer = RevertBuffer::new();
        buffer
            .insert_block(get_block_entity(1))
            .unwrap();
        buffer
            .insert_block(get_block_entity(2))
            .unwrap();
        buffer
            .insert_block(get_block_entity(3))
            .unwrap();

        let res = buffer.get_finality_status(version);

        assert_eq!(res, Some(exp));
    }

    #[test]
    fn test_get_finality_status_empty() {
        let buffer = RevertBuffer::<BlockEntityChanges>::new();

        let res = buffer.get_finality_status(BlockNumberOrTimestamp::Number(2));

        assert_eq!(res, None);
    }
}
