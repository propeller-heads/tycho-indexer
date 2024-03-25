#![allow(dead_code)] // TODO: remove when used
use std::collections::{HashMap, HashSet, VecDeque};

use tycho_core::{
    dto::TokenBalances,
    models::{ComponentId, MessageWithBlock},
    Bytes,
};

use super::evm::{Block, FilteredUpdates};

pub struct RevertBuffer<BM> {
    blocks: VecDeque<BM>,
}

impl<BM: MessageWithBlock<Block>> RevertBuffer<BM> {
    pub fn new() -> Self {
        Self { blocks: VecDeque::new() }
    }

    pub fn insert_block(&mut self, new: BM) {
        self.blocks.push_back(new);
    }

    // Given a new chain finalized block height, retrieve and drain all finalized block messages
    // from the buffer.
    pub fn drain_new_finalized_blocks(&mut self, final_block_height: u64) -> Vec<BM> {
        let mut res = Vec::new();

        while let Some(block) = self.blocks.pop_front() {
            if block.block().number > final_block_height {
                // We expect blocks to be ordered by ascending block number order
                break;
            }
            res.push(block);
        }
        res
    }
}

impl<BM: MessageWithBlock<Block>> Default for RevertBuffer<BM> {
    fn default() -> Self {
        Self::new()
    }
}

impl<B> RevertBuffer<B>
where
    B: FilteredUpdates,
{
    fn lookup_state(
        &self,
        keys: &[(&B::IdType, &B::KeyType)],
    ) -> (HashMap<(B::IdType, B::KeyType), B::ValueType>, Vec<(B::IdType, B::KeyType)>)
    where
        B::KeyType: std::hash::Hash + std::cmp::Eq + Clone,
        B::IdType: std::hash::Hash + std::cmp::Eq + Clone,
    {
        let mut res = HashMap::new();
        let mut remaning_keys: HashSet<(B::IdType, B::KeyType)> = HashSet::from_iter(
            keys.iter()
                .map(|(c_id, attr)| (c_id.to_owned().clone(), attr.to_owned().clone())),
        );

        for block_change in self.blocks.iter().rev() {
            if remaning_keys.is_empty() {
                break;
            }

            for (key, val) in block_change.get_filtered_state_update(
                remaning_keys
                    .iter()
                    .map(|k| (&k.0, &k.1))
                    .collect(),
            ) {
                if remaning_keys.remove(&(key.0.clone(), key.1.clone())) {
                    res.insert(key, val);
                }
            }
        }

        (res, remaning_keys.into_iter().collect())
    }

    #[allow(clippy::mutable_key_type)] // Clippy thinks that tuple with Bytes are a mutable type.
    fn lookup_balances(
        &self,
        keys: &[(&ComponentId, &Bytes)],
    ) -> (HashMap<String, TokenBalances>, Vec<(ComponentId, Bytes)>) {
        let mut res = HashMap::new();
        let mut remaning_keys: HashSet<_> = keys
            .iter()
            .map(|(c_id, token)| (c_id.to_string(), token.to_owned().to_owned()))
            .collect();

        for block_change in self.blocks.iter().rev() {
            if remaning_keys.is_empty() {
                break;
            }
            for (key, val) in block_change.get_filtered_balance_update(keys.to_vec().clone()) {
                if remaning_keys.remove(&key) {
                    res.entry(key).or_insert(val);
                }
            }
        }

        let mut results: HashMap<String, TokenBalances> = HashMap::new();
        for ((component_id, address), val) in res {
            results
                .entry(component_id)
                .or_insert(TokenBalances(HashMap::new()))
                .0
                .insert(address, val.into());
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
    use tycho_core::{dto::TokenBalances, models::Chain, Bytes};

    use crate::extractor::evm::{
        Block, BlockEntityChanges, ComponentBalance, ProtocolChangesWithTx, ProtocolStateDelta,
        Transaction,
    };

    use super::RevertBuffer;

    fn transaction() -> Transaction {
        Transaction::new(H256::zero(), H256::zero(), H160::zero(), Some(H160::zero()), 10)
    }

    fn blocks(version: u8) -> Block {
        match version {
            1 => Block {
                number: 1,
                hash: H256::from_low_u64_be(
                    0x0000000000000000000000000000000000000000000000000000000000000001,
                ),
                parent_hash: H256::from_low_u64_be(
                    0x0000000000000000000000000000000000000000000000000000000000000000,
                ),
                chain: Chain::Ethereum,
                ts: NaiveDateTime::from_timestamp_opt(1000, 0).unwrap(),
            },
            2 => Block {
                number: 2,
                hash: H256::from_low_u64_be(
                    0x0000000000000000000000000000000000000000000000000000000000000002,
                ),
                parent_hash: H256::from_low_u64_be(
                    0x0000000000000000000000000000000000000000000000000000000000000001,
                ),
                chain: Chain::Ethereum,
                ts: NaiveDateTime::from_timestamp_opt(2000, 0).unwrap(),
            },
            3 => Block {
                number: 3,
                hash: H256::from_low_u64_be(
                    0x0000000000000000000000000000000000000000000000000000000000000003,
                ),
                parent_hash: H256::from_low_u64_be(
                    0x0000000000000000000000000000000000000000000000000000000000000002,
                ),
                chain: Chain::Ethereum,
                ts: NaiveDateTime::from_timestamp_opt(3000, 0).unwrap(),
            },
            _ => panic!("transaction version not implemented"),
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
        revert_buffer.insert_block(get_block_entity(1));
        revert_buffer.insert_block(get_block_entity(2));

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
        revert_buffer.insert_block(get_block_entity(1));
        revert_buffer.insert_block(get_block_entity(2));
        revert_buffer.insert_block(get_block_entity(3));

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
                    TokenBalances(HashMap::from([(
                        token_key.clone(),
                        tycho_core::dto::ComponentBalance {
                            token: token_key.clone(),
                            balance: Bytes::from(3_i32.to_le_bytes()),
                            modify_tx: transaction().hash.into(),
                            component_id: c_ids[0].clone(),
                            balance_float: 3.0,
                        }
                    )]))
                ),
                (
                    c_ids[1].clone(),
                    TokenBalances(HashMap::from([(
                        token_key.clone(),
                        tycho_core::dto::ComponentBalance {
                            token: token_key.clone(),
                            balance: Bytes::from(30_i32.to_le_bytes()),
                            modify_tx: transaction().hash.into(),
                            component_id: c_ids[1].clone(),
                            balance_float: 30.0,
                        }
                    )]))
                )
            ])
        );
    }
}
