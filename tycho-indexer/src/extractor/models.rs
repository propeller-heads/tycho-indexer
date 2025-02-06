#![allow(deprecated)]
use std::collections::{HashMap, HashSet};

use tycho_core::{
    models::{
        blockchain::{Block, BlockAggregatedChanges, BlockScoped, TxWithChanges},
        contract::{AccountBalance, AccountChangesWithTx},
        protocol::{ComponentBalance, ProtocolChangesWithTx, ProtocolComponent},
        token::CurrencyToken,
        Address, AttrStoreKey, Chain, ComponentId,
    },
    Bytes,
};

use crate::extractor::{
    reorg_buffer::ProtocolStateIdType, AccountStateIdType, AccountStateKeyType,
    AccountStateValueType, ExtractionError, ProtocolStateKeyType, ProtocolStateValueType,
    StateUpdateBufferEntry,
};

/// A container for account updates grouped by transaction.
///
/// Hold the detailed state changes for a block alongside with protocol
/// component changes.
#[derive(Debug, PartialEq, Clone)]
#[deprecated(note = "Use BlockChanges instead")]
pub struct BlockContractChanges {
    extractor: String,
    chain: Chain,
    pub block: Block,
    pub finalized_block_height: u64,
    pub revert: bool,
    /// Required here, so it is part of the revert buffer and thus inserted into storage once
    /// finalized.
    pub new_tokens: HashMap<Address, CurrencyToken>,
    /// Vec of updates at this block, aggregated by tx and sorted by tx index in ascending order
    pub tx_updates: Vec<AccountChangesWithTx>,
}

impl BlockContractChanges {
    pub fn new(
        extractor: String,
        chain: Chain,
        block: Block,
        finalized_block_height: u64,
        revert: bool,
        tx_updates: Vec<AccountChangesWithTx>,
    ) -> Self {
        BlockContractChanges {
            extractor,
            chain,
            block,
            finalized_block_height,
            revert,
            new_tokens: HashMap::new(),
            tx_updates,
        }
    }

    pub fn protocol_components(&self) -> Vec<ProtocolComponent> {
        self.tx_updates
            .iter()
            .flat_map(|tx_u| {
                tx_u.protocol_components
                    .values()
                    .cloned()
            })
            .collect()
    }
}

impl BlockScoped for BlockContractChanges {
    fn block(&self) -> tycho_core::models::blockchain::Block {
        self.block.clone()
    }
}

/// A container for state updates grouped by transaction
///
/// Hold the detailed state changes for a block alongside with protocol
/// component changes.
#[derive(Debug, PartialEq, Default, Clone)]
#[deprecated(note = "Use BlockChanges instead")]
pub struct BlockEntityChanges {
    extractor: String,
    chain: Chain,
    pub block: Block,
    pub finalized_block_height: u64,
    pub revert: bool,
    /// Required here, so it is part of the revert buffer and thus inserted into storage once
    /// finalized.
    pub new_tokens: HashMap<Address, CurrencyToken>,
    /// Vec of updates at this block, aggregated by tx and sorted by tx index in ascending order
    pub txs_with_update: Vec<ProtocolChangesWithTx>,
}

impl BlockEntityChanges {
    pub fn new(
        extractor: String,
        chain: Chain,
        block: Block,
        finalized_block_height: u64,
        revert: bool,
        txs_with_update: Vec<ProtocolChangesWithTx>,
    ) -> Self {
        BlockEntityChanges {
            extractor,
            chain,
            block,
            finalized_block_height,
            revert,
            new_tokens: HashMap::new(),
            txs_with_update,
        }
    }

    pub fn protocol_components(&self) -> Vec<ProtocolComponent> {
        self.txs_with_update
            .iter()
            .flat_map(|tx_u| {
                tx_u.new_protocol_components
                    .values()
                    .cloned()
            })
            .collect()
    }
}

impl BlockScoped for BlockEntityChanges {
    fn block(&self) -> tycho_core::models::blockchain::Block {
        self.block.clone()
    }
}

#[derive(Debug, PartialEq, Default, Clone)]
pub struct BlockChanges {
    extractor: String,
    chain: Chain,
    pub block: Block,
    pub finalized_block_height: u64,
    pub revert: bool,
    /// Required here, so it is part of the revert buffer and thus inserted into storage once
    /// finalized.
    pub new_tokens: HashMap<Address, CurrencyToken>,
    /// Vec of updates at this block, aggregated by tx and sorted by tx index in ascending order
    pub txs_with_update: Vec<TxWithChanges>,
}

impl BlockChanges {
    pub fn new(
        extractor: String,
        chain: Chain,
        block: Block,
        finalized_block_height: u64,
        revert: bool,
        txs_with_update: Vec<TxWithChanges>,
    ) -> Self {
        BlockChanges {
            extractor,
            chain,
            block,
            finalized_block_height,
            revert,
            new_tokens: HashMap::new(),
            txs_with_update,
        }
    }

    /// Aggregates state updates.
    ///
    /// This function aggregates the protocol updates
    /// for different protocol components into a [`AggregatedBlockChanges`] object.
    /// This new object should have only one final ProtocolStateDelta and a HashMap to hold
    /// `AccountUpdate` per component_id.
    ///
    /// After merging all updates, a [`AggregatedBlockChanges`] object is returned
    /// which contains, amongst other data, the compacted state updates.
    ///
    /// # Errors
    ///
    /// This returns an error if there was a problem during merge. The error
    /// type is `ExtractionError`.
    pub fn aggregate_updates(self) -> Result<BlockAggregatedChanges, ExtractionError> {
        let mut iter = self.txs_with_update.into_iter();

        // Use unwrap_or_else to provide a default state if iter.next() is None
        let first_state = iter.next().unwrap_or_default();

        let aggregated_changes = iter
            .try_fold(first_state, |mut acc_state, new_state| {
                acc_state
                    .merge(new_state.clone())
                    .map_err(ExtractionError::MergeError)?;
                Ok::<_, ExtractionError>(acc_state.clone())
            })
            .unwrap();

        Ok(BlockAggregatedChanges {
            extractor: self.extractor,
            chain: self.chain,
            block: self.block,
            finalized_block_height: self.finalized_block_height,
            revert: self.revert,
            new_protocol_components: aggregated_changes.protocol_components,
            new_tokens: self.new_tokens,
            deleted_protocol_components: HashMap::new(),
            state_deltas: aggregated_changes.state_updates,
            account_deltas: aggregated_changes.account_deltas,
            component_balances: aggregated_changes.balance_changes,
            account_balances: aggregated_changes.account_balance_changes,
            component_tvl: HashMap::new(),
        })
    }

    pub fn protocol_components(&self) -> Vec<ProtocolComponent> {
        self.txs_with_update
            .iter()
            .flat_map(|tx_u| {
                tx_u.protocol_components
                    .values()
                    .cloned()
            })
            .collect()
    }
}

impl StateUpdateBufferEntry for BlockChanges {
    fn get_filtered_protocol_state_update(
        &self,
        keys: Vec<(&ProtocolStateIdType, &ProtocolStateKeyType)>,
    ) -> HashMap<(ProtocolStateIdType, ProtocolStateKeyType), ProtocolStateValueType> {
        // Convert keys to a HashSet for faster lookups
        let keys_set: HashSet<(&ComponentId, &AttrStoreKey)> = keys.into_iter().collect();
        let mut res = HashMap::new();

        for update in self.txs_with_update.iter().rev() {
            for (component_id, protocol_update) in update.state_updates.iter() {
                for (attr, val) in protocol_update
                    .updated_attributes
                    .iter()
                    .filter(|(attr, _)| keys_set.contains(&(component_id, attr)))
                {
                    res.entry((component_id.clone(), attr.clone()))
                        .or_insert(val.clone());
                }
            }
        }

        res
    }

    #[allow(clippy::mutable_key_type)]
    fn get_filtered_account_state_update(
        &self,
        keys: Vec<(&AccountStateIdType, &AccountStateKeyType)>,
    ) -> HashMap<(AccountStateIdType, AccountStateKeyType), AccountStateValueType> {
        let keys_set: HashSet<_> = keys.into_iter().collect();
        let mut res = HashMap::new();

        for update in self.txs_with_update.iter().rev() {
            for (address, account_update) in update.account_deltas.iter() {
                for (slot, val) in account_update
                    .slots
                    .iter()
                    .filter(|(slot, _)| keys_set.contains(&(address, *slot)))
                {
                    res.entry((address.clone(), slot.clone()))
                        .or_insert(val.clone().unwrap_or_default());
                }
            }
        }

        res
    }

    #[allow(clippy::mutable_key_type)] // Clippy thinks that tuple with Bytes are a mutable type.
    fn get_filtered_component_balance_update(
        &self,
        keys: Vec<(&ComponentId, &Address)>,
    ) -> HashMap<(String, Bytes), ComponentBalance> {
        // Convert keys to a HashSet for faster lookups
        let keys_set: HashSet<(&String, &Bytes)> = keys.into_iter().collect();

        let mut res = HashMap::new();

        for update in self.txs_with_update.iter().rev() {
            for (component_id, balance_update) in update.balance_changes.iter() {
                for (token, value) in balance_update
                    .iter()
                    .filter(|(token, _)| keys_set.contains(&(component_id, token)))
                {
                    res.entry((component_id.clone(), token.clone()))
                        .or_insert(value.clone());
                }
            }
        }

        res
    }

    #[allow(clippy::mutable_key_type)] // Clippy thinks that tuple with Bytes are a mutable type.
    fn get_filtered_account_balance_update(
        &self,
        keys: Vec<(&Address, &Address)>,
    ) -> HashMap<(Address, Address), AccountBalance> {
        // Convert keys to a HashSet for faster lookups
        let keys_set: HashSet<(&Bytes, &Bytes)> = keys.into_iter().collect();

        let mut res = HashMap::new();

        for update in self.txs_with_update.iter().rev() {
            for (account, balance_update) in update.account_balance_changes.iter() {
                for (token, value) in balance_update
                    .iter()
                    .filter(|(token, _)| keys_set.contains(&(account, token)))
                {
                    res.entry((account.clone(), token.clone()))
                        .or_insert(value.clone());
                }
            }
        }

        res
    }
}

impl BlockScoped for BlockChanges {
    fn block(&self) -> tycho_core::models::blockchain::Block {
        self.block.clone()
    }
}

impl From<BlockContractChanges> for BlockChanges {
    fn from(value: BlockContractChanges) -> Self {
        Self {
            extractor: value.extractor,
            chain: value.chain,
            block: value.block,
            finalized_block_height: value.finalized_block_height,
            revert: value.revert,
            new_tokens: value.new_tokens,
            txs_with_update: value
                .tx_updates
                .into_iter()
                .map(Into::into)
                .collect(),
        }
    }
}

impl From<BlockEntityChanges> for BlockChanges {
    fn from(value: BlockEntityChanges) -> Self {
        Self {
            extractor: value.extractor,
            chain: value.chain,
            block: value.block,
            finalized_block_height: value.finalized_block_height,
            revert: value.revert,
            new_tokens: value.new_tokens,
            txs_with_update: value
                .txs_with_update
                .into_iter()
                .map(Into::into)
                .collect(),
        }
    }
}

#[cfg(test)]
pub mod fixtures {
    use super::*;
    use chrono::NaiveDateTime;
    use prost::Message;
    use std::str::FromStr;

    use tycho_core::models::{
        blockchain::Transaction, contract::AccountDelta, protocol::ProtocolComponentStateDelta,
        ChangeType,
    };
    use tycho_storage::postgres::db_fixtures::yesterday_midnight;

    pub const HASH_256_0: &str =
        "0x0000000000000000000000000000000000000000000000000000000000000000";
    pub const HASH_256_1: &str =
        "0x0000000000000000000000000000000000000000000000000000000000000001";

    impl BlockChanges {
        pub fn new_with_tokens(
            extractor: String,
            chain: Chain,
            block: Block,
            finalized_block_height: u64,
            revert: bool,
            new_tokens: HashMap<Address, CurrencyToken>,
            txs_with_update: Vec<TxWithChanges>,
        ) -> Self {
            BlockChanges {
                extractor,
                chain,
                block,
                finalized_block_height,
                revert,
                new_tokens,
                txs_with_update,
            }
        }
    }

    pub fn slots(data: impl IntoIterator<Item = (u64, u64)>) -> HashMap<Bytes, Bytes> {
        data.into_iter()
            .map(|(s, v)| (Bytes::from(s).lpad(32, 0), Bytes::from(v).lpad(32, 0)))
            .collect()
    }

    // Utils function that return slots that match `AccountDelta` slots.
    // TODO: this is temporary, we shoud make AccountDelta.slots use Bytes instead of Option<Bytes>
    pub fn optional_slots(
        data: impl IntoIterator<Item = (u64, u64)>,
    ) -> HashMap<Bytes, Option<Bytes>> {
        data.into_iter()
            .map(|(s, v)| (Bytes::from(s).lpad(32, 0), Some(Bytes::from(v).lpad(32, 0))))
            .collect()
    }

    pub fn transaction01() -> Transaction {
        Transaction::new(
            Bytes::zero(32),
            Bytes::zero(32),
            Bytes::zero(20),
            Some(Bytes::zero(20)),
            10,
        )
    }

    pub fn create_transaction(hash: &str, block: &str, index: u64) -> Transaction {
        Transaction::new(
            hash.parse().unwrap(),
            block.parse().unwrap(),
            Bytes::zero(20),
            Some(Bytes::zero(20)),
            index,
        )
    }

    pub fn create_full_transaction(
        hash: &str,
        block: &str,
        from: &str,
        to: &str,
        index: u64,
    ) -> Transaction {
        Transaction::new(
            hash.parse().unwrap(),
            block.parse().unwrap(),
            from.parse().unwrap(),
            Some(to.parse().unwrap()),
            index,
        )
    }

    fn create_protocol_component(tx_hash: Bytes) -> ProtocolComponent {
        ProtocolComponent {
            id: "d417ff54652c09bd9f31f216b1a2e5d1e28c1dce1ba840c40d16f2b4d09b5902".to_owned(),
            protocol_system: "ambient".to_string(),
            protocol_type_name: String::from("WeightedPool"),
            chain: Chain::Ethereum,
            tokens: vec![
                Bytes::from_str("0x6B175474E89094C44Da98b954EedeAC495271d0F").unwrap(),
                Bytes::from_str("0x6B175474E89094C44Da98b954EedeAC495271d0F").unwrap(),
            ],
            contract_addresses: vec![
                Bytes::from_str("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2").unwrap(),
                Bytes::from_str("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2").unwrap(),
            ],
            static_attributes: HashMap::from([
                ("key1".to_string(), Bytes::from(b"value1".to_vec())),
                ("key2".to_string(), Bytes::from(b"value2".to_vec())),
            ]),
            change: ChangeType::Creation,
            creation_tx: tx_hash,
            created_at: NaiveDateTime::from_timestamp_opt(1000, 0).unwrap(),
        }
    }

    pub fn block_state_changes() -> BlockContractChanges {
        let tx = create_full_transaction(
            "0000000000000000000000000000000000000000000000000000000011121314",
            "0000000000000000000000000000000000000000000000000000000031323334",
            "0x0000000000000000000000000000000041424344",
            "0x0000000000000000000000000000000051525354",
            2,
        );
        let tx_5 = create_full_transaction(
            HASH_256_1,
            "0000000000000000000000000000000000000000000000000000000031323334",
            "0x0000000000000000000000000000000041424344",
            "0x0000000000000000000000000000000051525354",
            5,
        );
        let protocol_component = create_protocol_component(tx.hash.clone());
        let account_addr = Bytes::from_str("0x0000000000000000000000000000000061626364").unwrap();
        let weth_addr = Bytes::from_str("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2").unwrap();
        BlockContractChanges::new(
            "test".to_string(),
            Chain::Ethereum,
            Block::new(
                1,
                Chain::Ethereum,
                Bytes::from_str("0x0000000000000000000000000000000000000000000000000000000031323334").unwrap(),
                Bytes::from_str("0x0000000000000000000000000000000000000000000000000000000021222324").unwrap(),
                NaiveDateTime::from_timestamp_opt(1000, 0).unwrap(),
            ),
            0,
            false,
            vec![
                AccountChangesWithTx {
                    account_deltas: [(
                        account_addr.clone(),
                        AccountDelta::new(
                            Chain::Ethereum,
                            account_addr.clone(),
                            fixtures::optional_slots([
                                (2711790500, 2981278644),
                                (3250766788, 3520254932),
                            ]),
                            Some(Bytes::from(1903326068u64).lpad(32,0)),
                            Some(vec![129, 130, 131, 132].into()),
                            ChangeType::Update,
                        ),
                    )]
                        .into_iter()
                        .collect(),
                    protocol_components: [(protocol_component.id.clone(), protocol_component)]
                        .into_iter()
                        .collect(),
                    component_balances: [(
                        "d417ff54652c09bd9f31f216b1a2e5d1e28c1dce1ba840c40d16f2b4d09b5902".to_string(),
                        [(
                            weth_addr.clone(),
                            ComponentBalance {
                                token: weth_addr.clone(),
                                balance: Bytes::from(50000000.encode_to_vec()),
                                balance_float: 36522027799.0,
                                modify_tx: Bytes::from_str("0x0000000000000000000000000000000000000000000000000000000011121314").unwrap(),
                                component_id: "d417ff54652c09bd9f31f216b1a2e5d1e28c1dce1ba840c40d16f2b4d09b5902".to_string(),
                            },
                        )]
                            .into_iter()
                            .collect(),
                    )]
                        .into_iter()
                        .collect(),
                    account_balances: [(
                        account_addr.clone(),
                        [(
                            weth_addr.clone(),
                            AccountBalance {
                                token: weth_addr.clone(),
                                balance: Bytes::from(50000000.encode_to_vec()),
                                modify_tx: Bytes::from_str("0x0000000000000000000000000000000000000000000000000000000011121314").unwrap(),
                                account: account_addr.clone(),
                            },
                        )]
                        .into_iter()
                        .collect(),
                    )]
                        .into_iter()
                        .collect(),
                    tx,
                },
                AccountChangesWithTx {
                    account_deltas: [(
                        account_addr.clone(),
                        AccountDelta::new(
                            Chain::Ethereum,
                            account_addr.clone(),
                            fixtures::optional_slots([
                                (2711790500, 3250766788),
                                (2442302356, 2711790500),
                            ]),
                            Some(Bytes::from(4059231220u64).lpad(32,0)),
                            Some(vec![1, 2, 3, 4].into()),
                            ChangeType::Update,
                        ),
                    )]
                        .into_iter()
                        .collect(),
                    protocol_components: HashMap::new(),
                    component_balances: [(
                        "d417ff54652c09bd9f31f216b1a2e5d1e28c1dce1ba840c40d16f2b4d09b5902".to_string(),
                        [(
                            weth_addr.clone(),
                            ComponentBalance {
                                token: weth_addr.clone(),
                                balance: Bytes::from(10.encode_to_vec()),
                                balance_float: 2058.0,
                                modify_tx: Bytes::from_str("0x0000000000000000000000000000000000000000000000000000000000000001").unwrap(),
                                component_id: "d417ff54652c09bd9f31f216b1a2e5d1e28c1dce1ba840c40d16f2b4d09b5902".to_string(),
                            },
                        )]
                            .into_iter()
                            .collect(),
                    )]
                        .into_iter()
                        .collect(),
                    account_balances: [(
                        account_addr.clone(),
                        [(
                            weth_addr.clone(),
                            AccountBalance {
                                token: weth_addr,
                                balance: Bytes::from(10.encode_to_vec()),
                                modify_tx: Bytes::from_str("0x0000000000000000000000000000000000000000000000000000000000000001").unwrap(),
                                account: account_addr,
                            },
                        )]
                        .into_iter()
                        .collect(),
                    )]
                        .into_iter()
                        .collect(),
                    tx: tx_5,
                },
            ],
            )
    }

    fn create_state(id: String) -> ProtocolComponentStateDelta {
        let attributes1: HashMap<String, Bytes> = vec![
            ("reserve1".to_owned(), Bytes::from(1000u64).lpad(32, 0)),
            ("reserve2".to_owned(), Bytes::from(500u64).lpad(32, 0)),
            ("static_attribute".to_owned(), Bytes::from(1u64).lpad(32, 0)),
        ]
        .into_iter()
        .collect();
        ProtocolComponentStateDelta {
            component_id: id,
            updated_attributes: attributes1,
            deleted_attributes: HashSet::new(),
        }
    }

    fn protocol_state_with_tx() -> ProtocolChangesWithTx {
        let state_1 = create_state("State1".to_owned());
        let state_2 = create_state("State2".to_owned());
        let states: HashMap<String, ProtocolComponentStateDelta> =
            vec![(state_1.component_id.clone(), state_1), (state_2.component_id.clone(), state_2)]
                .into_iter()
                .collect();
        ProtocolChangesWithTx { protocol_states: states, tx: transaction01(), ..Default::default() }
    }

    pub fn block_entity_changes() -> BlockEntityChanges {
        let tx = create_full_transaction(
            "0x0000000000000000000000000000000000000000000000000000000011121314",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0x0000000000000000000000000000000041424344",
            "0x0000000000000000000000000000000051525354",
            11,
        );
        let attr: HashMap<String, Bytes> = vec![
            ("reserve".to_owned(), Bytes::from(600u64).lpad(32, 0)),
            ("new".to_owned(), Bytes::zero(32)),
        ]
        .into_iter()
        .collect();
        let state_updates: HashMap<String, ProtocolComponentStateDelta> = vec![(
            "State1".to_owned(),
            ProtocolComponentStateDelta {
                component_id: "State1".to_owned(),
                updated_attributes: attr,
                deleted_attributes: HashSet::new(),
            },
        )]
        .into_iter()
        .collect();
        let static_attr: HashMap<String, Bytes> =
            vec![("key".to_owned(), Bytes::from(600u64).lpad(32, 0))]
                .into_iter()
                .collect();
        let new_protocol_components: HashMap<String, ProtocolComponent> = vec![(
            "Pool".to_owned(),
            ProtocolComponent {
                id: "Pool".to_owned(),
                protocol_system: "ambient".to_string(),
                protocol_type_name: "WeightedPool".to_owned(),
                chain: Chain::Ethereum,
                tokens: vec![
                    Bytes::from_str("0x6B175474E89094C44Da98b954EedeAC495271d0F").unwrap(),
                    Bytes::from_str("0x6B175474E89094C44Da98b954EedeAC495271d0F").unwrap(),
                ],
                static_attributes: static_attr,
                contract_addresses: vec![Bytes::from_str(
                    "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
                )
                .unwrap()],
                change: ChangeType::Creation,
                creation_tx: tx.hash.clone(),
                created_at: yesterday_midnight(),
            },
        )]
        .into_iter()
        .collect();
        let new_balances = HashMap::from([(
            "Balance1".to_string(),
            [(
                Bytes::from_str("0x6B175474E89094C44Da98b954EedeAC495271d0F").unwrap(),
                ComponentBalance {
                    token: Bytes::from_str("0x6B175474E89094C44Da98b954EedeAC495271d0F").unwrap(),
                    balance: Bytes::from(1_i32.to_le_bytes()),
                    modify_tx: tx.hash.clone(),
                    component_id: "Balance1".to_string(),
                    balance_float: 16777216.0,
                },
            )]
            .into_iter()
            .collect(),
        )]);
        BlockEntityChanges::new(
            "test".to_string(),
            Chain::Ethereum,
            Block::new(
                1,
                Chain::Ethereum,
                Bytes::from_str(
                    "0x0000000000000000000000000000000000000000000000000000000000000000",
                )
                .unwrap(),
                Bytes::from_str(
                    "0x0000000000000000000000000000000000000000000000000000000021222324",
                )
                .unwrap(),
                yesterday_midnight(),
            ),
            420,
            false,
            vec![
                protocol_state_with_tx(),
                ProtocolChangesWithTx {
                    protocol_states: state_updates,
                    tx,
                    new_protocol_components: new_protocol_components.clone(),
                    balance_changes: new_balances,
                },
            ],
        )
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use prost::Message;
    use std::str::FromStr;

    #[test]
    fn test_block_contract_changes_state_filter() {
        let block = fixtures::block_state_changes();

        let account1 = Bytes::from_str("0000000000000000000000000000000061626364").unwrap();
        let slot1 = Bytes::from(2711790500_u64).lpad(32, 0);
        let slot2 = Bytes::from(3250766788_u64).lpad(32, 0);
        let account_missing = Bytes::from_str("000000000000000000000000000000000badbabe").unwrap();
        let slot_missing = Bytes::from(12345678_u64).lpad(32, 0);

        let keys = vec![
            (&account1, &slot1),
            (&account1, &slot2),
            (&account_missing, &slot1),
            (&account1, &slot_missing),
        ];

        #[allow(clippy::mutable_key_type)]
        // Clippy thinks that hashmaps with Bytes are a mutable type.
        let filtered = BlockChanges::from(block).get_filtered_account_state_update(keys);

        assert_eq!(
            filtered,
            HashMap::from([
                ((account1.clone(), slot1), Bytes::from(3250766788_u64).lpad(32, 0)),
                ((account1, slot2), Bytes::from(3520254932_u64).lpad(32, 0))
            ])
        );
    }

    #[test]
    fn test_block_contract_changes_balance_filter() {
        let block = fixtures::block_state_changes();

        let c_id_key =
            "d417ff54652c09bd9f31f216b1a2e5d1e28c1dce1ba840c40d16f2b4d09b5902".to_string();
        let token_key = Bytes::from_str("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2").unwrap();
        let missing_token = Bytes::from_str("0x0000000000000000000000000000000000000000").unwrap();
        let missing_component = "missing".to_string();

        let keys = vec![
            (&c_id_key, &token_key),
            (&c_id_key, &missing_token),
            (&missing_component, &token_key),
        ];

        #[allow(clippy::mutable_key_type)]
        // Clippy thinks that hashmaps with Bytes are a mutable type.
        let filtered = BlockChanges::from(block).get_filtered_component_balance_update(keys);

        assert_eq!(
            filtered,
            HashMap::from([(
                (c_id_key.clone(), token_key.clone()),
                tycho_core::models::protocol::ComponentBalance {
                    token: Bytes::from_str("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2").unwrap(),
                    balance: Bytes::from(10.encode_to_vec()),
                    balance_float: 2058.0,
                    modify_tx: Bytes::from(
                        "0x0000000000000000000000000000000000000000000000000000000000000001"
                    ),
                    component_id: c_id_key.clone()
                }
            )])
        )
    }

    #[test]
    fn test_block_contract_changes_account_balance_filter() {
        let block = fixtures::block_state_changes();

        let account = Bytes::from_str("0x0000000000000000000000000000000061626364").unwrap();
        let token_key = Bytes::from_str("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2").unwrap();
        let missing_token = Bytes::from_str("0x0000000000000000000000000000000000000000").unwrap();
        let missing_account =
            Bytes::from_str("0x0000000000000000000000000000000000000001").unwrap();

        let keys = vec![
            (&account, &token_key),
            (&account, &missing_token),
            (&missing_account, &token_key),
        ];

        #[allow(clippy::mutable_key_type)]
        // Clippy thinks that hashmaps with Bytes are a mutable type.
        let filtered = BlockChanges::from(block).get_filtered_account_balance_update(keys);

        assert_eq!(
            filtered,
            HashMap::from([(
                (account.clone(), token_key.clone()),
                AccountBalance {
                    token: Bytes::from_str("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2").unwrap(),
                    balance: Bytes::from(10.encode_to_vec()),
                    modify_tx: Bytes::from(
                        "0x0000000000000000000000000000000000000000000000000000000000000001"
                    ),
                    account: account.clone()
                }
            )])
        )
    }

    #[test]
    fn test_block_entity_changes_state_filter() {
        let block = fixtures::block_entity_changes();

        let state1_key = "State1".to_string();
        let reserve_value = "reserve".to_string();
        let missing = "missing".to_string();

        let keys = vec![
            (&state1_key, &reserve_value),
            (&missing, &reserve_value),
            (&state1_key, &missing),
        ];

        let filtered = BlockChanges::from(block).get_filtered_protocol_state_update(keys);
        assert_eq!(
            filtered,
            HashMap::from([(
                (state1_key.clone(), reserve_value.clone()),
                Bytes::from(600u64).lpad(32, 0),
            )])
        );
    }

    #[test]
    fn test_block_entity_changes_balance_filter() {
        let block = fixtures::block_entity_changes();

        let c_id_key = "Balance1".to_string();
        let token_key = Bytes::from_str("0x6B175474E89094C44Da98b954EedeAC495271d0F").unwrap();
        let missing_token = Bytes::from_str("0x0000000000000000000000000000000000000000").unwrap();
        let missing_component = "missing".to_string();

        let keys = vec![
            (&c_id_key, &token_key),
            (&c_id_key, &missing_token),
            (&missing_component, &token_key),
        ];

        #[allow(clippy::mutable_key_type)]
        // Clippy thinks that hashmaps with Bytes are a mutable type.
        let filtered = BlockChanges::from(block).get_filtered_component_balance_update(keys);

        assert_eq!(
            filtered,
            HashMap::from([(
                (c_id_key.clone(), token_key.clone()),
                tycho_core::models::protocol::ComponentBalance {
                    token: Bytes::from_str("0x6B175474E89094C44Da98b954EedeAC495271d0F").unwrap(),
                    balance: Bytes::from(1_i32.to_le_bytes()),
                    balance_float: 16777216.0,
                    modify_tx: Bytes::from(
                        "0x0000000000000000000000000000000000000000000000000000000011121314"
                    ),
                    component_id: c_id_key.clone()
                }
            )])
        )
    }
}
