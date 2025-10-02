#![allow(deprecated)]
use std::collections::{hash_map::Entry, HashMap, HashSet};

use tycho_common::{
    models::{
        blockchain::{
            Block, BlockAggregatedChanges, BlockScoped, DCIUpdate, TracedEntryPoint, TracingResult,
            Transaction, TxWithChanges,
        },
        contract::{AccountBalance, AccountChangesWithTx, AccountToContractChange},
        protocol::{
            ComponentBalance, ProtocolChangesWithTx, ProtocolComponent, ProtocolComponentStateDelta,
        },
        token::Token,
        Address, AttrStoreKey, Chain, ComponentId, MergeError,
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
    pub new_tokens: HashMap<Address, Token>,
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
    fn block(&self) -> tycho_common::models::blockchain::Block {
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
    pub new_tokens: HashMap<Address, Token>,
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
    fn block(&self) -> tycho_common::models::blockchain::Block {
        self.block.clone()
    }
}

/// Storage changes grouped by transaction
#[derive(Debug, PartialEq, Default, Clone)]
pub struct TxWithStorageChanges {
    pub tx: Transaction,
    pub storage_changes: AccountToContractChange,
}

#[derive(Debug, PartialEq, Default, Clone)]
pub struct BlockChanges {
    extractor: String,
    chain: Chain,
    pub block: Block,
    pub finalized_block_height: u64,
    pub revert: bool,
    pub new_tokens: HashMap<Address, Token>,
    /// Vec of updates at this block, aggregated by tx and sorted by tx index in ascending order
    pub txs_with_update: Vec<TxWithChanges>,
    // Raw block storage changes. This is intended as DCI input and is to be omitted from the
    // reorg buffer and aggregation into the `BlockAggregatedChanges` object.
    pub block_storage_changes: Vec<TxWithStorageChanges>,
    /// Required here so that it is part of the reorg buffer and thus inserted into storage once
    /// finalized.
    /// Populated by the `DynamicContractIndexer`
    pub trace_results: Vec<TracedEntryPoint>,
}

impl BlockChanges {
    pub fn new(
        extractor: String,
        chain: Chain,
        block: Block,
        finalized_block_height: u64,
        revert: bool,
        txs_with_update: Vec<TxWithChanges>,
        block_storage_changes: Vec<TxWithStorageChanges>,
    ) -> Self {
        BlockChanges {
            extractor,
            chain,
            block,
            finalized_block_height,
            revert,
            new_tokens: HashMap::new(),
            txs_with_update,
            block_storage_changes,
            trace_results: Vec::new(),
        }
    }

    /// Aggregates component and account updates.
    ///
    /// This function aggregates all protocol updates into a [`BlockAggregatedChanges`] object. This
    /// new object should have all individual changes merged into only one final/compacted change
    /// per component and account. This means there is only one state delta and component balance
    /// per component, and one account delta and account balance per account. DCI trace results are
    /// also aggregated into a result per entry point.
    ///
    /// Note - all non-protocol specific data in the BlockChanges object are lost during
    /// aggregation. This means block_storage_changes is dropped.
    ///
    /// # Errors
    ///
    /// This returns an `ExtractionError` if there was a problem during merge.
    pub fn into_aggregated(
        self,
        db_committed_block_height: Option<u64>,
    ) -> Result<BlockAggregatedChanges, ExtractionError> {
        if db_committed_block_height.is_some_and(|h| h > self.finalized_block_height) {
            return Err(ExtractionError::ReorgBufferError(format!(
                "Database committed block height {:?} is greater than finalized_block_height {}",
                db_committed_block_height, self.finalized_block_height
            )));
        }

        let mut iter = self.txs_with_update.into_iter();

        // Use unwrap_or_else to provide a default state if iter.next() is None
        let first_state = iter.next().unwrap_or_default();

        // Aggregate txs_with_update
        let aggregated_changes = iter
            .try_fold(first_state, |mut acc_state, new_state| {
                acc_state.merge(new_state.clone())?;
                Ok::<_, ExtractionError>(acc_state.clone())
            })
            .unwrap();

        // Aggregate trace_results
        let mut aggregated_trace_results = HashMap::new();
        for result in self.trace_results {
            let external_id = result.entry_point_id();
            aggregated_trace_results
                .entry(external_id)
                .and_modify(|existing: &mut TracingResult| {
                    existing.merge(result.tracing_result.clone())
                })
                .or_insert(result.tracing_result);
        }

        Ok(BlockAggregatedChanges {
            extractor: self.extractor,
            chain: self.chain,
            block: self.block,
            db_committed_block_height,
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
            dci_update: DCIUpdate {
                new_entrypoints: aggregated_changes.entrypoints,
                new_entrypoint_params: aggregated_changes.entrypoint_params,
                trace_results: aggregated_trace_results,
            },
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

/// Inserts or updates a state attribute for a protocol component within a specific transaction.
///
/// If a transaction with the same hash already exists, the state delta is merged with any
/// existing deltas for the same component. Otherwise, a new transaction entry is created.
///
/// # Arguments
///
/// * `txs_with_update` - Mutable reference to the vector of transaction changes
/// * `component_id` - The unique identifier of the protocol component
/// * `tx` - The transaction in which the state change occurred
/// * `attr` - The attribute key being updated
/// * `val` - The new value for the attribute
///
/// # Returns
///
/// * `Ok(())` if the operation succeeds
/// * `Err(MergeError)` if merging with existing deltas fails
pub(crate) fn insert_state_attribute_update(
    txs_with_update: &mut Vec<TxWithChanges>,
    component_id: &ComponentId,
    tx: &Transaction,
    attr: &AttrStoreKey,
    val: &ProtocolStateValueType,
) -> Result<(), MergeError> {
    let delta = ProtocolComponentStateDelta::new(
        component_id,
        HashMap::from([(attr.clone(), val.clone())]),
        HashSet::new(),
    );
    match txs_with_update
        .iter_mut()
        .find(|tx_with_changes| tx_with_changes.tx.hash == tx.hash)
    {
        Some(tx_with_changes) => {
            match tx_with_changes
                .state_updates
                .entry(component_id.clone())
            {
                Entry::Vacant(entry) => {
                    entry.insert(delta);
                }
                Entry::Occupied(mut entry) => {
                    let existing_delta = entry.get_mut();
                    existing_delta.merge(delta)?;
                }
            }
        }
        None => {
            let tx_with_changes = TxWithChanges {
                tx: tx.clone(),
                state_updates: HashMap::from([(component_id.clone(), delta)]),
                ..Default::default()
            };
            txs_with_update.push(tx_with_changes);
        }
    }
    Ok(())
}

/// Inserts a state attribute deletion for a protocol component within a specific transaction.
///
/// If a transaction with the same hash already exists, the state delta is merged with any
/// existing deltas for the same component. Otherwise, a new transaction entry is created.
///
/// # Arguments
///
/// * `txs_with_update` - Mutable reference to the vector of transaction changes
/// * `component_id` - The unique identifier of the protocol component
/// * `tx` - The transaction in which the attribute deletion occurred
/// * `attr` - The attribute key being deleted
///
/// # Returns
///
/// * `Ok(())` if the operation succeeds
/// * `Err(MergeError)` if merging with existing deltas fails
#[allow(dead_code)]
pub(crate) fn insert_state_attribute_deletion(
    txs_with_update: &mut Vec<TxWithChanges>,
    component_id: &ComponentId,
    tx: &Transaction,
    attr: &AttrStoreKey,
) -> Result<(), MergeError> {
    let delta = ProtocolComponentStateDelta::new(
        component_id,
        HashMap::new(),
        HashSet::from([attr.clone()]),
    );
    match txs_with_update
        .iter_mut()
        .find(|tx_with_changes| tx_with_changes.tx.hash == tx.hash)
    {
        Some(tx_with_changes) => {
            match tx_with_changes
                .state_updates
                .entry(component_id.clone())
            {
                Entry::Vacant(entry) => {
                    entry.insert(delta);
                }
                Entry::Occupied(mut entry) => {
                    let existing_delta = entry.get_mut();
                    existing_delta.merge(delta)?;
                }
            }
        }
        None => {
            let tx_with_changes = TxWithChanges {
                tx: tx.clone(),
                state_updates: HashMap::from([(component_id.clone(), delta)]),
                ..Default::default()
            };
            txs_with_update.push(tx_with_changes);
        }
    }
    Ok(())
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
    fn block(&self) -> tycho_common::models::blockchain::Block {
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
            block_storage_changes: Vec::new(),
            trace_results: Vec::new(),
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
            block_storage_changes: Vec::new(),
            trace_results: Vec::new(),
        }
    }
}

#[cfg(test)]
pub mod fixtures {
    use std::str::FromStr;

    use chrono::DateTime;
    use prost::Message;
    use tycho_common::models::{
        blockchain::Transaction, contract::AccountDelta, protocol::ProtocolComponentStateDelta,
        ChangeType,
    };
    use tycho_storage::postgres::db_fixtures::yesterday_midnight;

    use super::*;

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
            new_tokens: HashMap<Address, Token>,
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
                block_storage_changes: Vec::new(),
                trace_results: Vec::new(),
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
            created_at: DateTime::from_timestamp(1000, 0)
                .unwrap()
                .naive_utc(),
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
                DateTime::from_timestamp(1000, 0).unwrap().naive_utc(),
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
                    balance: Bytes::from(1_i32.to_be_bytes()),
                    modify_tx: tx.hash.clone(),
                    component_id: "Balance1".to_string(),
                    balance_float: 1.0,
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
    use std::str::FromStr;

    use fixtures::create_transaction;
    use prost::Message;
    use rstest::rstest;

    use super::*;

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

    #[rstest]
    #[case::commit_before_finalized(None, Ok(None))]
    #[case::commit_before_finalized(Some(4), Ok(Some(4)))]
    #[case::commit_equals_finalized(Some(5), Ok(Some(5)))]
    #[case::commit_exceeds_finalized(Some(6), Err(ExtractionError::ReorgBufferError("Some Error".to_string())))]
    fn into_aggregated_respects_commit_invariant(
        #[case] committed_height: Option<u64>,
        #[case] expected: Result<Option<u64>, ExtractionError>,
    ) {
        use chrono::NaiveDateTime;

        let block = Block::new(
            1,
            Chain::Ethereum,
            Bytes::zero(32),
            Bytes::zero(32),
            NaiveDateTime::from_timestamp_opt(0, 0).unwrap(),
        );

        let changes = BlockChanges::new(
            "test".to_string(),
            Chain::Ethereum,
            block,
            5,
            false,
            Vec::new(),
            Vec::new(),
        );

        let result = changes.into_aggregated(committed_height);

        match expected {
            Ok(expected_height) => {
                let aggregated = result.expect("expected success");
                assert_eq!(aggregated.db_committed_block_height, expected_height);
            }
            Err(ExtractionError::ReorgBufferError(_)) => {
                assert!(matches!(result, Err(ExtractionError::ReorgBufferError(_))));
            }
            _ => panic!("unexpected error type"),
        }
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
                tycho_common::models::protocol::ComponentBalance {
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
                tycho_common::models::protocol::ComponentBalance {
                    token: Bytes::from_str("0x6B175474E89094C44Da98b954EedeAC495271d0F").unwrap(),
                    balance: Bytes::from(1_i32.to_be_bytes()),
                    balance_float: 1.0,
                    modify_tx: Bytes::from(
                        "0x0000000000000000000000000000000000000000000000000000000011121314"
                    ),
                    component_id: c_id_key.clone()
                }
            )])
        )
    }

    #[test]
    fn test_insert_state_attribute_update_new_transaction() {
        use chrono::NaiveDateTime;

        let mut block_changes = BlockChanges::new(
            "test_extractor".to_string(),
            Chain::Ethereum,
            Block::new(
                1,
                Chain::Ethereum,
                Bytes::zero(32),
                Bytes::zero(32),
                NaiveDateTime::from_timestamp_opt(1000, 0).unwrap(),
            ),
            0,
            false,
            vec![],
            vec![],
        );

        let component_id = "test_component".to_string();
        let tx = create_transaction(
            "0x1111111111111111111111111111111111111111111111111111111111111111",
            "0x0000000000000000000000000000000000000000000000000000000000000000",
            0,
        );
        let attr = "reserve0".to_string();
        let val = Bytes::from(1000u64).lpad(32, 0);

        insert_state_attribute_update(
            &mut block_changes.txs_with_update,
            &component_id,
            &tx,
            &attr,
            &val,
        )
        .unwrap();

        assert_eq!(block_changes.txs_with_update.len(), 1);
        let state_delta = &block_changes.txs_with_update[0].state_updates[&component_id];
        assert_eq!(state_delta.updated_attributes[&attr], val);
    }

    #[test]
    fn test_insert_state_attribute_update_existing_transaction_no_component() {
        use chrono::NaiveDateTime;
        use tycho_common::models::blockchain::TxWithChanges;

        let tx = create_transaction(
            "0x1111111111111111111111111111111111111111111111111111111111111111",
            "0x0000000000000000000000000000000000000000000000000000000000000000",
            0,
        );
        let existing_tx_with_changes =
            TxWithChanges { tx: tx.clone(), state_updates: HashMap::new(), ..Default::default() };

        let mut block_changes = BlockChanges::new(
            "test_extractor".to_string(),
            Chain::Ethereum,
            Block::new(
                1,
                Chain::Ethereum,
                Bytes::zero(32),
                Bytes::zero(32),
                NaiveDateTime::from_timestamp_opt(1000, 0).unwrap(),
            ),
            0,
            false,
            vec![existing_tx_with_changes],
            vec![],
        );

        let component_id = "test_component".to_string();
        let attr = "reserve0".to_string();
        let val = Bytes::from(1000u64).lpad(32, 0);

        insert_state_attribute_update(
            &mut block_changes.txs_with_update,
            &component_id,
            &tx,
            &attr,
            &val,
        )
        .unwrap();

        assert_eq!(block_changes.txs_with_update.len(), 1);
        let state_delta = &block_changes.txs_with_update[0].state_updates[&component_id];
        assert_eq!(state_delta.updated_attributes[&attr], val);
    }

    #[test]
    fn test_insert_state_attribute_update_existing_transaction_with_component() {
        use chrono::NaiveDateTime;
        use tycho_common::models::blockchain::TxWithChanges;

        let component_id = "test_component".to_string();
        let tx = create_transaction(
            "0x1111111111111111111111111111111111111111111111111111111111111111",
            "0x0000000000000000000000000000000000000000000000000000000000000000",
            0,
        );

        // Create existing delta for the component
        let existing_delta = ProtocolComponentStateDelta::new(
            &component_id,
            HashMap::from([("existing_attr".to_string(), Bytes::from(500u64).lpad(32, 0))]),
            HashSet::new(),
        );

        let existing_tx_with_changes = TxWithChanges {
            tx: tx.clone(),
            state_updates: HashMap::from([(component_id.clone(), existing_delta)]),
            ..Default::default()
        };

        let mut block_changes = BlockChanges::new(
            "test_extractor".to_string(),
            Chain::Ethereum,
            Block::new(
                1,
                Chain::Ethereum,
                Bytes::zero(32),
                Bytes::zero(32),
                NaiveDateTime::from_timestamp_opt(1000, 0).unwrap(),
            ),
            0,
            false,
            vec![existing_tx_with_changes],
            vec![],
        );

        let attr = "new_attr".to_string();
        let val = Bytes::from(1000u64).lpad(32, 0);

        insert_state_attribute_update(
            &mut block_changes.txs_with_update,
            &component_id,
            &tx,
            &attr,
            &val,
        )
        .unwrap();

        assert_eq!(block_changes.txs_with_update.len(), 1);
        let state_delta = &block_changes.txs_with_update[0].state_updates[&component_id];
        assert_eq!(state_delta.updated_attributes.len(), 2);
        assert_eq!(state_delta.updated_attributes[&attr], val);
        assert_eq!(
            state_delta.updated_attributes["existing_attr"],
            Bytes::from(500u64).lpad(32, 0)
        );
    }

    #[test]
    fn test_insert_state_attribute_deletion_new_transaction() {
        use chrono::NaiveDateTime;

        let mut block_changes = BlockChanges::new(
            "test_extractor".to_string(),
            Chain::Ethereum,
            Block::new(
                1,
                Chain::Ethereum,
                Bytes::zero(32),
                Bytes::zero(32),
                NaiveDateTime::from_timestamp_opt(1000, 0).unwrap(),
            ),
            0,
            false,
            vec![],
            vec![],
        );

        let component_id = "test_component".to_string();
        let tx = create_transaction(
            "0x2222222222222222222222222222222222222222222222222222222222222222",
            "0x0000000000000000000000000000000000000000000000000000000000000000",
            0,
        );
        let attr = "deprecated_attr".to_string();

        insert_state_attribute_deletion(
            &mut block_changes.txs_with_update,
            &component_id,
            &tx,
            &attr,
        )
        .unwrap();

        assert_eq!(block_changes.txs_with_update.len(), 1);
        let state_delta = &block_changes.txs_with_update[0].state_updates[&component_id];
        assert!(state_delta
            .deleted_attributes
            .contains(&attr));
    }

    #[test]
    fn test_insert_state_attribute_deletion_existing_transaction_no_component() {
        use chrono::NaiveDateTime;
        use tycho_common::models::blockchain::TxWithChanges;

        let tx = create_transaction(
            "0x2222222222222222222222222222222222222222222222222222222222222222",
            "0x0000000000000000000000000000000000000000000000000000000000000000",
            0,
        );
        let existing_tx_with_changes =
            TxWithChanges { tx: tx.clone(), state_updates: HashMap::new(), ..Default::default() };

        let mut block_changes = BlockChanges::new(
            "test_extractor".to_string(),
            Chain::Ethereum,
            Block::new(
                1,
                Chain::Ethereum,
                Bytes::zero(32),
                Bytes::zero(32),
                NaiveDateTime::from_timestamp_opt(1000, 0).unwrap(),
            ),
            0,
            false,
            vec![existing_tx_with_changes],
            vec![],
        );

        let component_id = "test_component".to_string();
        let attr = "deprecated_attr".to_string();

        insert_state_attribute_deletion(
            &mut block_changes.txs_with_update,
            &component_id,
            &tx,
            &attr,
        )
        .unwrap();

        assert_eq!(block_changes.txs_with_update.len(), 1);
        let state_delta = &block_changes.txs_with_update[0].state_updates[&component_id];
        assert!(state_delta
            .deleted_attributes
            .contains(&attr));
    }

    #[test]
    fn test_insert_state_attribute_deletion_existing_transaction_with_component() {
        use chrono::NaiveDateTime;
        use tycho_common::models::blockchain::TxWithChanges;

        let component_id = "test_component".to_string();
        let tx = create_transaction(
            "0x2222222222222222222222222222222222222222222222222222222222222222",
            "0x0000000000000000000000000000000000000000000000000000000000000000",
            0,
        );

        // Create existing delta for the component
        let existing_delta = ProtocolComponentStateDelta::new(
            &component_id,
            HashMap::new(),
            HashSet::from(["existing_deleted_attr".to_string()]),
        );

        let existing_tx_with_changes = TxWithChanges {
            tx: tx.clone(),
            state_updates: HashMap::from([(component_id.clone(), existing_delta)]),
            ..Default::default()
        };

        let mut block_changes = BlockChanges::new(
            "test_extractor".to_string(),
            Chain::Ethereum,
            Block::new(
                1,
                Chain::Ethereum,
                Bytes::zero(32),
                Bytes::zero(32),
                NaiveDateTime::from_timestamp_opt(1000, 0).unwrap(),
            ),
            0,
            false,
            vec![existing_tx_with_changes],
            vec![],
        );

        let attr = "new_deleted_attr".to_string();

        insert_state_attribute_deletion(
            &mut block_changes.txs_with_update,
            &component_id,
            &tx,
            &attr,
        )
        .unwrap();

        assert_eq!(block_changes.txs_with_update.len(), 1);
        let state_delta = &block_changes.txs_with_update[0].state_updates[&component_id];
        assert_eq!(state_delta.deleted_attributes.len(), 2);
        assert!(state_delta
            .deleted_attributes
            .contains(&attr));
        assert!(state_delta
            .deleted_attributes
            .contains("existing_deleted_attr"));
    }
}
