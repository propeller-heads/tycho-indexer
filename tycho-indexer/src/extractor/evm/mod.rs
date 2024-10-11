use std::collections::{hash_map::Entry, HashMap, HashSet};

use chrono::NaiveDateTime;
use tracing::log::warn;

use tycho_core::{
    models::{
        blockchain::{Block, BlockAggregatedChanges, BlockScoped, Transaction, TxWithChanges},
        contract::{AccountDelta, TransactionVMUpdates},
        protocol::{
            self as tycho_core_protocol, ComponentBalance, ProtocolChangesWithTx,
            ProtocolComponent, ProtocolComponentStateDelta,
        },
        token::CurrencyToken,
        Address, AttrStoreKey, Chain, ChangeType, ComponentId, ProtocolType, TxHash,
    },
    Bytes,
};

use crate::{
    extractor::reorg_buffer::{
        AccountStateIdType, AccountStateKeyType, AccountStateValueType, ProtocolStateIdType,
        ProtocolStateKeyType, ProtocolStateValueType,
    },
    pb::tycho::evm::v1 as substreams,
};

use super::{reorg_buffer::StateUpdateBufferEntry, u256_num::bytes_to_f64, ExtractionError};

pub mod chain_state;
pub mod hybrid;
pub mod protocol_cache;
pub mod token_analysis_cron;

pub trait TryFromMessage {
    type Args<'a>;

    fn try_from_message(args: Self::Args<'_>) -> Result<Self, ExtractionError>
    where
        Self: Sized;
}

impl TryFromMessage for AccountDelta {
    type Args<'a> = (substreams::ContractChange, Chain);

    fn try_from_message(args: Self::Args<'_>) -> Result<Self, ExtractionError> {
        let (msg, chain) = args;
        let change = msg.change().into();
        let update = AccountDelta::new(
            chain,
            msg.address.into(),
            msg.slots
                .into_iter()
                .map(|cs| (cs.slot.into(), Some(cs.value.into())))
                .collect(),
            if !msg.balance.is_empty() { Some(msg.balance.into()) } else { None },
            if !msg.code.is_empty() { Some(msg.code.into()) } else { None },
            change,
        );
        Ok(update)
    }
}

/// A container for account updates grouped by transaction.
///
/// Hold the detailed state changes for a block alongside with protocol
/// component changes.
#[derive(Debug, PartialEq, Clone)]
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
    pub tx_updates: Vec<TransactionVMUpdates>,
}

impl BlockScoped for BlockContractChanges {
    fn block(&self) -> tycho_core::models::blockchain::Block {
        self.block.clone()
    }
}

impl TryFromMessage for Block {
    type Args<'a> = (substreams::Block, Chain);

    /// Parses block from tychos protobuf block message
    fn try_from_message(args: Self::Args<'_>) -> Result<Self, ExtractionError> {
        let (msg, chain) = args;
        let ts_nano = match chain {
            // For blockchains with subsecond block times, like Arbitrum, timestamps aren't precise
            // enough to distinguish between two blocks accurately. To maintain accurate ordering,
            // we adjust timestamps by appending part of the current block number as microseconds.
            Chain::Arbitrum => (msg.number as u32 % 1000) * 1000,
            _ => 0,
        };

        Ok(Self {
            chain,
            number: msg.number,
            hash: msg.hash.into(),
            parent_hash: msg.parent_hash.into(),
            ts: NaiveDateTime::from_timestamp_opt(msg.ts as i64, ts_nano).ok_or_else(|| {
                ExtractionError::DecodeError(format!(
                    "Failed to convert timestamp {} to datetime!",
                    msg.ts
                ))
            })?,
        })
    }
}

impl TryFromMessage for Transaction {
    type Args<'a> = (substreams::Transaction, &'a Bytes);

    fn try_from_message(args: Self::Args<'_>) -> Result<Self, ExtractionError> {
        let (msg, block_hash) = args;

        let to = if !msg.to.is_empty() { Some(msg.to.into()) } else { None };

        Ok(Self {
            hash: msg.hash.into(),
            block_hash: block_hash.clone(),
            from: msg.from.into(),
            to,
            index: msg.index,
        })
    }
}

impl TryFromMessage for ComponentBalance {
    type Args<'a> = (substreams::BalanceChange, &'a Transaction);

    fn try_from_message(args: Self::Args<'_>) -> Result<Self, ExtractionError> {
        let (msg, tx) = args;
        let balance_float = bytes_to_f64(&msg.balance).unwrap_or(f64::NAN);
        Ok(Self {
            token: msg.token.into(),
            balance: Bytes::from(msg.balance),
            balance_float,
            modify_tx: tx.hash.clone(),
            component_id: String::from_utf8(msg.component_id)
                .map_err(|error| ExtractionError::DecodeError(error.to_string()))?,
        })
    }
}

impl TryFromMessage for ProtocolComponent {
    type Args<'a> = (
        substreams::ProtocolComponent,
        Chain,
        &'a str,
        &'a HashMap<String, ProtocolType>,
        TxHash,
        NaiveDateTime,
    );

    fn try_from_message(args: Self::Args<'_>) -> Result<Self, ExtractionError> {
        let (msg, chain, protocol_system, protocol_types, tx_hash, creation_ts) = args;
        let tokens: Vec<Bytes> = msg
            .tokens
            .clone()
            .into_iter()
            .map(Into::into)
            .collect();

        let contract_ids = msg
            .contracts
            .clone()
            .into_iter()
            .map(Into::into)
            .collect();

        let static_attributes = msg
            .static_att
            .clone()
            .into_iter()
            .map(|attribute| (attribute.name, Bytes::from(attribute.value)))
            .collect();

        let protocol_type = msg
            .protocol_type
            .clone()
            .ok_or(ExtractionError::DecodeError("Missing protocol type".to_owned()))?;

        if !protocol_types.contains_key(&protocol_type.name) {
            return Err(ExtractionError::DecodeError(format!(
                "Unknown protocol type name: {}",
                protocol_type.name
            )));
        }

        Ok(Self {
            id: msg.id.clone(),
            protocol_type_name: protocol_type.name,
            protocol_system: protocol_system.to_owned(),
            tokens,
            contract_addresses: contract_ids,
            static_attributes,
            chain,
            change: msg.change().into(),
            creation_tx: tx_hash,
            created_at: creation_ts,
        })
    }
}

impl From<substreams::ChangeType> for ChangeType {
    fn from(value: substreams::ChangeType) -> Self {
        match value {
            substreams::ChangeType::Unspecified => {
                panic!("Unkown enum member encountered: {:?}", value)
            }
            substreams::ChangeType::Update => ChangeType::Update,
            substreams::ChangeType::Creation => ChangeType::Creation,
            substreams::ChangeType::Deletion => ChangeType::Deletion,
        }
    }
}

impl BlockContractChanges {
    pub fn new(
        extractor: String,
        chain: Chain,
        block: Block,
        finalized_block_height: u64,
        revert: bool,
        tx_updates: Vec<TransactionVMUpdates>,
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
    /// Parse from tychos protobuf message
    pub fn try_from_message(
        msg: substreams::BlockContractChanges,
        extractor: &str,
        chain: Chain,
        protocol_system: String,
        protocol_types: &HashMap<String, ProtocolType>,
        finalized_block_height: u64,
    ) -> Result<Self, ExtractionError> {
        if let Some(block) = msg.block {
            let block = Block::try_from_message((block, chain))?;
            let mut tx_updates = Vec::new();

            for change in msg.changes.into_iter() {
                let mut account_updates = HashMap::new();
                let mut protocol_components = HashMap::new();
                let mut balances_changes: HashMap<ComponentId, HashMap<Bytes, ComponentBalance>> =
                    HashMap::new();

                if let Some(tx) = change.tx {
                    let tx = Transaction::try_from_message((tx, &block.hash.clone()))?;
                    for contract_change in change.contract_changes.into_iter() {
                        let update = AccountDelta::try_from_message((contract_change, chain))?;
                        account_updates.insert(update.address.clone(), update);
                    }
                    for component_msg in change.component_changes.into_iter() {
                        let component = ProtocolComponent::try_from_message((
                            component_msg,
                            chain,
                            &protocol_system,
                            protocol_types,
                            tx.hash.clone(),
                            block.ts,
                        ))?;
                        protocol_components.insert(component.id.clone(), component);
                    }

                    for balance_change in change.balance_changes.into_iter() {
                        let component_id =
                            String::from_utf8(balance_change.component_id.clone())
                                .map_err(|error| ExtractionError::DecodeError(error.to_string()))?;
                        let token_address = balance_change.token.clone().into();
                        let balance = ComponentBalance::try_from_message((balance_change, &tx))?;

                        balances_changes
                            .entry(component_id)
                            .or_default()
                            .insert(token_address, balance);
                    }

                    tx_updates.push(TransactionVMUpdates::new(
                        account_updates,
                        protocol_components,
                        balances_changes,
                        tx,
                    ));
                }
            }
            tx_updates.sort_unstable_by_key(|update| update.tx.index);
            return Ok(Self {
                extractor: extractor.to_owned(),
                chain,
                block,
                finalized_block_height,
                revert: false,
                new_tokens: HashMap::new(),
                tx_updates,
            });
        }
        Err(ExtractionError::Empty)
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

impl TryFromMessage for ProtocolComponentStateDelta {
    type Args<'a> = substreams::EntityChanges;

    fn try_from_message(args: Self::Args<'_>) -> Result<Self, ExtractionError> {
        let msg = args;

        let (mut updates, mut deletions) = (HashMap::new(), HashSet::new());

        for attribute in msg.attributes.into_iter() {
            match attribute.change().into() {
                ChangeType::Update | ChangeType::Creation => {
                    updates.insert(attribute.name, Bytes::from(attribute.value));
                }
                ChangeType::Deletion => {
                    deletions.insert(attribute.name);
                }
            }
        }

        Ok(Self {
            component_id: msg.component_id,
            updated_attributes: updates,
            deleted_attributes: deletions,
        })
    }
}

impl TryFromMessage for ProtocolChangesWithTx {
    type Args<'a> = (
        substreams::TransactionEntityChanges,
        &'a Block,
        &'a str,
        &'a HashMap<String, ProtocolType>,
    );

    fn try_from_message(args: Self::Args<'_>) -> Result<Self, ExtractionError> {
        let (msg, block, protocol_system, protocol_types) = args;
        let tx = Transaction::try_from_message((
            msg.tx
                .expect("TransactionEntityChanges should have a transaction"),
            &block.hash.clone(),
        ))?;

        let mut new_protocol_components: HashMap<String, ProtocolComponent> = HashMap::new();
        let mut state_updates: HashMap<String, ProtocolComponentStateDelta> = HashMap::new();
        let mut component_balances: HashMap<String, HashMap<Bytes, ComponentBalance>> =
            HashMap::new();

        // First, parse the new protocol components
        for change in msg.component_changes.into_iter() {
            let component = ProtocolComponent::try_from_message((
                change.clone(),
                block.chain,
                protocol_system,
                protocol_types,
                tx.hash.clone(),
                block.ts,
            ))?;
            new_protocol_components.insert(change.id, component);
        }

        // Then, parse the state updates
        for state_msg in msg.entity_changes.into_iter() {
            let state = ProtocolComponentStateDelta::try_from_message(state_msg)?;
            // Check if a state update for the same component already exists
            // If it exists, overwrite the existing state update with the new one and log a warning
            match state_updates.entry(state.component_id.clone()) {
                Entry::Vacant(e) => {
                    e.insert(state);
                }
                Entry::Occupied(mut e) => {
                    warn!("Received two state updates for the same component. Overwriting state for component {}", e.key());
                    e.insert(state);
                }
            }
        }

        // Finally, parse the balance changes
        for balance_change in msg.balance_changes.into_iter() {
            let component_balance = ComponentBalance::try_from_message((balance_change, &tx))?;

            // Check if a balance change for the same token and component already exists
            // If it exists, overwrite the existing balance change with the new one and log a
            // warning
            let token_balances = component_balances
                .entry(component_balance.component_id.clone())
                .or_default();

            if let Some(existing_balance) =
                token_balances.insert(component_balance.token.clone(), component_balance)
            {
                warn!(
                    "Received two balance updates for the same component id: {} and token {}. Overwriting balance change",
                    existing_balance.component_id, existing_balance.token
                );
            }
        }

        Ok(Self {
            new_protocol_components,
            protocol_states: state_updates,
            balance_changes: component_balances,
            tx,
        })
    }
}

/// A container for state updates grouped by transaction
///
/// Hold the detailed state changes for a block alongside with protocol
/// component changes.
#[derive(Debug, PartialEq, Default, Clone)]
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

impl BlockScoped for BlockEntityChanges {
    fn block(&self) -> tycho_core::models::blockchain::Block {
        self.block.clone()
    }
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
    /// Parse from tychos protobuf message
    pub fn try_from_message(
        msg: substreams::BlockEntityChanges,
        extractor: &str,
        chain: Chain,
        protocol_system: &str,
        protocol_types: &HashMap<String, ProtocolType>,
        finalized_block_height: u64,
    ) -> Result<Self, ExtractionError> {
        if let Some(block) = msg.block {
            let block = Block::try_from_message((block, chain))?;

            let mut txs_with_update = msg
                .changes
                .into_iter()
                .map(|change| {
                    change.tx.as_ref().ok_or_else(|| {
                        ExtractionError::DecodeError(
                            "TransactionEntityChanges misses a transaction".to_owned(),
                        )
                    })?;

                    ProtocolChangesWithTx::try_from_message((
                        change,
                        &block,
                        protocol_system,
                        protocol_types,
                    ))
                })
                .collect::<Result<Vec<ProtocolChangesWithTx>, ExtractionError>>()?;

            // Sort updates by transaction index
            txs_with_update.sort_unstable_by_key(|update| update.tx.index);

            Ok(Self {
                extractor: extractor.to_string(),
                chain,
                block,
                finalized_block_height,
                revert: false,
                new_tokens: HashMap::new(),
                txs_with_update,
            })
        } else {
            Err(ExtractionError::Empty)
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

impl TryFromMessage for TxWithChanges {
    type Args<'a> =
        (substreams::TransactionChanges, &'a Block, &'a str, &'a HashMap<String, ProtocolType>);

    fn try_from_message(args: Self::Args<'_>) -> Result<Self, ExtractionError> {
        let (msg, block, protocol_system, protocol_types) = args;
        let tx = Transaction::try_from_message((
            msg.tx
                .expect("TransactionChanges should have a transaction"),
            &block.hash.clone(),
        ))?;

        let mut new_protocol_components: HashMap<String, ProtocolComponent> = HashMap::new();
        let mut account_updates: HashMap<Bytes, AccountDelta> = HashMap::new();
        let mut state_updates: HashMap<String, ProtocolComponentStateDelta> = HashMap::new();
        let mut balance_changes: HashMap<String, HashMap<Bytes, ComponentBalance>> = HashMap::new();

        // First, parse the new protocol components
        for change in msg.component_changes.into_iter() {
            let component = ProtocolComponent::try_from_message((
                change,
                block.chain,
                protocol_system,
                protocol_types,
                tx.hash.clone(),
                block.ts,
            ))?;
            new_protocol_components.insert(component.id.clone(), component);
        }

        // Then, parse the account updates
        for contract_change in msg.contract_changes.into_iter() {
            let update = AccountDelta::try_from_message((contract_change, block.chain))?;
            account_updates.insert(update.address.clone(), update);
        }

        // Then, parse the state updates
        for state_msg in msg.entity_changes.into_iter() {
            let state = ProtocolComponentStateDelta::try_from_message(state_msg)?;
            // Check if a state update for the same component already exists
            // If it exists, overwrite the existing state update with the new one and log a warning
            match state_updates.entry(state.component_id.clone()) {
                Entry::Vacant(e) => {
                    e.insert(state);
                }
                Entry::Occupied(mut e) => {
                    warn!("Received two state updates for the same component. Overwriting state for component {}", e.key());
                    e.insert(state);
                }
            }
        }

        // Finally, parse the balance changes
        for balance_change in msg.balance_changes.into_iter() {
            let component_id = String::from_utf8(balance_change.component_id.clone())
                .map_err(|error| ExtractionError::DecodeError(error.to_string()))?;
            let token_address = Bytes::from(balance_change.token.clone());
            let balance = ComponentBalance::try_from_message((balance_change, &tx))?;

            balance_changes
                .entry(component_id)
                .or_default()
                .insert(token_address, balance);
        }

        Ok(Self {
            protocol_components: new_protocol_components,
            account_deltas: account_updates,
            state_updates,
            balance_changes,
            tx,
        })
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
    fn get_filtered_balance_update(
        &self,
        keys: Vec<(&ComponentId, &Address)>,
    ) -> HashMap<(String, Bytes), tycho_core_protocol::ComponentBalance> {
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
}

impl BlockScoped for BlockChanges {
    fn block(&self) -> tycho_core::models::blockchain::Block {
        self.block.clone()
    }
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

    /// Parse from Tycho's protobuf message
    pub fn try_from_message(
        msg: substreams::BlockChanges,
        extractor: &str,
        chain: Chain,
        protocol_system: &str,
        protocol_types: &HashMap<String, ProtocolType>,
        finalized_block_height: u64,
    ) -> Result<Self, ExtractionError> {
        if let Some(block) = msg.block {
            let block = Block::try_from_message((block, chain))?;

            let txs_with_update = msg
                .changes
                .into_iter()
                .map(|change| {
                    change.tx.as_ref().ok_or_else(|| {
                        ExtractionError::DecodeError(
                            "TransactionEntityChanges misses a transaction".to_owned(),
                        )
                    })?;

                    TxWithChanges::try_from_message((
                        change,
                        &block,
                        protocol_system,
                        protocol_types,
                    ))
                })
                .collect::<Result<Vec<TxWithChanges>, ExtractionError>>()?;

            // Sort updates by transaction index
            let mut txs_with_update = txs_with_update;
            txs_with_update.sort_unstable_by_key(|update| update.tx.index);

            Ok(Self {
                extractor: extractor.to_string(),
                chain,
                block,
                finalized_block_height,
                revert: false,
                new_tokens: HashMap::new(),
                txs_with_update,
            })
        } else {
            Err(ExtractionError::Empty)
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
    use std::str::FromStr;

    use prost::Message;

    use tycho_storage::postgres::db_fixtures::yesterday_midnight;

    use super::*;

    pub const HASH_256_0: &str =
        "0x0000000000000000000000000000000000000000000000000000000000000000";

    pub fn transaction01() -> Transaction {
        Transaction::new(
            Bytes::zero(32),
            Bytes::zero(32),
            Bytes::zero(20),
            Some(Bytes::zero(20)),
            10,
        )
    }

    pub fn transaction02(hash: &str, block: &str, index: u64) -> Transaction {
        Transaction::new(
            hash.parse().unwrap(),
            block.parse().unwrap(),
            Bytes::zero(20),
            Some(Bytes::zero(20)),
            index,
        )
    }

    pub fn evm_slots(data: impl IntoIterator<Item = (u64, u64)>) -> HashMap<Bytes, Bytes> {
        data.into_iter()
            .map(|(s, v)| (Bytes::from(s).lpad(32, 0), Bytes::from(v).lpad(32, 0)))
            .collect()
    }

    // Utils function that return slots that match `AccountUpdate` slots.
    // TODO: this is temporary, we shoud make AccountUpdate.slots use Bytes instead of Option<Bytes>
    pub fn slots(data: impl IntoIterator<Item = (u64, u64)>) -> HashMap<Bytes, Option<Bytes>> {
        data.into_iter()
            .map(|(s, v)| (Bytes::from(s).lpad(32, 0), Some(Bytes::from(v).lpad(32, 0))))
            .collect()
    }

    pub fn pb_block_scoped_data(
        msg: impl prost::Message,
        cursor: Option<&str>,
        final_block_height: Option<u64>,
    ) -> crate::pb::sf::substreams::rpc::v2::BlockScopedData {
        use crate::pb::sf::substreams::{rpc::v2::*, v1::Clock};
        let val = msg.encode_to_vec();
        BlockScopedData {
            output: Some(MapModuleOutput {
                name: "map_changes".to_owned(),
                map_output: Some(prost_types::Any {
                    type_url: "tycho.evm.v1.BlockChanges".to_owned(),
                    value: val,
                }),
                debug_info: None,
            }),
            clock: Some(Clock {
                id: HASH_256_0.to_owned(),
                number: 420,
                timestamp: Some(prost_types::Timestamp { seconds: 1000, nanos: 0 }),
            }),
            cursor: cursor
                .unwrap_or("cursor@420")
                .to_owned(),
            final_block_height: final_block_height.unwrap_or(420),
            debug_map_outputs: vec![],
            debug_store_outputs: vec![],
        }
    }

    pub fn pb_block_contract_changes(
        version: u8,
    ) -> crate::pb::tycho::evm::v1::BlockContractChanges {
        use crate::pb::tycho::evm::v1::*;

        match version {
            0 => BlockContractChanges {
                block: Some(Block {
                    hash: Bytes::from(vec![0x31, 0x32, 0x33, 0x34])
                        .lpad(32, 0)
                        .to_vec(),
                    parent_hash: Bytes::from(vec![0x21, 0x22, 0x23, 0x24])
                        .lpad(32, 0)
                        .to_vec(),
                    number: 1,
                    ts: 1000,
                }),

                changes: vec![
                    TransactionContractChanges {
                        tx: Some(Transaction {
                            hash: Bytes::from(vec![0x11, 0x12, 0x13, 0x14])
                                .lpad(32, 0)
                                .to_vec(),
                            from: Bytes::from(vec![0x41, 0x42, 0x43, 0x44])
                                .lpad(20, 0)
                                .to_vec(),
                            to: Bytes::from(vec![0x51, 0x52, 0x53, 0x54])
                                .lpad(20, 0)
                                .to_vec(),
                            index: 2,
                        }),
                        contract_changes: vec![ContractChange {
                            address: Bytes::from(vec![0x61, 0x62, 0x63, 0x64])
                                .lpad(20, 0)
                                .to_vec(),
                            balance: Bytes::from(vec![0x71, 0x72, 0x73, 0x74])
                                .lpad(32, 0)
                                .to_vec(),
                            code: vec![0x81, 0x82, 0x83, 0x84],
                            slots: vec![
                                ContractSlot {
                                    slot: Bytes::from(vec![0xc1, 0xc2, 0xc3, 0xc4])
                                        .lpad(32, 0)
                                        .to_vec(),
                                    value: Bytes::from(vec![0xd1, 0xd2, 0xd3, 0xd4])
                                        .lpad(32, 0)
                                        .to_vec(),
                                },
                                ContractSlot {
                                    slot: Bytes::from(vec![0xa1, 0xa2, 0xa3, 0xa4])
                                        .lpad(32, 0)
                                        .to_vec(),
                                    value: Bytes::from(vec![0xb1, 0xb2, 0xb3, 0xb4])
                                        .lpad(32, 0)
                                        .to_vec(),
                                },
                            ],
                            change: ChangeType::Update.into(),
                        }],
                        component_changes: vec![ProtocolComponent {
                            id: "d417ff54652c09bd9f31f216b1a2e5d1e28c1dce1ba840c40d16f2b4d09b5902"
                                .to_owned(),
                            tokens: vec![
                                Bytes::from_str("0x6B175474E89094C44Da98b954EedeAC495271d0F")
                                    .unwrap()
                                    .to_vec(),
                                Bytes::from_str("0x6B175474E89094C44Da98b954EedeAC495271d0F")
                                    .unwrap()
                                    .to_vec(),
                            ],
                            contracts: vec![
                                Bytes::from_str("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2")
                                    .unwrap()
                                    .to_vec(),
                                Bytes::from_str("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2")
                                    .unwrap()
                                    .to_vec(),
                            ],
                            static_att: vec![
                                Attribute {
                                    name: "key1".to_owned(),
                                    value: b"value1".to_vec(),
                                    change: ChangeType::Creation.into(),
                                },
                                Attribute {
                                    name: "key2".to_owned(),
                                    value: b"value2".to_vec(),
                                    change: ChangeType::Creation.into(),
                                },
                            ],
                            change: ChangeType::Creation.into(),
                            protocol_type: Some(ProtocolType {
                                name: "WeightedPool".to_string(),
                                financial_type: 0,
                                attribute_schema: vec![],
                                implementation_type: 0,
                            }),
                        }],
                        balance_changes: vec![BalanceChange {
                            token: hex::decode(
                                "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"
                                    .trim_start_matches("0x"),
                            )
                            .unwrap(),
                            balance: 50000000.encode_to_vec(),
                            component_id:
                                "d417ff54652c09bd9f31f216b1a2e5d1e28c1dce1ba840c40d16f2b4d09b5902"
                                    .as_bytes()
                                    .to_vec(),
                        }],
                    },
                    TransactionContractChanges {
                        tx: Some(Transaction {
                            hash: Bytes::from(vec![0x01])
                                .lpad(32, 0)
                                .to_vec(),
                            from: Bytes::from(vec![0x41, 0x42, 0x43, 0x44])
                                .lpad(20, 0)
                                .to_vec(),
                            to: Bytes::from(vec![0x51, 0x52, 0x53, 0x54])
                                .lpad(20, 0)
                                .to_vec(),
                            index: 5,
                        }),
                        contract_changes: vec![ContractChange {
                            address: Bytes::from(vec![0x61, 0x62, 0x63, 0x64])
                                .lpad(20, 0)
                                .to_vec(),
                            balance: Bytes::from(vec![0xf1, 0xf2, 0xf3, 0xf4])
                                .lpad(32, 0)
                                .to_vec(),
                            code: vec![0x01, 0x02, 0x03, 0x04],
                            slots: vec![
                                ContractSlot {
                                    slot: Bytes::from(vec![0x91, 0x92, 0x93, 0x94])
                                        .lpad(32, 0)
                                        .to_vec(),
                                    value: Bytes::from(vec![0xa1, 0xa2, 0xa3, 0xa4])
                                        .lpad(32, 0)
                                        .to_vec(),
                                },
                                ContractSlot {
                                    slot: Bytes::from(vec![0xa1, 0xa2, 0xa3, 0xa4])
                                        .lpad(32, 0)
                                        .to_vec(),
                                    value: Bytes::from(vec![0xc1, 0xc2, 0xc3, 0xc4])
                                        .lpad(32, 0)
                                        .to_vec(),
                                },
                            ],
                            change: ChangeType::Update.into(),
                        }],
                        component_changes: vec![],
                        balance_changes: vec![BalanceChange {
                            token: hex::decode(
                                "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"
                                    .trim_start_matches("0x"),
                            )
                            .unwrap(),
                            balance: 10.encode_to_vec(),
                            component_id:
                                "d417ff54652c09bd9f31f216b1a2e5d1e28c1dce1ba840c40d16f2b4d09b5902"
                                    .to_string()
                                    .as_bytes()
                                    .to_vec(),
                        }],
                    },
                ],
            },
            1 => BlockContractChanges {
                block: Some(pb_blocks(version as u64)),
                changes: vec![TransactionContractChanges {
                    tx: Some(pb_transactions(1, 1)),
                    contract_changes: vec![ContractChange {
                        address: address_from_str("0000000000000000000000000000000000000001"),
                        balance: 1_i32.to_be_bytes().to_vec(),
                        code: 123_i32.to_be_bytes().to_vec(),
                        slots: vec![ContractSlot {
                            slot: Bytes::from("0x01").into(),
                            value: Bytes::from("0x01").into(),
                        }],
                        change: ChangeType::Creation.into(),
                    }],
                    component_changes: vec![ProtocolComponent {
                        id: "pc_1".to_owned(),
                        tokens: vec![
                            address_from_str(WETH_ADDRESS),
                            address_from_str(USDC_ADDRESS),
                        ],
                        contracts: vec![],
                        static_att: vec![],
                        change: ChangeType::Creation.into(),
                        protocol_type: Some(ProtocolType {
                            name: "pt_1".to_string(),
                            financial_type: 0,
                            attribute_schema: vec![],
                            implementation_type: 0,
                        }),
                    }],
                    balance_changes: vec![
                        BalanceChange {
                            token: address_from_str(USDC_ADDRESS),
                            balance: 1_i32.to_be_bytes().to_vec(),
                            component_id: "pc_1".into(),
                        },
                        BalanceChange {
                            token: address_from_str(WETH_ADDRESS),
                            balance: 1_i32.to_be_bytes().to_vec(),
                            component_id: "pc_1".into(),
                        },
                    ],
                }],
            },
            2 => BlockContractChanges {
                block: Some(pb_blocks(version as u64)),
                changes: vec![TransactionContractChanges {
                    tx: Some(pb_transactions(2, 1)),
                    contract_changes: vec![
                        ContractChange {
                            address: address_from_str("0000000000000000000000000000000000000002"),
                            balance: 2_i32.to_be_bytes().to_vec(),
                            code: 123_i32.to_be_bytes().to_vec(),
                            slots: vec![ContractSlot {
                                slot: Bytes::from("0x01").into(),
                                value: Bytes::from("0x02").into(),
                            }],
                            change: ChangeType::Creation.into(),
                        },
                        ContractChange {
                            address: address_from_str("0000000000000000000000000000000000000001"),
                            balance: 10_i32.to_be_bytes().to_vec(),
                            code: 123_i32.to_be_bytes().to_vec(),
                            slots: vec![
                                ContractSlot {
                                    slot: Bytes::from("0x01").into(),
                                    value: Bytes::from(10u8).lpad(32, 0).into(),
                                },
                                ContractSlot {
                                    slot: Bytes::from("0x02").into(),
                                    value: Bytes::from("0x0a").into(),
                                },
                            ],
                            change: ChangeType::Update.into(),
                        },
                    ],
                    component_changes: vec![ProtocolComponent {
                        id: "pc_2".to_owned(),
                        tokens: vec![
                            address_from_str(USDT_ADDRESS),
                            address_from_str(USDC_ADDRESS),
                        ],
                        contracts: vec![address_from_str(
                            "0000000000000000000000000000000000000002",
                        )],
                        static_att: vec![],
                        change: ChangeType::Creation.into(),
                        protocol_type: Some(ProtocolType {
                            name: "pt_1".to_string(),
                            financial_type: 0,
                            attribute_schema: vec![],
                            implementation_type: 0,
                        }),
                    }],
                    balance_changes: vec![
                        BalanceChange {
                            token: address_from_str(USDC_ADDRESS),
                            balance: 20_i32.to_be_bytes().to_vec(),
                            component_id: "pc_2".into(),
                        },
                        BalanceChange {
                            token: address_from_str(USDT_ADDRESS),
                            balance: 20_i32.to_be_bytes().to_vec(),
                            component_id: "pc_2".into(),
                        },
                        BalanceChange {
                            token: address_from_str(USDC_ADDRESS),
                            balance: 10_i32.to_be_bytes().to_vec(),
                            component_id: "pc_1".into(),
                        },
                    ],
                }],
            },
            3 => BlockContractChanges {
                block: Some(pb_blocks(version as u64)),
                changes: vec![
                    TransactionContractChanges {
                        tx: Some(pb_transactions(3, 1)),
                        contract_changes: vec![
                            ContractChange {
                                address: address_from_str(
                                    "0000000000000000000000000000000000000001",
                                ),
                                balance: 1_i32.to_be_bytes().to_vec(),
                                code: 123_i32.to_le_bytes().to_vec(),
                                slots: vec![ContractSlot {
                                    slot: Bytes::from("0x01").into(),
                                    value: Bytes::from("0x01").into(),
                                }],
                                change: ChangeType::Update.into(),
                            },
                            ContractChange {
                                address: address_from_str(
                                    "0000000000000000000000000000000000000002",
                                ),
                                balance: 20_i32.to_be_bytes().to_vec(),
                                code: 123_i32.to_le_bytes().to_vec(),
                                slots: vec![ContractSlot {
                                    slot: Bytes::from("0x02").into(),
                                    value: Bytes::from(200u8).lpad(32, 0).into(),
                                }],
                                change: ChangeType::Update.into(),
                            },
                        ],
                        component_changes: vec![],
                        balance_changes: vec![BalanceChange {
                            token: address_from_str(USDC_ADDRESS),
                            balance: 1_i32.to_be_bytes().to_vec(),
                            component_id: "pc_2".into(),
                        }],
                    },
                    TransactionContractChanges {
                        tx: Some(pb_transactions(3, 2)),
                        contract_changes: vec![ContractChange {
                            address: address_from_str("0000000000000000000000000000000000000001"),
                            balance: 1_i32.to_be_bytes().to_vec(),
                            code: 123_i32.to_le_bytes().to_vec(),
                            slots: vec![ContractSlot {
                                slot: Bytes::from("0x01").into(),
                                value: Bytes::from("0x01").into(),
                            }],
                            change: ChangeType::Update.into(),
                        }],
                        component_changes: vec![],
                        balance_changes: vec![
                            BalanceChange {
                                token: address_from_str(USDC_ADDRESS),
                                balance: 100_i32.to_be_bytes().to_vec(),
                                component_id: "pc_1".into(),
                            },
                            BalanceChange {
                                token: address_from_str(USDC_ADDRESS),
                                balance: 2_i32.to_be_bytes().to_vec(),
                                component_id: "pc_2".into(),
                            },
                        ],
                    },
                ],
            },
            4 => BlockContractChanges {
                block: Some(pb_blocks(version as u64)),
                changes: vec![TransactionContractChanges {
                    tx: Some(pb_transactions(4, 1)),
                    contract_changes: vec![ContractChange {
                        address: address_from_str("0000000000000000000000000000000000000001"),
                        balance: 1_i32.to_be_bytes().to_vec(),
                        code: 123_i32.to_le_bytes().to_vec(),
                        slots: vec![ContractSlot {
                            slot: Bytes::from(3u8).lpad(32, 0).into(),
                            value: Bytes::from(10u8).lpad(32, 0).into(),
                        }],
                        change: ChangeType::Update.into(),
                    }],
                    component_changes: vec![ProtocolComponent {
                        id: "pc_3".to_owned(),
                        tokens: vec![address_from_str(DAI_ADDRESS), address_from_str(USDC_ADDRESS)],
                        contracts: vec![address_from_str(
                            "0000000000000000000000000000000000000001",
                        )],
                        static_att: vec![],
                        change: ChangeType::Creation.into(),
                        protocol_type: Some(ProtocolType {
                            name: "pt_1".to_string(),
                            financial_type: 0,
                            attribute_schema: vec![],
                            implementation_type: 0,
                        }),
                    }],
                    balance_changes: vec![],
                }],
            },
            5 => BlockContractChanges {
                block: Some(pb_blocks(version as u64)),
                changes: vec![TransactionContractChanges {
                    tx: Some(pb_transactions(5, 1)),
                    contract_changes: vec![
                        ContractChange {
                            address: address_from_str("0000000000000000000000000000000000000001"),
                            balance: 1_i32.to_be_bytes().to_vec(),
                            code: 123_i32.to_le_bytes().to_vec(),
                            slots: vec![ContractSlot {
                                slot: Bytes::from("0x01").into(),
                                value: Bytes::from(10u8).lpad(32, 0).into(),
                            }],
                            change: ChangeType::Update.into(),
                        },
                        ContractChange {
                            address: address_from_str("0000000000000000000000000000000000000002"),
                            balance: 1_i32.to_be_bytes().to_vec(),
                            code: 123_i32.to_le_bytes().to_vec(),
                            slots: vec![ContractSlot {
                                slot: Bytes::from("0x01").into(),
                                value: Bytes::from(10u8).lpad(32, 0).into(),
                            }],
                            change: ChangeType::Update.into(),
                        },
                    ],
                    component_changes: vec![],
                    balance_changes: vec![
                        BalanceChange {
                            token: address_from_str(USDC_ADDRESS),
                            balance: 1_i32.to_be_bytes().to_vec(),
                            component_id: "pc_1".into(),
                        },
                        BalanceChange {
                            token: address_from_str(USDC_ADDRESS),
                            balance: 1_i32.to_be_bytes().to_vec(),
                            component_id: "pc_3".into(),
                        },
                        BalanceChange {
                            token: address_from_str(WETH_ADDRESS),
                            balance: 1_i32.to_be_bytes().to_vec(),
                            component_id: "pc_1".into(),
                        },
                    ],
                }],
            },
            _ => panic!("Requested BlockContractChanges version doesn't exist"),
        }
    }

    pub fn pb_vm_block_changes(version: u8) -> crate::pb::tycho::evm::v1::BlockChanges {
        use crate::pb::tycho::evm::v1::*;

        match version {
            0 => BlockChanges {
                block: Some(Block {
                    hash: vec![0x31, 0x32, 0x33, 0x34],
                    parent_hash: vec![0x21, 0x22, 0x23, 0x24],
                    number: 1,
                    ts: 1000,
                }),

                changes: vec![
                    TransactionChanges {
                        tx: Some(Transaction {
                            hash: vec![0x11, 0x12, 0x13, 0x14],
                            from: vec![0x41, 0x42, 0x43, 0x44],
                            to: vec![0x51, 0x52, 0x53, 0x54],
                            index: 2,
                        }),
                        contract_changes: vec![ContractChange {
                            address: vec![0x61, 0x62, 0x63, 0x64],
                            balance: vec![0x71, 0x72, 0x73, 0x74],
                            code: vec![0x81, 0x82, 0x83, 0x84],
                            slots: vec![
                                ContractSlot {
                                    slot: vec![0xa1, 0xa2, 0xa3, 0xa4],
                                    value: vec![0xb1, 0xb2, 0xb3, 0xb4],
                                },
                                ContractSlot {
                                    slot: vec![0xc1, 0xc2, 0xc3, 0xc4],
                                    value: vec![0xd1, 0xd2, 0xd3, 0xd4],
                                },
                            ],
                            change: ChangeType::Update.into(),
                        }],
                        entity_changes: vec![],
                        component_changes: vec![ProtocolComponent {
                            id: "d417ff54652c09bd9f31f216b1a2e5d1e28c1dce1ba840c40d16f2b4d09b5902"
                                .to_owned(),
                            tokens: vec![
                                Bytes::from_str("0x6B175474E89094C44Da98b954EedeAC495271d0F")
                                    .unwrap()
                                    .0
                                    .to_vec(),
                                Bytes::from_str("0x6B175474E89094C44Da98b954EedeAC495271d0F")
                                    .unwrap()
                                    .0
                                    .to_vec(),
                            ],
                            contracts: vec![
                                Bytes::from_str("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2")
                                    .unwrap()
                                    .0
                                    .to_vec(),
                                Bytes::from_str("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2")
                                    .unwrap()
                                    .0
                                    .to_vec(),
                            ],
                            static_att: vec![
                                Attribute {
                                    name: "key1".to_owned(),
                                    value: b"value1".to_vec(),
                                    change: ChangeType::Creation.into(),
                                },
                                Attribute {
                                    name: "key2".to_owned(),
                                    value: b"value2".to_vec(),
                                    change: ChangeType::Creation.into(),
                                },
                            ],
                            change: ChangeType::Creation.into(),
                            protocol_type: Some(ProtocolType {
                                name: "WeightedPool".to_string(),
                                financial_type: 0,
                                attribute_schema: vec![],
                                implementation_type: 0,
                            }),
                        }],
                        balance_changes: vec![BalanceChange {
                            token: hex::decode(
                                "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"
                                    .trim_start_matches("0x"),
                            )
                            .unwrap(),
                            balance: 50000000.encode_to_vec(),
                            component_id:
                                "d417ff54652c09bd9f31f216b1a2e5d1e28c1dce1ba840c40d16f2b4d09b5902"
                                    .as_bytes()
                                    .to_vec(),
                        }],
                    },
                    TransactionChanges {
                        tx: Some(Transaction {
                            hash: vec![
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
                            ],
                            from: vec![0x41, 0x42, 0x43, 0x44],
                            to: vec![0x51, 0x52, 0x53, 0x54],
                            index: 5,
                        }),
                        contract_changes: vec![ContractChange {
                            address: vec![0x61, 0x62, 0x63, 0x64],
                            balance: vec![0xf1, 0xf2, 0xf3, 0xf4],
                            code: vec![0x01, 0x02, 0x03, 0x04],
                            slots: vec![
                                ContractSlot {
                                    slot: vec![0x91, 0x92, 0x93, 0x94],
                                    value: vec![0xa1, 0xa2, 0xa3, 0xa4],
                                },
                                ContractSlot {
                                    slot: vec![0xa1, 0xa2, 0xa3, 0xa4],
                                    value: vec![0xc1, 0xc2, 0xc3, 0xc4],
                                },
                            ],
                            change: ChangeType::Update.into(),
                        }],
                        entity_changes: vec![],
                        component_changes: vec![],
                        balance_changes: vec![BalanceChange {
                            token: hex::decode(
                                "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"
                                    .trim_start_matches("0x"),
                            )
                            .unwrap(),
                            balance: 10.encode_to_vec(),
                            component_id:
                                "d417ff54652c09bd9f31f216b1a2e5d1e28c1dce1ba840c40d16f2b4d09b5902"
                                    .to_string()
                                    .as_bytes()
                                    .to_vec(),
                        }],
                    },
                ],
            },
            1 => BlockChanges {
                block: Some(pb_blocks(version as u64)),
                changes: vec![TransactionChanges {
                    tx: Some(pb_transactions(1, 1)),
                    contract_changes: vec![ContractChange {
                        address: address_from_str("0000000000000000000000000000000000000001"),
                        balance: 1_i32.to_be_bytes().to_vec(),
                        code: 123_i32.to_be_bytes().to_vec(),
                        slots: vec![ContractSlot {
                            slot: Bytes::from("0x01").into(),
                            value: Bytes::from("0x01").into(),
                        }],
                        change: ChangeType::Creation.into(),
                    }],
                    entity_changes: vec![],
                    component_changes: vec![ProtocolComponent {
                        id: "pc_1".to_owned(),
                        tokens: vec![
                            address_from_str(WETH_ADDRESS),
                            address_from_str(USDC_ADDRESS),
                        ],
                        contracts: vec![],
                        static_att: vec![],
                        change: ChangeType::Creation.into(),
                        protocol_type: Some(ProtocolType {
                            name: "pt_1".to_string(),
                            financial_type: 0,
                            attribute_schema: vec![],
                            implementation_type: 0,
                        }),
                    }],
                    balance_changes: vec![
                        BalanceChange {
                            token: address_from_str(USDC_ADDRESS),
                            balance: 1_i32.to_be_bytes().to_vec(),
                            component_id: "pc_1".into(),
                        },
                        BalanceChange {
                            token: address_from_str(WETH_ADDRESS),
                            balance: 1_i32.to_be_bytes().to_vec(),
                            component_id: "pc_1".into(),
                        },
                    ],
                }],
            },
            2 => BlockChanges {
                block: Some(pb_blocks(version as u64)),
                changes: vec![TransactionChanges {
                    tx: Some(pb_transactions(2, 1)),
                    contract_changes: vec![
                        ContractChange {
                            address: address_from_str("0000000000000000000000000000000000000002"),
                            balance: 2_i32.to_be_bytes().to_vec(),
                            code: 123_i32.to_be_bytes().to_vec(),
                            slots: vec![ContractSlot {
                                slot: Bytes::from("0x01").into(),
                                value: Bytes::from("0x02").into(),
                            }],
                            change: ChangeType::Creation.into(),
                        },
                        ContractChange {
                            address: address_from_str("0000000000000000000000000000000000000001"),
                            balance: 10_i32.to_be_bytes().to_vec(),
                            code: 123_i32.to_be_bytes().to_vec(),
                            slots: vec![
                                ContractSlot {
                                    slot: Bytes::from("0x01").into(),
                                    value: Bytes::from("0x10").into(),
                                },
                                ContractSlot {
                                    slot: Bytes::from("0x02").into(),
                                    value: Bytes::from("0x0a").into(),
                                },
                            ],
                            change: ChangeType::Update.into(),
                        },
                    ],
                    entity_changes: vec![],
                    component_changes: vec![ProtocolComponent {
                        id: "pc_2".to_owned(),
                        tokens: vec![
                            address_from_str(USDT_ADDRESS),
                            address_from_str(USDC_ADDRESS),
                        ],
                        contracts: vec![address_from_str(
                            "0000000000000000000000000000000000000002",
                        )],
                        static_att: vec![],
                        change: ChangeType::Creation.into(),
                        protocol_type: Some(ProtocolType {
                            name: "pt_1".to_string(),
                            financial_type: 0,
                            attribute_schema: vec![],
                            implementation_type: 0,
                        }),
                    }],
                    balance_changes: vec![
                        BalanceChange {
                            token: address_from_str(USDC_ADDRESS),
                            balance: 20_i32.to_be_bytes().to_vec(),
                            component_id: "pc_2".into(),
                        },
                        BalanceChange {
                            token: address_from_str(USDT_ADDRESS),
                            balance: 20_i32.to_be_bytes().to_vec(),
                            component_id: "pc_2".into(),
                        },
                        BalanceChange {
                            token: address_from_str(USDC_ADDRESS),
                            balance: 10_i32.to_be_bytes().to_vec(),
                            component_id: "pc_1".into(),
                        },
                    ],
                }],
            },
            3 => BlockChanges {
                block: Some(pb_blocks(version as u64)),
                changes: vec![
                    TransactionChanges {
                        tx: Some(pb_transactions(3, 1)),
                        contract_changes: vec![
                            ContractChange {
                                address: address_from_str(
                                    "0000000000000000000000000000000000000001",
                                ),
                                balance: 1_i32.to_be_bytes().to_vec(),
                                code: 123_i32.to_le_bytes().to_vec(),
                                slots: vec![ContractSlot {
                                    slot: Bytes::from("0x01").into(),
                                    value: Bytes::from("0x01").into(),
                                }],
                                change: ChangeType::Update.into(),
                            },
                            ContractChange {
                                address: address_from_str(
                                    "0000000000000000000000000000000000000002",
                                ),
                                balance: 20_i32.to_be_bytes().to_vec(),
                                code: 123_i32.to_le_bytes().to_vec(),
                                slots: vec![ContractSlot {
                                    slot: Bytes::from("0x02").into(),
                                    value: Bytes::from("0xc8").into(),
                                }],
                                change: ChangeType::Update.into(),
                            },
                        ],
                        entity_changes: vec![],
                        component_changes: vec![],
                        balance_changes: vec![BalanceChange {
                            token: address_from_str(USDC_ADDRESS),
                            balance: 1_i32.to_be_bytes().to_vec(),
                            component_id: "pc_2".into(),
                        }],
                    },
                    TransactionChanges {
                        tx: Some(pb_transactions(3, 2)),
                        contract_changes: vec![ContractChange {
                            address: address_from_str("0000000000000000000000000000000000000001"),
                            balance: 1_i32.to_be_bytes().to_vec(),
                            code: 123_i32.to_le_bytes().to_vec(),
                            slots: vec![ContractSlot {
                                slot: Bytes::from("0x01").into(),
                                value: Bytes::from("0x01").into(),
                            }],
                            change: ChangeType::Update.into(),
                        }],
                        entity_changes: vec![],
                        component_changes: vec![],
                        balance_changes: vec![
                            BalanceChange {
                                token: address_from_str(USDC_ADDRESS),
                                balance: 100_i32.to_be_bytes().to_vec(),
                                component_id: "pc_1".into(),
                            },
                            BalanceChange {
                                token: address_from_str(USDC_ADDRESS),
                                balance: 2_i32.to_be_bytes().to_vec(),
                                component_id: "pc_2".into(),
                            },
                        ],
                    },
                ],
            },
            4 => BlockChanges {
                block: Some(pb_blocks(version as u64)),
                changes: vec![TransactionChanges {
                    tx: Some(pb_transactions(4, 1)),
                    contract_changes: vec![ContractChange {
                        address: address_from_str("0000000000000000000000000000000000000001"),
                        balance: 1_i32.to_be_bytes().to_vec(),
                        code: 123_i32.to_le_bytes().to_vec(),
                        slots: vec![ContractSlot {
                            slot: Bytes::from("0x03").into(),
                            value: Bytes::from("0x10").into(),
                        }],
                        change: ChangeType::Update.into(),
                    }],
                    entity_changes: vec![],
                    component_changes: vec![ProtocolComponent {
                        id: "pc_3".to_owned(),
                        tokens: vec![address_from_str(DAI_ADDRESS), address_from_str(USDC_ADDRESS)],
                        contracts: vec![address_from_str(
                            "0000000000000000000000000000000000000001",
                        )],
                        static_att: vec![],
                        change: ChangeType::Creation.into(),
                        protocol_type: Some(ProtocolType {
                            name: "pt_1".to_string(),
                            financial_type: 0,
                            attribute_schema: vec![],
                            implementation_type: 0,
                        }),
                    }],
                    balance_changes: vec![],
                }],
            },
            5 => BlockChanges {
                block: Some(pb_blocks(version as u64)),
                changes: vec![TransactionChanges {
                    tx: Some(pb_transactions(5, 1)),
                    contract_changes: vec![
                        ContractChange {
                            address: address_from_str("0000000000000000000000000000000000000001"),
                            balance: 1_i32.to_be_bytes().to_vec(),
                            code: 123_i32.to_le_bytes().to_vec(),
                            slots: vec![ContractSlot {
                                slot: Bytes::from("0x01").into(),
                                value: Bytes::from("0x10").into(),
                            }],
                            change: ChangeType::Update.into(),
                        },
                        ContractChange {
                            address: address_from_str("0000000000000000000000000000000000000002"),
                            balance: 1_i32.to_be_bytes().to_vec(),
                            code: 123_i32.to_le_bytes().to_vec(),
                            slots: vec![ContractSlot {
                                slot: Bytes::from("0x01").into(),
                                value: Bytes::from("0x10").into(),
                            }],
                            change: ChangeType::Update.into(),
                        },
                    ],
                    entity_changes: vec![],
                    component_changes: vec![],
                    balance_changes: vec![
                        BalanceChange {
                            token: address_from_str(USDC_ADDRESS),
                            balance: 1_i32.to_be_bytes().to_vec(),
                            component_id: "pc_1".into(),
                        },
                        BalanceChange {
                            token: address_from_str(USDC_ADDRESS),
                            balance: 1_i32.to_be_bytes().to_vec(),
                            component_id: "pc_3".into(),
                        },
                        BalanceChange {
                            token: address_from_str(WETH_ADDRESS),
                            balance: 1_i32.to_be_bytes().to_vec(),
                            component_id: "pc_1".into(),
                        },
                    ],
                }],
            },
            _ => panic!("Requested BlockChanges version doesn't exist"),
        }
    }

    pub fn pb_state_changes() -> crate::pb::tycho::evm::v1::EntityChanges {
        use crate::pb::tycho::evm::v1::*;
        let res1_value = 1000_u64.to_be_bytes().to_vec();
        let res2_value = 500_u64.to_be_bytes().to_vec();
        EntityChanges {
            component_id: "State1".to_owned(),
            attributes: vec![
                Attribute {
                    name: "reserve1".to_owned(),
                    value: res1_value,
                    change: ChangeType::Update.into(),
                },
                Attribute {
                    name: "reserve2".to_owned(),
                    value: res2_value,
                    change: ChangeType::Update.into(),
                },
            ],
        }
    }

    pub fn pb_blocks(version: u64) -> crate::pb::tycho::evm::v1::Block {
        if version == 0 {
            panic!("Block version 0 doesn't exist. It starts at 1");
        }
        let base_ts = yesterday_midnight().timestamp() as u64;

        crate::pb::tycho::evm::v1::Block {
            number: version,
            hash: Bytes::from(version)
                .lpad(32, 0)
                .to_vec(),
            parent_hash: Bytes::from(version - 1)
                .lpad(32, 0)
                .to_vec(),
            ts: base_ts + version * 1000,
        }
    }

    pub fn pb_transactions(version: u64, index: u64) -> crate::pb::tycho::evm::v1::Transaction {
        crate::pb::tycho::evm::v1::Transaction {
            hash: Bytes::from(version * 10_000 + index)
                .lpad(32, 0)
                .to_vec(),
            from: Bytes::from(version * 100_000 + index)
                .lpad(20, 0)
                .to_vec(),
            to: Bytes::from(version * 1_000_000 + index)
                .lpad(20, 0)
                .to_vec(),
            index,
        }
    }

    const WETH_ADDRESS: &str = "C02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2";
    const USDC_ADDRESS: &str = "A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";
    const DAI_ADDRESS: &str = "6B175474E89094C44Da98b954EedeAC495271d0F";
    const USDT_ADDRESS: &str = "dAC17F958D2ee523a2206206994597C13D831ec7";

    pub fn address_from_str(token: &str) -> Vec<u8> {
        Bytes::from_str(token)
            .unwrap()
            .0
            .to_vec()
    }

    pub fn pb_block_entity_changes(version: u8) -> crate::pb::tycho::evm::v1::BlockEntityChanges {
        use crate::pb::tycho::evm::v1::*;

        match version {
            0 => BlockEntityChanges {
                block: Some(Block {
                    hash: Bytes::zero(32).to_vec(),
                    parent_hash: Bytes::from(vec![0x21, 0x22, 0x23, 0x24])
                        .lpad(32, 0)
                        .to_vec(),
                    number: 1,
                    ts: yesterday_midnight().timestamp() as u64,
                }),
                changes: vec![
                    TransactionEntityChanges {
                        tx: Some(Transaction {
                            hash: Bytes::zero(32).to_vec(),
                            from: Bytes::zero(20).to_vec(),
                            to: Bytes::zero(20).to_vec(),
                            index: 10,
                        }),
                        entity_changes: vec![
                            EntityChanges {
                                component_id: "State1".to_owned(),
                                attributes: vec![
                                    Attribute {
                                        name: "reserve".to_owned(),
                                        value: 1000_u64.to_be_bytes().to_vec(),
                                        change: ChangeType::Update.into(),
                                    },
                                    Attribute {
                                        name: "static_attribute".to_owned(),
                                        value: 1_u64.to_be_bytes().to_vec(),
                                        change: ChangeType::Update.into(),
                                    },
                                ],
                            },
                            EntityChanges {
                                component_id: "State2".to_owned(),
                                attributes: vec![
                                    Attribute {
                                        name: "reserve".to_owned(),
                                        value: 1000_u64.to_be_bytes().to_vec(),
                                        change: ChangeType::Update.into(),
                                    },
                                    Attribute {
                                        name: "static_attribute".to_owned(),
                                        value: 1_u64.to_be_bytes().to_vec(),
                                        change: ChangeType::Update.into(),
                                    },
                                ],
                            },
                        ],
                        component_changes: vec![],
                        balance_changes: vec![],
                    },
                    TransactionEntityChanges {
                        tx: Some(Transaction {
                            hash: Bytes::from(vec![0x11, 0x12, 0x13, 0x14])
                                .lpad(32, 0)
                                .to_vec(),
                            from: Bytes::from(vec![0x41, 0x42, 0x43, 0x44])
                                .lpad(20, 0)
                                .to_vec(),
                            to: Bytes::from(vec![0x51, 0x52, 0x53, 0x54])
                                .lpad(20, 0)
                                .to_vec(),
                            index: 11,
                        }),
                        entity_changes: vec![EntityChanges {
                            component_id: "State1".to_owned(),
                            attributes: vec![
                                Attribute {
                                    name: "reserve".to_owned(),
                                    value: 600_u64.to_be_bytes().to_vec(),
                                    change: ChangeType::Update.into(),
                                },
                                Attribute {
                                    name: "new".to_owned(),
                                    value: 0_u64.to_be_bytes().to_vec(),
                                    change: ChangeType::Update.into(),
                                },
                            ],
                        }],
                        component_changes: vec![ProtocolComponent {
                            id: "Pool".to_owned(),
                            tokens: vec![
                                Bytes::from_str("0x6B175474E89094C44Da98b954EedeAC495271d0F")
                                    .unwrap()
                                    .0
                                    .to_vec(),
                                Bytes::from_str("0x6B175474E89094C44Da98b954EedeAC495271d0F")
                                    .unwrap()
                                    .0
                                    .to_vec(),
                            ],
                            contracts: vec![Bytes::from_str(
                                "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
                            )
                            .unwrap()
                            .0
                            .to_vec()],
                            static_att: vec![Attribute {
                                name: "key".to_owned(),
                                value: 600_u64.to_be_bytes().to_vec(),
                                change: ChangeType::Creation.into(),
                            }],
                            change: ChangeType::Creation.into(),
                            protocol_type: Some(ProtocolType {
                                name: "WeightedPool".to_string(),
                                financial_type: 0,
                                attribute_schema: vec![],
                                implementation_type: 0,
                            }),
                        }],
                        balance_changes: vec![BalanceChange {
                            token: Bytes::from_str("0x6B175474E89094C44Da98b954EedeAC495271d0F")
                                .unwrap()
                                .0
                                .to_vec(),
                            balance: 1_i32.to_le_bytes().to_vec(),
                            component_id: "Balance1".into(),
                        }],
                    },
                ],
            },
            1 => BlockEntityChanges {
                block: Some(pb_blocks(version as u64)),
                changes: vec![TransactionEntityChanges {
                    tx: Some(pb_transactions(1, 1)),
                    entity_changes: vec![EntityChanges {
                        component_id: "pc_1".to_owned(),
                        attributes: vec![
                            Attribute {
                                name: "attr_1".to_owned(),
                                value: 1_u64.to_be_bytes().to_vec(),
                                change: ChangeType::Update.into(),
                            },
                            Attribute {
                                name: "attr_2".to_owned(),
                                value: 2_u64.to_be_bytes().to_vec(),
                                change: ChangeType::Update.into(),
                            },
                        ],
                    }],
                    component_changes: vec![ProtocolComponent {
                        id: "pc_1".to_owned(),
                        tokens: vec![
                            address_from_str(WETH_ADDRESS),
                            address_from_str(USDC_ADDRESS),
                        ],
                        contracts: vec![],
                        static_att: vec![Attribute {
                            name: "st_attr_1".to_owned(),
                            value: 1_u64.to_be_bytes().to_vec(),
                            change: ChangeType::Creation.into(),
                        }],
                        change: ChangeType::Creation.into(),
                        protocol_type: Some(ProtocolType {
                            name: "pt_1".to_string(),
                            financial_type: 0,
                            attribute_schema: vec![],
                            implementation_type: 0,
                        }),
                    }],
                    balance_changes: vec![BalanceChange {
                        token: address_from_str(USDC_ADDRESS),
                        balance: 1_i32.to_be_bytes().to_vec(),
                        component_id: "pc_1".into(),
                    }],
                }],
            },
            2 => BlockEntityChanges {
                block: Some(pb_blocks(version as u64)),
                changes: vec![TransactionEntityChanges {
                    tx: Some(pb_transactions(2, 1)),
                    entity_changes: vec![EntityChanges {
                        component_id: "pc_1".to_owned(),
                        attributes: vec![Attribute {
                            name: "attr_1".to_owned(),
                            value: 10_u64.to_be_bytes().to_vec(),
                            change: ChangeType::Update.into(),
                        }],
                    }],
                    component_changes: vec![ProtocolComponent {
                        id: "pc_2".to_owned(),
                        tokens: vec![
                            address_from_str(USDT_ADDRESS),
                            address_from_str(USDC_ADDRESS),
                        ],
                        contracts: vec![],
                        static_att: vec![],
                        change: ChangeType::Creation.into(),
                        protocol_type: Some(ProtocolType {
                            name: "pt_1".to_string(),
                            financial_type: 0,
                            attribute_schema: vec![],
                            implementation_type: 0,
                        }),
                    }],
                    balance_changes: vec![
                        BalanceChange {
                            token: address_from_str(USDC_ADDRESS),
                            balance: 1_i32.to_be_bytes().to_vec(),
                            component_id: "pc_2".into(),
                        },
                        BalanceChange {
                            token: address_from_str(USDT_ADDRESS),
                            balance: 1_i32.to_be_bytes().to_vec(),
                            component_id: "pc_2".into(),
                        },
                        BalanceChange {
                            token: address_from_str(WETH_ADDRESS),
                            balance: 1_i32.to_be_bytes().to_vec(),
                            component_id: "pc_1".into(),
                        },
                    ],
                }],
            },
            3 => BlockEntityChanges {
                block: Some(pb_blocks(version as u64)),
                changes: vec![
                    TransactionEntityChanges {
                        tx: Some(pb_transactions(3, 2)),
                        entity_changes: vec![EntityChanges {
                            component_id: "pc_1".to_owned(),
                            attributes: vec![Attribute {
                                name: "attr_1".to_owned(),
                                value: 1000_u64.to_be_bytes().to_vec(),
                                change: ChangeType::Update.into(),
                            }],
                        }],
                        component_changes: vec![],
                        balance_changes: vec![BalanceChange {
                            token: address_from_str(USDC_ADDRESS),
                            balance: 3_i32.to_be_bytes().to_vec(),
                            component_id: "pc_2".into(),
                        }],
                    },
                    TransactionEntityChanges {
                        tx: Some(pb_transactions(3, 1)),
                        entity_changes: vec![EntityChanges {
                            component_id: "pc_1".to_owned(),
                            attributes: vec![Attribute {
                                name: "attr_1".to_owned(),
                                value: 99999_u64.to_be_bytes().to_vec(),
                                change: ChangeType::Update.into(),
                            }],
                        }],
                        component_changes: vec![],
                        balance_changes: vec![
                            BalanceChange {
                                token: address_from_str(USDC_ADDRESS),
                                balance: 99999_i32.to_be_bytes().to_vec(),
                                component_id: "pc_2".into(),
                            },
                            BalanceChange {
                                token: address_from_str(WETH_ADDRESS),
                                balance: 1000_i32.to_be_bytes().to_vec(),
                                component_id: "pc_1".into(),
                            },
                        ],
                    },
                ],
            },
            4 => BlockEntityChanges {
                block: Some(pb_blocks(version as u64)),
                changes: vec![
                    TransactionEntityChanges {
                        tx: Some(pb_transactions(4, 1)),
                        entity_changes: vec![
                            EntityChanges {
                                component_id: "pc_1".to_owned(),
                                attributes: vec![Attribute {
                                    name: "attr_1".to_owned(),
                                    value: 10000_u64.to_be_bytes().to_vec(),
                                    change: ChangeType::Update.into(),
                                }],
                            },
                            EntityChanges {
                                component_id: "pc_3".to_owned(),
                                attributes: vec![Attribute {
                                    name: "attr_1".to_owned(),
                                    value: 3_u64.to_be_bytes().to_vec(),
                                    change: ChangeType::Update.into(),
                                }],
                            },
                        ],
                        component_changes: vec![ProtocolComponent {
                            id: "pc_3".to_owned(),
                            tokens: vec![
                                address_from_str(DAI_ADDRESS),
                                address_from_str(WETH_ADDRESS),
                            ],
                            contracts: vec![],
                            static_att: vec![],
                            change: ChangeType::Creation.into(),
                            protocol_type: Some(ProtocolType {
                                name: "pt_2".to_string(),
                                financial_type: 0,
                                attribute_schema: vec![],
                                implementation_type: 0,
                            }),
                        }],
                        balance_changes: vec![],
                    },
                    TransactionEntityChanges {
                        tx: Some(pb_transactions(4, 2)),
                        entity_changes: vec![
                            EntityChanges {
                                component_id: "pc_3".to_owned(),
                                attributes: vec![Attribute {
                                    name: "attr_1".to_owned(),
                                    value: 30_u64.to_be_bytes().to_vec(),
                                    change: ChangeType::Update.into(),
                                }],
                            },
                            EntityChanges {
                                component_id: "pc_1".to_owned(),
                                attributes: vec![Attribute {
                                    name: "attr_1".to_owned(),
                                    value: 100000_u64.to_be_bytes().to_vec(),
                                    change: ChangeType::Update.into(),
                                }],
                            },
                        ],
                        component_changes: vec![],
                        balance_changes: vec![
                            BalanceChange {
                                token: address_from_str(USDC_ADDRESS),
                                balance: 3000_i32.to_be_bytes().to_vec(),
                                component_id: "pc_3".into(),
                            },
                            BalanceChange {
                                token: address_from_str(USDC_ADDRESS),
                                balance: 1000_i32.to_be_bytes().to_vec(),
                                component_id: "pc_1".into(),
                            },
                        ],
                    },
                ],
            },
            5 => BlockEntityChanges {
                block: Some(pb_blocks(version as u64)),
                changes: vec![TransactionEntityChanges {
                    tx: Some(pb_transactions(5, 1)),
                    entity_changes: vec![EntityChanges {
                        component_id: "pc_1".to_owned(),
                        attributes: vec![Attribute {
                            name: "attr_2".to_owned(),
                            value: 1000000_u64.to_be_bytes().to_vec(),
                            change: ChangeType::Update.into(),
                        }],
                    }],
                    component_changes: vec![ProtocolComponent {
                        id: "pc_2".to_owned(),
                        tokens: vec![
                            address_from_str(USDT_ADDRESS),
                            address_from_str(USDC_ADDRESS),
                        ],
                        contracts: vec![],
                        static_att: vec![],
                        change: ChangeType::Deletion.into(),
                        protocol_type: Some(ProtocolType {
                            name: "pt_1".to_string(),
                            financial_type: 0,
                            attribute_schema: vec![],
                            implementation_type: 0,
                        }),
                    }],
                    balance_changes: vec![BalanceChange {
                        token: address_from_str(WETH_ADDRESS),
                        balance: 1000_i32.to_be_bytes().to_vec(),
                        component_id: "pc_1".into(),
                    }],
                }],
            },
            _ => panic!("Requested unknown version of block entity changes"),
        }
    }

    pub fn pb_native_block_changes(version: u8) -> crate::pb::tycho::evm::v1::BlockChanges {
        use crate::pb::tycho::evm::v1::*;

        match version {
            0 => BlockChanges {
                block: Some(Block {
                    hash: vec![0x0, 0x0, 0x0, 0x0],
                    parent_hash: vec![0x21, 0x22, 0x23, 0x24],
                    number: 1,
                    ts: yesterday_midnight().timestamp() as u64,
                }),
                changes: vec![
                    TransactionChanges {
                        tx: Some(Transaction {
                            hash: vec![0x0, 0x0, 0x0, 0x0],
                            from: vec![0x0, 0x0, 0x0, 0x0],
                            to: vec![0x0, 0x0, 0x0, 0x0],
                            index: 10,
                        }),
                        contract_changes: vec![],
                        entity_changes: vec![
                            EntityChanges {
                                component_id: "State1".to_owned(),
                                attributes: vec![
                                    Attribute {
                                        name: "reserve".to_owned(),
                                        value: 1000_u64.to_be_bytes().to_vec(),
                                        change: ChangeType::Update.into(),
                                    },
                                    Attribute {
                                        name: "static_attribute".to_owned(),
                                        value: 1_u64.to_be_bytes().to_vec(),
                                        change: ChangeType::Update.into(),
                                    },
                                ],
                            },
                            EntityChanges {
                                component_id: "State2".to_owned(),
                                attributes: vec![
                                    Attribute {
                                        name: "reserve".to_owned(),
                                        value: 1000_u64.to_be_bytes().to_vec(),
                                        change: ChangeType::Update.into(),
                                    },
                                    Attribute {
                                        name: "static_attribute".to_owned(),
                                        value: 1_u64.to_be_bytes().to_vec(),
                                        change: ChangeType::Update.into(),
                                    },
                                ],
                            },
                        ],
                        component_changes: vec![],
                        balance_changes: vec![],
                    },
                    TransactionChanges {
                        tx: Some(Transaction {
                            hash: vec![0x11, 0x12, 0x13, 0x14],
                            from: vec![0x41, 0x42, 0x43, 0x44],
                            to: vec![0x51, 0x52, 0x53, 0x54],
                            index: 11,
                        }),
                        contract_changes: vec![],
                        entity_changes: vec![EntityChanges {
                            component_id: "State1".to_owned(),
                            attributes: vec![
                                Attribute {
                                    name: "reserve".to_owned(),
                                    value: 600_u64.to_be_bytes().to_vec(),
                                    change: ChangeType::Update.into(),
                                },
                                Attribute {
                                    name: "new".to_owned(),
                                    value: 0_u64.to_be_bytes().to_vec(),
                                    change: ChangeType::Update.into(),
                                },
                            ],
                        }],
                        component_changes: vec![ProtocolComponent {
                            id: "Pool".to_owned(),
                            tokens: vec![
                                Bytes::from_str("0x6B175474E89094C44Da98b954EedeAC495271d0F")
                                    .unwrap()
                                    .0
                                    .to_vec(),
                                Bytes::from_str("0x6B175474E89094C44Da98b954EedeAC495271d0F")
                                    .unwrap()
                                    .0
                                    .to_vec(),
                            ],
                            contracts: vec![Bytes::from_str(
                                "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
                            )
                            .unwrap()
                            .0
                            .to_vec()],
                            static_att: vec![Attribute {
                                name: "key".to_owned(),
                                value: 600_u64.to_be_bytes().to_vec(),
                                change: ChangeType::Creation.into(),
                            }],
                            change: ChangeType::Creation.into(),
                            protocol_type: Some(ProtocolType {
                                name: "WeightedPool".to_string(),
                                financial_type: 0,
                                attribute_schema: vec![],
                                implementation_type: 0,
                            }),
                        }],
                        balance_changes: vec![BalanceChange {
                            token: Bytes::from_str("0x6B175474E89094C44Da98b954EedeAC495271d0F")
                                .unwrap()
                                .0
                                .to_vec(),
                            balance: 1_i32.to_le_bytes().to_vec(),
                            component_id: "Balance1".into(),
                        }],
                    },
                ],
            },
            1 => BlockChanges {
                block: Some(pb_blocks(version as u64)),
                changes: vec![TransactionChanges {
                    tx: Some(pb_transactions(1, 1)),
                    contract_changes: vec![],
                    entity_changes: vec![EntityChanges {
                        component_id: "pc_1".to_owned(),
                        attributes: vec![
                            Attribute {
                                name: "attr_1".to_owned(),
                                value: 1_u64.to_be_bytes().to_vec(),
                                change: ChangeType::Update.into(),
                            },
                            Attribute {
                                name: "attr_2".to_owned(),
                                value: 2_u64.to_be_bytes().to_vec(),
                                change: ChangeType::Update.into(),
                            },
                        ],
                    }],
                    component_changes: vec![ProtocolComponent {
                        id: "pc_1".to_owned(),
                        tokens: vec![
                            address_from_str(WETH_ADDRESS),
                            address_from_str(USDC_ADDRESS),
                        ],
                        contracts: vec![],
                        static_att: vec![Attribute {
                            name: "st_attr_1".to_owned(),
                            value: 1_u64.to_be_bytes().to_vec(),
                            change: ChangeType::Creation.into(),
                        }],
                        change: ChangeType::Creation.into(),
                        protocol_type: Some(ProtocolType {
                            name: "pt_1".to_string(),
                            financial_type: 0,
                            attribute_schema: vec![],
                            implementation_type: 0,
                        }),
                    }],
                    balance_changes: vec![BalanceChange {
                        token: address_from_str(USDC_ADDRESS),
                        balance: 1_i32.to_be_bytes().to_vec(),
                        component_id: "pc_1".into(),
                    }],
                }],
            },
            2 => BlockChanges {
                block: Some(pb_blocks(version as u64)),
                changes: vec![TransactionChanges {
                    tx: Some(pb_transactions(2, 1)),
                    contract_changes: vec![],
                    entity_changes: vec![EntityChanges {
                        component_id: "pc_1".to_owned(),
                        attributes: vec![Attribute {
                            name: "attr_1".to_owned(),
                            value: 10_u64.to_be_bytes().to_vec(),
                            change: ChangeType::Update.into(),
                        }],
                    }],
                    component_changes: vec![ProtocolComponent {
                        id: "pc_2".to_owned(),
                        tokens: vec![
                            address_from_str(USDT_ADDRESS),
                            address_from_str(USDC_ADDRESS),
                        ],
                        contracts: vec![],
                        static_att: vec![],
                        change: ChangeType::Creation.into(),
                        protocol_type: Some(ProtocolType {
                            name: "pt_1".to_string(),
                            financial_type: 0,
                            attribute_schema: vec![],
                            implementation_type: 0,
                        }),
                    }],
                    balance_changes: vec![
                        BalanceChange {
                            token: address_from_str(USDC_ADDRESS),
                            balance: 1_i32.to_be_bytes().to_vec(),
                            component_id: "pc_2".into(),
                        },
                        BalanceChange {
                            token: address_from_str(USDT_ADDRESS),
                            balance: 1_i32.to_be_bytes().to_vec(),
                            component_id: "pc_2".into(),
                        },
                        BalanceChange {
                            token: address_from_str(WETH_ADDRESS),
                            balance: 1_i32.to_be_bytes().to_vec(),
                            component_id: "pc_1".into(),
                        },
                    ],
                }],
            },
            3 => BlockChanges {
                block: Some(pb_blocks(version as u64)),
                changes: vec![
                    TransactionChanges {
                        tx: Some(pb_transactions(3, 2)),
                        contract_changes: vec![],
                        entity_changes: vec![EntityChanges {
                            component_id: "pc_1".to_owned(),
                            attributes: vec![Attribute {
                                name: "attr_1".to_owned(),
                                value: 1000_u64.to_be_bytes().to_vec(),
                                change: ChangeType::Update.into(),
                            }],
                        }],
                        component_changes: vec![],
                        balance_changes: vec![BalanceChange {
                            token: address_from_str(USDC_ADDRESS),
                            balance: 3_i32.to_be_bytes().to_vec(),
                            component_id: "pc_2".into(),
                        }],
                    },
                    TransactionChanges {
                        tx: Some(pb_transactions(3, 1)),
                        contract_changes: vec![],
                        entity_changes: vec![EntityChanges {
                            component_id: "pc_1".to_owned(),
                            attributes: vec![Attribute {
                                name: "attr_1".to_owned(),
                                value: 99999_u64.to_be_bytes().to_vec(),
                                change: ChangeType::Update.into(),
                            }],
                        }],
                        component_changes: vec![],
                        balance_changes: vec![
                            BalanceChange {
                                token: address_from_str(USDC_ADDRESS),
                                balance: 99999_i32.to_be_bytes().to_vec(),
                                component_id: "pc_2".into(),
                            },
                            BalanceChange {
                                token: address_from_str(WETH_ADDRESS),
                                balance: 1000_i32.to_be_bytes().to_vec(),
                                component_id: "pc_1".into(),
                            },
                        ],
                    },
                ],
            },
            4 => BlockChanges {
                block: Some(pb_blocks(version as u64)),
                changes: vec![
                    TransactionChanges {
                        tx: Some(pb_transactions(4, 1)),
                        contract_changes: vec![],
                        entity_changes: vec![
                            EntityChanges {
                                component_id: "pc_1".to_owned(),
                                attributes: vec![Attribute {
                                    name: "attr_1".to_owned(),
                                    value: 10000_u64.to_be_bytes().to_vec(),
                                    change: ChangeType::Update.into(),
                                }],
                            },
                            EntityChanges {
                                component_id: "pc_3".to_owned(),
                                attributes: vec![Attribute {
                                    name: "attr_1".to_owned(),
                                    value: 3_u64.to_be_bytes().to_vec(),
                                    change: ChangeType::Update.into(),
                                }],
                            },
                        ],
                        component_changes: vec![ProtocolComponent {
                            id: "pc_3".to_owned(),
                            tokens: vec![
                                address_from_str(DAI_ADDRESS),
                                address_from_str(WETH_ADDRESS),
                            ],
                            contracts: vec![],
                            static_att: vec![],
                            change: ChangeType::Creation.into(),
                            protocol_type: Some(ProtocolType {
                                name: "pt_2".to_string(),
                                financial_type: 0,
                                attribute_schema: vec![],
                                implementation_type: 0,
                            }),
                        }],
                        balance_changes: vec![],
                    },
                    TransactionChanges {
                        tx: Some(pb_transactions(4, 2)),
                        contract_changes: vec![],
                        entity_changes: vec![
                            EntityChanges {
                                component_id: "pc_3".to_owned(),
                                attributes: vec![Attribute {
                                    name: "attr_1".to_owned(),
                                    value: 30_u64.to_be_bytes().to_vec(),
                                    change: ChangeType::Update.into(),
                                }],
                            },
                            EntityChanges {
                                component_id: "pc_1".to_owned(),
                                attributes: vec![Attribute {
                                    name: "attr_1".to_owned(),
                                    value: 100000_u64.to_be_bytes().to_vec(),
                                    change: ChangeType::Update.into(),
                                }],
                            },
                        ],
                        component_changes: vec![],
                        balance_changes: vec![
                            BalanceChange {
                                token: address_from_str(USDC_ADDRESS),
                                balance: 3000_i32.to_be_bytes().to_vec(),
                                component_id: "pc_3".into(),
                            },
                            BalanceChange {
                                token: address_from_str(USDC_ADDRESS),
                                balance: 1000_i32.to_be_bytes().to_vec(),
                                component_id: "pc_1".into(),
                            },
                        ],
                    },
                ],
            },
            5 => BlockChanges {
                block: Some(pb_blocks(version as u64)),
                changes: vec![TransactionChanges {
                    tx: Some(pb_transactions(5, 1)),
                    contract_changes: vec![],
                    entity_changes: vec![EntityChanges {
                        component_id: "pc_1".to_owned(),
                        attributes: vec![Attribute {
                            name: "attr_2".to_owned(),
                            value: 1000000_u64.to_be_bytes().to_vec(),
                            change: ChangeType::Update.into(),
                        }],
                    }],
                    component_changes: vec![ProtocolComponent {
                        id: "pc_2".to_owned(),
                        tokens: vec![
                            address_from_str(USDT_ADDRESS),
                            address_from_str(USDC_ADDRESS),
                        ],
                        contracts: vec![],
                        static_att: vec![],
                        change: ChangeType::Deletion.into(),
                        protocol_type: Some(ProtocolType {
                            name: "pt_1".to_string(),
                            financial_type: 0,
                            attribute_schema: vec![],
                            implementation_type: 0,
                        }),
                    }],
                    balance_changes: vec![BalanceChange {
                        token: address_from_str(WETH_ADDRESS),
                        balance: 1000_i32.to_be_bytes().to_vec(),
                        component_id: "pc_1".into(),
                    }],
                }],
            },
            _ => panic!("Requested unknown version of block entity changes"),
        }
    }

    pub fn pb_protocol_component() -> crate::pb::tycho::evm::v1::ProtocolComponent {
        use crate::pb::tycho::evm::v1::*;
        ProtocolComponent {
            id: "d417ff54652c09bd9f31f216b1a2e5d1e28c1dce1ba840c40d16f2b4d09b5902".to_owned(),
            tokens: vec![
                Bytes::from_str("0x6B175474E89094C44Da98b954EedeAC495271d0F")
                    .unwrap()
                    .0
                    .to_vec(),
                Bytes::from_str("0x6B175474E89094C44Da98b954EedeAC495271d0F")
                    .unwrap()
                    .0
                    .to_vec(),
            ],
            contracts: vec![
                Bytes::from_str("0x31fF2589Ee5275a2038beB855F44b9Be993aA804")
                    .unwrap()
                    .0
                    .to_vec(),
                Bytes::from_str("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2")
                    .unwrap()
                    .0
                    .to_vec(),
            ],
            static_att: vec![
                Attribute {
                    name: "balance".to_owned(),
                    value: 100_u64.to_be_bytes().to_vec(),
                    change: ChangeType::Creation.into(),
                },
                Attribute {
                    name: "factory_address".to_owned(),
                    value: b"0x0fwe0g240g20".to_vec(),
                    change: ChangeType::Creation.into(),
                },
            ],
            change: ChangeType::Creation.into(),
            protocol_type: Some(ProtocolType {
                name: "WeightedPool".to_string(),
                financial_type: 0,
                attribute_schema: vec![],
                implementation_type: 0,
            }),
        }
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use prost::Message;
    use rstest::rstest;

    use tycho_core::{keccak256, models::contract::Account};
    use tycho_storage::postgres::db_fixtures::yesterday_midnight;

    use crate::extractor::evm::fixtures::transaction01;

    use super::*;

    const HASH_256_0: &str = "0x0000000000000000000000000000000000000000000000000000000000000000";
    const HASH_256_1: &str = "0x0000000000000000000000000000000000000000000000000000000000000001";

    fn account01() -> Account {
        let code = vec![0, 0, 0, 0];
        let code_hash = Bytes::from(keccak256(&code));
        Account::new(
            Chain::Ethereum,
            "0xe688b84b23f322a994A53dbF8E15FA82CDB71127"
                .parse()
                .unwrap(),
            "0xe688b84b23f322a994a53dbf8e15fa82cdb71127".into(),
            HashMap::new(),
            Bytes::from(10000u64).lpad(32, 0),
            code.into(),
            code_hash,
            Bytes::zero(32),
            Bytes::zero(32),
            Some(Bytes::zero(32)),
        )
    }

    fn tx_update() -> TransactionVMUpdates {
        let code = vec![0, 0, 0, 0];
        let mut account_updates = HashMap::new();
        account_updates.insert(
            "0xe688b84b23f322a994A53dbF8E15FA82CDB71127"
                .parse()
                .unwrap(),
            AccountDelta::new(
                Chain::Ethereum,
                Bytes::from_str("e688b84b23f322a994A53dbF8E15FA82CDB71127").unwrap(),
                HashMap::new(),
                Some(Bytes::from(10000u64).lpad(32, 0)),
                Some(code.into()),
                ChangeType::Update,
            ),
        );

        TransactionVMUpdates::new(
            account_updates,
            HashMap::new(),
            HashMap::new(),
            fixtures::transaction01(),
        )
    }

    fn update_balance() -> AccountDelta {
        AccountDelta::new(
            Chain::Ethereum,
            Bytes::from_str("e688b84b23f322a994A53dbF8E15FA82CDB71127").unwrap(),
            HashMap::new(),
            Some(Bytes::from(420u64).lpad(32, 0)),
            None,
            ChangeType::Update,
        )
    }

    fn update_slots() -> AccountDelta {
        AccountDelta::new(
            Chain::Ethereum,
            Bytes::from_str("e688b84b23f322a994A53dbF8E15FA82CDB71127").unwrap(),
            fixtures::slots([(0, 1), (1, 2)]),
            None,
            None,
            ChangeType::Update,
        )
    }

    #[test]
    fn test_account_from_update_w_tx() {
        let update = tx_update();
        let exp = account01();

        assert_eq!(
            update
                .account_deltas
                .values()
                .next()
                .unwrap()
                .ref_into_account(&update.tx),
            exp
        );
    }

    #[test]
    fn test_merge_account_update() {
        let mut update_left = update_balance();
        let update_right = update_slots();
        let mut exp = update_slots();
        exp.balance = Some(Bytes::from(420u64).lpad(32, 0));

        update_left.merge(update_right).unwrap();

        assert_eq!(update_left, exp);
    }

    #[test]
    fn test_merge_account_update_wrong_address() {
        let mut update_left = update_balance();
        let mut update_right = update_slots();
        update_right.address = Bytes::zero(20);
        let exp = Err("Can't merge AccountUpdates from differing identities; \
            Expected 0xe688b84b23f322a994a53dbf8e15fa82cdb71127, \
            got 0x0000000000000000000000000000000000000000"
            .into());

        let res = update_left.merge(update_right);

        assert_eq!(res, exp);
    }

    #[rstest]
    #[case::diff_block(
    fixtures::transaction02(HASH_256_1, HASH_256_1, 11),
    Err(format ! ("Can't merge TransactionVMUpdates from different blocks: {:x} != {}", Bytes::zero(32), HASH_256_1))
    )]
    #[case::same_tx(
    fixtures::transaction02(HASH_256_0, HASH_256_0, 11),
    Err(format ! ("Can't merge TransactionVMUpdates from the same transaction: {:x}", Bytes::zero(32)))
    )]
    #[case::lower_idx(
    fixtures::transaction02(HASH_256_1, HASH_256_0, 1),
    Err("Can't merge TransactionVMUpdates with lower transaction index: 10 > 1".to_owned())
    )]
    fn test_merge_account_update_w_tx(#[case] tx: Transaction, #[case] exp: Result<(), String>) {
        let mut left = tx_update();
        let mut right = left.clone();
        right.tx = tx;

        let res = left.merge(&right);

        assert_eq!(res, exp);
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

    fn block_state_changes() -> BlockContractChanges {
        let tx = Transaction {
            hash: Bytes::from_str(
                "0000000000000000000000000000000000000000000000000000000011121314",
            )
            .unwrap(),
            block_hash: Bytes::from_str(
                "0000000000000000000000000000000000000000000000000000000031323334",
            )
            .unwrap(),
            from: Bytes::from_str("0000000000000000000000000000000041424344").unwrap(),
            to: Some(Bytes::from_str("0000000000000000000000000000000051525354").unwrap()),
            index: 2,
        };
        let tx_5 = Transaction {
            hash: Bytes::from_str(HASH_256_1).unwrap(),
            block_hash: Bytes::from_str(
                "0000000000000000000000000000000000000000000000000000000031323334",
            )
            .unwrap(),
            from: Bytes::from_str("0000000000000000000000000000000041424344").unwrap(),
            to: Some(Bytes::from_str("0000000000000000000000000000000051525354").unwrap()),
            index: 5,
        };
        let protocol_component = create_protocol_component(tx.hash.clone());
        BlockContractChanges {
            extractor: "test".to_string(),
            chain: Chain::Ethereum,
            block: Block::new(
                1,
                Chain::Ethereum,
                Bytes::from_str("0x0000000000000000000000000000000000000000000000000000000031323334").unwrap(),
                Bytes::from_str("0x0000000000000000000000000000000000000000000000000000000021222324").unwrap(),
                NaiveDateTime::from_timestamp_opt(1000, 0).unwrap(),
            ),
            finalized_block_height: 0,
            revert: false,
            new_tokens: HashMap::new(),
            tx_updates: vec![
                TransactionVMUpdates {
                    account_deltas: [(
                        Bytes::from_str("0x0000000000000000000000000000000061626364").unwrap(),
                        AccountDelta::new(
                            Chain::Ethereum,
                            Bytes::from_str("0000000000000000000000000000000061626364").unwrap(),
                            fixtures::slots([
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
                            Bytes::from_str("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2").unwrap(),
                            ComponentBalance {
                                token: Bytes::from_str("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2").unwrap(),
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

                    tx,
                },
                TransactionVMUpdates {
                    account_deltas: [(
                        Bytes::from_str("0x0000000000000000000000000000000061626364").unwrap(),
                        AccountDelta::new(
                            Chain::Ethereum,
                            Bytes::from_str("0000000000000000000000000000000061626364").unwrap(),
                            fixtures::slots([
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
                            Bytes::from_str("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2").unwrap(),
                            ComponentBalance {
                                token: Bytes::from_str("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2").unwrap(),
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
                    tx: tx_5,
                },
            ],
        }
    }

    #[test]
    fn test_block_state_changes_parse_msg() {
        let msg = fixtures::pb_block_contract_changes(0);

        let res = BlockContractChanges::try_from_message(
            msg,
            "test",
            Chain::Ethereum,
            "ambient".to_string(),
            &HashMap::from([("WeightedPool".to_string(), ProtocolType::default())]),
            0,
        )
        .unwrap();
        assert_eq!(res, block_state_changes());
    }

    #[test]
    fn test_merge_protocol_state_updates() {
        let up_attributes1: HashMap<String, Bytes> = vec![
            ("reserve1".to_owned(), Bytes::from(1000u64).lpad(32, 0)),
            ("reserve2".to_owned(), Bytes::from(500u64).lpad(32, 0)),
            ("static_attribute".to_owned(), Bytes::from(1u64).lpad(32, 0)),
            ("to_be_removed".to_owned(), Bytes::from(1u64).lpad(32, 0)),
        ]
        .into_iter()
        .collect();
        let del_attributes1: HashSet<String> = vec!["to_add_back".to_owned()]
            .into_iter()
            .collect();
        let mut state1 = ProtocolComponentStateDelta {
            component_id: "State1".to_owned(),
            updated_attributes: up_attributes1,
            deleted_attributes: del_attributes1,
        };

        let up_attributes2: HashMap<String, Bytes> = vec![
            ("reserve1".to_owned(), Bytes::from(900u64).lpad(32, 0)),
            ("reserve2".to_owned(), Bytes::from(550u64).lpad(32, 0)),
            ("new_attribute".to_owned(), Bytes::from(1u64).lpad(32, 0)),
            ("to_add_back".to_owned(), Bytes::from(200u64).lpad(32, 0)),
        ]
        .into_iter()
        .collect();
        let del_attributes2: HashSet<String> = vec!["to_be_removed".to_owned()]
            .into_iter()
            .collect();
        let state2 = ProtocolComponentStateDelta {
            component_id: "State1".to_owned(),
            updated_attributes: up_attributes2.clone(),
            deleted_attributes: del_attributes2,
        };

        let res = state1.merge(state2);

        assert!(res.is_ok());
        let expected_up_attributes: HashMap<String, Bytes> = vec![
            ("reserve1".to_owned(), Bytes::from(900u64).lpad(32, 0)),
            ("reserve2".to_owned(), Bytes::from(550u64).lpad(32, 0)),
            ("static_attribute".to_owned(), Bytes::from(1u64).lpad(32, 0)),
            ("new_attribute".to_owned(), Bytes::from(1u64).lpad(32, 0)),
            ("to_add_back".to_owned(), Bytes::from(200u64).lpad(32, 0)),
        ]
        .into_iter()
        .collect();
        assert_eq!(state1.updated_attributes, expected_up_attributes);
        let expected_del_attributes: HashSet<String> = vec!["to_be_removed".to_owned()]
            .into_iter()
            .collect();
        assert_eq!(state1.deleted_attributes, expected_del_attributes);
    }

    fn protocol_state_with_tx() -> ProtocolChangesWithTx {
        let attributes: HashMap<String, Bytes> = vec![
            ("reserve".to_owned(), Bytes::from(1000_u64.to_be_bytes().to_vec())),
            ("static_attribute".to_owned(), Bytes::from(1_u64.to_be_bytes().to_vec())),
        ]
        .into_iter()
        .collect();
        let states: HashMap<String, ProtocolComponentStateDelta> = vec![
            (
                "State1".to_owned(),
                ProtocolComponentStateDelta {
                    component_id: "State1".to_owned(),
                    updated_attributes: attributes.clone(),
                    deleted_attributes: HashSet::new(),
                },
            ),
            (
                "State2".to_owned(),
                ProtocolComponentStateDelta {
                    component_id: "State2".to_owned(),
                    updated_attributes: attributes,
                    deleted_attributes: HashSet::new(),
                },
            ),
        ]
        .into_iter()
        .collect();
        ProtocolChangesWithTx { protocol_states: states, tx: transaction01(), ..Default::default() }
    }

    #[test]
    fn test_block_contract_changes_state_filter() {
        let block = block_state_changes();

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
        let block = block_state_changes();

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
        // Clippy thinks that tuple with Bytes are a mutable type.
        let filtered = BlockChanges::from(block).get_filtered_balance_update(keys);

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
    fn test_merge_protocol_state_update_with_tx() {
        let mut base_state = protocol_state_with_tx();

        let new_attributes: HashMap<String, Bytes> = vec![
            ("reserve".to_owned(), Bytes::from(900_u64.to_be_bytes().to_vec())),
            ("new_attribute".to_owned(), Bytes::from(1_u64.to_be_bytes().to_vec())),
        ]
        .into_iter()
        .collect();
        let new_tx = fixtures::transaction02(HASH_256_1, HASH_256_0, 11);
        let new_states: HashMap<String, ProtocolComponentStateDelta> = vec![(
            "State1".to_owned(),
            ProtocolComponentStateDelta {
                component_id: "State1".to_owned(),
                updated_attributes: new_attributes,
                deleted_attributes: HashSet::new(),
            },
        )]
        .into_iter()
        .collect();

        let tx_update =
            ProtocolChangesWithTx { protocol_states: new_states, tx: new_tx, ..Default::default() };

        let res = base_state.merge(tx_update);

        assert!(res.is_ok());
        assert_eq!(base_state.protocol_states.len(), 2);
        let expected_attributes: HashMap<String, Bytes> = vec![
            ("reserve".to_owned(), Bytes::from(900_u64.to_be_bytes().to_vec())),
            ("static_attribute".to_owned(), Bytes::from(1_u64.to_be_bytes().to_vec())),
            ("new_attribute".to_owned(), Bytes::from(1_u64.to_be_bytes().to_vec())),
        ]
        .into_iter()
        .collect();
        assert_eq!(
            base_state
                .protocol_states
                .get("State1")
                .unwrap()
                .updated_attributes,
            expected_attributes
        );
    }

    #[rstest]
    #[case::diff_block(
    fixtures::transaction02(HASH_256_1, HASH_256_1, 11),
    Err(format ! ("Can't merge ProtocolStates from different blocks: {:x} != {}", Bytes::zero(32), HASH_256_1))
    )]
    #[case::same_tx(
    fixtures::transaction02(HASH_256_0, HASH_256_0, 11),
    Err(format ! ("Can't merge ProtocolStates from the same transaction: {:x}", Bytes::zero(32)))
    )]
    #[case::lower_idx(
    fixtures::transaction02(HASH_256_1, HASH_256_0, 1),
    Err("Can't merge ProtocolStates with lower transaction index: 10 > 1".to_owned())
    )]
    fn test_merge_pool_state_update_with_tx_errors(
        #[case] tx: Transaction,
        #[case] exp: Result<(), String>,
    ) {
        let mut base_state = protocol_state_with_tx();

        let mut new_state = protocol_state_with_tx();
        new_state.tx = tx;

        let res = base_state.merge(new_state);

        assert_eq!(res, exp);
    }

    fn protocol_state() -> ProtocolComponentStateDelta {
        let res1_value = 1000_u64.to_be_bytes().to_vec();
        let res2_value = 500_u64.to_be_bytes().to_vec();
        ProtocolComponentStateDelta {
            component_id: "State1".to_string(),
            updated_attributes: vec![
                ("reserve1".to_owned(), Bytes::from(res1_value)),
                ("reserve2".to_owned(), Bytes::from(res2_value)),
            ]
            .into_iter()
            .collect(),
            deleted_attributes: HashSet::new(),
        }
    }

    #[test]
    fn test_merge_protocol_state_update_wrong_id() {
        let mut state1 = protocol_state();

        let attributes2: HashMap<String, Bytes> =
            vec![("reserve".to_owned(), Bytes::from(900u64).lpad(32, 0))]
                .into_iter()
                .collect();
        let state2 = ProtocolComponentStateDelta {
            component_id: "State2".to_owned(),
            updated_attributes: attributes2.clone(),
            deleted_attributes: HashSet::new(),
        };

        let res = state1.merge(state2);

        assert_eq!(
            res,
            Err(
                "Can't merge ProtocolStates from differing identities; Expected State1, got State2"
                    .to_owned()
            )
        );
    }

    #[test]
    fn test_protocol_state_update_parse_msg() {
        let msg = fixtures::pb_state_changes();

        let res = ProtocolComponentStateDelta::try_from_message(msg).unwrap();

        assert_eq!(res, protocol_state());
    }

    fn block_entity_changes() -> BlockEntityChanges {
        let tx = Transaction {
            hash: Bytes::from_str(
                "0x0000000000000000000000000000000000000000000000000000000011121314",
            )
            .unwrap(),
            block_hash: Bytes::from_str(
                "0000000000000000000000000000000000000000000000000000000000000000",
            )
            .unwrap(),
            from: Bytes::from_str("0000000000000000000000000000000041424344").unwrap(),
            to: Some(Bytes::from_str("0000000000000000000000000000000051525354").unwrap()),
            index: 11,
        };
        let attr: HashMap<String, Bytes> = vec![
            ("reserve".to_owned(), Bytes::from(600_u64.to_be_bytes().to_vec())),
            ("new".to_owned(), Bytes::from(0_u64.to_be_bytes().to_vec())),
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
            vec![("key".to_owned(), Bytes::from(600_u64.to_be_bytes().to_vec()))]
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
        BlockEntityChanges {
            extractor: "test".to_string(),
            chain: Chain::Ethereum,
            block: Block::new(
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
            finalized_block_height: 420,
            revert: false,
            new_tokens: HashMap::new(),
            txs_with_update: vec![
                protocol_state_with_tx(),
                ProtocolChangesWithTx {
                    protocol_states: state_updates,
                    tx,
                    new_protocol_components: new_protocol_components.clone(),
                    balance_changes: new_balances,
                },
            ],
        }
    }

    #[test]
    fn test_block_entity_changes_state_filter() {
        let block = block_entity_changes();

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
                Bytes::from(600_u64.to_be_bytes().to_vec())
            )])
        );
    }

    #[test]
    fn test_block_entity_changes_balance_filter() {
        let block = block_entity_changes();

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
        // Clippy thinks that tuple with Bytes are a mutable type.
        let filtered = BlockChanges::from(block).get_filtered_balance_update(keys);

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

    #[test]
    fn test_block_entity_changes_parse_msg() {
        let msg = fixtures::pb_block_entity_changes(0);

        let res = BlockEntityChanges::try_from_message(
            msg,
            "test",
            Chain::Ethereum,
            "ambient",
            &HashMap::from([
                ("Pool".to_string(), ProtocolType::default()),
                ("WeightedPool".to_string(), ProtocolType::default()),
            ]),
            420,
        )
        .unwrap();
        assert_eq!(res, block_entity_changes());
    }

    fn create_transaction() -> Transaction {
        Transaction {
            hash: Bytes::from_str(
                "0000000000000000000000000000000000000000000000000000000011121314",
            )
            .unwrap(),
            block_hash: Bytes::from_str(
                "0000000000000000000000000000000000000000000000000000000031323334",
            )
            .unwrap(),
            from: Bytes::from_str("0000000000000000000000000000000041424344").unwrap(),
            to: Some(Bytes::from_str("0000000000000000000000000000000051525354").unwrap()),
            index: 2,
        }
    }

    #[rstest]
    fn test_try_from_message_protocol_component() {
        let msg = fixtures::pb_protocol_component();

        let expected_chain = Chain::Ethereum;
        let expected_protocol_system = "ambient".to_string();
        let expected_attribute_map: HashMap<String, Bytes> = vec![
            ("balance".to_string(), Bytes::from(100_u64.to_be_bytes().to_vec())),
            ("factory_address".to_string(), Bytes::from(b"0x0fwe0g240g20".to_vec())),
        ]
        .into_iter()
        .collect();

        let protocol_type_id = "WeightedPool".to_string();
        let protocol_types: HashMap<String, ProtocolType> =
            HashMap::from([(protocol_type_id.clone(), ProtocolType::default())]);

        // Call the try_from_message method
        let result = ProtocolComponent::try_from_message((
            msg,
            expected_chain,
            &expected_protocol_system,
            &protocol_types,
            Bytes::from_str("0x0e22048af8040c102d96d14b0988c6195ffda24021de4d856801553aa468bcac")
                .unwrap(),
            Default::default(),
        ));

        // Assert the result
        assert!(result.is_ok());

        // Unwrap the result for further assertions
        let protocol_component = result.unwrap();

        // Assert specific properties of the protocol component
        assert_eq!(
            protocol_component.id,
            "d417ff54652c09bd9f31f216b1a2e5d1e28c1dce1ba840c40d16f2b4d09b5902".to_string()
        );
        assert_eq!(protocol_component.protocol_system, expected_protocol_system);
        assert_eq!(protocol_component.protocol_type_name, protocol_type_id);
        assert_eq!(protocol_component.chain, expected_chain);
        assert_eq!(
            protocol_component.tokens,
            vec![
                Bytes::from_str("6B175474E89094C44Da98b954EedeAC495271d0F").unwrap(),
                Bytes::from_str("6B175474E89094C44Da98b954EedeAC495271d0F").unwrap(),
            ]
        );
        assert_eq!(
            protocol_component.contract_addresses,
            vec![
                Bytes::from_str("31fF2589Ee5275a2038beB855F44b9Be993aA804").unwrap(),
                Bytes::from_str("C02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2").unwrap(),
            ]
        );
        assert_eq!(protocol_component.static_attributes, expected_attribute_map);
    }

    #[rstest]
    fn test_try_from_message_component_balance() {
        let tx = create_transaction();
        let expected_balance: f64 = 3000.0;
        let msg_balance = expected_balance.to_le_bytes().to_vec();

        let expected_token = Bytes::from_str("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2").unwrap();
        let msg_token = expected_token.0.to_vec();
        let expected_component_id =
            "d417ff54652c09bd9f31f216b1a2e5d1e28c1dce1ba840c40d16f2b4d09b5902";
        let msg_component_id = expected_component_id
            .as_bytes()
            .to_vec();
        let msg = substreams::BalanceChange {
            balance: msg_balance.to_vec(),
            token: msg_token,
            component_id: msg_component_id,
        };
        let from_message = ComponentBalance::try_from_message((msg, &tx)).unwrap();

        assert_eq!(from_message.balance, msg_balance);
        assert_eq!(from_message.modify_tx, tx.hash);
        assert_eq!(from_message.token, expected_token);
        assert_eq!(from_message.component_id, expected_component_id);
    }

    #[rstest]
    fn test_merge() {
        let tx_first_update = fixtures::transaction01();
        let tx_second_update = fixtures::transaction02(HASH_256_1, HASH_256_0, 15);
        let protocol_component_first_tx = create_protocol_component(tx_first_update.hash.clone());
        let protocol_component_second_tx = create_protocol_component(tx_second_update.hash.clone());

        let first_update = TransactionVMUpdates {
            account_deltas: [(
                Bytes::from_str("0x0000000000000000000000000000000061626364").unwrap(),
                AccountDelta::new(
                    Chain::Ethereum,
                    Bytes::from_str("0000000000000000000000000000000061626364").unwrap(),
                    fixtures::slots([(2711790500, 2981278644), (3250766788, 3520254932)]),
                    Some(Bytes::from(1903326068u64).lpad(32, 0)),
                    Some(vec![129, 130, 131, 132].into()),
                    ChangeType::Update,
                ),
            )]
            .into_iter()
            .collect(),
            protocol_components: [(
                protocol_component_first_tx.id.clone(),
                protocol_component_first_tx.clone(),
            )]
            .into_iter()
            .collect(),
            component_balances: [(
                protocol_component_first_tx.id.clone(),
                [(
                    Bytes::from_str("0x0000000000000000000000000000000061626364").unwrap(),
                    ComponentBalance {
                        token: Bytes::from_str("0x0000000000000000000000000000000066666666")
                            .unwrap(),
                        balance: Bytes::from(0_i32.to_le_bytes()),
                        modify_tx: Default::default(),
                        component_id: protocol_component_first_tx.id.clone(),
                        balance_float: 0.0,
                    },
                )]
                .into_iter()
                .collect(),
            )]
            .into_iter()
            .collect(),
            tx: tx_first_update,
        };
        let second_update = TransactionVMUpdates {
            account_deltas: [(
                Bytes::from_str("0x0000000000000000000000000000000061626364").unwrap(),
                AccountDelta::new(
                    Chain::Ethereum,
                    Bytes::from_str("0000000000000000000000000000000061626364").unwrap(),
                    fixtures::slots([(2981278644, 3250766788), (2442302356, 2711790500)]),
                    Some(Bytes::from(4059231220u64).lpad(32, 0)),
                    Some(vec![1, 2, 3, 4].into()),
                    ChangeType::Update,
                ),
            )]
            .into_iter()
            .collect(),
            protocol_components: [(
                protocol_component_second_tx.id.clone(),
                protocol_component_second_tx.clone(),
            )]
            .into_iter()
            .collect(),
            component_balances: [(
                protocol_component_second_tx.id.clone(),
                [(
                    Bytes::from_str("0x0000000000000000000000000000000061626364").unwrap(),
                    ComponentBalance {
                        token: Bytes::from_str("0x0000000000000000000000000000000066666666")
                            .unwrap(),
                        balance: Bytes::from(500000_i32.to_le_bytes()),
                        modify_tx: Default::default(),
                        component_id: protocol_component_first_tx.id.clone(),
                        balance_float: 500000.0,
                    },
                )]
                .into_iter()
                .collect(),
            )]
            .into_iter()
            .collect(),
            tx: tx_second_update,
        };

        let mut to_merge_on = first_update.clone();
        to_merge_on
            .merge(&second_update)
            .unwrap();

        let expected_protocol_components: HashMap<ComponentId, ProtocolComponent> = [
            (protocol_component_first_tx.id.clone(), protocol_component_first_tx.clone()),
            (protocol_component_second_tx.id.clone(), protocol_component_second_tx.clone()),
        ]
        .into_iter()
        .collect();
        assert_eq!(to_merge_on.component_balances, second_update.component_balances);
        assert_eq!(to_merge_on.protocol_components, expected_protocol_components);

        let mut acc_update = second_update
            .account_deltas
            .clone()
            .into_values()
            .next()
            .unwrap();

        acc_update.slots = fixtures::slots([
            (2442302356, 2711790500),
            (2711790500, 2981278644),
            (3250766788, 3520254932),
            (2981278644, 3250766788),
        ]);

        let acc_update = [(acc_update.address.clone(), acc_update)]
            .iter()
            .cloned()
            .collect();

        assert_eq!(to_merge_on.account_deltas, acc_update);
    }
}
