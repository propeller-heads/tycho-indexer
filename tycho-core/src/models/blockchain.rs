use crate::{
    models::{
        contract::AccountDelta,
        protocol::{ComponentBalance, ProtocolComponent, ProtocolComponentStateDelta},
        Chain, ComponentId,
    },
    Bytes,
};
use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use std::{
    any::Any,
    collections::{hash_map::Entry, HashMap},
    sync::Arc,
};
use tracing::warn;

use super::{
    contract::TransactionVMUpdates, protocol::ProtocolChangesWithTx, token::CurrencyToken, Address,
    ExtractorIdentity, NormalisedMessage,
};

#[derive(Clone, Default, PartialEq, Serialize, Deserialize, Debug)]
pub struct Block {
    pub number: u64,
    pub chain: Chain,
    pub hash: Bytes,
    pub parent_hash: Bytes,
    pub ts: NaiveDateTime,
}

impl Block {
    pub fn new(
        number: u64,
        chain: Chain,
        hash: Bytes,
        parent_hash: Bytes,
        ts: NaiveDateTime,
    ) -> Self {
        Block { hash, parent_hash, number, chain, ts }
    }
}

#[derive(Clone, Default, PartialEq, Debug)]
pub struct Transaction {
    pub hash: Bytes,
    pub block_hash: Bytes,
    pub from: Bytes,
    pub to: Option<Bytes>,
    pub index: u64,
}

impl Transaction {
    pub fn new(hash: Bytes, block_hash: Bytes, from: Bytes, to: Option<Bytes>, index: u64) -> Self {
        Transaction { hash, block_hash, from, to, index }
    }
}

pub struct BlockTransactionDeltas<T> {
    pub extractor: String,
    pub chain: Chain,
    pub block: Block,
    pub revert: bool,
    pub deltas: Vec<TransactionDeltaGroup<T>>,
}

#[allow(dead_code)]
pub struct TransactionDeltaGroup<T> {
    changes: T,
    protocol_component: HashMap<String, ProtocolComponent>,
    component_balances: HashMap<String, ComponentBalance>,
    component_tvl: HashMap<String, f64>,
    tx: Transaction,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq)]
pub struct BlockAggregatedChanges {
    pub extractor: String,
    pub chain: Chain,
    pub block: Block,
    pub finalized_block_height: u64,
    pub revert: bool,
    pub state_deltas: HashMap<String, ProtocolComponentStateDelta>,
    pub account_deltas: HashMap<Bytes, AccountDelta>,
    pub new_tokens: HashMap<Address, CurrencyToken>,
    pub new_protocol_components: HashMap<String, ProtocolComponent>,
    pub deleted_protocol_components: HashMap<String, ProtocolComponent>,
    pub component_balances: HashMap<ComponentId, HashMap<Bytes, ComponentBalance>>,
    pub component_tvl: HashMap<String, f64>,
}

impl BlockAggregatedChanges {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        extractor: &str,
        chain: Chain,
        block: Block,
        finalized_block_height: u64,
        revert: bool,
        state_deltas: HashMap<String, ProtocolComponentStateDelta>,
        account_deltas: HashMap<Bytes, AccountDelta>,
        new_tokens: HashMap<Address, CurrencyToken>,
        new_components: HashMap<String, ProtocolComponent>,
        deleted_components: HashMap<String, ProtocolComponent>,
        component_balances: HashMap<ComponentId, HashMap<Bytes, ComponentBalance>>,
        component_tvl: HashMap<String, f64>,
    ) -> Self {
        Self {
            extractor: extractor.to_string(),
            chain,
            block,
            finalized_block_height,
            revert,
            state_deltas,
            account_deltas,
            new_protocol_components: new_components,
            deleted_protocol_components: deleted_components,
            component_balances,
            component_tvl,
            new_tokens,
        }
    }
}

impl std::fmt::Display for BlockAggregatedChanges {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "block_number: {}, extractor: {}", self.block.number, self.extractor)
    }
}

#[typetag::serde]
impl NormalisedMessage for BlockAggregatedChanges {
    fn source(&self) -> ExtractorIdentity {
        ExtractorIdentity::new(self.chain, &self.extractor)
    }

    fn drop_state(&self) -> Arc<dyn NormalisedMessage> {
        Arc::new(Self {
            extractor: self.extractor.clone(),
            chain: self.chain,
            block: self.block.clone(),
            finalized_block_height: self.finalized_block_height,
            revert: self.revert,
            account_deltas: HashMap::new(),
            state_deltas: HashMap::new(),
            new_tokens: self.new_tokens.clone(),
            new_protocol_components: self.new_protocol_components.clone(),
            deleted_protocol_components: self.deleted_protocol_components.clone(),
            component_balances: self.component_balances.clone(),
            component_tvl: self.component_tvl.clone(),
        })
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

pub trait BlockScoped {
    fn block(&self) -> Block;
}

impl BlockScoped for BlockAggregatedChanges {
    fn block(&self) -> Block {
        self.block.clone()
    }
}

/// Changes grouped by their respective transaction.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct TxWithChanges {
    pub protocol_components: HashMap<ComponentId, ProtocolComponent>,
    pub account_deltas: HashMap<Bytes, AccountDelta>,
    pub state_updates: HashMap<ComponentId, ProtocolComponentStateDelta>,
    pub balance_changes: HashMap<ComponentId, HashMap<Bytes, ComponentBalance>>,
    pub tx: Transaction,
}

impl TxWithChanges {
    pub fn new(
        protocol_components: HashMap<ComponentId, ProtocolComponent>,
        account_deltas: HashMap<Bytes, AccountDelta>,
        protocol_states: HashMap<ComponentId, ProtocolComponentStateDelta>,
        balance_changes: HashMap<ComponentId, HashMap<Bytes, ComponentBalance>>,
        tx: Transaction,
    ) -> Self {
        Self {
            account_deltas,
            protocol_components,
            state_updates: protocol_states,
            balance_changes,
            tx,
        }
    }

    /// Merges this update with another one.
    ///
    /// The method combines two `ChangesWithTx` instances if they are for the same
    /// transaction.
    ///
    /// NB: It is assumed that `other` is a more recent update than `self` is and the two are
    /// combined accordingly.
    ///
    /// # Errors
    /// This method will return an error if any of the above conditions is violated.
    pub fn merge(&mut self, other: TxWithChanges) -> Result<(), String> {
        if self.tx.block_hash != other.tx.block_hash {
            return Err(format!(
                "Can't merge TxWithChanges from different blocks: 0x{:x} != 0x{:x}",
                self.tx.block_hash, other.tx.block_hash,
            ));
        }
        if self.tx.hash == other.tx.hash {
            return Err(format!(
                "Can't merge TxWithChanges from the same transaction: 0x{:x}",
                self.tx.hash
            ));
        }
        if self.tx.index > other.tx.index {
            return Err(format!(
                "Can't merge TxWithChanges with lower transaction index: {} > {}",
                self.tx.index, other.tx.index
            ));
        }

        self.tx = other.tx;

        // Merge new protocol components
        // Log a warning if a new protocol component for the same id already exists, because this
        // should never happen.
        for (key, value) in other.protocol_components {
            match self.protocol_components.entry(key) {
                Entry::Occupied(mut entry) => {
                    warn!(
                        "Overwriting new protocol component for id {} with a new one. This should never happen! Please check logic",
                        entry.get().id
                    );
                    entry.insert(value);
                }
                Entry::Vacant(entry) => {
                    entry.insert(value);
                }
            }
        }

        // Merge Account Updates
        for (address, update) in other.account_deltas.clone().into_iter() {
            match self.account_deltas.entry(address) {
                Entry::Occupied(mut e) => {
                    e.get_mut().merge(update)?;
                }
                Entry::Vacant(e) => {
                    e.insert(update);
                }
            }
        }

        // Merge Protocol States
        for (key, value) in other.state_updates {
            match self.state_updates.entry(key) {
                Entry::Occupied(mut entry) => {
                    entry.get_mut().merge(value)?;
                }
                Entry::Vacant(entry) => {
                    entry.insert(value);
                }
            }
        }

        // Merge Balance Changes
        for (component_id, balance_changes) in other.balance_changes {
            let token_balances = self
                .balance_changes
                .entry(component_id)
                .or_default();
            for (token, balance) in balance_changes {
                token_balances.insert(token, balance);
            }
        }
        Ok(())
    }
}

impl From<TransactionVMUpdates> for TxWithChanges {
    fn from(value: TransactionVMUpdates) -> Self {
        Self {
            protocol_components: value.protocol_components,
            account_deltas: value.account_deltas,
            state_updates: HashMap::new(),
            balance_changes: value.component_balances,
            tx: value.tx,
        }
    }
}

impl From<ProtocolChangesWithTx> for TxWithChanges {
    fn from(value: ProtocolChangesWithTx) -> TxWithChanges {
        TxWithChanges {
            protocol_components: value.new_protocol_components,
            account_deltas: HashMap::new(),
            state_updates: value.protocol_states,
            balance_changes: value.balance_changes,
            tx: value.tx,
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum BlockTag {
    /// Finalized block
    Finalized,
    /// Safe block
    Safe,
    /// Latest block
    Latest,
    /// Earliest block (genesis)
    Earliest,
    /// Pending block (not yet part of the blockchain)
    Pending,
    /// Block by number
    Number(u64),
}
