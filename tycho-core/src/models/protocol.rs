use crate::{
    models::{Chain, ChangeType},
    Bytes,
};
use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use std::collections::{hash_map::Entry, HashMap, HashSet};
use tracing::warn;

use super::{
    blockchain::Transaction, Address, AttrStoreKey, Balance, ComponentId, DeltaError, StoreVal,
    TxHash,
};

/// `ProtocolComponent` provides detailed descriptions of a component of a protocol,
/// for example, swap pools that enables the exchange of two tokens.
///
/// A `ProtocolComponent` can be associated with an `Account`, and it has an identifier (`id`) that
/// can be either the on-chain address or a custom one. It belongs to a specific `ProtocolSystem`
/// and has a `ProtocolTypeID` that associates it with a `ProtocolType` that describes its behaviour
/// e.g., swap, lend, bridge. The component is associated with a specific `Chain` and holds
/// information about tradable tokens, related contract IDs, and static attributes.
///
/// Every values of a `ProtocolComponent` must be static, they can't ever be changed after creation.
/// The dynamic values associated to a component must be given using `ProtocolComponentState`.
#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProtocolComponent {
    pub id: ComponentId,
    pub protocol_system: String,
    pub protocol_type_name: String,
    pub chain: Chain,
    pub tokens: Vec<Address>,
    pub contract_ids: Vec<Address>,
    pub static_attributes: HashMap<AttrStoreKey, StoreVal>,
    pub change: ChangeType,
    pub creation_tx: TxHash,
    pub created_at: NaiveDateTime,
}

impl ProtocolComponent {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: &str,
        protocol_system: &str,
        protocol_type_name: &str,
        chain: Chain,
        tokens: Vec<Address>,
        contract_addresses: Vec<Address>,
        static_attributes: HashMap<AttrStoreKey, StoreVal>,
        change: ChangeType,
        creation_tx: TxHash,
        created_at: NaiveDateTime,
    ) -> Self {
        Self {
            id: id.to_string(),
            protocol_system: protocol_system.to_string(),
            protocol_type_name: protocol_type_name.to_string(),
            chain,
            tokens,
            contract_ids: contract_addresses,
            static_attributes,
            change,
            creation_tx,
            created_at,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ProtocolComponentState {
    pub component_id: ComponentId,
    pub attributes: HashMap<AttrStoreKey, StoreVal>,
    // used during snapshots retrieval by the gateway
    pub balances: HashMap<Address, Balance>,
}

impl ProtocolComponentState {
    pub fn new(
        component_id: &str,
        attributes: HashMap<AttrStoreKey, StoreVal>,
        balances: HashMap<Address, Balance>,
    ) -> Self {
        Self { component_id: component_id.to_string(), attributes, balances }
    }

    /// Applies state deltas to this state.
    ///
    /// This method assumes that the passed delta is "newer" than the current state.
    pub fn apply_state_delta(
        &mut self,
        delta: &ProtocolComponentStateDelta,
    ) -> Result<(), DeltaError> {
        if self.component_id != delta.component_id {
            return Err(DeltaError::IdMismatch(
                self.component_id.clone(),
                delta.component_id.clone(),
            ));
        }
        self.attributes
            .extend(delta.updated_attributes.clone());

        self.attributes
            .retain(|attr, _| !delta.deleted_attributes.contains(attr));

        Ok(())
    }

    /// Applies balance deltas to this state.
    ///
    /// This method assumes that the passed delta is "newer" than the current state.
    pub fn apply_balance_delta(
        &mut self,
        delta: &HashMap<Bytes, ComponentBalance>,
    ) -> Result<(), DeltaError> {
        self.balances.extend(
            delta
                .iter()
                .map(|(k, v)| (k.clone(), v.balance.clone())),
        );

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProtocolComponentStateDelta {
    pub component_id: ComponentId,
    pub updated_attributes: HashMap<AttrStoreKey, StoreVal>,
    pub deleted_attributes: HashSet<AttrStoreKey>,
}

impl ProtocolComponentStateDelta {
    pub fn new(
        component_id: &str,
        updated_attributes: HashMap<AttrStoreKey, StoreVal>,
        deleted_attributes: HashSet<AttrStoreKey>,
    ) -> Self {
        Self { component_id: component_id.to_string(), updated_attributes, deleted_attributes }
    }

    /// Merges this update with another one.
    ///
    /// The method combines two `ProtocolComponentStateDelta` instances if they are for the same
    /// protocol component.
    ///
    /// NB: It is assumed that `other` is a more recent update than `self` is and the two are
    /// combined accordingly.
    ///
    /// # Errors
    /// This method will return `CoreError::MergeError` if any of the above
    /// conditions is violated.
    pub fn merge(&mut self, other: ProtocolComponentStateDelta) -> Result<(), String> {
        if self.component_id != other.component_id {
            return Err(format!(
                "Can't merge ProtocolStates from differing identities; Expected {}, got {}",
                self.component_id, other.component_id
            ));
        }
        for attr in &other.deleted_attributes {
            self.updated_attributes.remove(attr);
        }
        for attr in other.updated_attributes.keys() {
            self.deleted_attributes.remove(attr);
        }
        self.updated_attributes
            .extend(other.updated_attributes);
        self.deleted_attributes
            .extend(other.deleted_attributes);
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ComponentBalance {
    pub token: Address,
    pub balance: Balance,
    pub balance_float: f64,
    pub modify_tx: TxHash,
    pub component_id: ComponentId,
}

impl ComponentBalance {
    pub fn new(
        token: Address,
        new_balance: Balance,
        balance_float: f64,
        modify_tx: TxHash,
        component_id: &str,
    ) -> Self {
        Self {
            token,
            balance: new_balance,
            balance_float,
            modify_tx,
            component_id: component_id.to_string(),
        }
    }
}

/// Updates grouped by their respective transaction.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ProtocolChangesWithTx {
    pub new_protocol_components: HashMap<ComponentId, ProtocolComponent>,
    pub protocol_states: HashMap<ComponentId, ProtocolComponentStateDelta>,
    pub balance_changes: HashMap<ComponentId, HashMap<Bytes, ComponentBalance>>,
    pub tx: Transaction,
}

impl ProtocolChangesWithTx {
    /// Merges this update with another one.
    ///
    /// The method combines two `ProtocolStatesWithTx` instances under certain
    /// conditions:
    /// - The block from which both updates came should be the same. If the updates are from
    ///   different blocks, the method will return an error.
    /// - The transactions for each of the updates should be distinct. If they come from the same
    ///   transaction, the method will return an error.
    /// - The order of the transaction matters. The transaction from `other` must have occurred
    ///   later than the self transaction. If the self transaction has a higher index than `other`,
    ///   the method will return an error.
    ///
    /// The merged update keeps the transaction of `other`.
    ///
    /// # Errors
    /// This method will return an error if any of the above conditions is violated.
    pub fn merge(&mut self, other: ProtocolChangesWithTx) -> Result<(), String> {
        if self.tx.block_hash != other.tx.block_hash {
            return Err(format!(
                "Can't merge ProtocolStates from different blocks: {:x} != {:x}",
                self.tx.block_hash, other.tx.block_hash,
            ));
        }
        if self.tx.hash == other.tx.hash {
            return Err(format!(
                "Can't merge ProtocolStates from the same transaction: {:x}",
                self.tx.hash
            ));
        }
        if self.tx.index > other.tx.index {
            return Err(format!(
                "Can't merge ProtocolStates with lower transaction index: {} > {}",
                self.tx.index, other.tx.index
            ));
        }
        self.tx = other.tx;
        // Merge protocol states
        for (key, value) in other.protocol_states {
            match self.protocol_states.entry(key) {
                Entry::Occupied(mut entry) => {
                    entry.get_mut().merge(value)?;
                }
                Entry::Vacant(entry) => {
                    entry.insert(value);
                }
            }
        }

        // Merge token balances
        for (component_id, balance_changes) in other.balance_changes {
            let token_balances = self
                .balance_changes
                .entry(component_id)
                .or_default();
            for (token, balance) in balance_changes {
                token_balances.insert(token, balance);
            }
        }

        // Merge new protocol components
        // Log a warning if a new protocol component for the same id already exists, because this
        // should never happen.
        for (key, value) in other.new_protocol_components {
            match self.new_protocol_components.entry(key) {
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

        Ok(())
    }
}
