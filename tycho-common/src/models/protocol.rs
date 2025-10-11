use std::collections::{hash_map::Entry, HashMap, HashSet};

use chrono::NaiveDateTime;
use deepsize::{Context, DeepSizeOf};
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::{
    models::{
        blockchain::Transaction, Address, AttrStoreKey, Balance, Chain, ChangeType, ComponentId,
        MergeError, StoreVal, TxHash,
    },
    Bytes,
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
    pub contract_addresses: Vec<Address>,
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
            contract_addresses,
            static_attributes,
            change,
            creation_tx,
            created_at,
        }
    }
}

impl DeepSizeOf for ProtocolComponent {
    fn deep_size_of_children(&self, ctx: &mut Context) -> usize {
        self.id.deep_size_of_children(ctx) +
            self.protocol_system
                .deep_size_of_children(ctx) +
            self.protocol_type_name
                .deep_size_of_children(ctx) +
            self.chain.deep_size_of_children(ctx) +
            self.tokens.deep_size_of_children(ctx) +
            self.contract_addresses
                .deep_size_of_children(ctx) +
            self.static_attributes
                .deep_size_of_children(ctx) +
            self.change.deep_size_of_children(ctx) +
            self.creation_tx
                .deep_size_of_children(ctx)
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
    ) -> Result<(), MergeError> {
        if self.component_id != delta.component_id {
            return Err(MergeError::IdMismatch(
                "ProtocolComponentStates".to_string(),
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
    ) -> Result<(), MergeError> {
        self.balances.extend(
            delta
                .iter()
                .map(|(k, v)| (k.clone(), v.balance.clone())),
        );

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, DeepSizeOf)]
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
    pub fn merge(&mut self, other: ProtocolComponentStateDelta) -> Result<(), MergeError> {
        if self.component_id != other.component_id {
            return Err(MergeError::IdMismatch(
                "ProtocolComponentStateDeltas".to_string(),
                self.component_id.clone(),
                other.component_id.clone(),
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, DeepSizeOf)]
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

/// Token quality range filter
///
/// The quality range is considered inclusive and used as a filter, will be applied as such.
#[derive(Debug, Clone)]
pub struct QualityRange {
    pub min: Option<i32>,
    pub max: Option<i32>,
}

impl QualityRange {
    pub fn new(min: i32, max: i32) -> Self {
        Self { min: Some(min), max: Some(max) }
    }

    pub fn min_only(min: i32) -> Self {
        Self { min: Some(min), max: None }
    }

    #[allow(non_snake_case)]
    pub fn None() -> Self {
        Self { min: None, max: None }
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
    pub fn merge(&mut self, other: ProtocolChangesWithTx) -> Result<(), MergeError> {
        if self.tx.block_hash != other.tx.block_hash {
            return Err(MergeError::BlockMismatch(
                "ProtocolChangesWithTx".to_string(),
                self.tx.block_hash.clone(),
                other.tx.block_hash,
            ));
        }
        if self.tx.hash == other.tx.hash {
            return Err(MergeError::SameTransaction(
                "ProtocolChangesWithTx".to_string(),
                other.tx.hash,
            ));
        }
        if self.tx.index > other.tx.index {
            return Err(MergeError::TransactionOrderError(
                "ProtocolChangesWithTx".to_string(),
                self.tx.index,
                other.tx.index,
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

pub struct GetAmountOutParams {
    pub amount_in: BigUint,
    pub token_in: Bytes,
    pub token_out: Bytes,
    pub sender: Bytes,
    pub receiver: Bytes,
}

#[cfg(test)]
mod test {
    use rstest::rstest;

    use super::*;
    use crate::models::blockchain::fixtures as block_fixtures;

    const HASH_256_0: &str = "0x0000000000000000000000000000000000000000000000000000000000000000";
    const HASH_256_1: &str = "0x0000000000000000000000000000000000000000000000000000000000000001";

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

    #[test]
    fn test_merge_protocol_state_updates() {
        let mut state_1 = create_state("State1".to_owned());
        state_1
            .updated_attributes
            .insert("to_be_removed".to_owned(), Bytes::from(1u64).lpad(32, 0));
        state_1.deleted_attributes = vec!["to_add_back".to_owned()]
            .into_iter()
            .collect();

        let attributes2: HashMap<String, Bytes> = vec![
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
        let mut state_2 = create_state("State1".to_owned());
        state_2.updated_attributes = attributes2;
        state_2.deleted_attributes = del_attributes2;

        let res = state_1.merge(state_2);

        assert!(res.is_ok());
        let expected_attributes: HashMap<String, Bytes> = vec![
            ("reserve1".to_owned(), Bytes::from(900u64).lpad(32, 0)),
            ("reserve2".to_owned(), Bytes::from(550u64).lpad(32, 0)),
            ("static_attribute".to_owned(), Bytes::from(1u64).lpad(32, 0)),
            ("new_attribute".to_owned(), Bytes::from(1u64).lpad(32, 0)),
            ("to_add_back".to_owned(), Bytes::from(200u64).lpad(32, 0)),
        ]
        .into_iter()
        .collect();
        assert_eq!(state_1.updated_attributes, expected_attributes);
        let expected_del_attributes: HashSet<String> = vec!["to_be_removed".to_owned()]
            .into_iter()
            .collect();
        assert_eq!(state_1.deleted_attributes, expected_del_attributes);
    }

    fn protocol_state_with_tx() -> ProtocolChangesWithTx {
        let state_1 = create_state("State1".to_owned());
        let state_2 = create_state("State2".to_owned());
        let states: HashMap<String, ProtocolComponentStateDelta> =
            vec![(state_1.component_id.clone(), state_1), (state_2.component_id.clone(), state_2)]
                .into_iter()
                .collect();
        ProtocolChangesWithTx {
            protocol_states: states,
            tx: block_fixtures::transaction01(),
            ..Default::default()
        }
    }

    #[test]
    fn test_merge_protocol_state_update_with_tx() {
        let mut base_state = protocol_state_with_tx();

        let new_attributes: HashMap<String, Bytes> = vec![
            ("reserve1".to_owned(), Bytes::from(600u64).lpad(32, 0)),
            ("new_attribute".to_owned(), Bytes::from(10u64).lpad(32, 0)),
        ]
        .into_iter()
        .collect();
        let new_tx = block_fixtures::create_transaction(HASH_256_1, HASH_256_0, 11);
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
            ("reserve1".to_owned(), Bytes::from(600u64).lpad(32, 0)),
            ("reserve2".to_owned(), Bytes::from(500u64).lpad(32, 0)),
            ("static_attribute".to_owned(), Bytes::from(1u64).lpad(32, 0)),
            ("new_attribute".to_owned(), Bytes::from(10u64).lpad(32, 0)),
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
    block_fixtures::create_transaction(HASH_256_1, HASH_256_1, 11),
    Err(MergeError::BlockMismatch(
        "ProtocolChangesWithTx".to_string(),
        Bytes::zero(32),
        HASH_256_1.into(),
    ))
    )]
    #[case::same_tx(
    block_fixtures::create_transaction(HASH_256_0, HASH_256_0, 11),
    Err(MergeError::SameTransaction(
        "ProtocolChangesWithTx".to_string(),
        Bytes::zero(32),
    ))
    )]
    #[case::lower_idx(
    block_fixtures::create_transaction(HASH_256_1, HASH_256_0, 1),
    Err(MergeError::TransactionOrderError(
        "ProtocolChangesWithTx".to_string(),
        10,
        1,
    ))
    )]
    fn test_merge_pool_state_update_with_tx_errors(
        #[case] tx: Transaction,
        #[case] exp: Result<(), MergeError>,
    ) {
        let mut base_state = protocol_state_with_tx();

        let mut new_state = protocol_state_with_tx();
        new_state.tx = tx;

        let res = base_state.merge(new_state);

        assert_eq!(res, exp);
    }

    #[test]
    fn test_merge_protocol_state_update_wrong_id() {
        let mut state1 = create_state("State1".to_owned());
        let state2 = create_state("State2".to_owned());

        let res = state1.merge(state2);

        assert_eq!(
            res,
            Err(MergeError::IdMismatch(
                "ProtocolComponentStateDeltas".to_string(),
                "State1".to_string(),
                "State2".to_string(),
            ))
        );
    }
}
