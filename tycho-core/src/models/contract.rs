use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::{
    keccak256,
    models::{Chain, ChangeType, ContractId, DeltaError},
    Bytes,
};
use std::collections::{hash_map::Entry, HashMap};

use super::{
    blockchain::Transaction,
    protocol::{ComponentBalance, ProtocolComponent},
    Address, Balance, Code, CodeHash, ComponentId, StoreKey, StoreVal, TxHash,
};

#[derive(Clone, Debug, PartialEq)]
pub struct Account {
    pub chain: Chain,
    pub address: Address,
    pub title: String,
    pub slots: HashMap<StoreKey, StoreVal>,
    pub native_balance: Balance,
    pub code: Code,
    pub code_hash: CodeHash,
    pub balance_modify_tx: TxHash,
    pub code_modify_tx: TxHash,
    pub creation_tx: Option<TxHash>,
}

impl Account {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chain: Chain,
        address: Address,
        title: String,
        slots: HashMap<StoreKey, StoreVal>,
        native_balance: Balance,
        code: Code,
        code_hash: CodeHash,
        balance_modify_tx: TxHash,
        code_modify_tx: TxHash,
        creation_tx: Option<TxHash>,
    ) -> Self {
        Self {
            chain,
            address,
            title,
            slots,
            native_balance,
            code,
            code_hash,
            balance_modify_tx,
            code_modify_tx,
            creation_tx,
        }
    }

    pub fn set_balance(&mut self, new_balance: &Balance, modified_at: &Balance) {
        self.native_balance = new_balance.clone();
        self.balance_modify_tx = modified_at.clone();
    }

    pub fn apply_delta(&mut self, delta: &AccountDelta) -> Result<(), DeltaError> {
        let self_id = (self.chain, &self.address);
        let other_id = (delta.chain, &delta.address);
        if self_id != other_id {
            return Err(DeltaError::IdMismatch(format!("{:?}", self_id), format!("{:?}", other_id)));
        }
        if let Some(balance) = delta.balance.as_ref() {
            self.native_balance.clone_from(balance);
        }
        if let Some(code) = delta.code.as_ref() {
            self.code.clone_from(code);
        }
        self.slots.extend(
            delta
                .slots
                .clone()
                .into_iter()
                .map(|(k, v)| (k, v.unwrap_or_default())),
        );
        // TODO: Update modify_tx, code_modify_tx and code_hash.
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct AccountDelta {
    pub chain: Chain,
    pub address: Address,
    pub slots: HashMap<StoreKey, Option<StoreVal>>,
    pub balance: Option<Balance>,
    pub code: Option<Code>,
    pub change: ChangeType,
}

impl AccountDelta {
    pub fn deleted(chain: &Chain, address: &Address) -> Self {
        Self {
            chain: *chain,
            address: address.clone(),
            change: ChangeType::Deletion,
            ..Default::default()
        }
    }

    pub fn new(
        chain: Chain,
        address: Address,
        slots: HashMap<StoreKey, Option<StoreVal>>,
        balance: Option<Balance>,
        code: Option<Code>,
        change: ChangeType,
    ) -> Self {
        Self { chain, address, change, slots, balance, code }
    }

    pub fn contract_id(&self) -> ContractId {
        ContractId::new(self.chain, self.address.clone())
    }

    pub fn into_account(self, tx: &Transaction) -> Account {
        let empty_hash = keccak256(Vec::new());
        Account::new(
            self.chain,
            self.address.clone(),
            format!("{:#020x}", self.address),
            self.slots
                .into_iter()
                .map(|(k, v)| (k, v.map(Into::into).unwrap_or_default()))
                .collect(),
            self.balance.unwrap_or_default(),
            self.code.clone().unwrap_or_default(),
            self.code
                .as_ref()
                .map(keccak256)
                .unwrap_or(empty_hash)
                .into(),
            tx.hash.clone(),
            tx.hash.clone(),
            Some(tx.hash.clone()),
        )
    }

    /// Convert the delta into an account. Note that data not present in the delta, such as
    /// creation_tx etc, will be initialized to default values.
    pub fn into_account_without_tx(self) -> Account {
        let empty_hash = keccak256(Vec::new());
        Account::new(
            self.chain,
            self.address.clone(),
            format!("{:#020x}", self.address),
            self.slots
                .into_iter()
                .map(|(k, v)| (k, v.map(Into::into).unwrap_or_default()))
                .collect(),
            self.balance.unwrap_or_default(),
            self.code.clone().unwrap_or_default(),
            self.code
                .as_ref()
                .map(keccak256)
                .unwrap_or(empty_hash)
                .into(),
            Bytes::from("0x00"),
            Bytes::from("0x00"),
            None,
        )
    }

    // Convert AccountUpdate into Account using references.
    pub fn ref_into_account(&self, tx: &Transaction) -> Account {
        let empty_hash = keccak256(Vec::new());
        if self.change != ChangeType::Creation {
            warn!("Creating an account from a partial change!")
        }

        Account::new(
            self.chain,
            self.address.clone(),
            format!("{:#020x}", self.address),
            self.slots
                .clone()
                .into_iter()
                .map(|(k, v)| (k, v.unwrap_or_default()))
                .collect(),
            self.balance.clone().unwrap_or_default(),
            self.code.clone().unwrap_or_default(),
            self.code
                .as_ref()
                .map(keccak256)
                .unwrap_or(empty_hash)
                .into(),
            tx.hash.clone(),
            tx.hash.clone(),
            Some(tx.hash.clone()),
        )
    }

    /// Merge this update (`self`) with another one (`other`)
    ///
    /// This function is utilized for aggregating multiple updates into a single
    /// update. The attribute values of `other` are set on `self`.
    /// Meanwhile, contract storage maps are merged, with keys from `other` taking precedence.
    ///
    /// Be noted that, this function will mutate the state of the calling
    /// struct. An error will occur if merging updates from different accounts.
    ///
    /// There are no further validation checks within this method, hence it
    /// could be used as needed. However, you should give preference to
    /// utilizing [TransactionVMUpdates] for merging, when possible.
    ///
    /// # Errors
    ///
    /// It returns an `CoreError::MergeError` error if `self.address` and
    /// `other.address` are not identical.
    ///
    /// # Arguments
    ///
    /// * `other`: An instance of `AccountUpdate`. The attribute values and keys of `other` will
    ///   overwrite those of `self`.
    pub fn merge(&mut self, other: AccountDelta) -> Result<(), String> {
        if self.address != other.address {
            return Err(format!(
                "Can't merge AccountUpdates from differing identities; Expected {:#020x}, got {:#020x}",
                self.address, other.address
            ));
        }

        self.slots.extend(other.slots);

        if let Some(balance) = other.balance {
            self.balance = Some(balance)
        }
        self.code = other.code.or(self.code.take());

        Ok(())
    }

    pub fn is_update(&self) -> bool {
        self.change == ChangeType::Update
    }

    pub fn is_creation(&self) -> bool {
        self.change == ChangeType::Creation
    }
}

impl From<Account> for AccountDelta {
    fn from(value: Account) -> Self {
        Self {
            chain: value.chain,
            address: value.address,
            slots: value
                .slots
                .into_iter()
                .map(|(k, v)| (k, Some(v)))
                .collect(),
            balance: Some(value.native_balance),
            code: Some(value.code),
            change: ChangeType::Creation,
        }
    }
}

/// Updates grouped by their respective transaction.
#[derive(Debug, Clone, PartialEq)]
pub struct TransactionVMUpdates {
    pub account_deltas: HashMap<Bytes, AccountDelta>,
    pub protocol_components: HashMap<ComponentId, ProtocolComponent>,
    pub component_balances: HashMap<ComponentId, HashMap<Bytes, ComponentBalance>>,
    pub tx: Transaction,
}

impl TransactionVMUpdates {
    pub fn new(
        account_deltas: HashMap<Bytes, AccountDelta>,
        protocol_components: HashMap<ComponentId, ProtocolComponent>,
        component_balances: HashMap<ComponentId, HashMap<Bytes, ComponentBalance>>,
        tx: Transaction,
    ) -> Self {
        Self { account_deltas, protocol_components, component_balances, tx }
    }

    /// Merges this update with another one.
    ///
    /// The method combines two `AccountUpdateWithTx` instances under certain
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
    pub fn merge(&mut self, other: &TransactionVMUpdates) -> Result<(), String> {
        if self.tx.block_hash != other.tx.block_hash {
            return Err(format!(
                "Can't merge TransactionVMUpdates from different blocks: {:x} != {:x}",
                self.tx.block_hash, other.tx.block_hash,
            ));
        }
        if self.tx.hash == other.tx.hash {
            return Err(format!(
                "Can't merge TransactionVMUpdates from the same transaction: {:x}",
                self.tx.hash
            ));
        }
        if self.tx.index > other.tx.index {
            return Err(format!(
                "Can't merge TransactionVMUpdates with lower transaction index: {} > {}",
                self.tx.index, other.tx.index
            ));
        }
        self.tx = other.tx.clone();

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

        // Add new protocol components
        self.protocol_components
            .extend(other.protocol_components.clone());

        // Add new component balances and overwrite existing ones
        for (component_id, balance_by_token_map) in other
            .component_balances
            .clone()
            .into_iter()
        {
            // Check if the key exists in the first map
            if let Some(existing_inner_map) = self
                .component_balances
                .get_mut(&component_id)
            {
                // Iterate through the inner map and update values
                for (inner_key, value) in balance_by_token_map {
                    existing_inner_map.insert(inner_key, value);
                }
            } else {
                self.component_balances
                    .insert(component_id, balance_by_token_map);
            }
        }

        Ok(())
    }
}

impl From<&TransactionVMUpdates> for Vec<Account> {
    /// Creates a full account from a change.
    ///
    /// This can be used to get an insertable an account if we know the update
    /// is actually a creation.
    ///
    /// Assumes that all relevant changes are set on `self` if something is
    /// missing, it will use the corresponding types default.
    /// Will use the associated transaction as creation, balance and code modify
    /// transaction.
    fn from(value: &TransactionVMUpdates) -> Self {
        value
            .account_deltas
            .clone()
            .into_values()
            .map(|update| {
                let acc = Account::new(
                    update.chain,
                    update.address.clone(),
                    format!("{:#020x}", update.address),
                    update
                        .slots
                        .into_iter()
                        .map(|(k, v)| (k, v.unwrap_or_default())) //TODO: is default ok here or should it be Bytes::zero(32)
                        .collect(),
                    update.balance.unwrap_or_default(),
                    update.code.clone().unwrap_or_default(),
                    update
                        .code
                        .as_ref()
                        .map(keccak256)
                        .unwrap_or_default()
                        .into(),
                    value.tx.hash.clone(),
                    value.tx.hash.clone(),
                    Some(value.tx.hash.clone()),
                );
                acc
            })
            .collect()
    }
}
