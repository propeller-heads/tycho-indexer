use std::collections::{hash_map::Entry, HashMap};

use deepsize::DeepSizeOf;
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::{
    keccak256,
    models::{
        blockchain::Transaction,
        protocol::{ComponentBalance, ProtocolComponent},
        Address, Balance, Chain, ChangeType, Code, CodeHash, ComponentId, ContractId,
        ContractStore, ContractStoreDeltas, MergeError, StoreKey, TxHash,
    },
    Bytes,
};

#[derive(Clone, Debug, PartialEq)]
pub struct Account {
    pub chain: Chain,
    pub address: Address,
    pub title: String,
    pub slots: ContractStore,
    pub native_balance: Balance,
    pub token_balances: HashMap<Address, AccountBalance>,
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
        slots: ContractStore,
        native_balance: Balance,
        token_balances: HashMap<Address, AccountBalance>,
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
            token_balances,
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

    pub fn apply_delta(&mut self, delta: &AccountDelta) -> Result<(), MergeError> {
        let self_id = (self.chain, &self.address);
        let other_id = (delta.chain, &delta.address);
        if self_id != other_id {
            return Err(MergeError::IdMismatch(
                "AccountDeltas".to_string(),
                format!("{self_id:?}"),
                format!("{other_id:?}"),
            ));
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

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default, DeepSizeOf)]
pub struct AccountDelta {
    pub chain: Chain,
    pub address: Address,
    pub slots: ContractStoreDeltas,
    pub balance: Option<Balance>,
    code: Option<Code>,
    change: ChangeType,
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
        slots: ContractStoreDeltas,
        balance: Option<Balance>,
        code: Option<Code>,
        change: ChangeType,
    ) -> Self {
        if code.is_none() && matches!(change, ChangeType::Creation) {
            warn!(?address, "Instantiated AccountDelta without code marked as creation!")
        }
        Self { chain, address, slots, balance, code, change }
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
                .map(|(k, v)| (k, v.unwrap_or_default()))
                .collect(),
            self.balance.unwrap_or_default(),
            // token balances are not set in the delta
            HashMap::new(),
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
                .map(|(k, v)| (k, v.unwrap_or_default()))
                .collect(),
            self.balance.unwrap_or_default(),
            // token balances are not set in the delta
            HashMap::new(),
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
            // token balances are not set in the delta
            HashMap::new(),
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
    /// utilizing [AccountChangesWithTx] for merging, when possible.
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
    pub fn merge(&mut self, other: AccountDelta) -> Result<(), MergeError> {
        if self.address != other.address {
            return Err(MergeError::IdMismatch(
                "AccountDelta".to_string(),
                format!("{:#020x}", self.address),
                format!("{:#020x}", other.address),
            ));
        }

        self.slots.extend(other.slots);

        if let Some(balance) = other.balance {
            self.balance = Some(balance)
        }
        self.code = other.code.or(self.code.take());

        if self.code.is_none() && matches!(self.change, ChangeType::Creation) {
            warn!(address=?self.address, "AccountDelta without code marked as creation after merge!")
        }

        Ok(())
    }

    pub fn is_update(&self) -> bool {
        self.change == ChangeType::Update
    }

    pub fn is_creation(&self) -> bool {
        self.change == ChangeType::Creation
    }

    pub fn change_type(&self) -> ChangeType {
        self.change
    }

    pub fn code(&self) -> &Option<Code> {
        &self.code
    }

    pub fn set_code(&mut self, code: Bytes) {
        self.code = Some(code)
    }
}

impl From<Account> for AccountDelta {
    fn from(value: Account) -> Self {
        Self::new(
            value.chain,
            value.address,
            value
                .slots
                .into_iter()
                .map(|(k, v)| (k, Some(v)))
                .collect(),
            Some(value.native_balance),
            Some(value.code),
            ChangeType::Creation,
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, DeepSizeOf)]
pub struct AccountBalance {
    pub account: Address,
    pub token: Address,
    pub balance: Balance,
    pub modify_tx: TxHash,
}

impl AccountBalance {
    pub fn new(account: Address, token: Address, balance: Balance, modify_tx: TxHash) -> Self {
        Self { account, token, balance, modify_tx }
    }
}

/// Updates grouped by their respective transaction.
#[derive(Debug, Clone, PartialEq)]
pub struct AccountChangesWithTx {
    // map of account changes in the transaction
    pub account_deltas: HashMap<Address, AccountDelta>,
    // map of new protocol components created in the transaction
    pub protocol_components: HashMap<ComponentId, ProtocolComponent>,
    // map of component balance updates given as component ids to their token-balance pairs
    pub component_balances: HashMap<ComponentId, HashMap<Address, ComponentBalance>>,
    // map of account balance updates given as account addresses to their token-balance pairs
    pub account_balances: HashMap<Address, HashMap<Address, AccountBalance>>,
    // transaction linked to the updates
    pub tx: Transaction,
}

impl AccountChangesWithTx {
    pub fn new(
        account_deltas: HashMap<Address, AccountDelta>,
        protocol_components: HashMap<ComponentId, ProtocolComponent>,
        component_balances: HashMap<ComponentId, HashMap<Address, ComponentBalance>>,
        account_balances: HashMap<Address, HashMap<Address, AccountBalance>>,
        tx: Transaction,
    ) -> Self {
        Self { account_deltas, protocol_components, component_balances, account_balances, tx }
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
    pub fn merge(&mut self, other: &AccountChangesWithTx) -> Result<(), MergeError> {
        if self.tx.block_hash != other.tx.block_hash {
            return Err(MergeError::BlockMismatch(
                "AccountChangesWithTx".to_string(),
                self.tx.block_hash.clone(),
                other.tx.block_hash.clone(),
            ));
        }
        if self.tx.hash == other.tx.hash {
            return Err(MergeError::SameTransaction(
                "AccountChangesWithTx".to_string(),
                self.tx.hash.clone(),
            ));
        }
        if self.tx.index > other.tx.index {
            return Err(MergeError::TransactionOrderError(
                "AccountChangesWithTx".to_string(),
                self.tx.index,
                other.tx.index,
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
                for (token, value) in balance_by_token_map {
                    existing_inner_map.insert(token, value);
                }
            } else {
                self.component_balances
                    .insert(component_id, balance_by_token_map);
            }
        }

        // Add new account balances and overwrite existing ones
        for (account_addr, balance_by_token_map) in other
            .account_balances
            .clone()
            .into_iter()
        {
            // Check if the key exists in the first map
            if let Some(existing_inner_map) = self
                .account_balances
                .get_mut(&account_addr)
            {
                // Iterate through the inner map and update values
                for (token, value) in balance_by_token_map {
                    existing_inner_map.insert(token, value);
                }
            } else {
                self.account_balances
                    .insert(account_addr, balance_by_token_map);
            }
        }

        Ok(())
    }
}

impl From<&AccountChangesWithTx> for Vec<Account> {
    /// Creates a full account from a change.
    ///
    /// This can be used to get an insertable an account if we know the update
    /// is actually a creation.
    ///
    /// Assumes that all relevant changes are set on `self` if something is
    /// missing, it will use the corresponding types default.
    /// Will use the associated transaction as creation, balance and code modify
    /// transaction.
    fn from(value: &AccountChangesWithTx) -> Self {
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
                    value
                        .account_balances
                        .get(&update.address)
                        .cloned()
                        .unwrap_or_default(),
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

#[derive(Debug, PartialEq, Clone, DeepSizeOf)]
pub struct ContractStorageChange {
    pub value: Bytes,
    pub previous: Bytes,
}

impl ContractStorageChange {
    pub fn new(value: impl Into<Bytes>, previous: impl Into<Bytes>) -> Self {
        Self { value: value.into(), previous: previous.into() }
    }

    pub fn initial(value: impl Into<Bytes>) -> Self {
        Self { value: value.into(), previous: Bytes::default() }
    }
}

#[derive(Debug, PartialEq, Default, Clone, DeepSizeOf)]
pub struct ContractChanges {
    pub account: Address,
    pub slots: HashMap<StoreKey, ContractStorageChange>,
    pub native_balance: Option<Balance>,
}

impl ContractChanges {
    pub fn new(
        account: Address,
        slots: HashMap<StoreKey, ContractStorageChange>,
        native_balance: Option<Balance>,
    ) -> Self {
        Self { account, slots, native_balance }
    }
}

/// Multiple binary key-value stores grouped by account address.
pub type AccountToContractChanges = HashMap<Address, ContractChanges>;

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use chrono::DateTime;
    use rstest::rstest;

    use super::*;
    use crate::models::blockchain::fixtures as block_fixtures;

    const HASH_256_0: &str = "0x0000000000000000000000000000000000000000000000000000000000000000";
    const HASH_256_1: &str = "0x0000000000000000000000000000000000000000000000000000000000000001";

    fn update_balance_delta() -> AccountDelta {
        AccountDelta::new(
            Chain::Ethereum,
            Bytes::from_str("e688b84b23f322a994A53dbF8E15FA82CDB71127").unwrap(),
            HashMap::new(),
            Some(Bytes::from(420u64).lpad(32, 0)),
            None,
            ChangeType::Update,
        )
    }

    fn update_slots_delta() -> AccountDelta {
        AccountDelta::new(
            Chain::Ethereum,
            Bytes::from_str("e688b84b23f322a994A53dbF8E15FA82CDB71127").unwrap(),
            slots([(0, 1), (1, 2)]),
            None,
            None,
            ChangeType::Update,
        )
    }

    // Utils function that return slots that match `AccountDelta` slots.
    // TODO: this is temporary, we shoud make AccountDelta.slots use Bytes instead of Option<Bytes>
    pub fn slots(data: impl IntoIterator<Item = (u64, u64)>) -> HashMap<Bytes, Option<Bytes>> {
        data.into_iter()
            .map(|(s, v)| (Bytes::from(s).lpad(32, 0), Some(Bytes::from(v).lpad(32, 0))))
            .collect()
    }

    #[test]
    fn test_merge_account_deltas() {
        let mut update_left = update_balance_delta();
        let update_right = update_slots_delta();
        let mut exp = update_slots_delta();
        exp.balance = Some(Bytes::from(420u64).lpad(32, 0));

        update_left.merge(update_right).unwrap();

        assert_eq!(update_left, exp);
    }

    #[test]
    fn test_merge_account_delta_wrong_address() {
        let mut update_left = update_balance_delta();
        let mut update_right = update_slots_delta();
        update_right.address = Bytes::zero(20);
        let exp = Err(MergeError::IdMismatch(
            "AccountDelta".to_string(),
            format!("{:#020x}", update_left.address),
            format!("{:#020x}", update_right.address),
        ));

        let res = update_left.merge(update_right);

        assert_eq!(res, exp);
    }

    fn tx_vm_update() -> AccountChangesWithTx {
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

        AccountChangesWithTx::new(
            account_updates,
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            block_fixtures::transaction01(),
        )
    }

    fn account() -> Account {
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
            HashMap::new(),
            code.into(),
            code_hash,
            Bytes::zero(32),
            Bytes::zero(32),
            Some(Bytes::zero(32)),
        )
    }

    #[test]
    fn test_account_from_update_w_tx() {
        let update = tx_vm_update();
        let exp = account();

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

    #[rstest]
    #[case::diff_block(
    block_fixtures::create_transaction(HASH_256_1, HASH_256_1, 11),
    Err(MergeError::BlockMismatch(
        "AccountChangesWithTx".to_string(),
        Bytes::zero(32),
        HASH_256_1.into(),
    ))
    )]
    #[case::same_tx(
    block_fixtures::create_transaction(HASH_256_0, HASH_256_0, 11),
    Err(MergeError::SameTransaction(
        "AccountChangesWithTx".to_string(),
        Bytes::zero(32),
    ))
    )]
    #[case::lower_idx(
    block_fixtures::create_transaction(HASH_256_1, HASH_256_0, 1),
    Err(MergeError::TransactionOrderError(
        "AccountChangesWithTx".to_string(),
        10,
        1,
    ))
    )]
    fn test_merge_vm_updates_w_tx(#[case] tx: Transaction, #[case] exp: Result<(), MergeError>) {
        let mut left = tx_vm_update();
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
            created_at: DateTime::from_timestamp(1000, 0)
                .unwrap()
                .naive_utc(),
        }
    }

    #[rstest]
    fn test_merge_transaction_vm_updates() {
        let tx_first_update = block_fixtures::transaction01();
        let tx_second_update = block_fixtures::create_transaction(HASH_256_1, HASH_256_0, 15);
        let protocol_component_first_tx = create_protocol_component(tx_first_update.hash.clone());
        let protocol_component_second_tx = create_protocol_component(tx_second_update.hash.clone());
        let account_address =
            Bytes::from_str("0x0000000000000000000000000000000061626364").unwrap();
        let token_address = Bytes::from_str("0x0000000000000000000000000000000066666666").unwrap();

        let first_update = AccountChangesWithTx {
            account_deltas: [(
                account_address.clone(),
                AccountDelta::new(
                    Chain::Ethereum,
                    account_address.clone(),
                    slots([(2711790500, 2981278644), (3250766788, 3520254932)]),
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
                    token_address.clone(),
                    ComponentBalance {
                        token: token_address.clone(),
                        balance: Bytes::from(0_i32.to_be_bytes()),
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
            account_balances: [(
                account_address.clone(),
                [(
                    token_address.clone(),
                    AccountBalance {
                        token: token_address.clone(),
                        balance: Bytes::from(0_i32.to_be_bytes()),
                        modify_tx: Default::default(),
                        account: account_address.clone(),
                    },
                )]
                .into_iter()
                .collect(),
            )]
            .into_iter()
            .collect(),
            tx: tx_first_update,
        };
        let second_update = AccountChangesWithTx {
            account_deltas: [(
                account_address.clone(),
                AccountDelta::new(
                    Chain::Ethereum,
                    account_address.clone(),
                    slots([(2981278644, 3250766788), (2442302356, 2711790500)]),
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
                    token_address.clone(),
                    ComponentBalance {
                        token: token_address.clone(),
                        balance: Bytes::from(500000_i32.to_be_bytes()),
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
            account_balances: [(
                account_address.clone(),
                [(
                    token_address.clone(),
                    AccountBalance {
                        token: token_address,
                        balance: Bytes::from(20000_i32.to_be_bytes()),
                        modify_tx: Default::default(),
                        account: account_address,
                    },
                )]
                .into_iter()
                .collect(),
            )]
            .into_iter()
            .collect(),
            tx: tx_second_update,
        };

        // merge
        let mut to_merge_on = first_update.clone();
        to_merge_on
            .merge(&second_update)
            .unwrap();

        // assertions
        let expected_protocol_components: HashMap<ComponentId, ProtocolComponent> = [
            (protocol_component_first_tx.id.clone(), protocol_component_first_tx.clone()),
            (protocol_component_second_tx.id.clone(), protocol_component_second_tx.clone()),
        ]
        .into_iter()
        .collect();
        assert_eq!(to_merge_on.component_balances, second_update.component_balances);
        assert_eq!(to_merge_on.account_balances, second_update.account_balances);
        assert_eq!(to_merge_on.protocol_components, expected_protocol_components);

        let mut acc_update = second_update
            .account_deltas
            .clone()
            .into_values()
            .next()
            .unwrap();

        acc_update.slots = slots([
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
