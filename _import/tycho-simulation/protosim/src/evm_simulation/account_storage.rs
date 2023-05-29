use std::collections::HashMap;

use log::warn;

use revm::primitives::{hash_map, AccountInfo, B160, U256 as rU256};
use std::collections::hash_map::Entry::Vacant;
/// Represents the type of an Ethereum account.
///
/// The `AccountType` enum defines the different types of Ethereum accounts, including `Temp`,
/// `Permanent`, and `Mocked`.
///
/// # Variants
///
/// * `Temp`: Represents a temporary account. Only accounts queried during runtime will be considered temp and will be deleted with every new block.
/// * `Permanent`: Represents a permanent account. Will be updated with every new block. If data is missing it will be queried.
/// * `Mocked`: Represents a mocked account used for testing or simulation purposes. Will stay in the cache, if data is missing a default value will be returned
#[derive(Clone, PartialEq, Eq, Default, Debug)]
pub enum AccountType {
    #[default]
    Temp,
    Permanent,
    Mocked,
}
#[derive(Clone, Default)]
pub struct Account {
    pub info: AccountInfo,
    pub storage: hash_map::HashMap<rU256, rU256>,
    pub account_type: AccountType,
}

#[derive(Default)]
pub struct StateUpdate {
    pub storage: Option<hash_map::HashMap<rU256, rU256>>,
    pub balance: Option<rU256>,
}
#[derive(Default)]
/// A simpler implementation of CacheDB that can't query a node. It just stores data.
pub struct AccountStorage {
    accounts: HashMap<B160, Account>,
}

impl AccountStorage {
    pub fn new() -> Self {
        Self::default()
    }
    /// Inserts account data into the current instance.
    ///
    /// # Arguments
    ///
    /// * `address` - The address of the account to insert.
    /// * `info` - The account information to insert.
    /// * `storage` - Optional storage information associated with the account.
    /// * `account_type` - Determines the type of the account
    ///
    /// # Notes
    ///
    /// This function checks if the `address` is already present in the `accounts`
    /// collection. If so, it logs a warning and returns without modifying the instance.
    /// Otherwise, it inserts the `info` into the `accounts` collection. If `storage` is provided,
    /// it inserts the `storage` information into the `storage` collection associated with the `address`.
    pub fn init_account(
        &mut self,
        address: B160,
        info: AccountInfo,
        storage: Option<hash_map::HashMap<rU256, rU256>>,
        account_type: AccountType,
    ) {
        if let Vacant(e) = self.accounts.entry(address) {
            e.insert(Account {
                info,
                storage: match storage {
                    Some(s) => s,
                    None => hash_map::HashMap::default(),
                },
                account_type,
            });
        } else {
            warn!("Tried to init account that was already initialized");
        }
    }

    /// Updates the account information and storage associated with the given address.
    ///
    /// # Arguments
    ///
    /// * `address` - The address of the account to update.
    /// * `update` - The state update containing the new information to apply.
    ///
    /// # Notes
    ///
    /// This function looks for the account information and storage associated with the provided
    /// `address`. If the `address` exists in the `accounts` collection, it updates the account
    /// information based on the `balance` field in the `update` parameter. If the `address` exists
    /// in the `storage` collection, it updates the storage information based on the `storage` field
    /// in the `update` parameter.
    ///
    /// If the `address` is not found in either collection, a warning is logged and no changes are made.
    pub fn update_account(&mut self, address: &B160, update: &StateUpdate) {
        if let Some(account) = self.accounts.get_mut(address) {
            if let Some(new_balance) = update.balance {
                account.info.balance = new_balance;
            }
            if let Some(new_storage) = &update.storage {
                for (index, value) in new_storage {
                    account.storage.insert(*index, *value);
                }
            }
        } else {
            warn!(
                "Tried to update account {:?} that was not initialized",
                address
            );
        }
    }

    pub fn get_account_info(&self, address: &B160) -> Option<&AccountInfo> {
        match self.accounts.get(address) {
            Some(acc) => Some(&acc.info),
            None => None,
        }
    }

    pub fn account_present(&self, address: &B160) -> bool {
        self.accounts.contains_key(address)
    }

    pub fn set_storage(&mut self, address: B160, index: rU256, value: rU256) {
        if let Some(acc) = self.accounts.get_mut(&address) {
            acc.storage.insert(index, value);
        } else {
            warn!("Trying to set storage on unitialized account.");
        }
    }

    pub fn get_storage(&self, address: &B160, index: &rU256) -> Option<&rU256> {
        match self.accounts.get(address) {
            Some(acc) => acc.storage.get(index),
            None => None,
        }
    }

    pub fn remove_accounts_by_type(&mut self, type_to_remove: AccountType) {
        self.accounts
            .retain(|&_address, acc| !acc.account_type.eq(&type_to_remove));
    }

    pub fn get_account_type(&self, address: &B160) -> Option<&AccountType> {
        if let Some(acc) = self.accounts.get(address) {
            Some(&acc.account_type)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::evm_simulation::account_storage::{Account, AccountStorage, AccountType};
    use revm::primitives::hash_map;
    use revm::primitives::{AccountInfo, B160, KECCAK_EMPTY, U256 as rU256};
    use std::{error::Error, str::FromStr};

    use super::StateUpdate;

    #[test]
    fn test_insert_account() -> Result<(), Box<dyn Error>> {
        let mut account_stroage = AccountStorage::default();
        let expected_nonce = 100;
        let expected_balance = rU256::from(500);
        let acc_address = B160::from_str("0xb4e16d0168e52d35cacd2c6185b44281ec28c9dc")?;
        let info: AccountInfo = AccountInfo {
            nonce: expected_nonce,
            balance: expected_balance,
            code: None,
            code_hash: KECCAK_EMPTY,
        };
        let mut storage_new = hash_map::HashMap::new();
        let expected_storage_value = rU256::from_str("5").unwrap();
        storage_new.insert(rU256::from_str("1").unwrap(), expected_storage_value);

        account_stroage.init_account(acc_address, info, Some(storage_new), AccountType::Temp);

        let acc = account_stroage.get_account_info(&acc_address).unwrap();
        let storage_value = account_stroage
            .get_storage(&acc_address, &rU256::from_str("1").unwrap())
            .unwrap();
        assert_eq!(acc.nonce, expected_nonce);
        assert_eq!(acc.balance, expected_balance);
        assert_eq!(acc.code_hash, KECCAK_EMPTY);
        assert_eq!(storage_value, &expected_storage_value);
        Ok(())
    }

    #[test]
    fn test_update_account_info() -> Result<(), Box<dyn Error>> {
        let mut account_stroage = AccountStorage::default();
        let acc_address = B160::from_str("0xb4e16d0168e52d35cacd2c6185b44281ec28c9dc")?;
        let info: AccountInfo = AccountInfo {
            nonce: 100,
            balance: rU256::from(500),
            code: None,
            code_hash: KECCAK_EMPTY,
        };

        let mut og_storage = hash_map::HashMap::new();
        let storage_index = rU256::from_str("1").unwrap();
        og_storage.insert(storage_index, rU256::from_str("5").unwrap());

        account_stroage.accounts.insert(
            acc_address,
            Account {
                info,
                storage: og_storage,
                account_type: AccountType::Temp,
            },
        );
        let updated_balance = Some(rU256::from(100));
        let updated_storage_value = rU256::from_str("999").unwrap();
        let mut updated_storage = hash_map::HashMap::new();
        updated_storage.insert(storage_index, updated_storage_value);
        let state_update = StateUpdate {
            balance: updated_balance,
            storage: Some(updated_storage),
        };

        account_stroage.update_account(&acc_address, &state_update);

        assert_eq!(
            account_stroage
                .get_account_info(&acc_address)
                .unwrap()
                .balance,
            updated_balance.unwrap()
        );
        assert_eq!(
            account_stroage
                .get_storage(&acc_address, &storage_index)
                .unwrap(),
            &updated_storage_value
        );
        Ok(())
    }

    #[test]
    fn test_get_account_info() {
        let mut account_stroage = AccountStorage::default();
        let address_1 = B160::from_str("0xb4e16d0168e52d35cacd2c6185b44281ec28c9dc").unwrap();
        let address_2 = B160::from_str("0xb4e16d0168e52d35cacd2c6185b44281ec28c9dd").unwrap();
        let account_info_1 = AccountInfo::default();
        let account_info_2 = AccountInfo {
            nonce: 500,
            ..Default::default()
        };
        account_stroage.init_account(address_1, account_info_1, None, AccountType::Permanent);
        account_stroage.init_account(address_2, account_info_2, None, AccountType::Permanent);

        let existing_account = account_stroage.get_account_info(&address_1);
        let address_3 = B160::from_str("0xb4e16d0168e52d35cacd2c6185b44281ec28c9de").unwrap();
        let non_existing_account = account_stroage.get_account_info(&address_3);

        assert_eq!(existing_account, Some(&AccountInfo::default()));
        assert_eq!(non_existing_account, None);
    }

    #[test]
    fn test_account_present() {
        let mut account_stroage = AccountStorage::default();
        let existing_account =
            B160::from_str("0xb4e16d0168e52d35cacd2c6185b44281ec28c9dc").unwrap();
        let address_2 = B160::from_str("0xb4e16d0168e52d35cacd2c6185b44281ec28c9dd").unwrap();
        let non_existing_account =
            B160::from_str("0xb4e16d0168e52d35cacd2c6185b44281ec28c9de").unwrap();
        account_stroage
            .accounts
            .insert(existing_account, Account::default());
        account_stroage
            .accounts
            .insert(address_2, Account::default());

        assert!(account_stroage.account_present(&existing_account));
        assert!(!account_stroage.account_present(&non_existing_account));
    }

    #[test]
    fn test_set_get_storage() {
        // Create a new instance of the struct for testing
        let mut account_stroage = AccountStorage::default();
        // Add a test account
        let address = B160::from_str("0xb4e16d0168e52d35cacd2c6185b44281ec28c9dc").unwrap();
        let non_existing_address =
            B160::from_str("0xb4e16d0168e52d35cacd2c6185b44281ec28c9dd").unwrap();
        let account = Account::default();
        account_stroage.accounts.insert(address, account);
        let index = rU256::from_str("1").unwrap();
        let value = rU256::from_str("1").unwrap();

        // Set storage for an existing account
        account_stroage.set_storage(address, index, value);
        // Check if the storage value has been set correctly
        let storage = account_stroage.get_storage(&address, &index);
        assert_eq!(storage, Some(&value));

        // Set storage for a non-existing account
        let non_existing_index = rU256::from_str("2").unwrap();
        let non_existing_value = rU256::from_str("2").unwrap();
        account_stroage.set_storage(non_existing_address, non_existing_index, non_existing_value);
        let empty_storage = account_stroage.get_storage(&non_existing_address, &non_existing_index);

        assert_eq!(empty_storage, None);
    }

    #[test]
    fn test_remove_accounts_by_type() {
        let mut account_stroage = AccountStorage::default();
        let address_1 = B160::from_str("0xb4e16d0168e52d35cacd2c6185b44281ec28c9dc").unwrap();
        let address_2 = B160::from_str("0xb4e16d0168e52d35cacd2c6185b44281ec28c9dd").unwrap();
        let address_3 = B160::from_str("0xb4e16d0168e52d35cacd2c6185b44281ec28c9de").unwrap();
        let temp_account_1 = Account {
            account_type: AccountType::Temp,
            ..Default::default()
        };
        let perm_account = Account {
            account_type: AccountType::Permanent,
            ..Default::default()
        };
        let temp_account_2 = Account {
            account_type: AccountType::Temp,
            ..Default::default()
        };
        account_stroage.accounts.insert(address_1, temp_account_1);
        account_stroage.accounts.insert(address_2, perm_account);
        account_stroage.accounts.insert(address_3, temp_account_2);

        // Remove accounts of type AccountType::Temp
        account_stroage.remove_accounts_by_type(AccountType::Temp);

        // Check if accounts of type AccountType::Temp have been removed
        assert!(!account_stroage.accounts.contains_key(&address_1));
        assert!(!account_stroage.accounts.contains_key(&address_3));
        // Check if account of type AccountType::Permanent is still present
        assert!(account_stroage.accounts.contains_key(&address_2));
    }

    #[test]
    fn test_is_account_type() {
        let mut account_stroage = AccountStorage::default();
        let address_1 = B160::from_str("0xb4e16d0168e52d35cacd2c6185b44281ec28c9dc").unwrap();
        let address_2 = B160::from_str("0xb4e16d0168e52d35cacd2c6185b44281ec28c9dd").unwrap();
        let address_3 = B160::from_str("0xb4e16d0168e52d35cacd2c6185b44281ec28c9de").unwrap();
        let account_1 = Account {
            account_type: AccountType::Temp,
            ..Default::default()
        };
        let account_2 = Account {
            account_type: AccountType::Permanent,
            ..Default::default()
        };
        account_stroage
            .accounts
            .insert(address_1, account_1.clone());
        account_stroage
            .accounts
            .insert(address_2, account_2.clone());

        // Test for an existing account with the correct account type
        let temp_account = account_stroage.get_account_type(&address_1).unwrap();
        // Test for an existing account with a different account type
        let is_false_type = account_stroage.get_account_type(&address_2).unwrap();
        // Test for a non-existing account
        let is_not_present = account_stroage.get_account_type(&address_3);

        assert_eq!(temp_account, &account_1.account_type);
        assert_eq!(is_false_type, &account_2.account_type);
        assert_eq!(is_not_present, None);
    }
}
