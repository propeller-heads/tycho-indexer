use std::collections::HashMap;

use log::{debug, warn};
use revm::primitives::{AccountInfo, B160, U256 as rU256};
use std::collections::hash_map::Entry::Vacant;

/// Represents an account in the account storage.
///
/// # Fields
///
/// * `info` - The account information of type `AccountInfo`.
/// * `permanent_storage` - The permanent storage of the account.
/// * `temp_storage` - The temporary storage of the account.
/// * `mocked` - A boolean flag indicating whether the account is mocked.
#[derive(Clone, Default, Debug)]
pub struct Account {
    pub info: AccountInfo,
    pub permanent_storage: HashMap<rU256, rU256>,
    pub temp_storage: HashMap<rU256, rU256>,
    pub mocked: bool,
}

#[derive(Default, Clone, PartialEq, Eq, Debug)]
pub struct StateUpdate {
    pub storage: Option<HashMap<rU256, rU256>>,
    pub balance: Option<rU256>,
}
#[derive(Default, Debug)]
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
    /// * `permanent_storage` - Optional storage information associated with the account.
    /// * `mocked` - Whether this account should be considered mocked.
    ///
    /// # Notes
    ///
    /// This function checks if the `address` is already present in the `accounts`
    /// collection. If so, it logs a warning and returns without modifying the instance.
    /// Otherwise, it stores a new `Account` instance with the provided data at the given address.
    pub fn init_account(
        &mut self,
        address: B160,
        info: AccountInfo,
        permanent_storage: Option<HashMap<rU256, rU256>>,
        mocked: bool,
    ) {
        if let Vacant(e) = self.accounts.entry(address) {
            e.insert(Account {
                info,
                permanent_storage: permanent_storage.unwrap_or_default(),
                temp_storage: HashMap::new(),
                mocked,
            });
            debug!(
                "Inserted a {} account {:x?}",
                if mocked { "mocked" } else { "non-mocked" },
                address
            );
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
                    account.permanent_storage.insert(*index, *value);
                }
            }
        } else {
            warn!(
                "Tried to update account {:x?} that was not initialized",
                address
            );
        }
    }

    /// Retrieves the account information for a given address.
    ///
    /// This function retrieves the account information associated with the specified address from the storage.
    ///
    /// # Arguments
    ///
    /// * `address`: The address of the account to retrieve the information for.
    ///
    /// # Returns
    ///
    /// Returns an `Option` that holds a reference to the `AccountInfo`. If the account is not found, `None` is returned.
    pub fn get_account_info(&self, address: &B160) -> Option<&AccountInfo> {
        self.accounts.get(address).map(|acc| &acc.info)
    }

    /// Checks if an account with the given address is present in the storage.
    ///
    /// # Arguments
    ///
    /// * `address`: A reference to the address of the account to check.
    ///
    /// # Returns
    ///
    /// Returns `true` if an account with the specified address is present in the storage,
    /// otherwise returns `false`.
    pub fn account_present(&self, address: &B160) -> bool {
        self.accounts.contains_key(address)
    }

    /// Sets the storage value at the specified index for the given account.
    ///
    /// If the account exists in the storage, the storage value at the specified `index` is updated.
    /// If the account does not exist, a warning message is logged indicating an attempt to set storage on an uninitialized account.
    ///
    /// # Arguments
    ///
    /// * `address`: The address of the account to set the storage value for.
    /// * `index`: The index of the storage value to set.
    /// * `value`: The new value to set for the storage.
    pub fn set_temp_storage(&mut self, address: B160, index: rU256, value: rU256) {
        if let Some(acc) = self.accounts.get_mut(&address) {
            acc.temp_storage.insert(index, value);
        } else {
            warn!(
                "Trying to set storage on unitialized account {:x?}.",
                address
            );
        }
    }

    /// Retrieves the storage value at the specified index for the given account, if it exists.
    ///
    /// If the account exists in the storage, the storage value at the specified `index` is returned as a reference.
    /// Temp storage takes priority over permanent storage.
    /// If the account does not exist, `None` is returned.
    ///
    /// # Arguments
    ///
    /// * `address`: A reference to the address of the account to retrieve the storage value from.
    /// * `index`: A reference to the index of the storage value to retrieve.
    ///
    /// # Returns
    ///
    /// Returns an `Option` containing a reference to the storage value if it exists, otherwise returns `None`.
    pub fn get_storage(&self, address: &B160, index: &rU256) -> Option<rU256> {
        if let Some(acc) = self.accounts.get(address) {
            if let Some(s) = acc.temp_storage.get(index) {
                Some(*s)
            } else {
                acc.permanent_storage.get(index).copied()
            }
        } else {
            None
        }
    }

    /// Retrieves the permanent storage value for the given address and index.
    ///
    /// If an account with the specified address exists in the account storage, this function
    /// retrieves the corresponding permanent storage value associated with the given index.
    ///
    /// # Arguments
    ///
    /// * `address` - The address of the account.
    /// * `index` - The index of the desired storage value.
    ///
    pub fn get_permanent_storage(&self, address: &B160, index: &rU256) -> Option<rU256> {
        if let Some(acc) = self.accounts.get(address) {
            acc.permanent_storage.get(index).copied()
        } else {
            None
        }
    }

    /// Removes all temp storage values.
    ///
    /// Iterates over the accounts in the storage and removes all temp storage values
    pub fn clean_temp_storage(&mut self) {
        self.accounts
            .values_mut()
            .for_each(|acc| acc.temp_storage.clear());
    }

    /// Checks if an account is mocked based on its address.
    ///
    /// # Arguments
    ///
    /// * `address` - A reference to the account address.
    pub fn is_mocked_account(&self, address: &B160) -> Option<bool> {
        self.accounts.get(address).map(|acc| acc.mocked)
    }
}

#[cfg(test)]
mod tests {
    use super::StateUpdate;
    use crate::evm_simulation::account_storage::{Account, AccountStorage};
    use revm::primitives::{AccountInfo, B160, KECCAK_EMPTY, U256 as rU256};
    use std::collections::HashMap;
    use std::{error::Error, str::FromStr};

    #[test]
    fn test_insert_account() -> Result<(), Box<dyn Error>> {
        let mut account_storage = AccountStorage::default();
        let expected_nonce = 100;
        let expected_balance = rU256::from(500);
        let acc_address = B160::from_str("0xb4e16d0168e52d35cacd2c6185b44281ec28c9dc")?;
        let info: AccountInfo = AccountInfo {
            nonce: expected_nonce,
            balance: expected_balance,
            code: None,
            code_hash: KECCAK_EMPTY,
        };
        let mut storage_new = HashMap::new();
        let expected_storage_value = rU256::from_str("5").unwrap();
        storage_new.insert(rU256::from_str("1").unwrap(), expected_storage_value);

        account_storage.init_account(acc_address, info, Some(storage_new), false);

        let acc = account_storage.get_account_info(&acc_address).unwrap();
        let storage_value = account_storage
            .get_storage(&acc_address, &rU256::from_str("1").unwrap())
            .unwrap();
        assert_eq!(
            acc.nonce, expected_nonce,
            "Nonce should match expected value"
        );
        assert_eq!(
            acc.balance, expected_balance,
            "Balance should match expected value"
        );
        assert_eq!(
            acc.code_hash, KECCAK_EMPTY,
            "Code hash should match expected value"
        );
        assert_eq!(
            storage_value, expected_storage_value,
            "Storage value should match expected value"
        );
        Ok(())
    }

    #[test]
    fn test_update_account_info() -> Result<(), Box<dyn Error>> {
        let mut account_storage = AccountStorage::default();
        let acc_address = B160::from_str("0xb4e16d0168e52d35cacd2c6185b44281ec28c9dc")?;
        let info: AccountInfo = AccountInfo {
            nonce: 100,
            balance: rU256::from(500),
            code: None,
            code_hash: KECCAK_EMPTY,
        };
        let mut original_storage = HashMap::new();
        let storage_index = rU256::from_str("1").unwrap();
        original_storage.insert(storage_index, rU256::from_str("5").unwrap());
        account_storage.accounts.insert(
            acc_address,
            Account {
                info,
                permanent_storage: original_storage,
                temp_storage: HashMap::new(),
                mocked: false,
            },
        );
        let updated_balance = rU256::from(100);
        let updated_storage_value = rU256::from_str("999").unwrap();
        let mut updated_storage = HashMap::new();
        updated_storage.insert(storage_index, updated_storage_value);
        let state_update = StateUpdate {
            balance: Some(updated_balance),
            storage: Some(updated_storage),
        };

        account_storage.update_account(&acc_address, &state_update);

        assert_eq!(
            account_storage
                .get_account_info(&acc_address)
                .unwrap()
                .balance,
            updated_balance,
            "Account balance should be updated"
        );
        assert_eq!(
            account_storage
                .get_storage(&acc_address, &storage_index)
                .unwrap(),
            updated_storage_value,
            "Storage value should be updated"
        );
        Ok(())
    }

    #[test]
    fn test_get_account_info() {
        let mut account_storage = AccountStorage::default();
        let address_1 = B160::from_str("0xb4e16d0168e52d35cacd2c6185b44281ec28c9dc").unwrap();
        let address_2 = B160::from_str("0xb4e16d0168e52d35cacd2c6185b44281ec28c9dd").unwrap();
        let account_info_1 = AccountInfo::default();
        let account_info_2 = AccountInfo {
            nonce: 500,
            ..Default::default()
        };
        account_storage.init_account(address_1, account_info_1, None, false);
        account_storage.init_account(address_2, account_info_2, None, false);

        let existing_account = account_storage.get_account_info(&address_1);
        let address_3 = B160::from_str("0xb4e16d0168e52d35cacd2c6185b44281ec28c9de").unwrap();
        let non_existing_account = account_storage.get_account_info(&address_3);

        assert_eq!(
            existing_account.unwrap().nonce,
            AccountInfo::default().nonce,
            "Existing account's nonce should match the expected value"
        );
        assert_eq!(
            non_existing_account, None,
            "Non-existing account should return None"
        );
    }

    #[test]
    fn test_account_present() {
        let mut account_storage = AccountStorage::default();
        let existing_account =
            B160::from_str("0xb4e16d0168e52d35cacd2c6185b44281ec28c9dc").unwrap();
        let address_2 = B160::from_str("0xb4e16d0168e52d35cacd2c6185b44281ec28c9dd").unwrap();
        let non_existing_account =
            B160::from_str("0xb4e16d0168e52d35cacd2c6185b44281ec28c9de").unwrap();
        account_storage
            .accounts
            .insert(existing_account, Account::default());
        account_storage
            .accounts
            .insert(address_2, Account::default());

        assert!(
            account_storage.account_present(&existing_account),
            "Existing account should be present in the AccountStorage"
        );
        assert!(
            !account_storage.account_present(&non_existing_account),
            "Non-existing account should not be present in the AccountStorage"
        );
    }

    #[test]
    fn test_set_get_storage() {
        // Create a new instance of the struct for testing
        let mut account_storage = AccountStorage::default();
        // Add a test account
        let address = B160::from_str("0xb4e16d0168e52d35cacd2c6185b44281ec28c9dc").unwrap();
        let non_existing_address =
            B160::from_str("0xb4e16d0168e52d35cacd2c6185b44281ec28c9dd").unwrap();
        let account = Account::default();
        account_storage.accounts.insert(address, account);
        let index = rU256::from_str("1").unwrap();
        let value = rU256::from_str("1").unwrap();
        let non_existing_index = rU256::from_str("2").unwrap();
        let non_existing_value = rU256::from_str("2").unwrap();
        account_storage.set_temp_storage(
            non_existing_address,
            non_existing_index,
            non_existing_value,
        );
        account_storage.set_temp_storage(address, index, value);

        let storage = account_storage.get_storage(&address, &index);
        let empty_storage = account_storage.get_storage(&non_existing_address, &non_existing_index);

        assert_eq!(
            storage,
            Some(value),
            "Storage value should match the value that was set"
        );
        assert_eq!(
            empty_storage, None,
            "Storage value should be None for a non-existing account"
        );
    }

    #[test]
    fn test_get_storage() {
        let mut account_storage = AccountStorage::default();
        let existing_address =
            B160::from_str("0xb4e16d0168e52d35cacd2c6185b44281ec28c9dc").unwrap();
        let non_existent_address =
            B160::from_str("0xb4e16d0168e52d35cacd2c6185b44281ec28c9dd").unwrap();
        let index = rU256::from(42);
        let value = rU256::from(100);
        let non_existent_index = rU256::from(999);
        let mut account = Account::default();
        account.temp_storage.insert(index, value);
        account_storage.accounts.insert(existing_address, account);

        assert_eq!(
            account_storage.get_storage(&existing_address, &index),
            Some(value), "If the storage features the address and index the value at that position should be retunred."
        );

        // Test with non-existent address
        assert_eq!(
            account_storage.get_storage(&non_existent_address, &index),
            None,
            "If the storage does not feature the address None should be returned."
        );

        // Test with non-existent index
        assert_eq!(
            account_storage.get_storage(&existing_address, &non_existent_index),
            None,
            "If the storage does not feature the index None should be returned."
        );
    }

    #[test]
    fn test_get_storage_priority() {
        let mut account_storage = AccountStorage::default();
        let address = B160::from_str("0xb4e16d0168e52d35cacd2c6185b44281ec28c9dc").unwrap();
        let index = rU256::from(69);
        let temp_value = rU256::from(100);
        let permanent_value = rU256::from(200);
        let mut account = Account::default();
        account.temp_storage.insert(index, temp_value);
        account.permanent_storage.insert(index, permanent_value);
        account_storage.accounts.insert(address, account);

        assert_eq!(
            account_storage.get_storage(&address, &index),
            Some(temp_value),
            "Temp storage value should take priority over permanent storage value"
        );
    }

    #[test]
    fn test_is_mocked_account() {
        let mut account_storage = AccountStorage::default();
        let mocked_account_address =
            B160::from_str("0xb4e16d0168e52d35cacd2c6185b44281ec28c9dc").unwrap();
        let not_mocked_account_address =
            B160::from_str("0xb4e16d0168e52d35cacd2c6185b44281ec28c9dd").unwrap();
        let unknown_address = B160::from_str("0xb4e16d0168e52d35cacd2c6185b44281ec28c9de").unwrap();
        let mocked_account = Account {
            mocked: true,
            ..Default::default()
        };
        let not_mocked_account = Account {
            mocked: false,
            ..Default::default()
        };
        account_storage
            .accounts
            .insert(mocked_account_address, mocked_account);
        account_storage
            .accounts
            .insert(not_mocked_account_address, not_mocked_account);

        assert_eq!(
            account_storage.is_mocked_account(&mocked_account_address),
            Some(true)
        );
        assert_eq!(
            account_storage.is_mocked_account(&not_mocked_account_address),
            Some(false)
        );
        assert_eq!(account_storage.is_mocked_account(&unknown_address), None);
    }

    #[test]
    fn test_clean_temp_storage() {
        let mut account_storage = AccountStorage::default();
        let address_1 = B160::from_str("0xb4e16d0168e52d35cacd2c6185b44281ec28c9dc").unwrap();
        let address_2 = B160::from_str("0xb4e16d0168e52d35cacd2c6185b44281ec28c9dd").unwrap();
        let mut account_1 = Account::default();
        account_1
            .temp_storage
            .insert(rU256::from(1), rU256::from(10));
        let mut account_2 = Account::default();
        account_2
            .temp_storage
            .insert(rU256::from(2), rU256::from(20));
        account_storage.accounts.insert(address_1, account_1);
        account_storage.accounts.insert(address_2, account_2);

        account_storage.clean_temp_storage();

        let account_1_temp_storage = account_storage.accounts[&address_1].temp_storage.len();
        let account_2_temp_storage = account_storage.accounts[&address_2].temp_storage.len();
        assert_eq!(
            account_1_temp_storage, 0,
            "Temporary storage of account 1 should be cleared"
        );
        assert_eq!(
            account_2_temp_storage, 0,
            "Temporary storage of account 2 should be cleared"
        );
    }

    #[test]
    fn test_get_permanent_storage() {
        let mut account_storage = AccountStorage::default();
        let address = B160::from_str("0xb4e16d0168e52d35cacd2c6185b44281ec28c9dc").unwrap();
        let non_existing_address =
            B160::from_str("0xb4e16d0168e52d35cacd2c6185b44281ec28c9dd").unwrap();
        let index = rU256::from_str("123").unwrap();
        let value = rU256::from_str("456").unwrap();
        let mut account = Account::default();
        account.permanent_storage.insert(index, value);
        account_storage.accounts.insert(address, account);

        let result = account_storage.get_permanent_storage(&address, &index);
        let not_existing_result =
            account_storage.get_permanent_storage(&non_existing_address, &index);
        let empty_index = rU256::from_str("789").unwrap();
        let no_storage = account_storage.get_permanent_storage(&address, &empty_index);

        assert_eq!(
            result,
            Some(value),
            "Expected value for existing account with permanent storage"
        );
        assert_eq!(
            not_existing_result, None,
            "Expected None for non-existing account"
        );
        assert_eq!(
            no_storage, None,
            "Expected None for existing account without permanent storage"
        );
    }
}
