use std::collections::HashMap;

use log::warn;

use revm::primitives::{hash_map, AccountInfo, B160, U256 as rU256};

// TODO: Add doc-string explaining the types
#[derive(PartialEq, Default)]
pub enum AccountType {
    #[default]
    Temp,
    Permanent,
    Mocked,
}
#[derive(Default)]
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
pub struct CachedData {
    accounts: HashMap<B160, Account>,
}

impl CachedData {
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
        if self.accounts.contains_key(&address) {
            warn!("Tried to init account that was already initialized");
            return;
        }

        self.accounts.insert(
            address,
            Account {
                info,
                storage: match storage {
                    Some(s) => s,
                    None => hash_map::HashMap::default(),
                },
                account_type,
            },
        );
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
            } else {
                warn!(
                    "Tried to update account {:?} that was not initialized",
                    address
                );
            }
        }
    }

    pub fn get_account_info(&self, address: &B160) -> Option<&AccountInfo> {
        match self.accounts.get(address) {
            Some(acc) => Some(&acc.info),
            None => None,
        }
    }

    pub fn remove_account(&mut self, address: &B160) {
        self.accounts.remove(address);
    }

    pub fn account_present(&self, address: &B160) -> bool {
        self.accounts.contains_key(address)
    }

    pub fn set_storage(&mut self, address: B160, index: rU256, value: rU256) {
        if let Some(acc) = self.accounts.get_mut(&address) {
            acc.storage.insert(index, value);
        } else {
            warn!("Try to set storage on unitialized account. Account will be initialized.");
            let mut storage_map = hash_map::HashMap::new();
            storage_map.insert(index, value);
            self.init_account(
                address,
                AccountInfo::default(),
                Some(storage_map),
                AccountType::Temp,
            )
        }
    }

    pub fn get_storage(&self, address: &B160, index: &rU256) -> Option<&rU256> {
        match self.accounts.get(address) {
            Some(acc) => acc.storage.get(index),
            None => None,
        }
    }

    pub fn clone_account_storage(
        &mut self,
        address: &B160,
    ) -> Option<hash_map::HashMap<rU256, rU256>> {
        match self.accounts.get_mut(address) {
            Some(acc) => Some(acc.storage.clone()),
            None => None,
        }
    }

    pub fn clear_temp_accounts(&mut self) {
        self.accounts
            .retain(|&_address, acc| acc.account_type != AccountType::Temp);
    }

    pub fn is_account_type(&self, address: &B160, account_type: &AccountType) -> bool {
        match self.accounts.get(address) {
            Some(acc) => &acc.account_type == account_type,
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::evm_simulation::cache::{Account, AccountType, CachedData};
    use revm::primitives::hash_map;
    use revm::primitives::{AccountInfo, B160, KECCAK_EMPTY, U256 as rU256};
    use std::{error::Error, str::FromStr};

    use super::StateUpdate;

    #[test]
    fn test_insert_account() -> Result<(), Box<dyn Error>> {
        let mut cache = CachedData::default();
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

        cache.init_account(acc_address, info, Some(storage_new), AccountType::Temp);

        let acc = cache.get_account_info(&acc_address).unwrap();
        let storage_value = cache
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
        let mut cache = CachedData::default();
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

        cache.accounts.insert(
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

        cache.update_account(&acc_address, &state_update);

        assert_eq!(
            cache.get_account_info(&acc_address).unwrap().balance,
            updated_balance.unwrap()
        );
        assert_eq!(
            cache.get_storage(&acc_address, &storage_index).unwrap(),
            &updated_storage_value
        );
        Ok(())
    }
}
