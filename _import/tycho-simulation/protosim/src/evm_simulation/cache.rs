use std::collections::HashMap;

use log::warn;

use revm::primitives::{hash_map, AccountInfo, B160, U256 as rU256};

#[derive(Default)]
pub struct StateUpdate {
    pub storage: Option<hash_map::HashMap<rU256, rU256>>,
    pub balance: Option<rU256>,
}
#[derive(Default)]
/// A simpler implementation of CacheDB that can't query a node. It just stores data.
pub struct CachedData {
    accounts: HashMap<B160, AccountInfo>,
    storage: HashMap<B160, hash_map::HashMap<rU256, rU256>>,
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
    ///
    /// # Notes
    ///
    /// This function checks if the `address` is already present in the `accounts`
    /// collection. If so, it logs a warning and returns without modifying the instance.
    /// Otherwise, it inserts the `info` into the `accounts` collection. If `storage` is provided,
    /// it inserts the `storage` information into the `storage` collection associated with the `address`.
    pub fn insert_account_data(
        &mut self,
        address: B160,
        info: AccountInfo,
        storage: Option<hash_map::HashMap<rU256, rU256>>,
    ) {
        if self.accounts.contains_key(&address) {
            warn!("Tried to insert account info that was already inserted");
            return;
        }

        self.accounts.insert(address, info);
        if let Some(s) = storage {
            self.storage.insert(address, s);
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
    pub fn update_account_info(&mut self, address: &B160, update: &StateUpdate) {
        if let Some(account) = self.accounts.get_mut(address) {
            if let Some(new_balance) = update.balance {
                account.balance = new_balance;
            }
        } else {
            warn!(
                "Tried to update account {:?} that was not initialized",
                address
            );
        }

        if let Some(storage) = self.storage.get_mut(address) {
            if let Some(new_storage) = &update.storage {
                for (index, value) in new_storage {
                    storage.insert(*index, *value);
                }
            }
        } else {
            warn!(
                "Tried to update storage {:?} that was not initialized",
                address
            );
        }
    }

    pub fn get_account(&self, address: &B160) -> Option<&AccountInfo> {
        self.accounts.get(address)
    }

    pub fn get_mut_account(&mut self, address: &B160) -> Option<&mut AccountInfo> {
        self.accounts.get_mut(address)
    }

    pub fn remove_account(&mut self, address: &B160) -> Option<AccountInfo> {
        self.accounts.remove(address)
    }

    pub fn account_present(&self, address: &B160) -> bool {
        self.accounts.contains_key(address)
    }

    pub fn set_storage(&mut self, address: B160, index: rU256, value: rU256) {
        self.storage
            .entry(address)
            .or_default()
            .insert(index, value);
    }

    pub fn get_storage(&self, address: &B160, index: &rU256) -> Option<&rU256> {
        match self.storage.get(address) {
            Some(s) => match s.get(index) {
                Some(value) => Some(value),
                None => None,
            },
            None => None,
        }
    }

    pub fn clone_storage(&self, address: &B160) -> Option<hash_map::HashMap<rU256, rU256>> {
        self.storage.get(address).cloned()
    }
}

#[cfg(test)]
mod tests {
    use crate::evm_simulation::cache::CachedData;
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

        cache.insert_account_data(acc_address, info, Some(storage_new));

        let acc = cache.get_account(&acc_address).unwrap();
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
        cache.accounts.insert(acc_address, info);
        let mut storage_new = hash_map::HashMap::new();
        let storage_index = rU256::from_str("1").unwrap();
        storage_new.insert(storage_index, rU256::from_str("5").unwrap());
        cache.storage.insert(acc_address, storage_new);
        let updated_balance = Some(rU256::from(100));
        let updated_storage_value = rU256::from_str("999").unwrap();
        let mut updated_storage = hash_map::HashMap::new();
        updated_storage.insert(storage_index, updated_storage_value);
        let state_update = StateUpdate {
            balance: updated_balance,
            storage: Some(updated_storage),
        };

        cache.update_account_info(&acc_address, &state_update);

        assert_eq!(
            cache.get_account(&acc_address).unwrap().balance,
            updated_balance.unwrap()
        );
        assert_eq!(
            cache.get_storage(&acc_address, &storage_index).unwrap(),
            &updated_storage_value
        );
        Ok(())
    }
}
