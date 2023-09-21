use tracing::debug;

use std::collections::HashMap;
use thiserror::Error;

use revm::{
    db::DatabaseRef,
    interpreter::analysis::to_analysed,
    primitives::{AccountInfo, Bytecode, B160, B256, U256 as rU256},
};

use super::{
    account_storage::{AccountStorage, StateUpdate},
    tycho_models::Block,
};

#[derive(Error, Debug)]
pub enum TychoDBError {
    #[error("Account {0} not found")]
    MissingAccount(B160),
    #[error("Block needs to be set")]
    BlockNotSet(),
}

#[derive(Debug)]
pub struct TychoDB {
    /// Cached data
    account_storage: AccountStorage,
    /// Current block
    block: Option<Block>,
}

impl TychoDB {
    pub fn new(start_block: Option<Block>) -> Self {
        Self { account_storage: AccountStorage::new(), block: start_block }
    }

    /// Sets up a single account
    ///
    /// Full control over setting up an accounts. Allows to set up EOAs as
    /// well as smart contracts.
    ///
    /// # Arguments
    ///
    /// * `address` - Address of the account
    /// * `account` - The account information
    /// * `permanent_storage` - Storage to init the account with, this storage can only be updated
    ///   manually
    pub fn init_account(
        &mut self,
        address: B160,
        mut account: AccountInfo,
        permanent_storage: Option<HashMap<rU256, rU256>>,
    ) {
        if account.code.is_some() {
            account.code = Some(to_analysed(account.code.unwrap()));
        }

        self.account_storage
            .init_account(address, account, permanent_storage, true);
    }

    /// Update the simulation state.
    ///
    /// This method modifies the current state of the simulation by applying the provided updates to
    /// the accounts in the smart contract storage. These changes correspond to a particular
    /// block in the blockchain.
    ///
    /// # Arguments
    ///
    /// * `new_state`: A struct containing all the state changes for a particular block.
    pub fn update_state(&mut self, new_state: &HashMap<B160, StateUpdate>, block: Block) {
        //TODO: initialize new contracts
        self.block = Some(block);
        for (address, state_update) in new_state.iter() {
            self.account_storage
                .update_account(address, state_update);
        }
    }
}

impl DatabaseRef for TychoDB {
    type Error = TychoDBError;
    /// Retrieves basic information about an account.
    ///
    /// This function retrieves the basic account information for the specified address.
    ///
    /// # Arguments
    ///
    /// * `address`: The address of the account to retrieve the information for.
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing the account information or an error if the account is not
    /// found.
    fn basic(&self, address: B160) -> Result<Option<AccountInfo>, Self::Error> {
        if let Some(account) = self
            .account_storage
            .get_account_info(&address)
        {
            return Ok(Some(account.clone()))
        };
        Err(TychoDBError::MissingAccount(address))
    }

    fn code_by_hash(&self, _code_hash: B256) -> Result<Bytecode, Self::Error> {
        panic!("Code by hash is not implemented")
    }

    /// Retrieves the storage value at the specified address and index.
    ///
    /// # Arguments
    ///
    /// * `address`: The address of the contract to retrieve the storage value from.
    /// * `index`: The index of the storage value to retrieve.
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing the storage value if it exists.
    ///
    /// # Errors
    ///
    /// Returns an error if the storage value is not found.
    fn storage(&self, address: B160, index: rU256) -> Result<rU256, Self::Error> {
        debug!("Requested storage of account {:x?} slot {}", address, index);
        if let Some(storage_value) = self
            .account_storage
            .get_storage(&address, &index)
        {
            debug!("Got value locally. Value: {}", storage_value);
            Ok(storage_value)
        } else {
            // At this point we either don't know this address or we don't have anything at this
            // index (memory slot)
            if self
                .account_storage
                .account_present(&address)
            {
                // As we only store non-zero values, if the account is present it means this slot is
                // zero.
                Ok(rU256::ZERO)
            } else {
                // At this point we know we don't have data for this address.
                debug!("We don't have data for {}. Returning error.", address);
                Err(TychoDBError::MissingAccount(address))
            }
        }
    }

    /// If block header is set, returns the hash. Otherwise returns a zero hash.
    fn block_hash(&self, _number: rU256) -> Result<B256, Self::Error> {
        match &self.block {
            Some(header) => Ok(header.hash),
            None => Err(TychoDBError::BlockNotSet()),
        }
    }
}

#[cfg(test)]
mod tests {
    use chrono::NaiveDateTime;
    use revm::primitives::U256 as rU256;
    use rstest::{fixture, rstest};
    use std::{error::Error, str::FromStr};

    use crate::evm_simulation::tycho_models::Chain;

    use super::*;
    #[fixture]
    pub fn mock_db() -> TychoDB {
        TychoDB::new(None)
    }

    #[rstest]
    fn test_account_get_acc_info(mut mock_db: TychoDB) -> Result<(), Box<dyn Error>> {
        // Tests if the provider has not been queried.
        // Querying the mocked provider would cause a panic, therefore no assert is needed.
        let mock_acc_address = B160::from_str("0xb4e16d0168e52d35cacd2c6185b44281ec28c9dc")?;
        mock_db.init_account(mock_acc_address, AccountInfo::default(), None);

        let acc_info = mock_db
            .basic(mock_acc_address)
            .unwrap()
            .unwrap();

        assert_eq!(
            mock_db
                .account_storage
                .get_account_info(&mock_acc_address)
                .unwrap(),
            &acc_info
        );
        Ok(())
    }

    #[rstest]
    fn test_account_storage(mut mock_db: TychoDB) -> Result<(), Box<dyn Error>> {
        let mock_acc_address = B160::from_str("0xb4e16d0168e52d35cacd2c6185b44281ec28c9dc")?;
        let storage_address = rU256::from(1);
        let mut permanent_storage: HashMap<rU256, rU256> = HashMap::new();
        permanent_storage.insert(storage_address, rU256::from(10));
        mock_db.init_account(mock_acc_address, AccountInfo::default(), Some(permanent_storage));

        let storage = mock_db
            .storage(mock_acc_address, storage_address)
            .unwrap();

        assert_eq!(storage, rU256::from(10));
        Ok(())
    }

    #[rstest]
    fn test_account_storage_zero(mut mock_db: TychoDB) -> Result<(), Box<dyn Error>> {
        let mock_acc_address = B160::from_str("0xb4e16d0168e52d35cacd2c6185b44281ec28c9dc")?;
        let storage_address = rU256::from(1);
        mock_db.init_account(mock_acc_address, AccountInfo::default(), None);

        let storage = mock_db
            .storage(mock_acc_address, storage_address)
            .unwrap();

        assert_eq!(storage, rU256::ZERO);
        Ok(())
    }

    #[rstest]
    #[should_panic(
        expected = "called `Result::unwrap()` on an `Err` value: MissingAccount(0xb4e16d0168e52d35cacd2c6185b44281ec28c9dc)"
    )]
    fn test_account_storage_missing(mock_db: TychoDB) {
        let mock_acc_address =
            B160::from_str("0xb4e16d0168e52d35cacd2c6185b44281ec28c9dc").unwrap();
        let storage_address = rU256::from(1);

        // This will panic because this account isn't initialized
        mock_db
            .storage(mock_acc_address, storage_address)
            .unwrap();
    }

    #[rstest]
    fn test_update_state(mut mock_db: TychoDB) -> Result<(), Box<dyn Error>> {
        let address = B160::from_str("0xb4e16d0168e52d35cacd2c6185b44281ec28c9dc")?;
        mock_db.init_account(address, AccountInfo::default(), None);

        let mut new_storage = HashMap::default();
        let new_storage_value_index = rU256::from_limbs_slice(&[123]);
        new_storage.insert(new_storage_value_index, new_storage_value_index);
        let new_balance = rU256::from_limbs_slice(&[500]);
        let update = StateUpdate { storage: Some(new_storage), balance: Some(new_balance) };
        let new_block = Block {
            number: 1,
            hash: B256::default(),
            parent_hash: B256::default(),
            chain: Chain::Ethereum,
            ts: NaiveDateTime::from_timestamp_millis(123).unwrap(),
        };
        let mut updates = HashMap::default();
        updates.insert(address, update);

        mock_db.update_state(&updates, new_block);

        assert_eq!(
            mock_db
                .account_storage
                .get_storage(&address, &new_storage_value_index)
                .unwrap(),
            new_storage_value_index
        );
        assert_eq!(
            mock_db
                .account_storage
                .get_account_info(&address)
                .unwrap()
                .balance,
            new_balance
        );
        assert_eq!(mock_db.block.unwrap().number, 1);

        Ok(())
    }
}
