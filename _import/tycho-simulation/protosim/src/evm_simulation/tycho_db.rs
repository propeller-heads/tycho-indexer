use log::debug;
use std::cell::RefCell;
use std::collections::HashMap;
use thiserror::Error;

use revm::{
    db::DatabaseRef,
    interpreter::analysis::to_analysed,
    primitives::{AccountInfo, Bytecode, B160, B256, U256 as rU256},
};

use super::{
    account_storage::{AccountStorage, StateUpdate},
    tycho_models::{Block, BlockStateChanges},
};

#[derive(Error, Debug)]
pub enum TychoDBError {
    #[error("Account {0} not found")]
    MissingAccount(B160),
    #[error("Account {0} missing slot {1}")]
    MissingSlot(B160, rU256),
    #[error("Mocked account {0} missing slot {1}")]
    MissingMockedSlot(B160, rU256),
    #[error("Block needs to be set")]
    BlockNotSet(),
}

#[derive(Debug)]
pub struct TychoDB {
    /// Cached data
    account_storage: RefCell<AccountStorage>,
    /// Current block
    block: Option<Block>,
}

impl TychoDB {
    pub fn new(start_block: Option<Block>) -> Self {
        Self {
            account_storage: RefCell::new(AccountStorage::new()),
            block: start_block,
        }
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
    /// * `permanent_storage` - Storage to init the account with, this storage can only be updated manually
    /// * `mocked` - Whether this account should be considered mocked. For mocked accounts, all data must be inserted manually.
    pub fn init_account(
        &self,
        address: B160,
        mut account: AccountInfo,
        permanent_storage: Option<HashMap<rU256, rU256>>,
        mocked: bool,
    ) {
        if account.code.is_some() {
            account.code = Some(to_analysed(account.code.unwrap()));
        }

        self.account_storage
            .borrow_mut()
            .init_account(address, account, permanent_storage, mocked);
    }

    /// Update the simulation state.
    ///
    /// This method modifies the current state of the simulation by applying the provided updates to the accounts in the smart contract storage.
    /// These changes correspond to a particular block in the blockchain.
    ///
    /// # Arguments
    ///
    /// * `new_state`: A struct containing all the state changes for a particular block.
    pub fn update_state(&mut self, new_state: &BlockStateChanges) {
        //TODO: initialize new contracts
        self.block = Some(new_state.block);
        for (address, update_info) in new_state.account_updates.iter() {
            let account_update = StateUpdate {
                storage: update_info.slots.clone(),
                balance: update_info.balance,
            };
            self.account_storage
                .borrow_mut()
                .update_account(address, &account_update);
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
    /// Returns a `Result` containing the account information or an error if the account is not found.
    fn basic(&self, address: B160) -> Result<Option<AccountInfo>, Self::Error> {
        if let Some(account) = self.account_storage.borrow().get_account_info(&address) {
            return Ok(Some(account.clone()));
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
        let is_mocked; // will be None if we don't have this account at all
        {
            // This scope is to not make two simultaneous borrows (one occurs inside init_account)
            let borrowed_storage = self.account_storage.borrow();
            is_mocked = borrowed_storage.is_mocked_account(&address);
            if let Some(storage_value) = borrowed_storage.get_storage(&address, &index) {
                debug!(
                    "Got value locally. This is a {} account. Value: {}",
                    (if is_mocked.unwrap_or(false) {
                        "mocked"
                    } else {
                        "non-mocked"
                    }),
                    storage_value
                );
                return Ok(storage_value);
            }
        }
        // At this point we know we don't have data for this storage slot.
        match is_mocked {
            Some(true) => {
                debug!("This is a mocked account for which we don't have data. Returning error.");
                Err(TychoDBError::MissingMockedSlot(address, index))
            }
            _ => {
                debug!("We don't have this data. Returning error.");
                Err(TychoDBError::MissingSlot(address, index))
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
