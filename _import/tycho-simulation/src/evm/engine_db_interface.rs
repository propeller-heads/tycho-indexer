use std::collections::HashMap;

use revm::{
    precompile::Address,
    primitives::{AccountInfo, U256 as rU256},
    DatabaseRef,
};

pub trait EngineDatabaseInterface: DatabaseRef {
    type Error;

    /// Sets up a single account
    ///
    /// Full control over setting up an accounts. Allows to set up EOAs as
    /// well as smart contracts.
    ///
    /// # Arguments
    ///
    /// * `address` - Address of the account
    /// * `account` - The account information
    /// * `permanent_storage` - Storage to init the account with this storage can only be updated
    ///   manually.
    /// * `mocked` - Whether this account should be considered mocked. For mocked accounts, nothing
    ///   is downloaded from a node; all data must be inserted manually.
    fn init_account(
        &self,
        address: Address,
        account: AccountInfo,
        permanent_storage: Option<HashMap<rU256, rU256>>,
        mocked: bool,
    );

    fn clear_temp_storage(&mut self);
}
