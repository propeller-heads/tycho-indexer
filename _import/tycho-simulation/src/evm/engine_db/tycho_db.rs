use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use alloy_primitives::{Address, B256, U256};
use revm::{
    db::DatabaseRef,
    primitives::{AccountInfo, Bytecode, Bytes},
};
use thiserror::Error;
use tracing::{debug, error, info, instrument, warn};

use crate::evm::{
    account_storage::{AccountStorage, StateUpdate},
    engine_db::{engine_db_interface::EngineDatabaseInterface, simulation_db::BlockHeader},
    tycho_models::{AccountUpdate, ChangeType},
};

/// Perform bytecode analysis on the code of an account.
pub fn to_analysed(account_info: AccountInfo) -> AccountInfo {
    AccountInfo {
        code: account_info
            .code
            .map(revm::interpreter::analysis::to_analysed),
        ..account_info
    }
}

#[derive(Error, Debug)]
pub enum TychoClientError {
    #[error("Failed to parse URI: {0}. Error: {1}")]
    UriParsing(String, String),
    #[error("Failed to format request: {0}")]
    FormatRequest(String),
    #[error("Unexpected HTTP client error: {0}")]
    HttpClient(String),
    #[error("Failed to parse response: {0}")]
    ParseResponse(String),
}

#[derive(Error, Debug)]
pub enum PreCachedDBError {
    #[error("Account {0} not found")]
    MissingAccount(Address),
    #[error("Block needs to be set")]
    BlockNotSet(),
    #[error("Tycho Client error: {0}")]
    TychoClientError(#[from] TychoClientError),
}

#[derive(Clone, Debug)]
pub struct PreCachedDBInner {
    /// Storage for accounts
    accounts: AccountStorage,
    /// Current block
    block: Option<BlockHeader>,
}

#[derive(Clone, Debug)]
pub struct PreCachedDB {
    /// Cached inner data
    ///
    /// `inner` encapsulates `PreCachedDBInner` using `RwLock` for safe concurrent read or
    /// exclusive write access to the data and `Arc` for shared ownership of the lock across
    /// threads.
    pub inner: Arc<RwLock<PreCachedDBInner>>,
}

impl PreCachedDB {
    /// Create a new PreCachedDB instance
    pub fn new() -> Result<Self, PreCachedDBError> {
        Ok(PreCachedDB {
            inner: Arc::new(RwLock::new(PreCachedDBInner {
                accounts: AccountStorage::new(),
                block: None,
            })),
        })
    }

    #[instrument(skip_all)]
    pub fn update(&self, account_updates: Vec<AccountUpdate>, block: Option<BlockHeader>) {
        // Hold the write lock for the duration of the function so that no other thread can
        // write to the storage.
        let mut write_guard = self.inner.write().unwrap();

        write_guard.block = block;

        for update in account_updates {
            match update.change {
                ChangeType::Update => {
                    info!(%update.address, "Updating account");

                    // If the account is not present, the internal storage will handle throwing
                    // an exception.
                    write_guard.accounts.update_account(
                        &update.address,
                        &StateUpdate {
                            storage: Some(update.slots.clone()),
                            balance: update.balance,
                        },
                    );
                }
                ChangeType::Deletion => {
                    info!(%update.address, "Deleting account");

                    warn!(%update.address, "Deletion not implemented");
                }
                ChangeType::Creation => {
                    info!(%update.address, "Creating account");

                    // We expect the code and balance to be present.
                    let code = Bytecode::new_raw(Bytes::from(
                        update
                            .code
                            .clone()
                            .expect("account code"),
                    ));
                    let balance = update.balance.expect("account balance");

                    // Initialize the account.
                    write_guard.accounts.init_account(
                        update.address,
                        AccountInfo::new(balance, 0, code.hash_slow(), code),
                        Some(update.slots.clone()),
                        true, /* Flag all accounts in TychoDB mocked to sign that we cannot
                               * call an RPC provider for an update */
                    );
                }
                ChangeType::Unspecified => {
                    warn!(%update.address, "Unspecified change type");
                }
            }
        }
    }

    /// Retrieves the storage value at the specified index for the given account, if it exists.
    ///
    /// If the account exists in the storage, the storage value at the specified `index` is returned
    /// as a reference. Temp storage takes priority over permanent storage.
    /// If the account does not exist, `None` is returned.
    ///
    /// # Arguments
    ///
    /// * `address`: A reference to the address of the account to retrieve the storage value from.
    /// * `index`: A reference to the index of the storage value to retrieve.
    ///
    /// # Returns
    ///
    /// Returns an `Option` containing a reference to the storage value if it exists, otherwise
    /// returns `None`.
    pub fn get_storage(&self, address: &Address, index: &U256) -> Option<U256> {
        self.inner
            .read()
            .unwrap()
            .accounts
            .get_storage(address, index)
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
    pub fn update_state(
        &mut self,
        updates: &HashMap<Address, StateUpdate>,
        block: BlockHeader,
    ) -> HashMap<Address, StateUpdate> {
        // Hold the write lock for the duration of the function so that no other thread can
        // write to the storage.
        let mut write_guard = self.inner.write().unwrap();

        let mut revert_updates = HashMap::new();
        write_guard.block = Some(block);

        for (address, update_info) in updates.iter() {
            let mut revert_entry = StateUpdate::default();

            if let Some(current_account) = write_guard
                .accounts
                .get_account_info(address)
            {
                revert_entry.balance = Some(current_account.balance);
            }

            if update_info.storage.is_some() {
                let mut revert_storage = HashMap::default();
                for index in update_info
                    .storage
                    .as_ref()
                    .unwrap()
                    .keys()
                {
                    if let Some(s) = write_guard
                        .accounts
                        .get_storage(address, index)
                    {
                        revert_storage.insert(*index, s);
                    }
                }
                revert_entry.storage = Some(revert_storage);
            }
            revert_updates.insert(*address, revert_entry);
            write_guard
                .accounts
                .update_account(address, update_info);
        }

        revert_updates
    }

    #[cfg(test)]
    pub fn get_account_storage(&self) -> AccountStorage {
        self.inner
            .read()
            .unwrap()
            .accounts
            .clone()
    }

    /// If block is set, returns the number. Otherwise returns None.
    pub fn block_number(&self) -> Option<u64> {
        self.inner
            .read()
            .unwrap()
            .block
            .as_ref()
            .map(|header| header.number)
    }
}

impl EngineDatabaseInterface for PreCachedDB {
    type Error = String;

    /// Sets up a single account
    ///
    /// Full control over setting up an accounts. Allows to set up EOAs as well as smart contracts.
    ///
    /// # Arguments
    ///
    /// * `address` - Address of the account
    /// * `account` - The account information
    /// * `permanent_storage` - Storage to init the account with, this storage can only be updated
    ///   manually
    fn init_account(
        &self,
        address: Address,
        account: AccountInfo,
        permanent_storage: Option<HashMap<U256, U256>>,
        _mocked: bool,
    ) {
        self.inner
            .write()
            .unwrap()
            .accounts
            .init_account(address, to_analysed(account), permanent_storage, true)
    }

    /// Deprecated in TychoDB
    fn clear_temp_storage(&mut self) {
        debug!("Temp storage in TychoDB is never set, nothing to clear");
    }
}

impl DatabaseRef for PreCachedDB {
    type Error = PreCachedDBError;
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
    fn basic_ref(&self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        self.inner
            .read()
            .unwrap()
            .accounts
            .get_account_info(&address)
            .map(|acc| Some(acc.clone()))
            .ok_or(PreCachedDBError::MissingAccount(address))
    }

    fn code_by_hash_ref(&self, _code_hash: B256) -> Result<Bytecode, Self::Error> {
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
    fn storage_ref(&self, address: Address, index: U256) -> Result<U256, Self::Error> {
        debug!(%address, %index, "Requested storage of account");
        let read_guard = self.inner.read().unwrap();
        if let Some(storage_value) = read_guard
            .accounts
            .get_storage(&address, &index)
        {
            debug!(%address, %index, %storage_value, "Got value locally");
            Ok(storage_value)
        } else {
            // At this point we either don't know this address or we don't have anything at this
            if read_guard
                .accounts
                .account_present(&address)
            {
                // As we only store non-zero values, if the account is present it means this
                // slot is zero.
                debug!(%address, %index, "Account found, but slot is zero");
                Ok(U256::ZERO)
            } else {
                // At this point we know we don't have data for this address.
                debug!(%address, %index, "Account not found");
                Err(PreCachedDBError::MissingAccount(address))
            }
        }
    }

    /// If block header is set, returns the hash. Otherwise returns a zero hash.
    fn block_hash_ref(&self, _number: u64) -> Result<B256, Self::Error> {
        match self.inner.read().unwrap().block {
            Some(header) => Ok(header.hash),
            None => Ok(B256::default()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use chrono::DateTime;
    use revm::primitives::U256;
    use rstest::{fixture, rstest};
    use std::{error::Error, str::FromStr};

    use crate::evm::tycho_models::{AccountUpdate, Block, Chain, ChangeType};

    #[fixture]
    pub fn mock_db() -> PreCachedDB {
        PreCachedDB {
            inner: Arc::new(RwLock::new(PreCachedDBInner {
                accounts: AccountStorage::new(),
                block: None,
            })),
        }
    }

    #[rstest]
    #[tokio::test]
    async fn test_account_get_acc_info(mock_db: PreCachedDB) -> Result<(), Box<dyn Error>> {
        // Tests if the provider has not been queried.
        // Querying the mocked provider would cause a panic, therefore no assert is needed.
        let mock_acc_address = Address::from_str("0xb4e16d0168e52d35cacd2c6185b44281ec28c9dc")?;
        mock_db.init_account(mock_acc_address, AccountInfo::default(), None, false);

        let acc_info = mock_db
            .basic_ref(mock_acc_address)
            .unwrap()
            .unwrap();

        assert_eq!(
            mock_db
                .basic_ref(mock_acc_address)
                .unwrap()
                .unwrap(),
            acc_info
        );
        Ok(())
    }

    #[rstest]
    fn test_account_storage(mock_db: PreCachedDB) -> Result<(), Box<dyn Error>> {
        let mock_acc_address = Address::from_str("0xb4e16d0168e52d35cacd2c6185b44281ec28c9dc")?;
        let storage_address = U256::from(1);
        let mut permanent_storage: HashMap<U256, U256> = HashMap::new();
        permanent_storage.insert(storage_address, U256::from(10));
        mock_db.init_account(
            mock_acc_address,
            AccountInfo::default(),
            Some(permanent_storage),
            false,
        );

        let storage = mock_db
            .storage_ref(mock_acc_address, storage_address)
            .unwrap();

        assert_eq!(storage, U256::from(10));
        Ok(())
    }

    #[rstest]
    fn test_account_storage_zero(mock_db: PreCachedDB) -> Result<(), Box<dyn Error>> {
        let mock_acc_address = Address::from_str("0xb4e16d0168e52d35cacd2c6185b44281ec28c9dc")?;
        let storage_address = U256::from(1);
        mock_db.init_account(mock_acc_address, AccountInfo::default(), None, false);

        let storage = mock_db
            .storage_ref(mock_acc_address, storage_address)
            .unwrap();

        assert_eq!(storage, U256::ZERO);
        Ok(())
    }

    #[rstest]
    #[should_panic(
        expected = "called `Result::unwrap()` on an `Err` value: MissingAccount(0xb4e16d0168e52d35cacd2c6185b44281ec28c9dc)"
    )]
    fn test_account_storage_missing(mock_db: PreCachedDB) {
        let mock_acc_address =
            Address::from_str("0xb4e16d0168e52d35cacd2c6185b44281ec28c9dc").unwrap();
        let storage_address = U256::from(1);

        // This will panic because this account isn't initialized
        mock_db
            .storage_ref(mock_acc_address, storage_address)
            .unwrap();
    }

    #[rstest]
    #[tokio::test]
    async fn test_update_state(mut mock_db: PreCachedDB) -> Result<(), Box<dyn Error>> {
        let address = Address::from_str("0xb4e16d0168e52d35cacd2c6185b44281ec28c9dc")?;
        mock_db.init_account(address, AccountInfo::default(), None, false);

        let mut new_storage = HashMap::default();
        let new_storage_value_index = U256::from_limbs_slice(&[123]);
        new_storage.insert(new_storage_value_index, new_storage_value_index);
        let new_balance = U256::from_limbs_slice(&[500]);
        let update = StateUpdate { storage: Some(new_storage), balance: Some(new_balance) };
        let new_block = Block {
            number: 1,
            hash: B256::default(),
            parent_hash: B256::default(),
            chain: Chain::Ethereum,
            ts: DateTime::from_timestamp_millis(123)
                .unwrap()
                .naive_utc(),
        };
        let mut updates = HashMap::default();
        updates.insert(address, update);

        mock_db.update_state(&updates, new_block.into());

        assert_eq!(
            mock_db
                .get_storage(&address, &new_storage_value_index)
                .unwrap(),
            new_storage_value_index
        );
        let account_info = mock_db
            .basic_ref(address)
            .unwrap()
            .unwrap();
        assert_eq!(account_info.balance, new_balance);
        let block = mock_db
            .inner
            .read()
            .unwrap()
            .block
            .expect("block is Some");
        assert_eq!(block.number, 1);

        Ok(())
    }

    #[rstest]
    #[tokio::test]
    async fn test_block_number_getter(mut mock_db: PreCachedDB) -> Result<(), Box<dyn Error>> {
        let address = Address::from_str("0xb4e16d0168e52d35cacd2c6185b44281ec28c9dc")?;
        mock_db.init_account(address, AccountInfo::default(), None, false);

        let new_block = Block {
            number: 1,
            hash: B256::default(),
            parent_hash: B256::default(),
            chain: Chain::Ethereum,
            ts: DateTime::from_timestamp_millis(123)
                .unwrap()
                .naive_utc(),
        };
        let updates = HashMap::default();

        mock_db.update_state(&updates, new_block.into());

        let block_number = mock_db.block_number();
        assert_eq!(block_number.unwrap(), 1);

        Ok(())
    }

    #[rstest]
    #[tokio::test]
    async fn test_update() {
        let mock_db = PreCachedDB {
            inner: Arc::new(RwLock::new(PreCachedDBInner {
                accounts: AccountStorage::new(),
                block: None,
            })),
        };

        let account_update = AccountUpdate::new(
            Address::from_str("0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D").unwrap(),
            Chain::Ethereum,
            HashMap::new(),
            Some(U256::from(500)),
            Some(Vec::<u8>::new()),
            ChangeType::Creation,
        );

        let new_block = Block {
            number: 1,
            hash: B256::default(),
            parent_hash: B256::default(),
            chain: Chain::Ethereum,
            ts: DateTime::from_timestamp_millis(123)
                .unwrap()
                .naive_utc(),
        };

        mock_db.update(vec![account_update], Some(new_block.into()));

        let account_info = mock_db
            .basic_ref(Address::from_str("0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D").unwrap())
            .unwrap()
            .unwrap();

        assert_eq!(
            account_info,
            AccountInfo {
                nonce: 0,
                balance: U256::from(500),
                code_hash: B256::from_str(
                    "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
                )
                .unwrap(),
                code: Some(Bytecode::default()),
            }
        );

        assert_eq!(
            mock_db
                .inner
                .read()
                .unwrap()
                .block
                .expect("block is Some")
                .number,
            1
        );
    }

    /// This test requires a running TychoDB instance.
    ///
    /// To run this test, start TychoDB with the following command:
    /// ```bash
    /// cargo run --release -- \
    //     --endpoint https://mainnet.eth.streamingfast.io:443 \
    //     --module map_changes \
    //     --spkg substreams/ethereum-ambient/substreams-ethereum-ambient-v0.3.0.spkg
    /// ```
    /// 
    /// Then run the test with:
    /// ```bash
    /// cargo test --package src --lib -- --ignored --exact --nocapture
    /// evm::engine_db::tycho_db::tests::test_tycho_db_connection
    /// ```
    #[ignore]
    #[rstest]
    fn test_tycho_db_connection() {
        tracing_subscriber::fmt()
            .with_env_filter("debug")
            .init();

        let ambient_contract =
            Address::from_str("0xaaaaaaaaa24eeeb8d57d431224f73832bc34f688").unwrap();

        let tycho_http_url = "http://127.0.0.1:4242";
        info!(tycho_http_url, "Creating PreCachedDB");
        let db = PreCachedDB::new().expect("db should initialize");

        info!("Fetching account info");

        let acc_info = db
            .basic_ref(ambient_contract)
            .unwrap()
            .unwrap();

        debug!(?acc_info, "Account info");
    }
}
