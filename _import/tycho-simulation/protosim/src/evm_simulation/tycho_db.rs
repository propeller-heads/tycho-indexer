use ethers::types::Bytes;
use std::{collections::HashMap, str::FromStr, sync::Arc};
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{debug, error, info, info_span, instrument, warn};

use revm::{
    db::DatabaseRef,
    primitives::{AccountInfo, Bytecode, B160, B256, U256 as rU256},
};

use crate::evm_simulation::{
    account_storage::{AccountStorage, StateUpdate},
    database::BlockHeader,
    tycho_client::{TychoVMStateClient, AMBIENT_ACCOUNT_ADDRESS},
    tycho_models::{AccountUpdate, ChangeType, StateRequestBody, StateRequestParameters, Version},
};

use super::tycho_client::TychoClient;

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
pub enum PreCachedDBError {
    #[error("Account {0} not found")]
    MissingAccount(B160),
    #[error("Block needs to be set")]
    BlockNotSet(),
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
    /// Create a new PreCachedDB instance and run the update loop in a separate thread.
    pub fn new(tycho_url: &str) -> Self {
        info!(?tycho_url, "Creating new PreCachedDB instance");

        let tycho_db = PreCachedDB {
            inner: Arc::new(RwLock::new(PreCachedDBInner {
                accounts: AccountStorage::new(),
                block: None,
            })),
        };

        let client = TychoClient::new(tycho_url).unwrap();
        // Run the async get state initialization
        // Create a channel to send the result of the async block.
        let (tx, rx) = std::sync::mpsc::channel();
        let tycho_db_clone = tycho_db.clone();
        let client_clone = client.clone();

        info!("Spawning initialization thread");
        // We need to spawn a new thread to run the async block in a sync context.
        std::thread::spawn(move || {
            tokio::runtime::Runtime::new()
                .unwrap()
                .block_on(async move {
                    tycho_db_clone
                        .initialize_state(&client_clone)
                        .await
                });
            tx.send(()).unwrap();
        });

        // Block and wait for the result.
        rx.recv().unwrap();
        info!("Initialization thread finished");

        let tycho_db_clone = tycho_db.clone();
        let (_tx, rx) = tokio::sync::mpsc::channel::<()>(5); // TODO: Make this configurable

        let tycho_url_clone = tycho_url.to_owned();

        info!("Spawning update loop");
        std::thread::spawn(move || {
            tokio::runtime::Runtime::new()
                .unwrap()
                .block_on(async move {
                    info_span!("update_loop", tycho_url = tycho_url_clone);
                    tycho_db_clone
                        .update_loop(client, rx)
                        .await
                });
        });

        tycho_db
    }

    /// Initialize the state of the database.
    #[instrument(skip_all)]
    async fn initialize_state(&self, client: &impl TychoVMStateClient) {
        info!("Getting current state");
        let state = client
            .get_state(
                &StateRequestParameters::default(),
                &StateRequestBody::new(
                    Some(vec![B160::from_str(AMBIENT_ACCOUNT_ADDRESS).unwrap()]),
                    Version::default(),
                ),
            )
            .await
            .expect("current state");

        for account in state.accounts.into_iter() {
            info!(%account.address, "Initializing account");
            self.init_account(
                account.address,
                AccountInfo::new(
                    account.balance,
                    0,
                    account.code_hash,
                    Bytecode::new_raw(Bytes::from(account.code).0),
                ),
                Some(account.slots),
            );
        }
    }

    /// Start the update loop.
    #[instrument(skip_all)]
    async fn update_loop(
        &self,
        client: impl TychoVMStateClient,
        mut stop_signal: tokio::sync::mpsc::Receiver<()>,
    ) {
        // Start buffering messages
        info!("Starting message stream");
        let mut messages = client.realtime_messages().await;

        info!("Starting state update loop");
        // Continuous loop to handle incoming messages.
        loop {
            // Check for the stop signal.
            if stop_signal.try_recv().is_ok() {
                break
            }

            match messages.recv().await {
                // None means the channel is closed.
                None => break,
                Some(msg) => {
                    info!(%msg.block.number, "Received new block");

                    // Block the current thread until the future completes.
                    self.block_on(async {
                        // Hold the write lock for the duration of the function so that no other
                        // thread can write to the storage.
                        let mut write_guard = self.inner.write().await;

                        // Update the block header.
                        write_guard.block = Some(msg.block.into());

                        // Update existing accounts.
                        for (
                            _address,
                            AccountUpdate { address, chain: _, slots, balance, code, change },
                        ) in msg.account_updates.into_iter()
                        {
                            match change {
                                ChangeType::Update => {
                                    info!(%address, "Updating account");

                                    // If the account is not present, the internal storage will
                                    // handle throwing an
                                    // exception.
                                    write_guard.accounts.update_account(
                                        &address,
                                        &StateUpdate { storage: Some(slots), balance },
                                    );
                                }
                                ChangeType::Deletion => {
                                    info!(%address, "Deleting account");

                                    // TODO: Implement deletion.
                                    warn!(%address, "Deletion not implemented");
                                }
                                ChangeType::Creation => {
                                    info!(%address, "Creating account");

                                    // We expect the code and balance to be present.
                                    let code = Bytecode::new_raw(
                                        Bytes::from(code.expect("account code")).0,
                                    );
                                    let balance = balance.expect("account balance");

                                    // Initialize the account.
                                    write_guard.accounts.init_account(
                                        address,
                                        AccountInfo::new(balance, 0, code.hash_slow(), code),
                                        Some(slots),
                                        true, // Flag all accounts in TychoDB mocked to sign that we cannot call and RPC provider for update
                                    );
                                }
                            }
                        }
                    })
                }
            }
        }
    }

    /// Executes a future, blocking the current thread until the future completes.
    fn block_on<F: core::future::Future>(&self, f: F) -> F::Output {
        // If we get here and have to block the current thread, we really
        // messed up indexing / filling the storage. In that case this will save us
        // at the price of a very high time penalty.
        futures::executor::block_on(f)
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
    async fn get_storage_async(&self, address: &B160, index: &rU256) -> Option<rU256> {
        self.inner
            .read()
            .await
            .accounts
            .get_storage(address, index)
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
        &self,
        address: B160,
        account: AccountInfo,
        permanent_storage: Option<HashMap<rU256, rU256>>,
    ) {
        self.block_on(async {
            self.inner
                .write()
                .await
                .accounts
                .init_account(address, to_analysed(account), permanent_storage, true)
        });
    }

    /// Blocking version of [get_storage_async]
    pub fn get_storage(&self, address: &B160, index: &rU256) -> Option<rU256> {
        self.block_on(self.get_storage_async(address, index))
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
        updates: &HashMap<B160, StateUpdate>,
        block: BlockHeader,
    ) -> HashMap<B160, StateUpdate> {
        // Block the current thread until the future completes.
        self.block_on(async {
            // Hold the write lock for the duration of the function so that no other thread can
            // write to the storage.
            let mut write_guard = self.inner.write().await;

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
        })
    }

    /// Deprecated in TychoDB
    pub fn clear_temp_storage(&mut self) {
        info!("Temp storage in TychoDB is never set, nothing to clear");
    }

    /// If block is set, returns the number. Otherwise returns None.
    pub fn block_number(&self) -> Option<u64> {
        self.block_on(async { self.inner.read().await.block })
            .as_ref()
            .map(|header| header.number)
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
    fn basic(&self, address: B160) -> Result<Option<AccountInfo>, Self::Error> {
        self.block_on(async {
            self.inner
                .read()
                .await
                .accounts
                .get_account_info(&address)
                .map(|acc| Some(acc.clone()))
                .ok_or(PreCachedDBError::MissingAccount(address))
        })
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
        debug!(%address, %index, "Requested storage of account");
        self.block_on(async {
            let read_guard = self.inner.read().await;
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
                    Ok(rU256::ZERO)
                } else {
                    // At this point we know we don't have data for this address.
                    debug!(%address, %index, "Account not found");
                    Err(PreCachedDBError::MissingAccount(address))
                }
            }
        })
    }

    /// If block header is set, returns the hash. Otherwise returns a zero hash.
    fn block_hash(&self, _number: rU256) -> Result<B256, Self::Error> {
        match &self.block_on(async { self.inner.read().await.block }) {
            Some(header) => Ok(header.hash.into()),
            None => Ok(B256::default()),
        }
    }
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use chrono::NaiveDateTime;

    use revm::primitives::U256 as rU256;
    use rstest::{fixture, rstest};
    use std::{error::Error, str::FromStr};
    use tokio::sync::mpsc::{self, Receiver};

    use crate::evm_simulation::{
        tycho_client::TychoClientError,
        tycho_models::{
            AccountUpdate, Block, BlockAccountChanges, Chain, ChangeType, ResponseAccount,
            StateRequestParameters, StateRequestResponse,
        },
    };

    use super::*;

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
        let mock_acc_address = B160::from_str("0xb4e16d0168e52d35cacd2c6185b44281ec28c9dc")?;
        mock_db.init_account(mock_acc_address, AccountInfo::default(), None);

        let acc_info = mock_db
            .basic(mock_acc_address)
            .unwrap()
            .unwrap();

        assert_eq!(
            mock_db
                .basic(mock_acc_address)
                .unwrap()
                .unwrap(),
            acc_info
        );
        Ok(())
    }

    #[rstest]
    fn test_account_storage(mock_db: PreCachedDB) -> Result<(), Box<dyn Error>> {
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
    fn test_account_storage_zero(mock_db: PreCachedDB) -> Result<(), Box<dyn Error>> {
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
    fn test_account_storage_missing(mock_db: PreCachedDB) {
        let mock_acc_address =
            B160::from_str("0xb4e16d0168e52d35cacd2c6185b44281ec28c9dc").unwrap();
        let storage_address = rU256::from(1);

        // This will panic because this account isn't initialized
        mock_db
            .storage(mock_acc_address, storage_address)
            .unwrap();
    }

    #[rstest]
    #[tokio::test]
    async fn test_update_state(mut mock_db: PreCachedDB) -> Result<(), Box<dyn Error>> {
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

        mock_db.update_state(&updates, new_block.into());

        assert_eq!(
            mock_db
                .get_storage(&address, &new_storage_value_index)
                .unwrap(),
            new_storage_value_index
        );
        let account_info = mock_db.basic(address).unwrap().unwrap();
        assert_eq!(account_info.balance, new_balance);
        let block = mock_db
            .block_on(async { mock_db.inner.read().await.block })
            .expect("block is Some");
        assert_eq!(block.number, 1);

        Ok(())
    }

    #[rstest]
    #[tokio::test]
    async fn test_block_number_getter(mut mock_db: PreCachedDB) -> Result<(), Box<dyn Error>> {
        let address = B160::from_str("0xb4e16d0168e52d35cacd2c6185b44281ec28c9dc")?;
        mock_db.init_account(address, AccountInfo::default(), None);

        let new_block = Block {
            number: 1,
            hash: B256::default(),
            parent_hash: B256::default(),
            chain: Chain::Ethereum,
            ts: NaiveDateTime::from_timestamp_millis(123).unwrap(),
        };
        let updates = HashMap::default();

        mock_db.update_state(&updates, new_block.into());

        let block_number = mock_db.block_number();
        assert_eq!(block_number.unwrap(), 1);

        Ok(())
    }

    pub struct MockTychoVMStateClient {
        mock_state: StateRequestResponse,
    }

    impl MockTychoVMStateClient {
        pub fn new(mock_state: StateRequestResponse) -> Self {
            MockTychoVMStateClient { mock_state }
        }
    }

    #[fixture]
    pub fn mock_client() -> MockTychoVMStateClient {
        let mut contract_slots = HashMap::<rU256, rU256>::new();
        contract_slots.insert(rU256::from(1), rU256::from(987));

        let creation_tx =
            B256::from_str("0x1234000000000000000000000000000000000000000000000000000000000000")
                .unwrap();

        let account: ResponseAccount = ResponseAccount {
            chain: Chain::Ethereum,
            address: B160::from_str("0xb4e16d0168e52d35cacd2c6185b44281ec28c9dc").unwrap(),
            title: "mock".to_owned(),
            slots: contract_slots,
            balance: rU256::from(123),
            code: Vec::<u8>::new(),
            code_hash: B256::from_str(
                "0x0000000000000000000000000000000000000000000000000000000000000000",
            )
            .unwrap(),
            balance_modify_tx: creation_tx,
            code_modify_tx: creation_tx,
            creation_tx: Some(creation_tx),
        };

        let mock_state = StateRequestResponse::new(vec![account]);
        MockTychoVMStateClient::new(mock_state)
    }

    #[async_trait]
    impl TychoVMStateClient for MockTychoVMStateClient {
        async fn get_state(
            &self,
            _filters: &StateRequestParameters,
            _request: &StateRequestBody,
        ) -> Result<StateRequestResponse, TychoClientError> {
            Ok(self.mock_state.clone())
        }

        async fn realtime_messages(&self) -> Receiver<BlockAccountChanges> {
            let (tx, rx) = mpsc::channel::<BlockAccountChanges>(30);
            let blk = Block {
                number: 123,
                hash: B256::from_str(
                    "0x0000000000000000000000000000000000000000000000000000000000000000",
                )
                .unwrap(),
                parent_hash: B256::from_str(
                    "0x0000000000000000000000000000000000000000000000000000000000000000",
                )
                .unwrap(),
                chain: Chain::Ethereum,
                ts: NaiveDateTime::from_str("2023-09-14T00:00:00").unwrap(),
            };

            let account_update = AccountUpdate::new(
                B160::from_str("0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D").unwrap(),
                Chain::Ethereum,
                HashMap::new(),
                Some(rU256::from(500)),
                Some(Vec::<u8>::new()),
                ChangeType::Update,
            );
            let account_updates: HashMap<B160, AccountUpdate> = vec![(
                B160::from_str("0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D").unwrap(),
                account_update,
            )]
            .into_iter()
            .collect();
            let message = BlockAccountChanges::new(
                "vm:ambient".to_owned(),
                Chain::Ethereum,
                blk,
                account_updates,
                HashMap::new(),
            );
            tx.send(message.clone()).await.unwrap();
            tx.send(message).await.unwrap();
            rx
        }
    }

    #[rstest]
    #[tokio::test]
    async fn test_update_loop(mock_db: PreCachedDB, mock_client: MockTychoVMStateClient) {
        let (_tx, rx) = mpsc::channel::<()>(1);

        mock_db
            .initialize_state(&mock_client)
            .await;

        mock_db
            .clone()
            .update_loop(mock_client, rx)
            .await;

        let account_info = mock_db
            .basic(B160::from_str("0xb4e16d0168e52d35cacd2c6185b44281ec28c9dc").unwrap())
            .unwrap()
            .unwrap();
        dbg!(account_info);

        let block = mock_db
            .block_on(async { mock_db.inner.read().await.block })
            .expect("block is Some");
        assert_eq!(
            block,
            Block {
                number: 123,
                hash: B256::from_str(
                    "0x0000000000000000000000000000000000000000000000000000000000000000",
                )
                .unwrap(),
                parent_hash: B256::from_str(
                    "0x0000000000000000000000000000000000000000000000000000000000000000",
                )
                .unwrap(),
                chain: Chain::Ethereum,
                ts: NaiveDateTime::from_str("2023-09-14T00:00:00").unwrap(),
            }
            .into()
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
    /// cargo test --package protosim --lib -- --ignored --exact --nocapture
    /// evm_simulation::tycho_db::tests::test_tycho_db_connection
    /// ```
    #[ignore]
    #[rstest]
    fn test_tycho_db_connection() {
        tracing_subscriber::fmt()
            .with_env_filter("debug")
            .init();

        let ambient_contract =
            B160::from_str("0xaaaaaaaaa24eeeb8d57d431224f73832bc34f688").unwrap();

        let tycho_url = "127.0.0.1:4242";
        info!(tycho_url, "Creating PreCachedDB");
        let db = PreCachedDB::new(tycho_url);

        info!("Fetching account info");

        let acc_info = db
            .basic(ambient_contract)
            .unwrap()
            .unwrap();

        debug!(?acc_info, "Account info");
    }
}
