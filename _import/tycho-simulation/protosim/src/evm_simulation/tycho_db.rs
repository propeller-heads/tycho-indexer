use ethers::types::Bytes;
use std::{collections::HashMap, sync::Arc};
use thiserror::Error;
use tokio::sync::{
    mpsc::{self, Receiver},
    RwLock,
};
use tracing::debug;

use revm::{
    db::DatabaseRef,
    interpreter::analysis::to_analysed,
    primitives::{AccountInfo, Bytecode, B160, B256, U256 as rU256},
};

use super::{
    account_storage::{AccountStorage, StateUpdate},
    tycho_client::{StateRequestBody, StateRequestParameters, TychoClient, TychoVMStateClient},
    tycho_models::{AccountUpdate, Block},
};

#[derive(Error, Debug)]
pub enum PreCachedDBError {
    #[error("Account {0} not found")]
    MissingAccount(B160),
    #[error("Block needs to be set")]
    BlockNotSet(),
}

#[derive(Debug)]
pub struct PreCachedDB {
    /// Cached data
    accounts: AccountStorage,
    /// Current block
    block: Option<Block>,
}

impl PreCachedDB {
    pub fn new(start_block: Option<Block>) -> Self {
        Self { accounts: AccountStorage::new(), block: start_block }
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

        self.accounts
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
        self.block = Some(block);
        new_state
            .iter()
            .for_each(|(address, state_update)| {
                self.accounts
                    .update_account(address, state_update);
            });
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
        if let Some(account) = self.accounts.get_account_info(&address) {
            return Ok(Some(account.clone()))
        };
        Err(PreCachedDBError::MissingAccount(address))
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
            .accounts
            .get_storage(&address, &index)
        {
            debug!("Got value locally. Value: {}", storage_value);
            Ok(storage_value)
        } else {
            // At this point we either don't know this address or we don't have anything at this
            // index (memory slot)
            if self.accounts.account_present(&address) {
                // As we only store non-zero values, if the account is present it means this slot is
                // zero.
                Ok(rU256::ZERO)
            } else {
                // At this point we know we don't have data for this address.
                debug!("We don't have data for {}. Returning error.", address);
                Err(PreCachedDBError::MissingAccount(address))
            }
        }
    }

    /// If block header is set, returns the hash. Otherwise returns a zero hash.
    fn block_hash(&self, _number: rU256) -> Result<B256, Self::Error> {
        match &self.block {
            Some(header) => Ok(header.hash),
            None => Err(PreCachedDBError::BlockNotSet()),
        }
    }
}

// we might consider wrapping this type for a nicer API
pub type TychoDB = Arc<RwLock<PreCachedDB>>;

// main data update loop, runs in a separate tokio runtime
pub async fn update_loop(
    db: TychoDB,
    client: impl TychoVMStateClient,
    mut stop_signal: Receiver<()>,
) {
    // Start buffering messages
    let mut messages = client.realtime_messages().await;

    // Initialize state with the first message's block.
    let first_msg = messages
        .recv()
        .await
        .expect("stream ok");

    let state = client
        .get_state(
            &StateRequestParameters::default(),
            &StateRequestBody::from_block(first_msg.block),
        )
        .await
        .unwrap();

    // This scope ensures the lock is dropped after processing the message.
    {
        let mut db_guard = db.write().await;
        for account in state.into_iter() {
            db_guard.init_account(
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
                let mut db_guard = db.write().await;

                // Update block.
                db_guard.block = Some(msg.block);

                // Update existing accounts.
                for (
                    _address,
                    AccountUpdate { address, chain: _, slots, balance, code, change: _ },
                ) in msg.account_updates.into_iter()
                {
                    if db_guard
                        .accounts
                        .account_present(&address)
                    {
                        db_guard.accounts.update_account(
                            &address,
                            &StateUpdate { storage: Some(slots), balance },
                        );
                    } else {
                        db_guard.init_account(
                            address,
                            AccountInfo::new(
                                balance.unwrap_or_default(),
                                0,
                                B256::default(),
                                Bytecode::new_raw(Bytes::from(code.unwrap_or_default()).0),
                            ),
                            Some(slots),
                        );
                    }
                }
            }
        }
    }
}

// Create a new TychoDB
pub fn create_tycho_db(url: String) -> TychoDB {
    let inner = PreCachedDB { accounts: AccountStorage::new(), block: None };

    let db = Arc::new(RwLock::new(inner));
    let cloned_db = db.clone();
    let client = TychoClient::new(&url).unwrap();
    let (_tx, rx) = mpsc::channel::<()>(1);

    tokio::spawn(async move {
        update_loop(cloned_db, client, rx).await;
    });

    db
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
        tycho_client::{ResponseAccount, StateRequestParameters, TychoClientError},
        tycho_models::{AccountUpdate, BlockAccountChanges, Chain, ChangeType},
    };

    use super::*;

    #[fixture]
    pub fn mock_db() -> PreCachedDB {
        PreCachedDB::new(None)
    }

    #[rstest]
    fn test_account_get_acc_info(mut mock_db: PreCachedDB) -> Result<(), Box<dyn Error>> {
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
                .accounts
                .get_account_info(&mock_acc_address)
                .unwrap(),
            &acc_info
        );
        Ok(())
    }

    #[rstest]
    fn test_account_storage(mut mock_db: PreCachedDB) -> Result<(), Box<dyn Error>> {
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
    fn test_account_storage_zero(mut mock_db: PreCachedDB) -> Result<(), Box<dyn Error>> {
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
    fn test_update_state(mut mock_db: PreCachedDB) -> Result<(), Box<dyn Error>> {
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
                .accounts
                .get_storage(&address, &new_storage_value_index)
                .unwrap(),
            new_storage_value_index
        );
        assert_eq!(
            mock_db
                .accounts
                .get_account_info(&address)
                .unwrap()
                .balance,
            new_balance
        );
        assert_eq!(mock_db.block.unwrap().number, 1);

        Ok(())
    }

    pub struct MockTychoVMStateClient {
        mock_state: Vec<ResponseAccount>,
    }

    impl MockTychoVMStateClient {
        pub fn new(mock_state: Vec<ResponseAccount>) -> Self {
            MockTychoVMStateClient { mock_state }
        }
    }

    #[fixture]
    pub fn mock_client() -> MockTychoVMStateClient {
        let mut contract_slots = HashMap::<rU256, rU256>::new();
        contract_slots.insert(rU256::from(1), rU256::from(987));

        let account = ResponseAccount {
            address: B160::from_str("0xb4e16d0168e52d35cacd2c6185b44281ec28c9dc").unwrap(),
            slots: contract_slots,
            balance: rU256::from(123),
            code: Vec::<u8>::new(),
            code_hash: B256::from_str(
                "0x0000000000000000000000000000000000000000000000000000000000000000",
            )
            .unwrap(),
        };

        let mock_state = vec![account];
        MockTychoVMStateClient::new(mock_state)
    }

    #[async_trait]
    impl TychoVMStateClient for MockTychoVMStateClient {
        async fn get_state(
            &self,
            _filters: &StateRequestParameters,
            _request: &StateRequestBody,
        ) -> Result<Vec<ResponseAccount>, TychoClientError> {
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
        let db = Arc::new(RwLock::new(mock_db));
        let (_tx, rx) = mpsc::channel::<()>(1);

        update_loop(db.clone(), mock_client, rx).await;

        let read_guard = db.read().await;
        dbg!(read_guard.accounts.get_account_info(
            &B160::from_str("0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D").unwrap()
        ));

        assert_eq!(
            read_guard
                .block
                .expect("Block should be Some"),
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
        );
    }
}
