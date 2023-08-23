use ethers::{
    providers::Middleware,
    types::{BlockId, H160, H256},
};
use log::{debug, info};
use std::cell::RefCell;
use std::collections::HashMap;

use std::sync::Arc;

use revm::{
    db::DatabaseRef,
    interpreter::analysis::to_analysed,
    primitives::{AccountInfo, Bytecode, B160, B256, U256 as rU256},
};

use super::account_storage::{AccountStorage, StateUpdate};

/// A wrapper over an actual SimulationDB that allows overriding specific storage slots
pub struct OverriddenSimulationDB<'a, DB: DatabaseRef> {
    /// Wrapped database. Will be queried if a requested item is not found in the overrides.
    pub inner_db: &'a DB,
    /// A mapping from account address to storage.
    /// Storage is a mapping from slot index to slot value.
    pub overrides: &'a HashMap<B160, HashMap<rU256, rU256>>,
}

impl<'a, DB: DatabaseRef> DatabaseRef for OverriddenSimulationDB<'a, DB> {
    type Error = DB::Error;

    fn basic(&self, address: B160) -> Result<Option<AccountInfo>, Self::Error> {
        self.inner_db.basic(address)
    }

    fn code_by_hash(&self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        self.inner_db.code_by_hash(code_hash)
    }

    fn storage(&self, address: B160, index: rU256) -> Result<rU256, Self::Error> {
        match self.overrides.get(&address) {
            None => self.inner_db.storage(address, index),
            Some(overrides) => match overrides.get(&index) {
                Some(value) => {
                    debug!("Requested storage of account {:x?} slot {}", address, index);
                    debug!("Overridden slot. Value: {}", value);
                    Ok(*value)
                }
                None => self.inner_db.storage(address, index),
            },
        }
    }

    fn block_hash(&self, number: rU256) -> Result<B256, Self::Error> {
        self.inner_db.block_hash(number)
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct BlockHeader {
    pub number: u64,
    pub hash: H256,
    pub timestamp: u64,
}

impl From<BlockHeader> for BlockId {
    fn from(value: BlockHeader) -> Self {
        Self::from(value.hash)
    }
}

#[derive(Debug)]
pub struct SimulationDB<M: Middleware> {
    /// Client to connect to the RPC
    client: Arc<M>,
    /// Cached data
    account_storage: RefCell<AccountStorage>,
    /// Current block
    block: Option<BlockHeader>,
    /// Tokio runtime to execute async code
    pub runtime: Option<Arc<tokio::runtime::Runtime>>,
}

impl<M: Middleware> SimulationDB<M> {
    pub fn new(
        client: Arc<M>,
        runtime: Option<Arc<tokio::runtime::Runtime>>,
        block: Option<BlockHeader>,
    ) -> Self {
        Self {
            client,
            account_storage: RefCell::new(AccountStorage::new()),
            block: block.clone(),
            runtime,
        }
    }

    /// Set the block that will be used when querying a node
    pub fn set_block(&mut self, block: Option<BlockHeader>) {
        self.block = block;
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
    /// * `permanent_storage` - Storage to init the account with this storage can only be updated manually.
    /// * `mocked` - Whether this account should be considered mocked. For mocked accounts, nothing
    ///   is downloaded from a node; all data must be inserted manually.
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
    /// Updates the underlying smart contract storage. Any previously missed account,
    /// which was queried and whose state now is in the account_storage will be cleared.
    ///
    /// # Arguments
    ///
    /// * `updates` - Values for the updates that should be applied to the accounts
    /// * `block` - The newest block
    ///
    /// Returns a state update struct to revert this update.
    pub fn update_state(
        &mut self,
        updates: &HashMap<B160, StateUpdate>,
        block: BlockHeader,
    ) -> HashMap<B160, StateUpdate> {
        info!("Received account state update.");
        let mut revert_updates = HashMap::new();
        self.block = Some(block);
        for (address, update_info) in updates.iter() {
            let mut revert_entry = StateUpdate::default();
            if let Some(current_account) = self.account_storage.borrow().get_account_info(address) {
                revert_entry.balance = Some(current_account.balance);
            }
            if update_info.storage.is_some() {
                let mut revert_storage = HashMap::default();
                for index in update_info.storage.as_ref().unwrap().keys() {
                    if let Some(s) = self
                        .account_storage
                        .borrow()
                        .get_permanent_storage(address, index)
                    {
                        revert_storage.insert(*index, s);
                    }
                }
                revert_entry.storage = Some(revert_storage);
            }
            revert_updates.insert(*address, revert_entry);

            self.account_storage
                .borrow_mut()
                .update_account(address, update_info);
        }
        revert_updates
    }

    /// Clears temp storage
    ///
    /// It is recommended to call this after a new block is received,
    /// to avoid stored state leading to wrong results.
    pub fn clear_temp_storage(&mut self) {
        self.account_storage.borrow_mut().clean_temp_storage();
    }

    /// Query information about an Ethereum account.
    /// Gets account information not including storage.
    ///
    /// # Arguments
    ///
    /// * `address` - The Ethereum address to query.
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing either an `AccountInfo` object with balance, nonce, and code information,
    /// or an error of type `SimulationDB<M>::Error` if the query fails.
    fn query_account_info(
        &self,
        address: B160,
    ) -> Result<AccountInfo, <SimulationDB<M> as DatabaseRef>::Error> {
        debug!(
            "Querying account info of {:x?} at block {:?}",
            address, self.block
        );
        let block_id: Option<BlockId> = self.block.map(|v| v.into());
        let fut = async {
            tokio::join!(
                self.client.get_balance(H160(address.0), block_id),
                self.client.get_transaction_count(H160(address.0), block_id),
                self.client.get_code(H160(address.0), block_id),
            )
        };

        let (balance, nonce, code) = self.block_on(fut);
        let code = to_analysed(Bytecode::new_raw(
            code.unwrap_or_else(|e| panic!("ethers get code error: {e:?}"))
                .0,
        ));
        Ok(AccountInfo::new(
            rU256::from_limbs(
                balance
                    .unwrap_or_else(|e| panic!("ethers get balance error: {e:?}"))
                    .0,
            ),
            nonce
                .unwrap_or_else(|e| panic!("ethers get nonce error: {e:?}"))
                .as_u64(),
            code.hash_slow(),
            code,
        ))
    }

    /// Queries a value from storage at the specified index for a given Ethereum account.
    ///
    /// # Arguments
    ///
    /// * `address` - The Ethereum address of the account.
    /// * `index` - The index of the storage value to query.
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing the value from storage at the specified index as an `rU256`,
    /// or an error of type `SimulationDB<M>::Error` if the query fails.
    fn query_storage(
        &self,
        address: B160,
        index: rU256,
    ) -> Result<rU256, <SimulationDB<M> as DatabaseRef>::Error> {
        let index_h256 = H256::from(index.to_be_bytes());
        let fut = async {
            let address = H160::from(address.0);
            let storage = self
                .client
                .get_storage_at(address, index_h256, self.block.map(|v| v.into()))
                .await
                .unwrap();
            rU256::from_be_bytes(storage.to_fixed_bytes())
        };
        let storage = self.block_on(fut);

        Ok(storage)
    }

    fn block_on<F: core::future::Future>(&self, f: F) -> F::Output {
        // If we get here and have to block the current thread, we really
        // messed up indexing / filling the storage. In that case this will save us
        // at the price of a very high time penalty.
        match &self.runtime {
            Some(runtime) => runtime.block_on(f),
            None => futures::executor::block_on(f),
        }
    }
}

impl<M: Middleware> DatabaseRef for SimulationDB<M> {
    type Error = M::Error;

    /// Retrieves basic information about an account.
    ///
    /// This function retrieves the basic account information for the specified address.
    /// If the account is present in the storage, the stored account information is returned.
    /// If the account is not present in the storage, the function queries the account information from the contract
    /// and initializes the account in the storage with the retrieved information.
    ///
    /// # Arguments
    ///
    /// * `address`: The address of the account to retrieve the information for.
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing an `Option` that holds the account information if it exists. If the account is not found,
    /// `None` is returned.
    ///
    /// # Errors
    ///
    /// Returns an error if there was an issue querying the account information from the contract or accessing the storage.
    ///
    /// # Notes
    ///
    /// * If the account is present in the storage, the function returns a clone of the stored account information.
    ///
    /// * If the account is not present in the storage, the function queries the account
    ///   information from the contract, initializes the account in the storage with the retrieved information, and returns a clone
    ///   of the account information.
    fn basic(&self, address: B160) -> Result<Option<AccountInfo>, Self::Error> {
        if let Some(account) = self.account_storage.borrow().get_account_info(&address) {
            return Ok(Some(account.clone()));
        }
        let account_info = self.query_account_info(address)?;
        self.init_account(address, account_info.clone(), None, false);
        Ok(Some(account_info))
    }

    fn code_by_hash(&self, _code_hash: B256) -> Result<Bytecode, Self::Error> {
        panic!("Code by hash is not implemented")
    }

    /// Retrieves the storage value at the specified address and index.
    ///
    /// If we don't know the value, and the accessed contract is mocked, the function returns
    /// an empty slot instead of querying a node, to avoid potentially returning garbage values.
    ///
    /// # Arguments
    ///
    /// * `address`: The address of the contract to retrieve the storage value from.
    /// * `index`: The index of the storage value to retrieve.
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing the storage value if it exists. If the contract is mocked
    /// and the storage value is not found locally, an empty slot is returned as `rU256::ZERO`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was an issue querying the storage value from the contract or accessing the storage.
    ///
    /// # Notes
    ///
    /// * If the contract is present locally and is mocked, the function first checks if
    ///   the storage value exists locally. If found, it returns the stored value. If not found, it returns an empty slot.
    ///   Mocked contracts are not expected to have valid storage values, so the function does not query a node in this case.
    ///
    /// * If the contract is present locally and is not mocked, the function checks if the storage value exists locally.
    ///   If found, it returns the stored value.
    ///   If not found, it queries the storage value from a node, stores it locally, and returns it.
    ///
    /// * If the contract is not present locally, the function queries the account info and storage value from
    ///   a node, initializes the account locally with the retrieved information, and returns the storage value.
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
                debug!("This is a mocked account for which we don't have data. Returning zero.");
                Ok(rU256::ZERO)
            }
            Some(false) => {
                let storage_value = self.query_storage(address, index)?;
                self.account_storage
                    .borrow_mut()
                    .set_temp_storage(address, index, storage_value);
                debug!(
                    "This is non-mocked account for which we didn't have data. Fetched value: {}",
                    storage_value
                );
                Ok(storage_value)
            }
            None => {
                let account_info = self.query_account_info(address)?;
                let storage_value = self.query_storage(address, index)?;
                self.init_account(address, account_info, None, false);
                self.account_storage
                    .borrow_mut()
                    .set_temp_storage(address, index, storage_value);
                debug!(
                    "This is non-initialised account. Fetched value: {}",
                    storage_value
                );
                Ok(storage_value)
            }
        }
    }

    /// If block header is set, returns the hash. Otherwise returns a zero hash
    /// instead of querying a node.
    fn block_hash(&self, _number: rU256) -> Result<B256, Self::Error> {
        match &self.block {
            Some(header) => Ok(B256::from(header.hash)),
            None => Ok(B256::zero()),
        }
    }
}

#[cfg(test)]
mod tests {
    use revm::primitives::U256 as rU256;
    use rstest::{fixture, rstest};
    use std::{error::Error, str::FromStr, sync::Arc};

    use super::*;
    use ethers::{
        providers::{Http, MockProvider, Provider},
        types::U256,
    };
    use tokio::runtime::Runtime;

    #[fixture]
    pub fn mock_sim_db() -> SimulationDB<Provider<MockProvider>> {
        let (client, _) = Provider::mocked();
        SimulationDB::new(Arc::new(client), get_runtime(), None)
    }

    // region HELPERS
    fn get_runtime() -> Option<Arc<Runtime>> {
        let runtime = tokio::runtime::Handle::try_current()
            .is_err()
            .then(|| Runtime::new().unwrap())
            .unwrap();
        Some(Arc::new(runtime))
    }

    fn get_client() -> Arc<Provider<Http>> {
        let client = Provider::<Http>::try_from(
            "https://eth-mainnet.g.alchemy.com/v2/OTD5W7gdTPrzpVot41Lx9tJD9LUiAhbs",
        )
        .unwrap();
        Arc::new(client)
    }
    // endregion helpers

    #[rstest]
    fn test_query_account_info(mock_sim_db: SimulationDB<Provider<MockProvider>>) {
        //ethers::types::Bytes::from
        let response_code = U256::from(128_u64);
        let response_nonce = U256::from(50_i64);
        let response_balance = U256::from(500_i64);
        // Note: The mocked provider takes the pushed requests from the top of the stack
        mock_sim_db
            .client
            .as_ref()
            .as_ref()
            .push(response_code)
            .unwrap();
        mock_sim_db
            .client
            .as_ref()
            .as_ref()
            .push(response_nonce)
            .unwrap();
        mock_sim_db
            .client
            .as_ref()
            .as_ref()
            .push(response_balance)
            .unwrap();
        let address = B160::from_str("0x2910543Af39abA0Cd09dBb2D50200b3E800A63D2").unwrap();

        let acc_info = mock_sim_db.query_account_info(address).unwrap();

        assert_eq!(acc_info.balance, rU256::from_limbs(response_balance.0));
        assert_eq!(acc_info.nonce, response_nonce.as_u64());
        assert_eq!(
            acc_info.code,
            Some(to_analysed(Bytecode::new_raw(
                ethers::types::Bytes::from([128; 1]).0
            )))
        );
    }

    #[rstest]
    #[cfg_attr(not(feature = "network_tests"), ignore)]
    fn test_query_storage_latest_block() -> Result<(), Box<dyn Error>> {
        let db = SimulationDB::new(get_client(), get_runtime(), None);
        let address = B160::from_str("0xb4e16d0168e52d35cacd2c6185b44281ec28c9dc")?;
        let index = rU256::from_limbs_slice(&[8]);
        db.init_account(address, AccountInfo::default(), None, false);

        db.query_storage(address, index).unwrap();

        // There is no assertion, but has the querying failed, we would have panicked by now.
        // This test is not deterministic as it depends on the current state of the blockchain.
        // See the next test where we do this for a specific block.
        Ok(())
    }

    #[rstest]
    fn test_query_storage_past_block(
        mock_sim_db: SimulationDB<Provider<MockProvider>>,
    ) -> Result<(), Box<dyn Error>> {
        let address = B160::from_str("0xb4e16d0168e52d35cacd2c6185b44281ec28c9dc")?;
        let index = rU256::from_limbs_slice(&[8]);
        let response_storage = H256::from_low_u64_le(123);
        mock_sim_db.init_account(address, AccountInfo::default(), None, false);
        mock_sim_db
            .client
            .as_ref()
            .as_ref()
            .push(response_storage)
            .unwrap();

        let result = mock_sim_db.query_storage(address, index).unwrap();

        assert_eq!(
            result,
            rU256::from_be_bytes(response_storage.to_fixed_bytes())
        );
        Ok(())
    }

    #[rstest]
    fn test_mock_account_get_acc_info(
        mock_sim_db: SimulationDB<Provider<MockProvider>>,
    ) -> Result<(), Box<dyn Error>> {
        // Tests if the provider has not been queried.
        // Querying the mocked provider would cause a panic, therefore no assert is needed.
        let mock_acc_address = B160::from_str("0xb4e16d0168e52d35cacd2c6185b44281ec28c9dc")?;
        mock_sim_db.init_account(mock_acc_address, AccountInfo::default(), None, true);

        let acc_info = mock_sim_db.basic(mock_acc_address).unwrap().unwrap();

        assert_eq!(
            mock_sim_db
                .account_storage
                .borrow()
                .get_account_info(&mock_acc_address)
                .unwrap(),
            &acc_info
        );
        Ok(())
    }

    #[rstest]
    fn test_mock_account_get_storage(
        mock_sim_db: SimulationDB<Provider<MockProvider>>,
    ) -> Result<(), Box<dyn Error>> {
        // Tests if mock accounts are not considered temp accounts and if the provider has not been queried.
        // Querying the mocked provider would cause a panic, therefore no assert is needed.
        let mock_acc_address = B160::from_str("0xb4e16d0168e52d35cacd2c6185b44281ec28c9dc")?;
        let storage_address = rU256::ZERO;
        mock_sim_db.init_account(mock_acc_address, AccountInfo::default(), None, true);

        let storage = mock_sim_db
            .storage(mock_acc_address, storage_address)
            .unwrap();

        assert_eq!(storage, rU256::ZERO);
        Ok(())
    }

    #[rstest]
    fn test_update_state(
        mut mock_sim_db: SimulationDB<Provider<MockProvider>>,
    ) -> Result<(), Box<dyn Error>> {
        let address = B160::from_str("0xb4e16d0168e52d35cacd2c6185b44281ec28c9dc")?;
        mock_sim_db.init_account(address, AccountInfo::default(), None, false);

        let mut new_storage = HashMap::default();
        let new_storage_value_index = rU256::from_limbs_slice(&[123]);
        new_storage.insert(new_storage_value_index, new_storage_value_index);
        let new_balance = rU256::from_limbs_slice(&[500]);
        let update = StateUpdate {
            storage: Some(new_storage),
            balance: Some(new_balance),
        };
        let mut updates = HashMap::default();
        updates.insert(address, update);
        let new_block = BlockHeader {
            number: 1,
            hash: H256::default(),
            timestamp: 234,
        };

        let reverse_update = mock_sim_db.update_state(&updates, new_block);

        assert_eq!(
            mock_sim_db
                .account_storage
                .borrow()
                .get_storage(&address, &new_storage_value_index)
                .unwrap(),
            new_storage_value_index
        );
        assert_eq!(
            mock_sim_db
                .account_storage
                .borrow()
                .get_account_info(&address)
                .unwrap()
                .balance,
            new_balance
        );
        assert_eq!(mock_sim_db.block.unwrap().number, 1);

        assert_eq!(
            reverse_update.get(&address).unwrap().balance.unwrap(),
            AccountInfo::default().balance
        );
        assert_eq!(
            reverse_update.get(&address).unwrap().storage,
            Some(HashMap::default())
        );

        Ok(())
    }

    #[rstest]
    fn test_overridden_db(
        mock_sim_db: SimulationDB<Provider<MockProvider>>,
    ) -> Result<(), Box<dyn Error>> {
        // GIVEN...
        let slot1 = rU256::from_limbs_slice(&[1]);
        let slot2 = rU256::from_limbs_slice(&[2]);
        let orig_value1 = rU256::from_limbs_slice(&[100]);
        let orig_value2 = rU256::from_limbs_slice(&[200]);
        let original_storage: HashMap<rU256, rU256> = [(slot1, orig_value1), (slot2, orig_value2)]
            .iter()
            .cloned()
            .collect();

        let address1 = B160::from(1);
        mock_sim_db.init_account(
            address1,
            AccountInfo::default(),
            Some(original_storage.clone()),
            false,
        );
        let address2 = B160::from(2);
        mock_sim_db.init_account(
            address2,
            AccountInfo::default(),
            Some(original_storage),
            false,
        );

        // override slot 1 of address 2
        // and slot 1 of address 3 which doesn't exist in the original DB
        let address3 = B160::from(3);
        let overridden_value1 = rU256::from_limbs_slice(&[101]);
        let mut overrides: HashMap<B160, HashMap<revm::primitives::U256, revm::primitives::U256>> =
            HashMap::new();
        overrides.insert(
            address2,
            [(slot1, overridden_value1)].iter().cloned().collect(),
        );
        overrides.insert(
            address3,
            [(slot1, overridden_value1)].iter().cloned().collect(),
        );

        // WHEN...
        let overriden_db = OverriddenSimulationDB {
            inner_db: &mock_sim_db,
            overrides: &overrides,
        };

        // THEN...
        assert_eq!(
            overriden_db
                .storage(address1, slot1)
                .expect("Value should be available"),
            orig_value1,
            "Slots of non-overridden account should hold original values."
        );

        assert_eq!(
            overriden_db
                .storage(address1, slot2)
                .expect("Value should be available"),
            orig_value2,
            "Slots of non-overridden account should hold original values."
        );

        assert_eq!(
            overriden_db
                .storage(address2, slot1)
                .expect("Value should be available"),
            overridden_value1,
            "Overridden slot of overridden account should hold an overridden value."
        );

        assert_eq!(
            overriden_db
                .storage(address2, slot2)
                .expect("Value should be available"),
            orig_value2,
            "Non-overridden slot of an account with other slots overridden \
            should hold an original value."
        );

        assert_eq!(
            overriden_db
                .storage(address3, slot1)
                .expect("Value should be available"),
            overridden_value1,
            "Overridden slot of an overridden non-existent account should hold an overriden value."
        );

        // storage
        mock_sim_db
            .client
            .as_ref()
            .as_ref()
            .push(H256::from_low_u64_be(123))
            .unwrap();
        mock_sim_db
            .client
            .as_ref()
            .as_ref()
            .push(U256::from(128))
            .unwrap(); // code
        mock_sim_db
            .client
            .as_ref()
            .as_ref()
            .push(U256::zero())
            .unwrap(); // nonce
        mock_sim_db
            .client
            .as_ref()
            .as_ref()
            .push(U256::zero())
            .unwrap(); // balance
        assert_eq!(
            overriden_db
                .storage(address3, slot2)
                .expect("Value should be available"),
            rU256::from_limbs_slice(&[123]),
            "Non-overridden slot of a non-existent account should query a node."
        );

        Ok(())
    }
}
