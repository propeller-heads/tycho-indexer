use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use ethers::{
    providers::Middleware,
    types::{BlockId, H160, H256},
};
use revm::{
    db::DatabaseRef,
    interpreter::analysis::to_analysed,
    primitives::{AccountInfo, Address, Bytecode, B256, U256 as rU256},
};
use tracing::{debug, info};

use super::{
    super::account_storage::{AccountStorage, StateUpdate},
    engine_db_interface::EngineDatabaseInterface,
};

/// A wrapper over an actual SimulationDB that allows overriding specific storage slots
pub struct OverriddenSimulationDB<'a, DB: DatabaseRef> {
    /// Wrapped database. Will be queried if a requested item is not found in the overrides.
    pub inner_db: &'a DB,
    /// A mapping from account address to storage.
    /// Storage is a mapping from slot index to slot value.
    pub overrides: &'a HashMap<Address, HashMap<rU256, rU256>>,
}

impl<'a, DB: DatabaseRef> OverriddenSimulationDB<'a, DB> {
    /// Creates a new OverriddenSimulationDB
    ///
    /// # Arguments
    ///
    /// * `inner_db` - Reference to the inner database.
    /// * `overrides` - Reference to a HashMap containing the storage overrides.
    ///
    /// # Returns
    ///
    /// A new instance of OverriddenSimulationDB.
    pub fn new(inner_db: &'a DB, overrides: &'a HashMap<Address, HashMap<rU256, rU256>>) -> Self {
        OverriddenSimulationDB { inner_db, overrides }
    }
}

impl<DB: DatabaseRef> DatabaseRef for OverriddenSimulationDB<'_, DB> {
    type Error = DB::Error;

    fn basic_ref(&self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        self.inner_db.basic_ref(address)
    }

    fn code_by_hash_ref(&self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        self.inner_db
            .code_by_hash_ref(code_hash)
    }

    fn storage_ref(&self, address: Address, index: rU256) -> Result<rU256, Self::Error> {
        match self.overrides.get(&address) {
            None => self
                .inner_db
                .storage_ref(address, index),
            Some(slot_overrides) => match slot_overrides.get(&index) {
                Some(value) => {
                    debug!(%address, %index, %value, "Requested storage of account {:x?} slot {}", address, index);
                    Ok(*value)
                }
                None => self
                    .inner_db
                    .storage_ref(address, index),
            },
        }
    }

    fn block_hash_ref(&self, number: u64) -> Result<B256, Self::Error> {
        self.inner_db.block_hash_ref(number)
    }
}

#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq, Default)]
pub struct BlockHeader {
    pub number: u64,
    pub hash: B256,
    pub timestamp: u64,
}

impl From<BlockHeader> for BlockId {
    fn from(value: BlockHeader) -> Self {
        Self::from(H256::from_slice(&value.hash.0))
    }
}

/// A wrapper over an ethers Middleware with local storage cache and overrides.
#[derive(Clone, Debug)]
pub struct SimulationDB<M: Middleware> {
    /// Client to connect to the RPC
    client: Arc<M>,
    /// Cached data
    account_storage: Arc<RwLock<AccountStorage>>,
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
            account_storage: Arc::new(RwLock::new(AccountStorage::new())),
            block,
            runtime,
        }
    }

    /// Set the block that will be used when querying a node
    pub fn set_block(&mut self, block: Option<BlockHeader>) {
        self.block = block;
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
        updates: &HashMap<Address, StateUpdate>,
        block: BlockHeader,
    ) -> HashMap<Address, StateUpdate> {
        info!("Received account state update.");
        let mut revert_updates = HashMap::new();
        self.block = Some(block);
        for (address, update_info) in updates.iter() {
            let mut revert_entry = StateUpdate::default();
            if let Some(current_account) = self
                .account_storage
                .read()
                .unwrap()
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
                    if let Some(s) = self
                        .account_storage
                        .read()
                        .unwrap()
                        .get_permanent_storage(address, index)
                    {
                        revert_storage.insert(*index, s);
                    }
                }
                revert_entry.storage = Some(revert_storage);
            }
            revert_updates.insert(*address, revert_entry);

            self.account_storage
                .write()
                .unwrap()
                .update_account(address, update_info);
        }
        revert_updates
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
    /// Returns a `Result` containing either an `AccountInfo` object with balance, nonce, and code
    /// information, or an error of type `SimulationDB<M>::Error` if the query fails.
    fn query_account_info(
        &self,
        address: Address,
    ) -> Result<AccountInfo, <SimulationDB<M> as DatabaseRef>::Error> {
        debug!("Querying account info of {:x?} at block {:?}", address, self.block);
        let block_id: Option<BlockId> = self.block.map(|v| v.into());
        let fut = async {
            tokio::join!(
                self.client
                    .get_balance(H160(**address), block_id),
                self.client
                    .get_transaction_count(H160(**address), block_id),
                self.client
                    .get_code(H160(**address), block_id),
            )
        };

        let (balance, nonce, code) = self.block_on(fut);
        let code = to_analysed(Bytecode::new_raw(revm::primitives::Bytes::copy_from_slice(
            &code
                .unwrap_or_else(|e| panic!("ethers get code error: {e:?}"))
                .0,
        )));
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
    pub fn query_storage(
        &self,
        address: Address,
        index: rU256,
    ) -> Result<rU256, <SimulationDB<M> as DatabaseRef>::Error> {
        let index_h256 = H256::from(index.to_be_bytes());
        let fut = async {
            let address = H160::from(**address);
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

impl<M: Middleware> EngineDatabaseInterface for SimulationDB<M> {
    type Error = String;

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
        mut account: AccountInfo,
        permanent_storage: Option<HashMap<rU256, rU256>>,
        mocked: bool,
    ) {
        if account.code.is_some() {
            account.code = Some(to_analysed(account.code.unwrap()));
        }

        let mut account_storage = self.account_storage.write().unwrap();

        account_storage.init_account(address, account, permanent_storage, mocked);
    }

    /// Clears temp storage
    ///
    /// It is recommended to call this after a new block is received,
    /// to avoid stored state leading to wrong results.
    fn clear_temp_storage(&mut self) {
        self.account_storage
            .write()
            .unwrap()
            .clear_temp_storage();
    }
}

impl<M: Middleware> DatabaseRef for SimulationDB<M> {
    type Error = M::Error;

    /// Retrieves basic information about an account.
    ///
    /// This function retrieves the basic account information for the specified address.
    /// If the account is present in the storage, the stored account information is returned.
    /// If the account is not present in the storage, the function queries the account information
    /// from the contract and initializes the account in the storage with the retrieved
    /// information.
    ///
    /// # Arguments
    ///
    /// * `address`: The address of the account to retrieve the information for.
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing an `Option` that holds the account information if it exists.
    /// If the account is not found, `None` is returned.
    ///
    /// # Errors
    ///
    /// Returns an error if there was an issue querying the account information from the contract or
    /// accessing the storage.
    ///
    /// # Notes
    ///
    /// * If the account is present in the storage, the function returns a clone of the stored
    ///   account information.
    ///
    /// * If the account is not present in the storage, the function queries the account information
    ///   from the contract, initializes the account in the storage with the retrieved information,
    ///   and returns a clone of the account information.
    fn basic_ref(&self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        if let Some(account) = self
            .account_storage
            .read()
            .unwrap()
            .get_account_info(&address)
        {
            return Ok(Some(account.clone()));
        }
        let account_info = self.query_account_info(address)?;
        self.init_account(address, account_info.clone(), None, false);
        Ok(Some(account_info))
    }

    fn code_by_hash_ref(&self, _code_hash: B256) -> Result<Bytecode, Self::Error> {
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
    /// Returns an error if there was an issue querying the storage value from the contract or
    /// accessing the storage.
    ///
    /// # Notes
    ///
    /// * If the contract is present locally and is mocked, the function first checks if the storage
    ///   value exists locally. If found, it returns the stored value. If not found, it returns an
    ///   empty slot. Mocked contracts are not expected to have valid storage values, so the
    ///   function does not query a node in this case.
    ///
    /// * If the contract is present locally and is not mocked, the function checks if the storage
    ///   value exists locally. If found, it returns the stored value. If not found, it queries the
    ///   storage value from a node, stores it locally, and returns it.
    ///
    /// * If the contract is not present locally, the function queries the account info and storage
    ///   value from a node, initializes the account locally with the retrieved information, and
    ///   returns the storage value.
    fn storage_ref(&self, address: Address, index: rU256) -> Result<rU256, Self::Error> {
        debug!("Requested storage of account {:x?} slot {}", address, index);
        let is_mocked; // will be None if we don't have this account at all
        {
            let account_storage = self.account_storage.read().unwrap();
            // This scope is to not make two simultaneous borrows
            is_mocked = account_storage.is_mocked_account(&address);
            if let Some(storage_value) = account_storage.get_storage(&address, &index) {
                debug!(
                    "Got value locally. This is a {} account. Value: {}",
                    (if is_mocked.unwrap_or(false) { "mocked" } else { "non-mocked" }),
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
                let mut account_storage = self.account_storage.write().unwrap();

                account_storage.set_temp_storage(address, index, storage_value);
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
                let mut account_storage = self.account_storage.write().unwrap();
                account_storage.set_temp_storage(address, index, storage_value);
                debug!("This is non-initialised account. Fetched value: {}", storage_value);
                Ok(storage_value)
            }
        }
    }

    /// If block header is set, returns the hash. Otherwise returns a zero hash
    /// instead of querying a node.
    fn block_hash_ref(&self, _number: u64) -> Result<B256, Self::Error> {
        match &self.block {
            Some(header) => Ok(header.hash),
            None => Ok(B256::ZERO),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::{env, error::Error, str::FromStr};

    use dotenv::dotenv;
    use ethers::{
        providers::{Http, MockProvider, Provider},
        types::U256,
    };
    use rstest::{fixture, rstest};
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
        let eth_rpc_url = env::var("ETH_RPC_URL").unwrap_or_else(|_| {
            dotenv().expect("Missing .env file");
            env::var("ETH_RPC_URL").expect("Missing ETH_RPC_URL in .env file")
        });

        let client = Provider::<Http>::try_from(eth_rpc_url).unwrap();
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
        let address = Address::from_str("0x2910543Af39abA0Cd09dBb2D50200b3E800A63D2").unwrap();

        let acc_info = mock_sim_db
            .query_account_info(address)
            .unwrap();

        assert_eq!(acc_info.balance, rU256::from_limbs(response_balance.0));
        assert_eq!(acc_info.nonce, response_nonce.as_u64());
        assert_eq!(
            acc_info.code,
            Some(to_analysed(Bytecode::new_raw(revm::primitives::Bytes::from([128; 1]))))
        );
    }

    #[rstest]
    #[cfg_attr(not(feature = "network_tests"), ignore)]
    fn test_query_storage_latest_block() -> Result<(), Box<dyn Error>> {
        let db = SimulationDB::new(get_client(), get_runtime(), None);
        let address = Address::from_str("0xb4e16d0168e52d35cacd2c6185b44281ec28c9dc")?;
        let index = rU256::from_limbs_slice(&[8]);
        db.init_account(address, AccountInfo::default(), None, false);

        db.query_storage(address, index)
            .unwrap();

        // There is no assertion, but has the querying failed, we would have panicked by now.
        // This test is not deterministic as it depends on the current state of the blockchain.
        // See the next test where we do this for a specific block.
        Ok(())
    }

    #[rstest]
    fn test_query_storage_past_block(
        mock_sim_db: SimulationDB<Provider<MockProvider>>,
    ) -> Result<(), Box<dyn Error>> {
        let address = Address::from_str("0xb4e16d0168e52d35cacd2c6185b44281ec28c9dc")?;
        let index = rU256::from_limbs_slice(&[8]);
        let response_storage = H256::from_low_u64_le(123);
        mock_sim_db.init_account(address, AccountInfo::default(), None, false);
        mock_sim_db
            .client
            .as_ref()
            .as_ref()
            .push(response_storage)
            .unwrap();

        let result = mock_sim_db
            .query_storage(address, index)
            .unwrap();

        assert_eq!(result, rU256::from_be_bytes(response_storage.to_fixed_bytes()));
        Ok(())
    }

    #[rstest]
    fn test_mock_account_get_acc_info(
        mock_sim_db: SimulationDB<Provider<MockProvider>>,
    ) -> Result<(), Box<dyn Error>> {
        // Tests if the provider has not been queried.
        // Querying the mocked provider would cause a panic, therefore no assert is needed.
        let mock_acc_address = Address::from_str("0xb4e16d0168e52d35cacd2c6185b44281ec28c9dc")?;
        mock_sim_db.init_account(mock_acc_address, AccountInfo::default(), None, true);

        let acc_info = mock_sim_db
            .basic_ref(mock_acc_address)
            .unwrap()
            .unwrap();

        assert_eq!(
            mock_sim_db
                .account_storage
                .read()
                .unwrap()
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
        // Tests if mock accounts are not considered temp accounts and if the provider has not been
        // queried. Querying the mocked provider would cause a panic, therefore no assert is
        // needed.
        let mock_acc_address = Address::from_str("0xb4e16d0168e52d35cacd2c6185b44281ec28c9dc")?;
        let storage_address = rU256::ZERO;
        mock_sim_db.init_account(mock_acc_address, AccountInfo::default(), None, true);

        let storage = mock_sim_db
            .storage_ref(mock_acc_address, storage_address)
            .unwrap();

        assert_eq!(storage, rU256::ZERO);
        Ok(())
    }

    #[rstest]
    fn test_update_state(
        mut mock_sim_db: SimulationDB<Provider<MockProvider>>,
    ) -> Result<(), Box<dyn Error>> {
        let address = Address::from_str("0xb4e16d0168e52d35cacd2c6185b44281ec28c9dc")?;
        mock_sim_db.init_account(address, AccountInfo::default(), None, false);

        let mut new_storage = HashMap::default();
        let new_storage_value_index = rU256::from_limbs_slice(&[123]);
        new_storage.insert(new_storage_value_index, new_storage_value_index);
        let new_balance = rU256::from_limbs_slice(&[500]);
        let update = StateUpdate { storage: Some(new_storage), balance: Some(new_balance) };
        let mut updates = HashMap::default();
        updates.insert(address, update);
        let new_block = BlockHeader { number: 1, hash: B256::default(), timestamp: 234 };

        let reverse_update = mock_sim_db.update_state(&updates, new_block);

        assert_eq!(
            mock_sim_db
                .account_storage
                .read()
                .unwrap()
                .get_storage(&address, &new_storage_value_index)
                .unwrap(),
            new_storage_value_index
        );
        assert_eq!(
            mock_sim_db
                .account_storage
                .read()
                .unwrap()
                .get_account_info(&address)
                .unwrap()
                .balance,
            new_balance
        );
        assert_eq!(mock_sim_db.block.unwrap().number, 1);

        assert_eq!(
            reverse_update
                .get(&address)
                .unwrap()
                .balance
                .unwrap(),
            AccountInfo::default().balance
        );
        assert_eq!(
            reverse_update
                .get(&address)
                .unwrap()
                .storage,
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

        let address1 = Address::from_str("0000000000000000000000000000000000000001").unwrap();
        mock_sim_db.init_account(
            address1,
            AccountInfo::default(),
            Some(original_storage.clone()),
            false,
        );
        let address2 = Address::from_str("0000000000000000000000000000000000000002").unwrap();
        mock_sim_db.init_account(address2, AccountInfo::default(), Some(original_storage), false);

        // override slot 1 of address 2
        // and slot 1 of address 3 which doesn't exist in the original DB
        let address3 = Address::from_str("0000000000000000000000000000000000000003").unwrap();
        let overridden_value1 = rU256::from_limbs_slice(&[101]);
        let mut overrides: HashMap<
            Address,
            HashMap<revm::primitives::U256, revm::primitives::U256>,
        > = HashMap::new();
        overrides.insert(
            address2,
            [(slot1, overridden_value1)]
                .iter()
                .cloned()
                .collect(),
        );
        overrides.insert(
            address3,
            [(slot1, overridden_value1)]
                .iter()
                .cloned()
                .collect(),
        );

        // WHEN...
        let overriden_db = OverriddenSimulationDB::new(&mock_sim_db, &overrides);

        // THEN...
        assert_eq!(
            overriden_db
                .storage_ref(address1, slot1)
                .expect("Value should be available"),
            orig_value1,
            "Slots of non-overridden account should hold original values."
        );

        assert_eq!(
            overriden_db
                .storage_ref(address1, slot2)
                .expect("Value should be available"),
            orig_value2,
            "Slots of non-overridden account should hold original values."
        );

        assert_eq!(
            overriden_db
                .storage_ref(address2, slot1)
                .expect("Value should be available"),
            overridden_value1,
            "Overridden slot of overridden account should hold an overridden value."
        );

        assert_eq!(
            overriden_db
                .storage_ref(address2, slot2)
                .expect("Value should be available"),
            orig_value2,
            "Non-overridden slot of an account with other slots overridden \
            should hold an original value."
        );

        assert_eq!(
            overriden_db
                .storage_ref(address3, slot1)
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
                .storage_ref(address3, slot2)
                .expect("Value should be available"),
            rU256::from_limbs_slice(&[123]),
            "Non-overridden slot of a non-existent account should query a node."
        );

        Ok(())
    }
}
