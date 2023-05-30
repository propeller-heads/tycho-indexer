use std::cell::RefCell;
use ethers::{
    providers::Middleware,
    types::{BlockId, BlockNumber, H160, H256, U64},
};
use log::info;

use std::sync::Arc;

use revm::{
    interpreter::analysis::to_analysed,
    primitives::{hash_map, AccountInfo, Bytecode, B160, B256, U256 as rU256},
    db::DatabaseRef,
};

use super::account_storage::{AccountStorage, StateUpdate};

/// Short-lived object that wraps an actual SimulationDB and can be passed to REVM which takes
/// ownership of it.
pub struct SharedSimulationDB<'a, M>
where
    M: Middleware,
{
    db: &'a SimulationDB<M>,
}

impl<'a, M> SharedSimulationDB<'a, M>
where
    M: Middleware,
{
    pub fn new(db: &'a SimulationDB<M>) -> Self {
        Self { db }
    }
}

impl<'a, M: Middleware> DatabaseRef for SharedSimulationDB<'a, M> {
    type Error = M::Error;

    fn basic(&self, address: B160) -> Result<Option<AccountInfo>, Self::Error> {
        DatabaseRef::basic(self.db, address)
    }

    fn code_by_hash(&self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        DatabaseRef::code_by_hash(self.db, code_hash)
    }

    fn storage(&self, address: B160, index: rU256) -> Result<rU256, Self::Error> {
        DatabaseRef::storage(self.db, address, index)
    }

    fn block_hash(&self, number: rU256) -> Result<B256, Self::Error> {
        DatabaseRef::block_hash(self.db, number)
    }
}

pub struct BlockHeader {
    number: u64,
    hash: H256,
    timestamp: u64,
}

pub struct SimulationDB<M: Middleware> {
    /// Client to connect to the RPC
    client: Arc<M>,
    /// Cached data
    account_storage: RefCell<AccountStorage>,
    /// Current block
    block: Option<BlockHeader>,

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
            block,
            runtime,
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
    /// * `permanent_storage` - Storage to init the account with this storage can only be updated manually.
    /// * `temp_storage` - Storage to init the account with. This storage will be removed after each now block.
    /// * `account_type` - Determines the type of the account.
    pub fn init_account(
        &self,
        address: B160,
        mut account: AccountInfo,
        permanent_storage: Option<hash_map::HashMap<rU256, rU256>>,
        mocked: bool,
    ) {
        if account.code.is_some() {
            account.code = Some(to_analysed(account.code.unwrap()));
        }

        self.account_storage.borrow_mut()
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
        updates: &hash_map::HashMap<B160, StateUpdate>,
        block: BlockHeader,
    ) -> hash_map::HashMap<B160, StateUpdate> {
        info!("Received account state update.");
        let mut revert_updates = hash_map::HashMap::new();
        self.block = Some(block);
        for (address, update_info) in updates.iter() {
            let mut revert_entry = StateUpdate::default();
            if let Some(current_account) = self.account_storage
                .borrow()
                .get_account_info(address) {
                revert_entry.balance = Some(current_account.balance);
            }
            if update_info.storage.is_some() {
                let mut revert_storage = hash_map::HashMap::default();
                for index in update_info.storage.as_ref().unwrap().keys() {
                    if let Some(s) = self.account_storage
                        .borrow()
                        .get_permanent_storage(address, index) {
                        revert_storage.insert(*index, s);
                    }
                }
                revert_entry.storage = Some(revert_storage);
            }
            revert_updates.insert(*address, revert_entry);

            self.account_storage.borrow_mut().update_account(address, update_info);
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
        let fut = async {
            tokio::join!(
                self.client.get_balance(H160(address.0), None),
                self.client.get_transaction_count(H160(address.0), None),
                self.client.get_code(H160(address.0), None),
            )
        };

        let (balance, nonce, code) = self.block_on(fut);

        Ok(AccountInfo::new(
            rU256::from_limbs(
                balance
                    .unwrap_or_else(|e| panic!("ethers get balance error: {e:?}"))
                    .0,
            ),
            nonce
                .unwrap_or_else(|e| panic!("ethers get nonce error: {e:?}"))
                .as_u64(),
            to_analysed(Bytecode::new_raw(
                code.unwrap_or_else(|e| panic!("ethers get code error: {e:?}"))
                    .0,
            )),
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
                .get_storage_at(
                    address,
                    index_h256,
                    self.block
                        .as_ref()
                        .map(|value| BlockId::Number(BlockNumber::Number(U64::from(value.number)))),
                )
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
        panic!("Not implemented")
    }

    /// Retrieves the storage value at the specified address and index.
    ///
    /// If the accessed contract is of type `AccountType::Mocked`, the function returns an empty slot
    /// instead of querying the storage to avoid potentially returning garbage values.
    ///
    /// # Arguments
    ///
    /// * `address`: The address of the contract to retrieve the storage value from.
    /// * `index`: The index of the storage value to retrieve.
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing the storage value if it exists. If the contract is of type `AccountType::Mocked`
    /// and the storage value is not found in the storage, an empty slot is returned as `rU256::ZERO`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was an issue querying the storage value from the contract or accessing the storage.
    ///
    /// # Notes
    ///
    /// * If the contract is present in the storage and is of type `AccountType::Mocked`, the function first checks if
    ///   the storage value exists in the storage. If found, it returns the stored value. If not found, it returns an empty slot.
    ///   Mocked contracts are not expected to have valid storage values, so the function does not query the storage in this case.
    ///
    /// * If the contract is present in the storage, the function checks if the storage value exists in the storage.
    ///   If found, it returns the stored value.
    ///   If not found, it queries the storage value from the contract, stores it in the storage, and returns it.
    ///
    /// * If the contract is not present in the storage, the function queries the account info and storage value from
    ///   the contract, initializes the account in the storage with the retrieved information, and returns the storage value.
    fn storage(&self, address: B160, index: rU256) -> Result<rU256, Self::Error> {
        let mut is_mocked;
        {
            // This scope is to not make two simultaneous borrows (one occurs inside init_account)
            let borrowed_storage = self.account_storage.borrow();
            if let Some(storage_value) = borrowed_storage.get_storage(&address, &index) {
                return Ok(storage_value);
            }
            is_mocked = borrowed_storage.is_mocked_account(&address);
        }
        match is_mocked {
            Some(true) => Ok(rU256::ZERO),
            Some(false) => {
                let storage_value = self.query_storage(address, index)?;
                self.account_storage.borrow_mut()
                    .set_temp_storage(address, index, storage_value);
                Ok(storage_value)
            }
            None => {
                let account_info = self.query_account_info(address)?;
                let storage_value = self.query_storage(address, index)?;
                self.init_account(address, account_info, None, false);
                self.account_storage.borrow_mut()
                    .set_temp_storage(address, index, storage_value);
                Ok(storage_value)
            }
        }
    }

    fn block_hash(&self, _number: rU256) -> Result<B256, Self::Error> {
        panic!("Not implemented")
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
        mock_sim_db.client.as_ref().as_ref().push(response_code);
        mock_sim_db.client.as_ref().as_ref().push(response_nonce);
        mock_sim_db.client.as_ref().as_ref().push(response_balance);
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
        let mut db = SimulationDB::new(get_client(), get_runtime(), None);
        let address = B160::from_str("0xb4e16d0168e52d35cacd2c6185b44281ec28c9dc")?;
        let index = rU256::from(8);
        db.init_account(address, AccountInfo::default(), None, false);

        db.query_storage(address, index).unwrap();

        // There is no assertion, but has the querying failed, we would have panicked by now.
        // This test is not deterministic as it depends on the current state of the blockchain.
        // See the next test where we do this for a specific block.
        Ok(())
    }

    #[rstest]
    fn test_query_storage_past_block(
        mut mock_sim_db: SimulationDB<Provider<MockProvider>>,
    ) -> Result<(), Box<dyn Error>> {
        let address = B160::from_str("0xb4e16d0168e52d35cacd2c6185b44281ec28c9dc")?;
        let index = rU256::from(8);
        let response_storage = H256::from_low_u64_le(123);
        mock_sim_db.init_account(address, AccountInfo::default(), None, false);
        mock_sim_db.client.as_ref().as_ref().push(response_storage);

        let result = mock_sim_db.query_storage(address, index).unwrap();

        assert_eq!(
            result,
            rU256::from_be_bytes(response_storage.to_fixed_bytes())
        );
        Ok(())
    }

    #[rstest]
    fn test_mock_account_get_acc_info(
        mut mock_sim_db: SimulationDB<Provider<MockProvider>>,
    ) -> Result<(), Box<dyn Error>> {
        // Tests if the provider has not been queried.
        // Querying the mocked provider would cause a panic, therefore no assert is needed.
        let mock_acc_address = B160::from_str("0xb4e16d0168e52d35cacd2c6185b44281ec28c9dc")?;
        mock_sim_db.init_account(mock_acc_address, AccountInfo::default(), None, true);

        let acc_info = mock_sim_db.basic(mock_acc_address).unwrap().unwrap();

        assert_eq!(
            mock_sim_db
                .account_storage.borrow()
                .get_account_info(&mock_acc_address)
                .unwrap(),
            &acc_info
        );
        Ok(())
    }

    #[rstest]
    fn test_mock_account_get_storage(
        mut mock_sim_db: SimulationDB<Provider<MockProvider>>,
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

        let mut new_storage = hash_map::HashMap::default();
        let new_storage_value_index = rU256::from(123);
        new_storage.insert(new_storage_value_index, new_storage_value_index);
        let new_balance = rU256::from(500_i64);
        let update = StateUpdate {
            storage: Some(new_storage),
            balance: Some(new_balance),
        };
        let mut updates = hash_map::HashMap::default();
        updates.insert(address, update);
        let new_block = BlockHeader {
            number: 1,
            hash: H256::default(),
            timestamp: 234,
        };
        let revers_update = mock_sim_db.update_state(&updates, new_block);

        assert_eq!(
            mock_sim_db
                .account_storage.borrow()
                .get_storage(&address, &new_storage_value_index)
                .unwrap(),
            new_storage_value_index
        );
        assert_eq!(
            mock_sim_db
                .account_storage.borrow()
                .get_account_info(&address)
                .unwrap()
                .balance,
            new_balance
        );
        assert_eq!(mock_sim_db.block.unwrap().number, 1);

        assert_eq!(
            revers_update.get(&address).unwrap().balance.unwrap(),
            AccountInfo::default().balance
        );
        assert_eq!(
            revers_update.get(&address).unwrap().storage,
            Some(hash_map::HashMap::default())
        );

        Ok(())
    }
}
