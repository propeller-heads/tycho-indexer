use ethers::{
    providers::Middleware,
    types::{BlockId, BlockNumber, H160, H256, U64},
};

use std::{
    collections::{HashMap, HashSet},
    default,
    sync::Arc,
};

use ethers::{
    prelude::k256::sha2::digest::KeyInit,
    providers::Middleware,
    types::{BlockId, BlockNumber, H160, H256, U256},
};

use ethers::types::U64;

use log::warn;
use revm::{
    db::DbAccount,
    interpreter::analysis::to_analysed,
    primitives::{
        hash_map, AccountInfo, Bytecode, BytecodeState, B160, B256, KECCAK_EMPTY, U256 as rU256,
    },
    Database,
};

use super::cache::{CachedData, StateUpdate};

/// Short-lived object that wraps an actual SimulationDB and can be passed to REVM which takes
/// ownership of it.
pub struct SharedSimulationDB<'a, M>
where
    M: Middleware,
{
    db: &'a mut SimulationDB<M>,
}

impl<'a, M> SharedSimulationDB<'a, M>
where
    M: Middleware,
{
    pub fn new(db: &'a mut SimulationDB<M>) -> Self {
        Self { db }
    }
}

impl<'a, M: Middleware> Database for SharedSimulationDB<'a, M> {
    type Error = M::Error;

    fn basic(&mut self, address: B160) -> Result<Option<AccountInfo>, Self::Error> {
        Database::basic(self.db, address)
    }

    fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        Database::code_by_hash(self.db, code_hash)
    }

    fn storage(&mut self, address: B160, index: rU256) -> Result<rU256, Self::Error> {
        Database::storage(self.db, address, index)
    }

    fn block_hash(&mut self, number: rU256) -> Result<B256, Self::Error> {
        Database::block_hash(self.db, number)
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
    cache: CachedData,
    /// Accounts that we had to query because we didn't expect them to be accessed during simulations.
    /// They will only be stored temporarily.
    temp_accounts: HashSet<B160>,
    /// Accounts that should not fallback to using a storage query
    mocked_accounts: HashSet<B160>,
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
            cache: CachedData::new(),
            temp_accounts: HashSet::new(),
            mocked_accounts: HashSet::new(),
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
    /// * `storage` - Storage to init the account with
    /// * `mock` - If set true account will be tracked as mocked. Mocked accounts will not be allowed to query the
    /// underlying node for any missing state
    pub fn init_account(
        &mut self,
        address: B160,
        mut account: AccountInfo,
        storage: Option<hash_map::HashMap<rU256, rU256>>,
        mock: bool,
    ) {
        if account.code.is_some() {
            account.code = Some(to_analysed(account.code.unwrap()));
        }

        self.cache.insert_account_data(address, account, storage);

        if mock {
            self.mocked_accounts.insert(address);
        }
    }

    /// Update the simulation state.
    ///
    /// Updates the underlying smart contract storage. Any previously missed account,
    /// which was queried and whose state now is in the cache will be cleared.
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
        let mut revert_updates = hash_map::HashMap::new();
        self.block = Some(block);
        for (address, update_info) in updates.iter() {
            let mut revert_entry = StateUpdate::default();
            if let Some(current_account) = self.cache.get_mut_account(address) {
                revert_entry.balance = Some(current_account.balance);
            }
            revert_entry.storage = self.cache.clone_storage(&address);
            revert_updates.insert(*address, revert_entry);

            self.cache.update_account_info(address, update_info);
        }
        revert_updates
    }

    /// Clears accounts from state that were loaded using a query
    ///
    /// It is recommended to call this after a new block is received,
    /// to avoid cached state leading to wrong results.
    pub fn clear_temp_accounts(&mut self) {
        for address in self.temp_accounts.iter() {
            self.cache
                .remove_account(address)
                .expect("Inconsistency between missed_accounts and cache.accounts");
        }
        self.temp_accounts.clear();
    }

    /// Query blockchain for account info
    ///
    /// Gets account information not including storage: balance, nonce and code.
    /// /// Received data is NOT put into cache; this must be done separately.
    fn query_account_info(
        &self,
        address: B160,
    ) -> Result<AccountInfo, <SimulationDB<M> as Database>::Error> {
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

    /// Query blockchain for account storage at certain index
    ///
    /// Received data is NOT put into cache; this must be done separately.
    fn query_storage(
        &self,
        address: B160,
        index: rU256,
    ) -> Result<rU256, <SimulationDB<M> as Database>::Error> {
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

    fn track_miss(&mut self, address: B160) {
        if !self.cache.account_present(&address) {
            self.missed_accounts.insert(address);
        }
    }

    pub fn block_on<F: core::future::Future>(&self, f: F) -> F::Output {
        // If we get here and have to block the current thread, we really
        // messed up indexing / filling the cache. In that case this will save us
        // at the price of a very high time penalty.
        match &self.runtime {
            Some(runtime) => runtime.block_on(f),
            None => futures::executor::block_on(f),
        }
    }
}

impl<M: Middleware> Database for SimulationDB<M> {
    type Error = M::Error;

    fn basic(&mut self, address: B160) -> Result<Option<AccountInfo>, Self::Error> {
        match self.cache.get_account(&address) {
            Some(account) => Ok(Some(account.clone())),
            None => {
                if self.mocked_accounts.contains(&address) {
                    return Ok(Some(AccountInfo::default()));
                }
                let account_info = self.query_account_info(address)?;
                self.track_temp_accounts(address);
                self.init_account(address, account_info.clone(), None, false);
                Ok(Some(account_info))
            }
        }
    }

    fn code_by_hash(&mut self, _code_hash: B256) -> Result<Bytecode, Self::Error> {
        panic!("Not implemented")
    }

    fn storage(&mut self, address: B160, index: rU256) -> Result<rU256, Self::Error> {
        // if we are accessing a mocked contract, we should not allow it to do a
        // query as the query might return garbage, so in case we would do a query we
        // return an empty slot instead.
        if self.mocked_accounts.contains(&address) {
            if let Some(value) = self.cache.get_storage(&address, &index) {
                Ok(*value)
            } else {
                Ok(rU256::ZERO)
            }
        } else {
            // Note: we do only check on account level, not storage level as the existence
            // of an account is interpreted as the account being tracked.
            self.track_temp_accounts(address);
            match self.cache.get_storage(&address, &index) {
                Some(storage) => Ok(*storage),
                None => {
                    let storage = self.query_storage(address, index).unwrap();
                        self.cache
                            .accounts
                            .get_mut(&address)
                            .unwrap()
                            .storage
                            .insert(index, storage);
                    self.cache.set_storage(address, index, storage);
                    Ok(storage)
                }
                None => {
                    let account_info = self.query_account_info(address)?;
                    let storage_value = self.query_storage(address, index)?;
                    let mut storage = hash_map::HashMap::default();
                    storage.insert(index, storage_value);
                    self.init_account(address, account_info, Some(storage), false);

                    self.cache
                        .accounts
                        .get_mut(&address)
                        .unwrap()
                        .storage
                        .insert(index, storage);
                    Ok(storage_value)
                }
            }
        }
    }

    fn block_hash(&mut self, _number: rU256) -> Result<B256, Self::Error> {
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
            "https://nd-476-591-342.p2pify.com/47924752fae22aeef1e970c35e88efa0",
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
        db.init_account(address, AccountInfo::default(), false);

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
        mock_sim_db.init_account(address, AccountInfo::default(), false);
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
        // Tests if mock accounts are not considered temp accounts and if the provider has not been queried.
        // Querying the mocked provider would cause a panic, therefore no assert is needed.
        let mock_acc_address = B160::from_str("0xb4e16d0168e52d35cacd2c6185b44281ec28c9dc")?;
        mock_sim_db.mocked_accounts.insert(mock_acc_address);

        let acc_info = mock_sim_db.basic(mock_acc_address).unwrap().unwrap();

        assert!(!mock_sim_db.temp_accounts.contains(&mock_acc_address));
        assert!(!mock_sim_db.cache.accounts.contains_key(&mock_acc_address));
        assert_eq!(AccountInfo::default(), acc_info);
        Ok(())
    }

    #[rstest]
    fn test_clear_temp_accounts_doesnt_clear_mocked(
        mut mock_sim_db: SimulationDB<Provider<MockProvider>>,
    ) -> Result<(), Box<dyn Error>> {
        let mock_acc_address = B160::from_str("0xb4e16d0168e52d35cacd2c6185b44281ec28c9dc")?;
        let mock_acc: DbAccount = DbAccount {
            info: AccountInfo::default(),
            account_state: Default::default(),
            storage: Default::default(),
        };
        mock_sim_db.mocked_accounts.insert(mock_acc_address);
        mock_sim_db
            .cache
            .accounts
            .insert(mock_acc_address, mock_acc);

        mock_sim_db.clear_temp_accounts();

        assert!(mock_sim_db.mocked_accounts.contains(&mock_acc_address));
        assert!(mock_sim_db.cache.accounts.contains_key(&mock_acc_address));
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
        let mock_acc = DbAccount {
            info: AccountInfo::default(),
            account_state: Default::default(),
            storage: Default::default(),
        };
        mock_sim_db.mocked_accounts.insert(mock_acc_address);
        mock_sim_db
            .cache
            .accounts
            .insert(mock_acc_address, mock_acc);

        let storage = mock_sim_db
            .storage(mock_acc_address, storage_address)
            .unwrap();

        assert!(!mock_sim_db.temp_accounts.contains(&mock_acc_address));
        assert_eq!(storage, rU256::ZERO);
        Ok(())
    }
}
// TODO: Add test for update_state
