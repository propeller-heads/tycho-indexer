use std::{
    ops::{Deref, DerefMut},
    sync::{Arc, Mutex},
};

use ethers::{
    providers::Middleware,
    types::{H160, H256, U256},
};

use revm::{
    db::{CacheDB, DatabaseRef},
    interpreter::analysis::to_analysed,
    primitives::{hash_map, AccountInfo, Bytecode, HashMap, B160, B256, U256 as rU256},
    Database,
};

#[derive(Clone)]
pub struct SlotInfo {
    pub mutable: bool,
}

pub type ContractStorageLayout = hash_map::HashMap<U256, SlotInfo>;

pub type ContractStorageUpdate = hash_map::HashMap<H160, hash_map::HashMap<rU256, rU256>>;

pub type SimulationDB<M> = CacheDB<EthRpcDB<M>>;

pub struct SharedSimulationDB<'a, M>
where
    M: Middleware + Clone,
{
    db: &'a mut SimulationDB<M>,
}

impl<'a, M> SharedSimulationDB<'a, M>
where
    M: Middleware + Clone,
{
    pub fn new(db: &'a mut SimulationDB<M>) -> Self {
        Self { db }
    }

    pub fn replace_account_storage(
        &mut self,
        address: B160,
        storage: HashMap<rU256, rU256>,
    ) -> Result<(), M::Error> {
        self.db.replace_account_storage(address, storage)
    }

    pub fn update_code(&mut self, address: B160, code: Option<Bytecode>) -> Option<Bytecode> {
        let db_info = self.db.accounts.get_mut(&address).unwrap();
        let acc_info = &mut db_info.info;
        let old = acc_info.code.clone();
        acc_info.code = code;
        old
    }
}

impl<'a, M: Middleware + Clone> Database for SharedSimulationDB<'a, M> {
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

// If we use SharedDB we might not need the clone trait anymore
#[derive(Clone)]
pub struct EthRpcDB<M: Middleware + Clone> {
    pub client: Arc<M>,
    pub runtime: Option<Arc<tokio::runtime::Runtime>>,
}

impl<M: Middleware + Clone> EthRpcDB<M> {
    /// internal utility function to call tokio feature and wait for output
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

impl<M: Middleware + Clone> DatabaseRef for EthRpcDB<M> {
    type Error = M::Error;

    fn basic(&self, address: B160) -> Result<Option<AccountInfo>, Self::Error> {
        println!("loading basic data {address}!");
        let fut = async {
            tokio::join!(
                self.client.get_balance(H160(address.0), None),
                self.client.get_transaction_count(H160(address.0), None),
                self.client.get_code(H160(address.0), None),
            )
        };

        let (balance, nonce, code) = self.block_on(fut);

        Ok(Some(AccountInfo::new(
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
        )))
    }

    fn code_by_hash(&self, _code_hash: B256) -> Result<Bytecode, Self::Error> {
        panic!("Should not be called. Code is already loaded");
        // not needed because we already load code with basic info
    }

    fn storage(&self, address: B160, index: rU256) -> Result<rU256, Self::Error> {
        println!("Loading storage {address}, {index}");
        let add = H160::from(address.0);
        let index = H256::from(index.to_be_bytes());
        let fut = async {
            let storage = self.client.get_storage_at(add, index, None).await.unwrap();
            rU256::from_be_bytes(storage.to_fixed_bytes())
        };
        Ok(self.block_on(fut))
    }

    fn block_hash(&self, _number: rU256) -> Result<B256, Self::Error> {
        todo!()
    }
}
