// TODO: remove skip for clippy dead_code check
#![allow(dead_code)]
use crate::{
    evm::engine_db_interface::EngineDatabaseInterface,
    protocol::vm::constants::{EXTERNAL_ACCOUNT, MAX_BALANCE},
};
use lazy_static::lazy_static;
use revm::{
    primitives::{AccountInfo, Address},
    DatabaseRef,
};
use std::{collections::HashMap, fmt::Debug, sync::Arc};
use tokio::sync::RwLock;

use crate::evm::{
    simulation::SimulationEngine,
    simulation_db::BlockHeader,
    tycho_db::PreCachedDB,
    tycho_models::{AccountUpdate, ChangeType, ResponseAccount},
};

lazy_static! {
    pub static ref SHARED_TYCHO_DB: Arc<RwLock<PreCachedDB>> =
        create_shared_db_ref(PreCachedDB::new().expect("Failed to create PreCachedDB"));
}

pub fn create_shared_db_ref<D: EngineDatabaseInterface + DatabaseRef>(db: D) -> Arc<RwLock<D>> {
    Arc::new(RwLock::new(db))
}

/// Creates a simulation engine with a mocked ERC20 contract at the given addresses.
///
/// # Parameters
///
/// - `mocked_tokens`: A list of addresses at which a mocked ERC20 contract should be inserted.
/// - `trace`: Whether to trace calls. Only meant for debugging purposes, might print a lot of data
///   to stdout.
pub async fn create_engine<D: EngineDatabaseInterface + Clone + DatabaseRef>(
    db: Arc<RwLock<D>>,
    tokens: Vec<String>,
    trace: bool,
) -> SimulationEngine<D>
where
    <D as EngineDatabaseInterface>::Error: Debug,
    <D as DatabaseRef>::Error: Debug,
{
    // Acquire a read lock for the database instance
    let db_read = db.read().await;
    let engine = SimulationEngine::new(db_read.clone(), trace);

    for token in tokens {
        let info = AccountInfo {
            balance: Default::default(),
            nonce: 0,
            code_hash: Default::default(),
            code: None,
        };
        engine.state.init_account(
            Address::parse_checksummed(token, None).expect("Invalid checksum for token address"),
            info,
            None,
            false,
        );
    }

    engine.state.init_account(
        *EXTERNAL_ACCOUNT,
        AccountInfo { balance: *MAX_BALANCE, nonce: 0, code_hash: Default::default(), code: None },
        None,
        false,
    );

    engine
}

pub async fn update_engine(
    db: Arc<RwLock<PreCachedDB>>,
    block: BlockHeader,
    vm_storage: Option<HashMap<Address, ResponseAccount>>,
    account_updates: HashMap<Address, AccountUpdate>,
) -> Vec<AccountUpdate> {
    let db_write = db.write().await;

    let mut vm_updates: Vec<AccountUpdate> = Vec::new();

    for (_address, account_update) in account_updates.iter() {
        vm_updates.push(account_update.clone());
    }

    if let Some(vm_storage_values) = vm_storage {
        for (_address, vm_storage_values) in vm_storage_values.iter() {
            // ResponseAccount objects to AccountUpdate objects as required by the update method
            vm_updates.push(AccountUpdate {
                address: vm_storage_values.address,
                chain: vm_storage_values.chain,
                slots: vm_storage_values.slots.clone(),
                balance: Some(vm_storage_values.balance),
                code: Some(vm_storage_values.code.clone()),
                change: ChangeType::Creation,
            });
        }
    }

    if !vm_updates.is_empty() {
        db_write
            .update(vm_updates.clone(), Some(block))
            .await;
    }

    vm_updates
}

#[cfg(test)]
mod tests {
    use super::*;
    use revm::{
        precompile::B256,
        primitives::{Address, Bytecode, U256},
    };
    use std::{cell::RefCell, collections::HashMap, sync::Arc};
    use tokio::sync::RwLock;

    // Mock Database implementation for testing
    #[derive(Clone, Default)]
    struct MockDatabase {
        data: RefCell<HashMap<Address, AccountInfo>>,
    }

    impl EngineDatabaseInterface for MockDatabase {
        type Error = String;

        fn init_account(
            &self,
            address: Address,
            account: AccountInfo,
            _permanent_storage: Option<HashMap<U256, U256>>,
            _mocked: bool,
        ) {
            self.data
                .borrow_mut()
                .insert(address, account);
        }
    }

    impl DatabaseRef for MockDatabase {
        type Error = String;

        fn basic_ref(&self, _address: Address) -> Result<Option<AccountInfo>, Self::Error> {
            Ok(Some(AccountInfo {
                balance: U256::ZERO,
                nonce: 0,
                code_hash: B256::default(),
                code: None,
            }))
        }

        fn code_by_hash_ref(&self, _code_hash: B256) -> Result<Bytecode, Self::Error> {
            Ok(Bytecode::new())
        }

        fn storage_ref(&self, _address: Address, _index: U256) -> Result<U256, Self::Error> {
            Ok(U256::ZERO)
        }

        fn block_hash_ref(&self, _number: u64) -> Result<B256, Self::Error> {
            Ok(B256::default())
        }
    }

    unsafe impl Send for MockDatabase {}
    unsafe impl Sync for MockDatabase {}

    #[tokio::test]
    async fn test_create_engine() {
        let db = Arc::new(RwLock::new(MockDatabase::default()));
        let tokens = vec![
            "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48".to_string(),
            "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2".to_string(),
        ];

        let engine = create_engine(db, tokens.clone(), false).await;

        // Verify trace flag is unset
        assert!(!engine.trace);

        // Verify all tokens are initialized
        for token in tokens {
            let token_address = Address::parse_checksummed(token, None).expect("valid checksum");
            let account = engine
                .state
                .data
                .borrow()
                .get(&token_address)
                .unwrap()
                .clone();
            assert_eq!(account.balance, U256::default());
            assert_eq!(account.nonce, 0);
            assert_eq!(account.code_hash, B256::default());
            assert!(account.code.is_none());
        }

        // Verify external account initialization
        let external_account_address = *EXTERNAL_ACCOUNT;
        let external_account = engine
            .state
            .data
            .borrow()
            .get(&external_account_address)
            .unwrap()
            .clone();
        assert_eq!(external_account.balance, *MAX_BALANCE);
        assert_eq!(external_account.nonce, 0);
        assert_eq!(external_account.code_hash, B256::default());
        assert!(external_account.code.is_none());
    }

    #[tokio::test]
    async fn test_create_engine_with_trace() {
        let db = Arc::new(RwLock::new(MockDatabase::default()));
        let tokens = vec!["0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48".to_string()];

        let engine = create_engine(db, tokens, true).await;

        // Verify trace flag is set
        assert!(engine.trace);
    }
}
