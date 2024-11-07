// TODO: remove skip for clippy dead_code check
#![allow(dead_code)]
use std::{collections::HashMap, fmt::Debug};

use lazy_static::lazy_static;
use revm::{
    primitives::{AccountInfo, Address, KECCAK_EMPTY},
    DatabaseRef,
};

use crate::{
    evm::{
        engine_db_interface::EngineDatabaseInterface,
        simulation::SimulationEngine,
        simulation_db::BlockHeader,
        tycho_db::PreCachedDB,
        tycho_models::{AccountUpdate, ChangeType, ResponseAccount},
    },
    protocol::{
        errors::SimulationError,
        vm::{
            constants::{EXTERNAL_ACCOUNT, MAX_BALANCE},
            utils::load_erc20_bytecode,
        },
    },
};

lazy_static! {
    pub static ref SHARED_TYCHO_DB: PreCachedDB =
        PreCachedDB::new().expect("Failed to create PreCachedDB");
}

/// Creates a simulation engine with a mocked ERC20 contract at the given addresses.
///
/// # Parameters
///
/// - `mocked_tokens`: A list of addresses at which a mocked ERC20 contract should be inserted.
/// - `trace`: Whether to trace calls. Only meant for debugging purposes, might print a lot of data
///   to stdout.
pub fn create_engine<D: EngineDatabaseInterface + Clone + DatabaseRef>(
    db: D,
    tokens: Vec<String>,
    trace: bool,
) -> Result<SimulationEngine<D>, SimulationError>
where
    <D as EngineDatabaseInterface>::Error: Debug,
    <D as DatabaseRef>::Error: Debug,
{
    let engine = SimulationEngine::new(db.clone(), trace);

    let contract_bytecode = load_erc20_bytecode()?;

    for token in tokens {
        let info = AccountInfo {
            balance: Default::default(),
            nonce: 0,
            code_hash: KECCAK_EMPTY,
            code: Some(contract_bytecode.clone()),
        };
        engine.state.init_account(
            Address::parse_checksummed(token, None).map_err(|_| {
                SimulationError::EncodingError("Checksum for token address must be valid".into())
            })?,
            info,
            None,
            false,
        );
    }

    engine.state.init_account(
        *EXTERNAL_ACCOUNT,
        AccountInfo { balance: *MAX_BALANCE, nonce: 0, code_hash: KECCAK_EMPTY, code: None },
        None,
        false,
    );

    Ok(engine)
}

pub async fn update_engine(
    db: PreCachedDB,
    block: BlockHeader,
    vm_storage: Option<HashMap<Address, ResponseAccount>>,
    account_updates: HashMap<Address, AccountUpdate>,
) -> Vec<AccountUpdate> {
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
        db.update(vm_updates.clone(), Some(block))
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
    use rstest::rstest;
    use std::{cell::RefCell, collections::HashMap};

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

    #[rstest]
    fn test_create_engine() {
        let db = MockDatabase::default();
        let tokens = vec![
            "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48".to_string(),
            "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2".to_string(),
        ];

        let engine = create_engine(db, tokens.clone(), false);

        let state_data = engine.unwrap().state.data;
        // Verify all tokens are initialized
        for token in tokens {
            let token_address = Address::parse_checksummed(token, None).expect("valid checksum");
            let account = state_data
                .borrow()
                .get(&token_address)
                .unwrap()
                .clone();
            assert_eq!(account.balance, U256::default());
            assert_eq!(account.nonce, 0);
            assert_eq!(account.code_hash, KECCAK_EMPTY);
            assert!(account.code.is_some());
        }

        // Verify external account initialization
        let external_account_address = *EXTERNAL_ACCOUNT;
        let external_account = state_data
            .borrow()
            .get(&external_account_address)
            .unwrap()
            .clone();
        assert_eq!(external_account.balance, *MAX_BALANCE);
        assert_eq!(external_account.nonce, 0);
        assert_eq!(external_account.code_hash, KECCAK_EMPTY);
        assert!(external_account.code.is_none());
    }

    #[rstest]
    fn test_create_engine_with_trace() {
        let db = MockDatabase::default();
        let tokens = vec!["0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48".to_string()];

        let engine = create_engine(db, tokens, true);

        // Verify trace flag is set
        assert!(engine.unwrap().trace);
    }
}
