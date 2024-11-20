use std::{collections::HashMap, fmt::Debug};

use lazy_static::lazy_static;
use revm::{primitives::Address, DatabaseRef};

use crate::{
    evm::{
        engine_db_interface::EngineDatabaseInterface,
        simulation::SimulationEngine,
        simulation_db::BlockHeader,
        tycho_db::PreCachedDB,
        tycho_models::{AccountUpdate, ChangeType, ResponseAccount},
    },
    protocol::errors::SimulationError,
};

lazy_static! {
    pub static ref SHARED_TYCHO_DB: PreCachedDB =
        PreCachedDB::new().expect("Failed to create PreCachedDB");
}

/// Creates a simulation engine.
///
/// # Parameters
///
/// - `trace`: Whether to trace calls. Only meant for debugging purposes, might print a lot of data
///   to stdout.
pub fn create_engine<D: EngineDatabaseInterface + Clone>(
    db: D,
    trace: bool,
) -> Result<SimulationEngine<D>, SimulationError>
where
    <D as EngineDatabaseInterface>::Error: Debug,
    <D as DatabaseRef>::Error: Debug,
{
    let engine = SimulationEngine::new(db.clone(), trace);
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
