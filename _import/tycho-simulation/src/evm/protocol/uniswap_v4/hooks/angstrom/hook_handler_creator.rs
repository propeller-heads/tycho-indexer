use alloy::primitives::{aliases::U24, Address};

use super::hook_handler::{AngstromFees, AngstromHookHandler};
use crate::{
    evm::protocol::uniswap_v4::hooks::{
        hook_handler::HookHandler,
        hook_handler_creator::{HookCreationParams, HookHandlerCreator},
    },
    protocol::errors::InvalidSnapshotError,
};

pub struct AngstromHookCreator;

impl HookHandlerCreator for AngstromHookCreator {
    fn instantiate_hook_handler(
        &self,
        params: HookCreationParams,
    ) -> Result<Box<dyn HookHandler>, InvalidSnapshotError> {
        let hook_address_bytes = params
            .attributes
            .get("hooks")
            .ok_or_else(|| InvalidSnapshotError::MissingAttribute("hooks".to_string()))?;

        let pool_manager_address_bytes = params
            .attributes
            .get("balance_owner")
            .ok_or_else(|| InvalidSnapshotError::MissingAttribute("balance_owner".to_string()))?;

        let angstrom_unlocked_fee = params
            .attributes
            .get("angstrom_unlocked_fee")
            .ok_or_else(|| {
                InvalidSnapshotError::MissingAttribute("angstrom_unlocked_fee".to_string())
            })?;
        let angstrom_protocol_unlocked_fee = params
            .attributes
            .get("angstrom_protocol_unlocked_fee")
            .ok_or_else(|| {
                InvalidSnapshotError::MissingAttribute("angstrom_protocol_unlocked_fee".to_string())
            })?;
        let angstrom_removed_pool = params
            .attributes
            .get("angstrom_removed_pool")
            .ok_or_else(|| {
                InvalidSnapshotError::MissingAttribute("angstrom_removed_pool".to_string())
            })?;

        let unlock = U24::from_be_slice(angstrom_unlocked_fee);
        let protocol_unlock = U24::from_be_slice(angstrom_protocol_unlocked_fee);

        let hook_address = Address::from_slice(&hook_address_bytes.0);
        let pool_manager_address = Address::from_slice(&pool_manager_address_bytes.0);
        let pool_removed = !angstrom_removed_pool.is_zero();

        let hook_handler = AngstromHookHandler::new(
            hook_address,
            pool_manager_address,
            AngstromFees { unlock, protocol_unlock },
            pool_removed,
        );

        Ok(Box::new(hook_handler))
    }
}
