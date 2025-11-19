use std::collections::HashMap;

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
            .ok_or_else(|| InvalidSnapshotError::MissingAttribute("hook_address".to_string()))?;

        let pool_manager_address_bytes = params
            .attributes
            .get("balance_owner")
            .ok_or_else(|| {
                InvalidSnapshotError::MissingAttribute("pool_manager_address".to_string())
            })?;

        let angstrom_pool_config = params
            .attributes
            .get("angstrom_pool_config")
            .ok_or_else(|| {
                InvalidSnapshotError::MissingAttribute("angstrom_pool_config".to_string())
            })?;

        // Validate format: [count:u8][data:46*count bytes]
        if angstrom_pool_config.is_empty() || (angstrom_pool_config.len() - 1) % 46 != 0 {
            return Err(InvalidSnapshotError::ValueError(
                "angstrom pool config values are not encoded correctly".to_string(),
            ));
        }

        let mut pools = HashMap::new();
        let count = angstrom_pool_config[0];
        let mut offset = 1;

        for _ in 0..count {
            let token_0 = Address::from_slice(&angstrom_pool_config[offset..offset + 20]);
            let token_1 = Address::from_slice(&angstrom_pool_config[offset + 20..offset + 40]);
            let unlock = U24::from_be_slice(&angstrom_pool_config[offset + 40..offset + 43]);
            let protocol_unlock =
                U24::from_be_slice(&angstrom_pool_config[offset + 43..offset + 46]);
            pools.insert((token_0, token_1), AngstromFees { unlock, protocol_unlock });

            offset += 46;
        }

        let hook_address = Address::from_slice(&hook_address_bytes.0);
        let pool_manager_address = Address::from_slice(&pool_manager_address_bytes.0);

        let hook_handler = AngstromHookHandler::new(hook_address, pool_manager_address, pools);

        Ok(Box::new(hook_handler))
    }
}
