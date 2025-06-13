#![allow(dead_code)]
use std::{collections::HashMap, sync::RwLock};

use alloy::{primitives::Address, rpc::types::Header};
use lazy_static::lazy_static;
use tycho_common::Bytes;

use crate::{
    evm::{
        engine_db::{create_engine, SHARED_TYCHO_DB},
        protocol::uniswap_v4::{
            hooks::{generic_vm_hook_handler::GenericVMHookHandler, hook_handler::HookHandler},
            state::UniswapV4State,
        },
    },
    models::Token,
    protocol::errors::{InvalidSnapshotError, SimulationError},
};

/// Parameters for creating a HookHandler.
pub struct HookCreationParams<'a> {
    block: Header,
    account_balances: &'a HashMap<Bytes, HashMap<Bytes, Bytes>>,
    all_tokens: &'a HashMap<Bytes, Token>,
    state: UniswapV4State,
    /// Attributes of the component. If an attribute's value is a `bigint`,
    /// it will be encoded as a big endian signed hex string. See ResponseProtocolState for more
    /// details.
    pub(crate) attributes: &'a HashMap<String, Bytes>,
    /// Mapping from token address to big-endian encoded balance for this component.
    balances: &'a HashMap<Bytes, Bytes>,
}

impl<'a> HookCreationParams<'a> {
    pub fn new(
        block: Header,
        account_balances: &'a HashMap<Bytes, HashMap<Bytes, Bytes>>,
        all_tokens: &'a HashMap<Bytes, Token>,
        state: UniswapV4State,
        attributes: &'a HashMap<String, Bytes>,
        balances: &'a HashMap<Bytes, Bytes>,
    ) -> Self {
        Self { block, account_balances, all_tokens, state, attributes, balances }
    }
}

pub trait HookHandlerCreator: Send + Sync {
    fn instantiate_hook_handler(
        &self,
        params: HookCreationParams,
    ) -> Result<Box<dyn HookHandler>, InvalidSnapshotError>;
}

pub struct GenericVMHookHandlerCreator;

impl HookHandlerCreator for GenericVMHookHandlerCreator {
    fn instantiate_hook_handler(
        &self,
        params: HookCreationParams<'_>,
    ) -> Result<Box<dyn HookHandler>, InvalidSnapshotError> {
        let hook_address_bytes = params
            .attributes
            .get("hook_address")
            .ok_or_else(|| InvalidSnapshotError::MissingAttribute("hook_address".to_string()))?;

        let pool_manager_address_bytes = params
            .attributes
            .get("pool_manager_address")
            .ok_or_else(|| {
                InvalidSnapshotError::MissingAttribute("pool_manager_address".to_string())
            })?;

        let hook_address = Address::from_slice(&hook_address_bytes.0);
        let pool_manager_address = Address::from_slice(&pool_manager_address_bytes.0);

        let engine = create_engine(SHARED_TYCHO_DB.clone(), true).map_err(|e| {
            InvalidSnapshotError::VMError(SimulationError::FatalError(format!(
                "Failed to create engine: {e:?}"
            )))
        })?;

        let hook_handler = GenericVMHookHandler::new(
            hook_address,
            engine,
            pool_manager_address,
            params.all_tokens.clone(),
            params.account_balances.clone(),
        )
        .map_err(InvalidSnapshotError::VMError)?;

        Ok(Box::new(hook_handler))
    }
}

// Workaround for stateless decoder trait.
// Mapping from hook address to the handler creator.
lazy_static! {
    static ref HANDLER_FACTORY: RwLock<HashMap<Address, Box<dyn HookHandlerCreator>>> =
        RwLock::new(HashMap::new());
}

lazy_static! {
    static ref DEFAULT_HANDLER: Box<dyn HookHandlerCreator> =
        Box::new(GenericVMHookHandlerCreator {});
}

pub fn register_hook_handler(
    hook: Address,
    handler: Box<dyn HookHandlerCreator>,
) -> Result<(), SimulationError> {
    HANDLER_FACTORY
        .write()
        .map_err(|e| SimulationError::FatalError(e.to_string()))?
        .insert(hook, handler);
    Ok(())
}

pub fn instantiate_hook_handler(
    hook_address: &Address,
    params: HookCreationParams<'_>,
) -> Result<Box<dyn HookHandler>, InvalidSnapshotError> {
    let factory = HANDLER_FACTORY
        .read()
        .map_err(|e| InvalidSnapshotError::VMError(SimulationError::FatalError(e.to_string())))?;
    if let Some(creator) = factory.get(hook_address) {
        creator.instantiate_hook_handler(params)
    } else {
        DEFAULT_HANDLER.instantiate_hook_handler(params)
    }
}
