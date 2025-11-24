use std::{collections::HashMap, str::FromStr, sync::RwLock};

use alloy::primitives::{Address, U256};
use lazy_static::lazy_static;
use revm::{primitives::KECCAK_EMPTY, state::AccountInfo};
use tycho_common::{models::token::Token, simulation::errors::SimulationError, Bytes};

use crate::{
    evm::{
        engine_db::{create_engine, engine_db_interface::EngineDatabaseInterface, SHARED_TYCHO_DB},
        protocol::{
            uniswap_v4::{
                hooks::{
                    angstrom::hook_handler_creator::AngstromHookCreator,
                    generic_vm_hook_handler::GenericVMHookHandler, hook_handler::HookHandler,
                },
                state::UniswapV4State,
            },
            vm::constants::EXTERNAL_ACCOUNT,
        },
    },
    protocol::errors::InvalidSnapshotError,
};

/// Parameters for creating a HookHandler.
pub struct HookCreationParams<'a> {
    hook_address: Address,
    account_balances: &'a HashMap<Bytes, HashMap<Bytes, Bytes>>,
    all_tokens: &'a HashMap<Bytes, Token>,
    #[allow(dead_code)]
    state: UniswapV4State,
    /// Attributes of the component. If an attribute's value is a `bigint`,
    /// it will be encoded as a big endian signed hex string. See ResponseProtocolState for more
    /// details.
    pub(crate) attributes: &'a HashMap<String, Bytes>,
    #[allow(dead_code)]
    /// Mapping from token address to big-endian encoded balance for this component.
    balances: &'a HashMap<Bytes, Bytes>,
    /// Show vm traces in simulations or not
    vm_traces: Option<bool>,
}

impl<'a> HookCreationParams<'a> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        hook_address: Address,
        account_balances: &'a HashMap<Bytes, HashMap<Bytes, Bytes>>,
        all_tokens: &'a HashMap<Bytes, Token>,
        state: UniswapV4State,
        attributes: &'a HashMap<String, Bytes>,
        balances: &'a HashMap<Bytes, Bytes>,
        vm_traces: Option<bool>,
    ) -> Self {
        Self { hook_address, account_balances, all_tokens, state, attributes, balances, vm_traces }
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
        let pool_manager_address_bytes = params
            .attributes
            .get("balance_owner")
            .ok_or_else(|| InvalidSnapshotError::MissingAttribute("balance_owner".to_string()))?;

        let pool_manager_address = Address::from_slice(&pool_manager_address_bytes.0);

        let limits_entrypoint = params
            .attributes
            .get("limits_entrypoint")
            .and_then(|bytes| String::from_utf8(bytes.0.to_vec()).ok());

        let is_euler = params
            .attributes
            .get("hook_identifier")
            .and_then(|bytes| String::from_utf8(bytes.0.to_vec()).ok())
            .unwrap_or_default() ==
            "euler_v1";

        let mut trace = false;
        if let Some(vm_traces) = params.vm_traces {
            trace = vm_traces
        }

        let engine = create_engine(SHARED_TYCHO_DB.clone(), trace).map_err(|e| {
            InvalidSnapshotError::VMError(SimulationError::FatalError(format!(
                "Failed to create engine: {e:?}"
            )))
        })?;

        let external_account_info = AccountInfo {
            balance: U256::from(0),
            nonce: 0u64,
            code_hash: KECCAK_EMPTY,
            code: None,
        };

        engine
            .state
            .init_account(*EXTERNAL_ACCOUNT, external_account_info, None, true)
            .map_err(|err| {
                InvalidSnapshotError::VMError(SimulationError::FatalError(format!(
                    "Failed to init external account: {err:?}"
                )))
            })?;

        let hook_handler = GenericVMHookHandler::new(
            params.hook_address,
            engine,
            pool_manager_address,
            params.all_tokens.clone(),
            params.account_balances.clone(),
            limits_entrypoint,
            is_euler,
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

pub fn initialize_hook_handlers() -> Result<(), SimulationError> {
    let angstrom_hook_address = Address::from_str("0x0000000aa232009084Bd71A5797d089AA4Edfad4")
        .map_err(|_| {
            SimulationError::FatalError("Failed to parse Angstrom hook address".to_string())
        })?;
    register_hook_handler(angstrom_hook_address, Box::new(AngstromHookCreator))?;

    Ok(())
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
