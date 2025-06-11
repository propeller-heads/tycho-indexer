#![allow(dead_code)]
use std::{collections::HashMap, sync::RwLock};

use alloy::{
    primitives::{keccak256, Address, B256, U256},
    rpc::types::Header,
};
use lazy_static::lazy_static;
use revm::state::{AccountInfo, Bytecode};
use tycho_common::Bytes;

use crate::{
    evm::{
        engine_db::{
            create_engine,
            engine_db_interface::EngineDatabaseInterface,
            simulation_db::BlockHeader,
            SHARED_TYCHO_DB,
        },
        protocol::{
            uniswap_v4::{
                hooks::{generic_vm_hook_handler::GenericVMHookHandler, hook_handler::HookHandler},
                state::UniswapV4State,
            },
            vm::constants::ERC20_BYTECODE,
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
    /// Sum aggregated balances of the component. See ResponseProtocolState for more details.
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
        // TODO double check how the hook address and bytecode attributes are actually called
        let hook_address_bytes = params
            .attributes
            .get("hook_address")
            .ok_or_else(|| InvalidSnapshotError::MissingAttribute("hook_address".to_string()))?;

        let hook_address = Address::from_slice(&hook_address_bytes.0);

        let hook_bytecode_bytes = params
            .attributes
            .get("hook_bytecode")
            .ok_or_else(|| InvalidSnapshotError::MissingAttribute("hook_bytecode".to_string()))?;

        let bytecode =
            Bytecode::new_raw(alloy::primitives::Bytes::from(hook_bytecode_bytes.0.clone()));

        let _block_header = BlockHeader {
            number: params.block.number,
            hash: params.block.hash,
            timestamp: params.block.timestamp,
        };
        
        let engine = create_engine(SHARED_TYCHO_DB.clone(), true).map_err(|e| {
            InvalidSnapshotError::VMError(SimulationError::FatalError(format!(
                "Failed to create engine: {e:?}"
            )))
        })?;

        // Initialize all token contracts
        for token_address_bytes in params.all_tokens.keys() {
            let token_address = Address::from_slice(&token_address_bytes.0);

            // Deploy ERC20 contract for this token
            let erc20_bytecode = Bytecode::new_raw(alloy::primitives::Bytes::from(ERC20_BYTECODE));
            let code_hash = B256::from(keccak256(erc20_bytecode.clone().bytes()));

            engine.state.init_account(
                token_address,
                AccountInfo {
                    balance: U256::ZERO, // Token contracts have zero ETH balance
                    nonce: 1,
                    code_hash,
                    code: Some(erc20_bytecode),
                },
                None,
                false,
            );
        }

        let hook_handler = GenericVMHookHandler::new(hook_address, bytecode, engine)
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
