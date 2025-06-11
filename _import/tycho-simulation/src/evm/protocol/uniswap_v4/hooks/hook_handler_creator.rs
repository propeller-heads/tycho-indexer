#![allow(dead_code)]
use std::{collections::HashMap, sync::RwLock};

use alloy::{primitives::Address, rpc::types::Header};
use lazy_static::lazy_static;
use tycho_common::Bytes;

use crate::{
    evm::protocol::uniswap_v4::{hooks::hook_handler::HookHandler, state::UniswapV4State},
    models::Token,
    protocol::errors::InvalidSnapshotError,
};

/// Parameters for creating a HookHandler.
pub struct HookCreationParams<'a> {
    block: Header,
    account_balances: &'a HashMap<Bytes, HashMap<Bytes, Bytes>>,
    all_tokens: &'a HashMap<Bytes, Token>,
    state: UniswapV4State,
    /// Attributes of the component. If an attribute's value is a `bigint`,
    /// it will be encoded as a big endian signed hex string.
    pub(crate) attributes: &'a HashMap<String, Bytes>,
    /// Sum aggregated balances of the component.
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

// Workaround for stateless decoder trait.
lazy_static! {
    static ref HANDLER_FACTORY: RwLock<HashMap<Address, Box<dyn HookHandlerCreator>>> =
        RwLock::new(HashMap::new());
}
