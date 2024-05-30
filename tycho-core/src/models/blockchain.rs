use crate::{
    models::{
        contract::ContractDelta,
        protocol::{ComponentBalance, ProtocolComponent, ProtocolComponentStateDelta},
        Chain, ComponentId,
    },
    Bytes,
};
use chrono::NaiveDateTime;
use std::collections::HashMap;

#[derive(Clone, Default, PartialEq, Debug)]
pub struct Block {
    pub hash: Bytes,
    pub parent_hash: Bytes,
    pub number: u64,
    pub chain: Chain,
    pub ts: NaiveDateTime,
}

#[derive(Clone, Default, PartialEq, Debug)]
pub struct Transaction {
    pub hash: Bytes,
    pub block_hash: Bytes,
    pub from: Bytes,
    pub to: Option<Bytes>,
    pub index: u64,
}

pub struct BlockTransactionDeltas<T> {
    pub extractor: String,
    pub chain: Chain,
    pub block: Block,
    pub revert: bool,
    pub deltas: Vec<TransactionDeltaGroup<T>>,
}

#[allow(dead_code)]
pub struct TransactionDeltaGroup<T> {
    changes: T,
    protocol_component: HashMap<String, ProtocolComponent>,
    component_balances: HashMap<String, ComponentBalance>,
    component_tvl: HashMap<String, f64>,
    tx: Transaction,
}

#[derive(Debug, Clone, PartialEq)]
pub struct BlockAggregatedDeltas {
    pub extractor: String,
    pub chain: Chain,
    pub block: Block,
    pub finalised_block_height: u64,
    pub revert: bool,
    pub state_deltas: HashMap<String, ProtocolComponentStateDelta>,
    pub account_deltas: HashMap<Bytes, ContractDelta>,
    pub new_components: HashMap<String, ProtocolComponent>,
    pub deleted_components: HashMap<String, ProtocolComponent>,
    pub component_balances: HashMap<ComponentId, HashMap<Bytes, ComponentBalance>>,
    #[allow(dead_code)]
    component_tvl: HashMap<String, f64>,
}

impl BlockAggregatedDeltas {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        extractor: &str,
        chain: Chain,
        block: Block,
        finalised_block_height: u64,
        revert: bool,
        state_deltas: &HashMap<String, ProtocolComponentStateDelta>,
        account_deltas: &HashMap<Bytes, ContractDelta>,
        new_components: &HashMap<String, ProtocolComponent>,
        deleted_components: &HashMap<String, ProtocolComponent>,
        component_balances: &HashMap<ComponentId, HashMap<Bytes, ComponentBalance>>,
        component_tvl: &HashMap<String, f64>,
    ) -> Self {
        Self {
            extractor: extractor.to_string(),
            chain,
            block,
            finalised_block_height,
            revert,
            state_deltas: state_deltas.clone(),
            account_deltas: account_deltas.clone(),
            new_components: new_components.clone(),
            deleted_components: deleted_components.clone(),
            component_balances: component_balances.clone(),
            component_tvl: component_tvl.clone(),
        }
    }
}

pub trait BlockScoped {
    fn block(&self) -> Block;
}

impl BlockScoped for BlockAggregatedDeltas {
    fn block(&self) -> Block {
        self.block.clone()
    }
}
