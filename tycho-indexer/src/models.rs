#![allow(dead_code)]
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::extractor::evm::Transaction;
use strum_macros::{Display, EnumString};

use crate::hex_bytes::Bytes;

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, EnumString, Display, Default,
)]
#[serde(rename_all = "lowercase")]
#[strum(serialize_all = "lowercase")]
pub enum Chain {
    #[default]
    Ethereum,
    Starknet,
    ZkSync,
}

#[derive(PartialEq, Debug, Clone, Default, Deserialize, Serialize, Copy)]
pub enum ProtocolSystem {
    #[default]
    Ambient,
}

#[derive(PartialEq, Debug, Clone, Default, Deserialize, Serialize)]
pub enum ImplementationType {
    #[default]
    Vm,
    Custom,
}

#[derive(PartialEq, Debug, Clone, Default, Deserialize, Serialize)]
pub enum FinancialType {
    #[default]
    Swap,
    Lend,
    Leverage,
    Psm,
}

#[derive(PartialEq, Debug, Clone, Default, Deserialize, Serialize)]
pub struct ProtocolType {
    pub name: String,
    pub attribute_schema: serde_json::Value,
    pub financial_type: FinancialType,
    pub implementation_type: ImplementationType,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct ExtractorIdentity {
    pub chain: Chain,
    pub name: String,
}

impl ExtractorIdentity {
    pub fn new(chain: Chain, name: &str) -> Self {
        Self { chain, name: name.to_owned() }
    }
}

impl std::fmt::Display for ExtractorIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.chain, self.name)
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct ExtractionState {
    pub name: String,
    pub chain: Chain,
    pub attributes: serde_json::Value,
    pub cursor: Vec<u8>,
}

impl ExtractionState {
    pub fn new(
        name: String,
        chain: Chain,
        attributes: Option<serde_json::Value>,
        cursor: &[u8],
    ) -> Self {
        ExtractionState {
            name,
            chain,
            attributes: attributes.unwrap_or_default(),
            cursor: cursor.to_vec(),
        }
    }
}

#[typetag::serde(tag = "type")]
pub trait NormalisedMessage: std::fmt::Debug + std::fmt::Display + Send + Sync + 'static {
    fn source(&self) -> ExtractorIdentity;
}

#[allow(dead_code)]
pub struct ProtocolState {
    // associates back to a component, which has metadata like type, tokens , etc.
    pub component_id: String,
    // holds all the protocol specific attributes, validates by the components schema
    pub attributes: HashMap<String, Bytes>,
    // via transaction, we can trace back when this state became valid
    pub modify_tx: Transaction,
}
