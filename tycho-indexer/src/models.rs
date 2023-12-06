use std::collections::HashMap;
use crate::hex_bytes::Bytes;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use strum_macros::{Display, EnumString};

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

#[allow(dead_code)]
pub enum ProtocolSystem {
    Ambient,
}

#[allow(dead_code)]
pub enum ImplementationType {
    Vm,
    Custom,
}

#[allow(dead_code)]
pub enum FinancialType {
    Swap,
    Lend,
    Leverage,
    Psm,
}

#[allow(dead_code)]
pub struct ProtocolType {
    name: String,
    attribute_schema: serde_json::Value,
    financial_type: FinancialType,
    implementation_type: ImplementationType,
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

#[derive(Debug)]
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

pub trait NormalisedMessage:
    Serialize + DeserializeOwned + std::fmt::Debug + std::fmt::Display + Send + Sync + Clone + 'static
{
    fn source(&self) -> ExtractorIdentity;
}

pub struct ProtocolComponent <T>{
    // an id for this component, could be hex repr of contract address
    id: String,
    // what system this component belongs to
    protocol_system: ProtocolSystem,
    // more metadata information about the components general type (swap, lend, bridge, etc.)
    protocol_type: ProtocolType,
    // holds the tokens tradable
    tokens: Vec<T>,
    // allows to express some validation over the attributes if necessary
    attribute_schema: Bytes,
}

pub struct ProtocolState {
    // associates the back to a component, which has metadata like type, tokens , etc.
    component_id: String,
    // holds all the protocol specific attributes, validates by the components schema
    attributes: HashMap<String, Bytes>,
    // via transaction, we can trace back when this state became valid
}
