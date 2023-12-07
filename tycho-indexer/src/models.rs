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
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
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

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
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
        name: &str,
        chain: Chain,
        attributes: Option<serde_json::Value>,
        cursor: &[u8],
    ) -> Self {
        ExtractionState {
            name: name.to_owned(),
            chain,
            attributes: attributes.unwrap_or_default(),
            cursor: cursor.to_vec(),
        }
    }
}

pub trait NormalisedMessage:
    Serialize + DeserializeOwned + std::fmt::Debug + Send + Sync + Clone + 'static
{
    fn source(&self) -> ExtractorIdentity;
}

// remove this and use chain specific component
#[allow(dead_code)]
pub struct ProtocolComponent {
    id: Vec<u8>,
    chain: Chain,
    protocol_type_name: String,
    protocol_system: ProtocolSystem,
    token_ids: Vec<Vec<u8>>,
    calls_contracts: Vec<Vec<u8>>,
    attributes: serde_json::Value,
}

// remove this and use chain specific implementation
#[allow(dead_code)]
pub struct ProtocolState {
    id: Vec<u8>,
    chain: Chain,
    protocol_system: ProtocolSystem,
    tvl: Vec<f64>,
    inertias: Vec<f64>,
    attributes: serde_json::Value,
    modify_tx: Vec<u8>,
}
