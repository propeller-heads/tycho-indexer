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

pub enum ProtocolSystem {
    Ambient,
}

pub enum ImplementationType {
    Vm,
    Custom,
}

pub enum FinancialType {
    Swap,
    Lend,
    Leverage,
    Psm,
}

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

pub trait NormalisedMessage:
    Serialize + DeserializeOwned + std::fmt::Debug + Send + Sync + Clone + 'static
{
    fn source(&self) -> ExtractorIdentity;
}

// TODO: will require implementing
pub struct ProtocolComponent {}
