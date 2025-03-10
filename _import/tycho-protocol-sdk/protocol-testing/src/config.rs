use std::collections::HashMap;

use hex::FromHex;
use serde::{Deserialize, Serialize};

/// Represents a hexadecimal byte string: Check if we already have a default impl for this
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "String", into = "String")]
pub struct HexBytes(Vec<u8>);

impl From<String> for HexBytes {
    fn from(s: String) -> Self {
        let s = s
            .trim_start_matches("0x")
            .to_lowercase();
        HexBytes(Vec::from_hex(s).unwrap_or_default())
    }
}

impl From<HexBytes> for String {
    fn from(val: HexBytes) -> Self {
        format!("0x{}", hex::encode(val.0))
    }
}

/// Represents a ProtocolComponent with its main attributes
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ProtocolComponentExpectation {
    pub id: String,
    pub tokens: Vec<HexBytes>,
    #[serde(default)]
    pub static_attributes: HashMap<String, HexBytes>,
    pub creation_tx: HexBytes,
}

/// Represents a ProtocolComponent with test configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ProtocolComponentWithTestConfig {
    #[serde(flatten)]
    pub base: ProtocolComponentExpectation,
    #[serde(default = "default_false")]
    pub skip_simulation: bool,
}

fn default_false() -> bool {
    false
}

/// Configuration for an individual test
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct IntegrationTest {
    pub name: String,
    pub start_block: u64,
    pub stop_block: u64,
    pub initialized_accounts: Option<Vec<String>>,
    pub expected_components: Vec<ProtocolComponentWithTestConfig>,
}

/// Main integration test configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct IntegrationTestsConfig {
    pub substreams_yaml_path: String,
    pub adapter_contract: String,
    pub adapter_build_signature: Option<String>,
    pub adapter_build_args: Option<String>,
    pub initialized_accounts: Option<Vec<String>>,
    pub skip_balance_check: bool,
    pub protocol_type_names: Vec<String>,
    pub tests: Vec<IntegrationTest>,
}
