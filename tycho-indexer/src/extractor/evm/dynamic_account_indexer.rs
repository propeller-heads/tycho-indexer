use tycho_core::{models::Address, Bytes};

// DCI Specific EntityChanges. Each collection of dci_entrypoint_* attributes specify a contract
// that will be used on analysis. Those attributes are usually the function's getAmountOut, which
// will lead us to the contracts that are accessed on the price function.
// IDEA: Can't we use our Adapter contracts for this?
//
//         Attribute {
//             name: "dci_entrypoint_address_0".to_string(),
//             value: CONTRACT_ADDRESS.to_vec(),
//             change: ChangeType::Creation.into(),
//         },
//         Attribute {
//             name: "dci_entrypoint_function_signature_0".to_string(),
//             value: CONTRACT_SIGNATURE.to_vec(),
//             change: ChangeType::Creation.into(),
//         }
//         Attribute {
//             name: "dci_entrypoint_function_parameter_0_0".to_string(),
//             value: CONTRACT_PARAMETERS[0].to_vec(),
//             change: ChangeType::Creation.into(),
//         }
#[derive(Debug, Clone)]
pub struct ExternalAccountEntrypoint {
    pub address: Address,       // The address of the contract
    pub signature: String,      // The name of the function and parameter types
    pub parameters: Vec<Bytes>, // The parameters of the function
}

// Data model for Retriggers
// Retriggers are a collection of addresses and storage keys that trigger re-analysis
//         Attribute {
//             name: "dci_retrigger_address_0".to_string(),
//             value: CONTRACT_ADDRESS.to_vec(),
//             change: ChangeType::Creation.into(),
//         },
//         Attribute {
//             name: "dci_retrigger_storage_key_0_0".to_string(),
//             value: CONTRACT_ADDRESS.to_vec(),
//             change: ChangeType::Creation.into(),
//         },
//         Attribute {
//             name: "dci_retrigger_storage_key_0_1".to_string(),
//             value: CONTRACT_ADDRESS.to_vec(),
//             change: ChangeType::Creation.into(),
//         },
#[derive(Debug, Clone)]
pub struct EntrypointRetriggers {
    pub addresses: Vec<Address>,  // Collection of addresses
    pub storage_keys: Vec<Bytes>, // Collection of storage keys that trigger re-analysis
}

// Data model for Known Contracts. Those are contracts that are static (cannot be changed during a
// contract's lifetime), so we can index them without the need of a static analysis.
//         Attribute {
//             name: "external_contract_address_0".to_string(),
//             value: CONTRACT_ADDRESS.to_vec(),
//             change: ChangeType::Creation.into(),
//         },
#[derive(Debug, Clone)]
pub struct KnownContracts {
    pub related_contracts: Vec<Address>, // Collection of related contracts (e.g., Oracles)
}
