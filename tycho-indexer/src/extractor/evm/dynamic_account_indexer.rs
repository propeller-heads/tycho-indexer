use tycho_core::{models::Address, Bytes};

// Here we describe the data models for the Dynamic Contract Indexer.
// In the comments, there is an example of how this data could be added to the substreams via
// attributes.
// The goal of the DCI is to identify contracts that are accessed by a contract, so we can index
// them. The list of contracts should be saved as a relation to our protocol components, and
// propagated to DynamicContractExtractor, so it can extract the contract data.

// DCI Specific EntityChanges. Each collection of dci_entrypoint_* attributes specify a contract
// that will be used on analysis.
//
// Those attributes are, for example, an Oracle address, its interface and the parameters to call.
// IDEA: Can't we skip this and use our Adapter contracts for this? If yes, ExternalAccountEntrypoint should be
// removed.
//
//         Attribute {
//             name: "dci_entrypoint_address_0".to_string(),
//             value: CONTRACT_ADDRESS.to_vec(),
//             change: ChangeType::Creation.into(),
//         },
//         NAME FORMAT: dci_entrypoint_function_address_{address}_{function}

//         Attribute {
//             name: "dci_entrypoint_function_signature_0_0".to_string(),
//             value: CONTRACT_SIGNATURE.to_vec(),
//             change: ChangeType::Creation.into(),
//         }
//         NAME FORMAT: dci_entrypoint_function_signature_{address}_{function}

//         // getAmountOut(address tokenIn, address tokenOut, uint256 amountIn, caller address)
//         Attribute {
//             name: "dci_entrypoint_function_parameter_0_0_0_0".to_string(),
//             value: CONTRACT_PARAMETERS[0][0].to_vec(),
//             change: ChangeType::Creation.into(),
//         }
//         NAME FORMAT: dci_entrypoint_function_parameter_{address}_{function}_{parameter}_{idx}
//         // [0][1][3] -> 0x00000001232cow -> CowSwapCaller

#[derive(Debug, Clone)]
pub struct ExternalAccountEntrypoint {
    pub address: Address,       // The address of the contract
    pub signature: String,      // The name of the function and parameter types
    pub parameters: Vec<Bytes>, // The parameters of the function
}

// Example: How would we deal with AuthorizerWithAdaptorValidation.canperform function?
// We index it as an entrypoint:
// ExternalAccountEntrypoint{
//     address: "0x6048A8c631Fb7e77EcA533Cf9C29784e482391e7".to_string(),
//     signature: "canPerform(bytes32, address, address)".to_string(),
//     parameters: vec!["0xa5547190e3d59f2bfeb4174ca3454b2f2acaeed644bc7ad7018014516f73f2bd",
//                      "0x9008D19f58AAbD9eD0D60971565AA8510560ab41",
//                      "0xe96a45f66bdDA121B24F0a861372A72E8889523d"]
// }
// Substreams need to watch for storage slots where the address of AuthorizerWithAdaptorValidation
// is stored (it can be changed). In this case, we can watch for events instead.
// If it changes:
//     get the new value of storage slot
//     emit new ExternalAccountEntrypoint{
//          address: "0xnew_value".to_string(),
//          signature: "canPerform(bytes32, address, address)".to_string(),
//          parameters: vec!["0xa5547190e3d59f2bfeb4174ca3454b2f2acaeed644bc7ad7018014516f73f2bd",
//                          "0x9008D19f58AAbD9eD0D60971565AA8510560ab41",
//                          "0xe96a45f66bdDA121B24F0a861372A72E8889523d"]

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
