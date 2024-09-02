use std::collections::HashMap;
use tycho_core::{models::Address, Bytes};

// This file defines the data models for the Dynamic Contract Indexer (DCI).
// In the comments, you will find examples of how this data might be added to Substreams via
// attributes.
// The purpose of the DCI is to identify contracts accessed by another contract so that we can index them.
// The list of contracts should be saved as a relation to our protocol components and propagated
// to the DynamicContractExtractor for contract data extraction.

// 1st Data Model: External Account Entrypoint
//
// This data model guides the DCI on which functions should be explored during
// the fuzz analysis to identify all external contracts accessed by a
// ProtocolComponent. We aim to identify all external contracts that can be called by the
// contract's public functions, especially those covered in the AdapterContract
// (e.g., swap, mint, burn, getFees, permissions).
// Each `ExternalAccountEntrypoint` is defined by an address, signature, and
// parameters used to call the function. All functions will undergo fuzzing, so it is not
// necessary to specify all possible parameter values. It suffices to specify only special cases,
// such as a specific address that triggers particular behavior and calls a specific contract.
#[derive(Debug, Clone)]
pub struct ExternalAccountEntrypoint {
    pub address: Address,  // The contract's address
    pub signature: String, // The function name and parameter types
    pub parameters: HashMap<usize, Vec<Bytes>>, /* An optional HashMap containing the index
                            * of the parameter and an array of
                            * values to test during fuzzing. These parameters are only
                            * values that need special attention during fuzzing; other cases are
                            * still tested via the fuzzer.
                            * See: https://book.getfoundry.sh/forge/fuzz-testing#configuring-fuzz-test-execution
                            */
}
// SUBSTREAMS EXAMPLE: How would we handle Balancer's AuthorizerWithAdaptorValidation.canPerform
// function?
//
// let entrypoint = ExternalAccountEntrypoint {
//     address: "0x6048A8c631Fb7e77EcA533Cf9C29784e482391e7".to_string(),
//     signature: "canPerform(bytes32, address, address)".to_bytes(),
//     parameters: vec![
//     (0, vec!["0xa5547190e3d59f2bfeb4174ca3454b2f2acaeed644bc7ad7018014516f73f2bd".to_string()]),
//     (1, vec!["0x9008D19f58AAbD9eD0D60971565AA8510560ab41".to_bytes()]),
//     (2, vec!["0xe96a45f66bdDA121B24F0a861372A72E8889523d".to_bytes()]),
//     ]
//     .into_iter()
//     .collect(),
// };
// Attribute {
//     name: "dci_entrypoint_0".to_string(),
//     value: bincode::serialize(&entrypoint).unwrap(),
//     change: ChangeType::Creation.into(),
// },

// Special Case: Analysis Retriggers
// Occasionally, a contract needs to be re-analyzed when a specific event occurs. This can be detected
// on the Substreams side when a particular event is emitted or when a storage slot in a specific
// contract changes. If this happens, Substreams should emit a new `ExternalAccountEntrypoint` or
// modify the existing one.
// Q: What if a storage change impacts the `ExternalAccountEntrypoint`?
// A: We either emit a new `ExternalAccountEntrypoint` or modify the existing one, if possible.
// Example:
// Attribute {
//     name: "dci_entrypoint_0".to_string(),
//     value: bincode::serialize(&new_entrypoint).unwrap(),
//     change: ChangeType::Change.into(),
// },

// 2nd Data Model: Known Contracts
// This data model guides Tycho on which contracts are known and should be indexed.
// These contracts don't require analysis and can be indexed directly.
//         Attribute {
//             name: "external_contract_address_0".to_string(),
//             value: CONTRACT_ADDRESS.to_vec(),
//             change: ChangeType::Creation.into(),
//         },
// Q: Why include the index in the attribute name?
// A: To easily identify the contract address when it needs updating.
#[derive(Debug, Clone)]
pub struct KnownContracts {
    pub related_contracts: Vec<Address>, // Collection of related contracts (e.g., Oracles)
}
