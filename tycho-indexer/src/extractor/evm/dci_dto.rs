use std::collections::HashMap;
use tycho_core::{models::Address, Bytes};

// Here we describe the data models for the Dynamic Contract Indexer.
// In the comments, there is an example of how this data could be added to the substreams via
// attributes.
// The goal of the DCI is to identify contracts that are accessed by a contract, so we can index
// them. The list of contracts should be saved as a relation to our protocol components, and
// propagated to DynamicContractExtractor, so it can extract the contract data.

// 1st Data Model: External Account Entrypoint
//
// This data model serves to orient the DCI on which functions should be explored when
// running the fuzz analysis to identify all the external contracts that are accessed by a
// ProtocolComponent. We want to identify all the external contracts that can be called by the
// contract's public functions, specially the functions that are covered in the AdapterContract
// (swap, mint, burn, getFees, permissions, etc).
// Each ExternalAccountEntrypoint is a set of address, signature and
// parameters that will be used to call the function. All the functions will be fuzzed, so it's not
// necessary to specify all the possible values of the parameters. It's enough to specify only
// special cases, like a specific address that, when used to call a function can trigger a specific
// behavior and call a specific contract.
#[derive(Debug, Clone)]
pub struct ExternalAccountEntrypoint {
    pub address: Address,  // The address of the contract
    pub signature: String, // The name of the function and parameter types
    pub parameters: HashMap<usize, Vec<Bytes>>, /* An optional HashMap that contains the index
                           * of the parameter, and an array of
                           * values to be tested for the function. These parameters are only
                           * values that need to be tried during fuzzing, while the other cases are
                            still tested via fuzzer.
                            https://book.getfoundry.sh/forge/fuzz-testing#configuring-fuzz-test-execution
                            */
}
// SUBSTREAMS EXAMPLE: How would we deal with Balancer's AuthorizerWithAdaptorValidation.canPerform
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

// Special case: Analysis Retriggers
// Sometimes, we need to re-analyze a contract when a specific event happens. This can be detected
// on Substreams side when a specific event is emitted, or when a storage slot of a specific
// contract is changed. If that happens, Substreams should emit a new ExternalAccountEntrypoint or
// modify the existing one.
// Q: What happens if a storage change affects the ExternalAccountEntrypoint?
// A: We emit either a new ExternalAccountEntrypoint, or modify the existing one, if possible.
// Example:
// Attribute {
//     name: "dci_entrypoint_0".to_string(),
//     value: bincode::serialize(&new_entrypoint).unwrap(),
//     change: ChangeType::Change.into(),
// },

// 2nd Data Model: Known Contracts
// This data model serves to orient Tycho on which contracts are known and should be indexed.
// Since they don't require analysis, they can be indexed directly.
//         Attribute {
//             name: "external_contract_address_0".to_string(),
//             value: CONTRACT_ADDRESS.to_vec(),
//             change: ChangeType::Creation.into(),
//         },
// Q. Why have the index in the attribute name?
// A. So we can easily identify the contract address when we need to update it.
#[derive(Debug, Clone)]
pub struct KnownContracts {
    pub related_contracts: Vec<Address>, // Collection of related contracts (e.g., Oracles)
}
