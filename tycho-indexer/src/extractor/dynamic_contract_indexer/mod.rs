pub mod cache;
mod component_metadata;
pub(super) mod dci;
mod entrypoint_generator;
mod euler;
pub(crate) mod hook_dci;
mod hook_orchestrator;
mod hook_permissions_detector;
pub(crate) mod hooks_dci_setup;
mod metadata_orchestrator;
mod rpc_metadata_provider;

// Re-export the RPCRetryConfig from the rpc_metadata_provider module
pub use rpc_metadata_provider::RPCRetryConfig;

enum PausingReason {
    #[allow(dead_code)]
    Substreams,
    TracingError,
    MetadataError,
}

impl From<PausingReason> for u8 {
    fn from(reason: PausingReason) -> Self {
        match reason {
            PausingReason::Substreams => 1,
            PausingReason::TracingError => 2,
            PausingReason::MetadataError => 3,
        }
    }
}

impl From<PausingReason> for tycho_common::Bytes {
    fn from(reason: PausingReason) -> Self {
        match reason {
            PausingReason::Substreams => vec![1_u8].into(),
            PausingReason::TracingError => vec![2_u8].into(),
            PausingReason::MetadataError => vec![3_u8].into(),
        }
    }
}
