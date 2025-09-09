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

enum PausingReason {
    #[allow(dead_code)]
    Substreams,
    TracingError,
    MetadataError,
}

impl PausingReason {
    fn get_reason_index(&self) -> u8 {
        match self {
            PausingReason::Substreams => 1,
            PausingReason::TracingError => 2,
            PausingReason::MetadataError => 3,
        }
    }
}
