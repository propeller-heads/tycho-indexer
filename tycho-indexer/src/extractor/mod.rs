use crate::pb::sf::substreams::rpc::v2::{BlockScopedData, BlockUndoSignal, ModulesProgress};
use async_trait::async_trait;
use mockall::automock;
use prost::DecodeError;
use std::sync::Arc;
use thiserror::Error;
use tycho_core::{
    models::{ExtractorIdentity, NormalisedMessage},
    storage::StorageError,
};

pub mod evm;
pub mod revert_buffer;
pub mod runner;
mod u256_num;

pub mod compat;

#[derive(Error, Debug, PartialEq)]
pub enum ExtractionError {
    #[error("Extractor setup failed: {0}")]
    Setup(String),
    #[error("Failed to decode: {0}")]
    DecodeError(String),
    #[error("Protobuf error: {0}")]
    ProtobufError(#[from] DecodeError),
    #[error("Can't decode an empty message")]
    Empty,
    #[error("Unexpected extraction error: {0}")]
    Unknown(String),
    #[error("Storage failure: {0}")]
    Storage(#[from] StorageError),
    #[error("Stream errored: {0}")]
    SubstreamsError(String),
    #[error("Service error: {0}")]
    ServiceError(String),
    #[error("Merge error: {0}")]
    MergeError(String),
    #[error("Revert buffer error: {0}")]
    RevertBufferError(String),
}

pub type ExtractorMsg = Arc<dyn NormalisedMessage>;

#[automock]
#[async_trait]
pub trait Extractor: Send + Sync {
    fn get_id(&self) -> ExtractorIdentity;

    async fn ensure_protocol_types(&self);

    async fn get_cursor(&self) -> String;

    async fn get_last_processed_block(&self) -> Option<evm::Block>;

    async fn handle_tick_scoped_data(
        &self,
        inp: BlockScopedData,
    ) -> Result<Option<ExtractorMsg>, ExtractionError>;

    async fn handle_revert(
        &self,
        inp: BlockUndoSignal,
    ) -> Result<Option<ExtractorMsg>, ExtractionError>;

    async fn handle_progress(&self, inp: ModulesProgress) -> Result<(), ExtractionError>;
}
