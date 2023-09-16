pub mod evm;
pub mod runner;

use crate::{
    models::{ExtractorIdentity, NormalisedMessage},
    pb::sf::substreams::rpc::v2::{BlockScopedData, BlockUndoSignal, ModulesProgress},
    storage::StorageError,
};
use async_trait::async_trait;
use prost::DecodeError;
use thiserror::Error;

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
}

#[async_trait]
pub trait Extractor<G, M>: Send + Sync
where
    G: Send + Sync,
    M: NormalisedMessage,
{
    fn get_id(&self) -> ExtractorIdentity;

    async fn get_cursor(&self) -> String;

    async fn handle_tick_scoped_data(
        &self,
        inp: BlockScopedData,
    ) -> Result<Option<M>, ExtractionError>;

    async fn handle_revert(&self, inp: BlockUndoSignal) -> Result<Option<M>, ExtractionError>;

    async fn handle_progress(&self, inp: ModulesProgress) -> Result<(), ExtractionError>;
}
