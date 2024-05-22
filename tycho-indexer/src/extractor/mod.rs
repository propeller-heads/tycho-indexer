use crate::{
    extractor::revert_buffer::StateUpdateBufferEntry,
    pb::sf::substreams::rpc::v2::{BlockScopedData, BlockUndoSignal, ModulesProgress},
};
use async_trait::async_trait;
use mockall::automock;
use prost::DecodeError;
use std::{collections::HashMap, sync::Arc};
use thiserror::Error;
use tycho_core::{
    models::{
        blockchain::{Block, BlockScoped},
        protocol::ComponentBalance,
        ExtractorIdentity, NormalisedMessage,
    },
    storage::StorageError,
    Bytes,
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

/// Wrapper to carry a cursor along with another struct.
#[derive(Debug)]
pub(crate) struct BlockUpdateWithCursor<B: std::fmt::Debug> {
    block_update: B,
    cursor: String,
}

impl<B: std::fmt::Debug> BlockUpdateWithCursor<B> {
    pub(crate) fn new(block_update: B, cursor: String) -> Self {
        Self { block_update, cursor }
    }

    pub(crate) fn cursor(&self) -> &String {
        &self.cursor
    }

    pub(crate) fn block_update(&self) -> &B {
        &self.block_update
    }
}

impl<B> BlockScoped for BlockUpdateWithCursor<B>
where
    B: BlockScoped + std::fmt::Debug,
{
    fn block(&self) -> Block {
        self.block_update.block()
    }
}

impl<B> StateUpdateBufferEntry for BlockUpdateWithCursor<B>
where
    B: StateUpdateBufferEntry,
{
    type ProtocolStateIdType = B::ProtocolStateIdType;
    type ProtocolStateKeyType = B::ProtocolStateKeyType;
    type ProtocolStateValueType = B::ProtocolStateValueType;

    type AccountStateIdType = B::AccountStateIdType;
    type AccountStateKeyType = B::AccountStateKeyType;
    type AccountStateValueType = B::AccountStateValueType;

    fn get_filtered_balance_update(
        &self,
        keys: Vec<(&String, &Bytes)>,
    ) -> HashMap<(String, Bytes), ComponentBalance> {
        self.block_update
            .get_filtered_balance_update(keys)
    }

    fn get_filtered_protocol_state_update(
        &self,
        keys: Vec<(&Self::ProtocolStateIdType, &Self::ProtocolStateKeyType)>,
    ) -> HashMap<
        (Self::ProtocolStateIdType, Self::ProtocolStateKeyType),
        Self::ProtocolStateValueType,
    > {
        self.block_update
            .get_filtered_protocol_state_update(keys)
    }

    fn get_filtered_account_state_update(
        &self,
        keys: Vec<(&Self::AccountStateIdType, &Self::AccountStateKeyType)>,
    ) -> HashMap<(Self::AccountStateIdType, Self::AccountStateKeyType), Self::AccountStateValueType>
    {
        self.block_update
            .get_filtered_account_state_update(keys)
    }
}
