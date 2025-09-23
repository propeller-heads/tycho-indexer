use core::fmt::Debug;
use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;

use crate::{
    models::{
        blockchain::{Block, BlockTag, EntryPointWithTracingParams, TracedEntryPoint},
        contract::AccountDelta,
        token::{Token, TokenQuality, TransferCost, TransferTax},
        Address, Balance, BlockHash, StoreKey,
    },
    Bytes,
};

/// A struct representing a request to get an account state.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StorageSnapshotRequest {
    // The address of the account to get the state of.
    pub address: Address,
    // The specific slots to get the state of. If `None`, the entire account state will be
    // returned.
    pub slots: Option<Vec<StoreKey>>,
}

/// Trait for getting multiple account states from chain data.
#[cfg_attr(feature = "test-utils", mockall::automock(type Error = String;))]
#[async_trait]
pub trait AccountExtractor {
    type Error: Debug + Send + Sync;

    /// Get the account states at the end of the given block (after all transactions in the block
    /// have been applied).
    ///
    /// # Arguments
    ///
    /// * `block`: The block at which to retrieve the account states.
    /// * `requests`: A slice of `StorageSnapshotRequest` objects, each containing an address and
    ///   optional slots.
    /// Note: If the `slots` field is `None`, the function will return the entire account state.
    /// That could be a lot of data, so use with caution.
    ///
    /// returns: Result<HashMap<Bytes, AccountDelta, RandomState>, Self::Error>
    /// A result containing a HashMap where the keys are `Bytes` (addresses) and the values are
    /// `AccountDelta` objects.
    async fn get_accounts_at_block(
        &self,
        block: &Block,
        requests: &[StorageSnapshotRequest],
    ) -> Result<HashMap<Bytes, AccountDelta>, Self::Error>; //TODO: do not return `AccountUpdate` but `Account`
}

/// Trait for analyzing a token, including its quality, transfer cost, and transfer tax.
#[async_trait]
pub trait TokenAnalyzer: Send + Sync {
    type Error;

    /// Analyzes the quality of a token given its address and a block tag.
    ///
    /// # Parameters
    /// * `token` - The address of the token to analyze.
    /// * `block` - The block tag at which the analysis should be performed.
    ///
    /// # Returns
    /// A result containing:
    /// * `TokenQuality` - The quality assessment of the token (either `Good` or `Bad`).
    /// * `Option<TransferCost>` - The average cost per transfer, if available.
    /// * `Option<TransferTax>` - The transfer tax, if applicable.
    ///
    /// On failure, returns `Self::Error`.
    async fn analyze(
        &self,
        token: Bytes,
        block: BlockTag,
    ) -> Result<(TokenQuality, Option<TransferCost>, Option<TransferTax>), Self::Error>;
}

/// Trait for finding an address that owns a specific token. This is useful for detecting
/// bad tokens by identifying addresses with enough balance to simulate transactions.
#[async_trait]
pub trait TokenOwnerFinding: Send + Sync + Debug {
    /// Finds an address that holds at least `min_balance` of the specified token.
    ///
    /// # Parameters
    /// * `token` - The address of the token to search for.
    /// * `min_balance` - The minimum balance required for the address to be considered.
    ///
    /// # Returns
    /// A result containing:
    /// * `Option<(Address, Balance)>` - The address and its actual balance if an owner is found.
    /// If no address meets the criteria, returns `None`.
    /// On failure, returns a string representing an error message.
    async fn find_owner(
        &self,
        token: Address,
        min_balance: Balance,
    ) -> Result<Option<(Address, Balance)>, String>; // TODO: introduce custom error type
}

/// Trait for retrieving additional information about tokens, such as the number of decimals
/// and the token symbol, to help construct `CurrencyToken` objects.
#[async_trait]
pub trait TokenPreProcessor: Send + Sync {
    /// Given a list of token addresses, this function retrieves additional metadata for each token.
    ///
    /// # Parameters
    /// * `addresses` - A vector of token addresses to process.
    /// * `token_finder` - A reference to a `TokenOwnerFinding` implementation to help find token
    ///   owners.
    /// * `block` - The block tag at which the information should be retrieved.
    ///
    /// # Returns
    /// A vector of `CurrencyToken` objects, each containing the processed information for the
    /// token.
    async fn get_tokens(
        &self,
        addresses: Vec<Bytes>,
        token_finder: Arc<dyn TokenOwnerFinding>,
        block: BlockTag,
    ) -> Vec<Token>;
}

/// Trait for tracing blockchain transaction execution.
#[cfg_attr(feature = "test-utils", mockall::automock(type Error = String;))]
#[async_trait]
pub trait EntryPointTracer: Sync {
    type Error: Debug;

    /// Traces the execution of a list of entry points at a specific block.
    ///
    /// # Parameters
    /// * `block_hash` - The hash of the block at which to perform the trace. The trace will use the
    ///   state of the blockchain at this block.
    /// * `entry_points` - A list of entry points to trace with their data.
    ///
    /// # Returns
    /// Returns a vector of `TracedEntryPoint`, where each element contains:
    /// * `retriggers` - A set of (address, storage slot) pairs representing storage locations that
    ///   could alter tracing results. If any of these storage slots change, the set of called
    ///   contract might be outdated.
    /// * `accessed_slots` - A map of all contract addresses that were called during the trace with
    ///   a list of storage slots that were accessed (read or written).
    async fn trace(
        &self,
        block_hash: BlockHash,
        entry_points: Vec<EntryPointWithTracingParams>,
    ) -> Result<Vec<TracedEntryPoint>, Self::Error>;
}

/// Trait for calculating the memory weight/size of values for caching purposes
pub trait MemorySize {
    /// Returns the approximate memory size in bytes
    fn memory_size(&self) -> usize;
}
