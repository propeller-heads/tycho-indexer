//! # Storage Traits
//!
//! This module encapsulates the traits and structs meant for handling
//! operations such as retrieval, addition, and deletion pertaining to protocol
//! state.
//!
//! ## Versioning
//!
//! The core of Tycho keeps track of all states by timestamp versioning. This
//! strategy allows us to maintain and retrieve state across different
//! protocols, including those that rely on various clock mechanisms (e.g.,
//! blockchains).
//!
//! In addition to timestamps, blockchain state is further versioned using
//! transactions. Since a block carries a single timestamp only, there can be
//! instances where one block's timestamp might overlap with multiple states. In
//! these cases, an explicit input is required from the user. For example, a
//! user may want to track all states within a block or just the most recent
//! one. As every onchain state modification associates with a transaction
//! having an index, the original sequence of state modifications stays
//! preserved.
//!
//! ## Implementations
//!
//! To set up a storage system, you need to implement all the traits defined
//! below. Additionally, the entities you aim to store must also implement the
//! respective `Storable*` trait.
//!
//! Note that you will have different entities based on the specific blockchain
//! under consideration. For instance, entities for EVM and Starknet will vary!
//!
//! The gateways are not confined to a certain chain scope but are universally
//! applicable over a range of entity types. So, a gateway designed for EVM
//! entities can handle multiple EVM-based chains, like mainnet & arbitrum.
//!
//! However, if the entities for the chains differ, you may need to resort to
//! separate gateway instances. Alternatively, you can create an enum that
//! houses all different entity types and then implement the respective traits
//! for these enums. Following this approach paves the way for initializing a
//! cross-chain compatible gateway (For instance, refer
//! [enum_dispatch](https://docs.rs/enum_dispatch/latest/enum_dispatch/) crate).
pub mod postgres;

use std::{collections::HashMap, fmt::Display, sync::Arc};

use async_trait::async_trait;
use chrono::NaiveDateTime;
use thiserror::Error;

use crate::models::{Chain, ExtractionState, ProtocolSystem, ProtocolType};

/// Identifies a block in storage.
#[derive(Debug)]
pub enum BlockIdentifier {
    /// Identifies the block by its position on a specified chain.
    ///
    /// This form of identification has potential risks as it may become
    /// ambiguous in certain situations.For example, if the block has not been
    /// finalised, there exists a possibility of forks occurring. As a result,
    /// the same number could refer to different blocks on different forks.
    Number((Chain, i64)),

    /// Identifies a block by its hash.
    ///
    /// The hash should be unique across multiple chains. Preferred method if
    /// the block is very recent.
    Hash(Vec<u8>),
}

impl Display for BlockIdentifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// `StorableBlock` abstracts (de)serialization behavior of a block entity
/// specific to a storage backend.
///
/// It defines methods for converting from a storage-specific type to a block,
/// converting from a block to a storage-specific type, and getting the block's
/// chain.
pub trait StorableBlock<S, N> {
    /// Constructs a block from a storage-specific value `val` and a `Chain`.
    ///
    /// # Arguments
    ///
    /// * `val` - The storage-specific representation of the block
    /// * `chain` - The chain associated with the block
    ///
    /// # Returns
    ///
    /// A block constructed from `val` and `chain`
    fn from_storage(val: S, chain: Chain) -> Self;

    /// Converts the block to a storage-specific representation.
    ///
    /// # Arguments
    ///
    /// * `chain_id` - The id of the chain that the block belongs to
    ///
    /// # Returns
    ///
    /// The storage-specific representation of the block
    fn to_storage(&self, chain_id: i64) -> N;

    /// Returns the `Chain` object associated with the block.
    ///
    /// # Returns
    ///
    /// The `Chain` that the block is associated with
    fn chain(&self) -> Chain;
}

/// The `StorableTransaction` is a public trait which lays out the necessary
/// interface needed to store and retrieve transactions from storage. This trait
/// is generic over four types - `S`, `N`, `BH`, and `DbId`.
///
/// `S` represents the storage specific transaction type e.g. orm struct. `N`
/// represents the storage specific type for a new transaction,. `BH`
/// corresponds to the block hash type that uniquely identifies a block. `DbId`
/// is the ID used to refer to each transaction in the database.
pub trait StorableTransaction<S, N, DbId> {
    /// Converts a transaction from storage representation (`S`) to transaction
    /// form. This function uses the original block hash (`BH`), where the
    /// transaction resides, for this conversion.
    fn from_storage(val: S, block_hash: &[u8]) -> Self;

    /// Converts a transaction object to its storable representation (`N`),
    /// while also associating it with a specific block through a database ID
    /// (`DbId`).
    fn to_storage(&self, block_id: DbId) -> N;

    /// Returns the block hash (`BH`) associated with a transaction. This is
    /// necessary to ensure that transactions can be traced back to the blocks
    /// from which they originated.
    fn block_hash(&self) -> &[u8];

    /// Returns the transaction hash (`BH`) associated with a transaction. This
    /// is necessary to uniquely identify this transaction.
    fn hash(&self) -> &[u8];
}

#[derive(Error, Debug)]
pub enum StorageError {
    #[error("Could not find {0} with id `{1}`!")]
    NotFound(String, String),
    #[error("The entity {0} with id {1} was already present!")]
    DuplicateEntry(String, String),
    #[error("Could not find related {0} for {1} with id `{2}`!")]
    NoRelatedEntity(String, String, String),
    #[error("DecodeError: {0}")]
    DecodeError(String),
    #[error("Unexpected storage error: {0}")]
    Unexpected(String),
    #[error("Currently unsupported operation: {0}")]
    Unsupported(String),
}

/// Storage methods for chain specific objects.
///
/// This trait abstracts the specific implementation details of a blockchain's
/// entities, allowing the user to add and retrieve blocks and transactions in a
/// generic way.
///
/// For traceability protocol components and contracts changes are linked to
/// blocks of their respective chain if applicable. This means while indexing we
/// need to keep a lightweight and cross chain compatible representation of
/// blocks and transactions in storage.
///
/// It's defined generically over two associated types:
///
/// * `Block`: represents a block in the blockchain.
/// * `Transaction`: represents a transaction within a block.
#[async_trait]
pub trait ChainGateway {
    type DB;
    type Block;
    type Transaction;

    /// Upserts a new block to the blockchain's storage.
    ///
    /// Ignores any existing tx, if the new entry has different attributes
    /// no error is raised and the old entry is kept.
    ///
    /// # Parameters
    /// - `new`: An instance of `Self::Block`, representing the new block to be stored.
    ///
    /// # Returns
    /// - Empty ok result indicates success. Failure might occur if the block is already present.
    async fn upsert_block(&self, new: Self::Block, db: &mut Self::DB) -> Result<(), StorageError>;
    /// Retrieves a block from storage.
    ///
    /// # Parameters
    /// - `id`: Block's unique identifier of type `BlockIdentifier`.
    ///
    /// # Returns
    /// - An Ok result containing the block. Might fail if the block does not exist yet.
    async fn get_block(
        &self,
        id: BlockIdentifier,
        db: &mut Self::DB,
    ) -> Result<Self::Block, StorageError>;
    /// Upserts a transaction to storage.
    ///
    /// Ignores any existing tx, if the new entry has different attributes
    /// no error is raised and the old entry is kept.
    ///
    /// # Parameters
    /// - `new`: An instance of `Self::Transaction`, representing the new transaction to be stored.
    ///
    /// # Returns
    /// - Empty ok result indicates success. Failure might occur if the
    /// corresponding block does not exists yet, or if the transaction already
    /// exists.
    async fn upsert_tx(
        &self,
        new: Self::Transaction,
        db: &mut Self::DB,
    ) -> Result<(), StorageError>;

    /// Tries to retrieve a transaction from the blockchain's storage using its
    /// hash.
    ///
    /// # Parameters
    /// - `hash`: The byte slice representing the hash of the transaction to be retrieved.
    ///
    /// # Returns
    /// - An Ok result containing the transaction. Might fail if the transaction does not exist yet.
    async fn get_tx(
        &self,
        hash: &[u8],
        db: &mut Self::DB,
    ) -> Result<Self::Transaction, StorageError>;
}

/// Store and retrieve state of Extractors.
///
/// Sometimes extractors may wish to persist their state across restart. E.g.
/// substreams based extractors need to store the cursor, so they can continue
/// processing where they left off.
///
/// Extractors are uniquely identified by a name and the respective chain which
/// they are indexing.
#[async_trait]
pub trait ExtractionStateGateway {
    type DB;

    /// Retrieves the state of an extractor instance from a storage.
    ///
    /// # Parameters
    /// - `name` A unique name for the extractor instance.
    /// - `chain` The chain this extractor is indexing.
    ///
    /// # Returns
    /// Ok if the corrsponding state was retrieved successfully, Err in
    /// case the state was not found.
    async fn get_state(
        &self,
        name: &str,
        chain: Chain,
        conn: &mut Self::DB,
    ) -> Result<ExtractionState, StorageError>;

    /// Saves the state of an extractor instance to a storage.
    ///
    /// Creates an entry if not present yet, or updates an already existing
    /// entry.
    ///
    /// # Parameters
    /// - `state` The state of the extractor that needs to be saved.
    ///
    /// # Returns
    /// Ok, if state was stored successfully, Err if the state is not valid.
    async fn save_state(
        &self,
        state: &ExtractionState,
        conn: &mut Self::DB,
    ) -> Result<(), StorageError>;
}

/// Point in time as either block or timestamp. If a block is chosen it
/// timestamp attribute is used.
#[derive(Debug)]
pub enum BlockOrTimestamp {
    Block(BlockIdentifier),
    Timestamp(NaiveDateTime),
}

/// References certain states within a single block.
///
/// **Note:** Not all methods that take a version will support all version kinds,
/// the versions here are included for completeness and to document the
/// retrieval behaviour that is possible with the storage layout. Please refer
/// to the individual implementation for information about which version kinds
/// it supports.
#[derive(Debug, Default)]
pub enum VersionKind {
    /// Represents the final state within a specific block. Essentially, it
    /// retrieves the state subsequent to the execution of the last transaction
    /// executed in that block.
    #[default]
    Last,
    /// Represents the initial state of a specific block. In other words,
    /// it is the state before any transaction has been executed within that block.
    First,
    /// Represents a specific transactions indexed position within a block.
    /// It includes the state after executing the transaction at that index.
    Index(i64),
}

pub struct ContractId(Chain, Vec<u8>);

impl Display for ContractId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}: 0x{}", self.0, hex::encode(&self.1))
    }
}

pub struct Version(BlockOrTimestamp, VersionKind);

pub trait StorableToken<S, N, DbId> {
    fn from_storage(val: S, contract: ContractId) -> Self;

    fn to_storage(&self, contract_id: DbId) -> N;

    fn contract_id(&self) -> ContractId;
}

pub trait StorableProtocolComponent<S, N, T, DbId> {
    fn from_storage(
        val: S,
        tokens: Vec<T>,
        contracts: Vec<ContractId>,
        system: ProtocolSystem,
        protocol_type: ProtocolType,
    ) -> Self;

    fn to_storage(
        &self,
        tokens: Vec<DbId>,
        contracts: Vec<DbId>,
        chain: DbId,
        system: DbId,
        protocol_type: DbId,
    ) -> N;

    fn chain(&self) -> Chain;

    fn contracts(&self) -> Vec<ContractId>;

    fn tokens(&self) -> Vec<Vec<u8>>;

    fn system(&self) -> ProtocolSystem;
}

/// Store and retrieve protocol related structs.
///
/// This trait defines how to retrieve protocol components, state as well as
/// tokens from storage.
#[async_trait]
pub trait ProtocolGateway {
    type DB;
    type Token;
    type ProtocolComponent;
    // TODO: at this later type ProtocolState;

    /// Retrieve ProtocolComponent from the db
    ///
    /// # Parameters
    /// - `chain` The chain of the component
    /// - `system` Allows to optionally filter by system.
    /// - `id` Allows to optionally filter by id.
    ///
    /// # Returns
    /// Ok, if found else Err
    async fn get_components(
        &self,
        chain: Chain,
        system: Option<ProtocolSystem>,
        ids: Option<&[&str]>,
    ) -> Result<Vec<Self::ProtocolComponent>, StorageError>;

    /// Stores new found ProtocolComponents.
    ///
    /// Components are assumed to be immutable. Any state belonging to a
    /// component that is dynamic, should be made available on ProtocolState,
    /// not on the Component.
    ///
    /// # Parameters
    /// - `new`  The new protocol components.
    ///
    /// # Returns
    /// Ok if stored successfully, may error if:
    /// - related entities are not in store yet.
    /// - component with same is id already present.
    async fn upsert_components(&self, new: &[Self::ProtocolComponent]) -> Result<(), StorageError>;

    /// Retrieve protocol component states
    ///
    /// This resource is versioned, the version can be specified by either block
    /// or timestamp, for off-chain components, a block version will error.
    ///
    /// As the state is retained on a transaction basis on blockchain systems, a
    /// single version may relate to more than one state. In these cases a
    /// versioned result is returned, if requesting `Version:All` with the
    /// latest entry being the state at the end of the block and the first entry
    /// represents the first change to the state within the block.
    ///
    /// # Parameters
    /// - `chain` The chain of the component
    /// - `system` The protocol system this component belongs to
    /// - `id` The external id of the component e.g. address, or the pair
    /// - `at` The version at which the state is valid at.
    /*
    // TODO: implement once needed
    type ProtocolState;
    async fn get_states(
        &self,
        chain: Chain,
        at: Option<Version>,
        system: Option<ProtocolSystem>,
        id: Option<&[&str]>,
    ) -> Result<VersionedResult<Self::ProtocolState>, StorageError>;
     */

    /// Retrieves a tokens from storage
    ///
    /// # Parameters
    /// - `chain` The chain this token is implemented on.
    /// - `address` The address for the token within the chain.
    ///
    /// # Returns
    /// Ok if the results could be retrieved from the storage, else errors.
    async fn get_tokens(
        &self,
        chain: Chain,
        address: Option<&[&[u8]]>,
    ) -> Result<Vec<Self::Token>, StorageError>;

    /// Saves multiple tokens to storage.
    ///
    /// Inserts token into storage. Tokens and their properties are assumed to
    /// be immutable.
    ///
    /// # Parameters
    /// - `chain` The chain of the token.
    /// - `token` The tokens to insert.
    ///
    /// # Return
    /// Ok if all tokens could be inserted, Err if at least one token failed to
    /// insert.
    async fn add_tokens(&self, chain: Chain, token: &[Self::Token]) -> Result<(), StorageError>;
}

pub trait StorableContract<S, N, DbId> {
    fn from_storage(val: S) -> Self;

    fn to_storage(&self, chain_id: DbId) -> N;

    fn chain() -> Chain;
}

/// Manage contracts and their state in storage.
///
/// Specifies how to retrieve, add and update contracts in storage.
#[async_trait]
pub trait ContractStateGateway {
    type DB;
    type Transaction;
    type ContractState;
    type Address;
    type Slot;
    type Value;

    /// Get a contracts state from storage
    ///
    /// This method retrieves balance and code, but not storage.
    ///
    /// # Parameters
    /// - `id` The identifier for the contract.
    /// - `version` Version at which to retrieve state for. None retrieves the latest state.
    async fn get_contract(
        &self,
        id: &ContractId,
        version: Option<BlockOrTimestamp>,
        db: &mut Self::DB,
    ) -> Result<Self::ContractState, StorageError>;

    /// Save contract metadata.
    ///
    /// Inserts immutable contract metadata, as well as code and balance.
    ///
    /// # Parameters
    /// - `new` the new contract state to be saved.
    async fn add_contract(
        &self,
        new: &Self::ContractState,
        db: &mut Self::DB,
    ) -> Result<i64, StorageError>;

    /// Mark a contract as deleted
    ///
    /// Issues a soft delete of the contract.
    ///
    /// # Parameters
    /// - `id` The identifier for the contract.
    /// - `at_tx` The transaction hash which deleted the contract. This transaction is assumed to be
    ///   in storage already. None retrieves the latest state.
    /// - `db` The database handle or connection.
    ///
    /// # Returns
    /// Ok if the deletion was successful, might Err if:
    ///  - Contract is not present in storage.
    ///  - Deletion transaction is not present in storage.
    ///  - Contract was already deleted.
    async fn delete_contract(
        &self,
        id: ContractId,
        at_tx: &Self::Transaction,
        db: &mut Self::DB,
    ) -> Result<(), StorageError>;

    /// Retrieve contract storage.
    ///
    /// Retrieve the storage slots of contracts at a given time/version.
    ///
    /// Will return the slots state after the given block/timestamp. Later we
    /// might change to use VersionResult, but for now we keep it simple. Using
    /// anything else then Version::Last is currently not supported.
    ///
    /// # Parameters
    /// - `chain` The chain for which to retrieve slots for.
    /// - `contracts` Optionally allows filtering by contract address.
    /// - `at` The version at which to retrieve slots. None retrieves the latest
    /// - `db` The database handle or connection. state.
    async fn get_contract_slots(
        &self,
        chain: Chain,
        contracts: Option<&[Self::Address]>,
        at: Option<Version>,
        db: &mut Self::DB,
    ) -> Result<HashMap<Self::Address, HashMap<Self::Slot, Self::Value>>, StorageError>;

    /// Upserts slots for a given contract.
    ///
    /// Upserts slots from multiple accounts. To correctly track changes, it is
    /// necessary that each slot modification has a corresponding transaction
    /// assigned.
    ///
    /// # Parameters
    /// - `slots` A slice containing only the changed slots. Including slots that were changed to 0.
    ///   Must come with a corresponding transaction that modified the slots, as well as the account
    ///   identifier the slots belong to.
    ///
    /// # Returns
    /// An empty `Ok(())` if the operation succeeded. Will raise an error if any
    /// of the related entities can not be found: e.g. one of the referenced
    /// transactions or accounts is not or not yet persisted.
    async fn upsert_slots(
        &self,
        slots: &[(Self::Transaction, HashMap<Self::Address, HashMap<Self::Slot, Self::Value>>)],
        db: &mut Self::DB,
    ) -> Result<(), StorageError>;
    /// Retrieve a slot delta between two versions
    ///
    /// Given start version V1 and end version V2, this method will return the
    /// changes necessary to move from V1 to V2. So if V1 < V2, it will contain
    /// the value of all slots that changed between the two versions with the
    /// values corresponding to V2. If V2 < V1 then it will contain all the
    /// slots that changed between the two versions with the values
    /// corresponding to V1.
    ///
    /// # Parameters
    /// - `id` The identifier for the contract.
    /// - `chain` The chain for which to generate the delta changes. This is required because
    ///   version might be a timestamp.
    /// - `start_version` The deltas start version, given a block uses VersionKind::Last behaviour.
    ///   If None the latest version is assumed.
    /// - `end_version` The deltas end version, given a block uses VersionKind::Last behaviour.
    ///
    /// # Returns
    /// A map containing the necessary changes to update a state from
    /// start_version to end_version.
    /// Errors if:
    ///     - The versions can't be located in storage.
    ///     - There was an error with the database
    async fn get_slots_delta(
        &self,
        id: Chain,
        start_version: Option<BlockOrTimestamp>,
        end_version: BlockOrTimestamp,
        db: &mut Self::DB,
    ) -> Result<HashMap<Self::Address, HashMap<Self::Slot, Self::Value>>, StorageError>;

    /// Reverts the contract in storage to a previous version.
    ///
    /// This modification will delete version in storage. The state will be
    /// reset to the passed version.
    ///
    /// Note:
    /// This method is scoped to a chain via the id parameter. All changes on
    /// that chain will be reverted to the target version.
    ///
    /// # Parameters
    /// - `id` The identifier for the contract.
    /// - `to` The version to revert to. Given a block uses VersionKind::Last behaviour.
    async fn revert_contract_state(
        &self,
        to: BlockIdentifier,
        db: &mut Self::DB,
    ) -> Result<(), StorageError>;
}

pub trait StateGateway<DB, TX>:
    ExtractionStateGateway<DB = DB>
    + ChainGateway<DB = DB, Transaction = TX>
    + ProtocolGateway<DB = DB>
    + ContractStateGateway<DB = DB, Transaction = TX>
    + Send
    + Sync
{
}

pub type StateGatewayType<DB, B, TX, T, P, C, A, S, V> = Arc<
    dyn StateGateway<
        DB,
        TX,
        Block = B,
        Token = T,
        ProtocolComponent = P,
        ContractState = C,
        Address = A,
        Slot = S,
        Value = V,
    >,
>;
