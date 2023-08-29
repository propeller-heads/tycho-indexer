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
pub trait StorableTransaction<S, N, BH, DbId>
where
    BH: From<Vec<u8>> + Into<Vec<u8>>,
{
    /// Converts a transaction from storage representation (`S`) to transaction
    /// form. This function uses the original block hash (`BH`), where the
    /// transaction resides, for this conversion.
    fn from_storage(val: S, block_hash: BH) -> Self;

    /// Converts a transaction object to its storable representation (`N`),
    /// while also associating it with a specific block through a database ID
    /// (`DbId`).
    fn to_storage(&self, block_id: DbId) -> N;

    /// Returns the block hash (`BH`) associated with a transaction. This is
    /// necessary to ensure that transactions can be traced back to the blocks
    /// from which they originated.
    fn block_hash(&self) -> BH;
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
    /// - `new`: An instance of `Self::Block`, representing the new block to be
    ///   stored.
    ///
    /// # Returns
    /// - Empty ok result indicates success. Failure might occur if the block is
    ///   already present.
    async fn upsert_block(&self, new: Self::Block, db: &mut Self::DB) -> Result<(), StorageError>;
    /// Retrieves a block from storage.
    ///
    /// # Parameters
    /// - `id`: Block's unique identifier of type `BlockIdentifier`.
    ///
    /// # Returns
    /// - An Ok result containing the block. Might fail if the block does not
    ///   exist yet.
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
    /// - `new`: An instance of `Self::Transaction`, representing the new
    ///   transaction to be stored.
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
    /// - `hash`: The byte slice representing the hash of the transaction to be
    ///   retrieved.
    ///
    /// # Returns
    /// - An Ok result containing the transaction. Might fail if the transaction
    ///   does not exist yet.
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

#[derive(Debug)]
pub enum BlockOrTimestamp {
    Block(BlockIdentifier),
    Timestamp(NaiveDateTime),
}

pub enum VersionKind {
    /// Get all states within a given block.
    All,
    /// Get the latest state within a given block.
    Last,
}

pub enum VersionedResult<T> {
    All(Vec<T>),
    Last(T),
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

    /// Retrieve a single ProtocolComponent struct
    ///
    /// # Parameters
    /// - `chain` The chain of the component
    /// - `system` The protocol system this component belongs to
    /// - `id` The external id of the component e.g. address, or the pair
    ///
    /// # Returns
    /// Ok, if found else Err
    async fn get_component(
        &self,
        chain: Chain,
        system: ProtocolSystem,
        id: &str,
    ) -> Result<Self::ProtocolComponent, StorageError>;

    /// Stores a new ProtocolComponent
    ///
    /// Components are assumed to be immutable. Any state belonging to a
    /// component that is dynamic, should be made available on ProtocolState,
    /// not on the Component.
    ///
    /// # Parameters
    /// - `new`  The new protocol component.
    ///
    /// # Returns
    /// Ok if stored successfully, may error if:
    /// - related entities are not in store yet.
    /// - component with same is id already present.
    async fn add_component(&self, new: Self::ProtocolComponent) -> Result<(), StorageError>;

    /// Retrieve a protocol components state
    ///
    /// This resource is versioned for blockchain based protocols, the version
    /// can be specified by either block or timestamp, for off-chain components,
    /// a block version will error.
    ///
    /// As the state is retained on a transaction basis on blockchain systems, a
    /// single version may relate to more than one state. In these cases a
    /// vector with multiple entries is returned, with the latest entry being
    /// the state at the end of the block and the first entry represents the
    /// first change to the state within the block.
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
        system: ProtocolSystem,
        id: &str,
        at: Option<Version>,
    ) -> Result<VersionedResult<Self::ProtocolState>, StorageError>;
     */

    /// Retrieve a token from storage
    ///
    /// # Parameters
    /// - `chain` The chain this token is implemented on.
    /// - `address` The address for the token within the chain.
    ///
    /// # Returns
    /// Ok with the token if found, else Err.
    async fn get_token(&self, chain: Chain, address: &[u8]) -> Result<Self::Token, StorageError>;

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
    /// - `version` Version at which to retrieve state for. None retrieves the latest
    ///   state.
    async fn get_contract(
        &mut self,
        id: ContractId,
        version: Option<BlockOrTimestamp>,
        db: &mut Self::DB,
    ) -> Result<Self::ContractState, StorageError>;

    /// Save contract metadata.
    ///
    /// Inserts immutable contract metadata, as well as code and balance.
    ///
    /// # Parameters
    /// - `new` the new contract state to be saved.
    async fn add_contract(&mut self, new: Self::ContractState) -> Result<(), StorageError>;

    /// Mark a contract as deleted
    ///
    /// Issues a soft delete of the contract.
    ///
    /// # Parameters
    /// - `id` The identifier for the contract.
    /// - `at_tx` The transaction hash which deleted the contract. This
    ///     transaction is assumed to be in storage already. None retrieves the
    ///     latest state.
    ///
    /// # Returns
    /// Ok if the deletion was successful, might Err if:
    ///  - Contract is not present in storage.
    ///  - Deletion transaction is not present in storage.
    ///  - Contract was already deleted.
    async fn delete_contract(
        &self,
        id: ContractId,
        at_tx: Option<&[u8]>,
    ) -> Result<(), StorageError>;

    /// Retrieve contract storage.
    ///
    /// Retrieve the storage slots of a given contract at a given time.
    ///
    /// Will return the slots state after the given block/timestamp. Later we
    /// might change to use VersionResult, but for now we keep it simple.
    ///
    /// # Parameters
    /// - `id` The identifier for the contract.
    /// - `at` The version at which to retrieve slots. None retrieves the latest
    ///   state.
    async fn get_contract_slots(
        &self,
        id: ContractId,
        at: Option<Version>,
    ) -> Result<HashMap<Self::Slot, Self::Value>, StorageError>;

    /// Upserts slots for a given contract.
    ///
    /// Creates a new version and then add the new/updated slots accordingly.
    ///
    /// # Parameters
    /// - `id` The identifier for the contract.
    /// - `modify_tx` Transaction hash that modified the contract. Assumed to be
    ///     already present in storage.
    /// - `slots` A map containing only the changed slots. Including slots that
    ///     were changed to 0.
    async fn upsert_slots(
        &self,
        id: ContractId,
        modify_tx: &[u8],
        slots: HashMap<Self::Slot, Self::Value>,
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
    /// - `start_version` The deltas start version, given a block uses
    ///     VersionKind::Last behaviour. If None the latest version is assumed.
    /// - `end_version` The deltas end version, given a block uses
    ///     VersionKind::Last behaviour. If None the latest version is assumed.
    ///
    /// # Returns
    /// A map containing the necessary changes to update a state from
    /// start_version to end_version. Errors if: - The supplied version are the
    ///     same. - The versions can't be located in storage. - The contract
    ///     can't be located in storage.
    async fn get_slots_delta(
        &self,
        id: Chain,
        start_version: Option<BlockOrTimestamp>,
        end_version: Option<BlockOrTimestamp>,
        db: &mut Self::DB,
    ) -> Result<HashMap<Self::Address, HashMap<Self::Slot, Self::Value>>, StorageError>;

    /// Reverts the contract in storage to a previous version.
    ///
    /// This modification will delete version in storage. The state will be
    /// reset to the passed version.
    ///
    /// # Parameters
    /// - `id` The identifier for the contract.
    /// - `to` The version to revert to. Given a block uses VersionKind::Last
    ///   behaviour.
    async fn revert_contract_state(
        &self,
        to: BlockIdentifier,
        db: &mut Self::DB,
    ) -> Result<(), StorageError>;
}

pub trait StateGateway<DB>:
    ExtractionStateGateway<DB = DB>
    + ChainGateway<DB = DB>
    + ProtocolGateway<DB = DB>
    + ContractStateGateway<DB = DB>
    + Send
    + Sync
{
}

pub type StateGatewayType<DB, B, TX, T, P, C, A, S, V> = Arc<
    dyn StateGateway<
        DB,
        Block = B,
        Transaction = TX,
        Token = T,
        ProtocolComponent = P,
        ContractState = C,
        Address = A,
        Slot = S,
        Value = V,
    >,
>;
