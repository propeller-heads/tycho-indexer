//! # Postgres based storage backend
//!
//! This postgres-based storage backend provides implementations for the
//! traits defined in the storage module.
//!
//! ## Design Decisions
//!
//! ### Representation of Enums as Tables
//!
//! Certain enums such as 'Chain' are modelled as tables in our implementation.
//! This decision stems from an understanding that while extending the Rust
//! codebase to include more enums is a straightforward task, modifying the type
//! of a SQL column can be an intricate process. By representing enums as
//! tables, we circumvent unnecessary migrations when modifying Chain or
//! ProtocolSystem enums.
//!
//! With this representation, it's important to synchronize them whenever the
//! enums members changed. This can be done automatically once at system
//! startup.
//!
//!
//! Note: A removed enum can be ignored safely even though it might instigate a
//! panic if an associated entity still exists in the database and retrieved
//! with a codebase which no longer presents the enum value.
//!
//! ### Timestamps
//!
//! We use naive timestamps throughout the code as it is assumed that the server
//! that will be running the application will always use UTC as it's local time.
//! Thus all naive timestamps on the application are implcitly in UTC. Be aware
//! that especially tests might run on machines that violate this assumption so
//! in tests make sure to create a timestamp aware timestamp and convert it to
//! UTC before using the naive value.
//!
//! #### Timestamp fields
//!
//! As the are multiple different timestamp columns below is a short summary how
//! these are used:
//!
//! * `inserted` and `modified_ts`: These are pure "book-keeping" values, used to track when the
//!   record was inserted or updated. They are not used in any business logic. These values are
//!   automatically set via Postgres triggers, so they don't need to be manually set.
//!
//! * `valid_from` and `valid_to`: These timestamps enable data versioning aka time-travel
//!   functionality. Hence, these should always be set correctly. `valid_from` must be set to the
//!   timestamp at which the entity was created
//!   - most often that will be the value of the corresponding `block.ts`. Same
//!   applies for `valid_to`. There are triggers in place to automatically set
//!   `valid_to` if you insert a new entity with the same identity (not primary
//!   key). But to delete a record, `valid_to` needs to be manually set as no
//!   automatic trigger exists for deletes yet.
//!
//! * `created_ts`: For entities that are immutable, this timestamp records when the entity was
//!   created and is used for time-travel functionality. For example, for contracts, this timestamp
//!   will be the block timestamp of its deployment.
//!
//! * `deleted_ts`: This serves a similar purpose to `created_ts`, but in reverse. It indicates when
//!   an entity was deleted.
//!
//! * `block.ts`: This is the timestamp attached to the block. Ideally, it should coincide with the
//!   validation/mining start time.
//!
//! ### Versioning
//!
//! This implementation utilizes temporal tables for recording the changes in
//! entities over time. In this model, `valid_from` and `valid_to` determine the
//! timeframe during which the facts provided by the record are regarded as
//! accurate (validity period). Typically, in temporal tables, a valid version
//! for a specific timestamp is found using the following predicate:
//!
//! ```sql
//! valid_from < version_ts AND (version_ts <= valid_to OR valid_to is NULL)
//! ```
//!
//! The `valid_to` can be set to null, signifying that the version remains
//! valid. However, as all alterations within a block happen simultaneously,
//! this predicate might yield multiple valid versions for a single entity.
//!
//! To further assign a temporal sequence to these entities, the transaction
//! index within the block is recorded, usually through a `modify_tx` foreign
//! key.
//!
//! ```sql
//! SELECT * FROM table
//! JOIN transaction
//! WHERE valid_from < version_ts
//!     AND (version_ts <= valid_to OR valid_to is NULL)
//! ORDER BY entity_id, transaction.index DESC
//! DISTINCT ON entity_id
//! ```
//!
//! Here we select a set of versions by timestamp, then arrange rows by their
//! transaction index (descending) and choose the first row, thus obtaining the
//! latest version within the block (aka version at end of block).
//!
//! #### Contract Storage Table
//!
//! Special attention must be given to the contract_storage table, which also
//! records the previous value with each modification. This simplifies the
//! generation of a delta change structure utilized during reorgs for informing
//! clients about the necessary updates. Deletions in this table are modeled
//! as simple updates; in the case of deletion, it's value is updated to null.
//! This technique simplifies querying for delta changes while maintaining
//! efficiency at the cost of requiring additional storage space. As
//! `valid_from` and `valid_to` are not entirely sufficient to find a single
//! valid state within blockchain systems, the contract_storage table
//! additionally maintains an `ordinal` column. This column is redundant with
//! the transaction's index that produced the respective changes. This
//! redundancy is to avoid additional joins and further optimize query
//! performance.
//!
//! ### Reverts
//! If a reorg is observed, we will be asked by the stream to revert to a previous
//! block number. This is handled using the `ON DELETE CASCADE` feature provided by
//! postgres. Each state change is tracked by a creation or modification transaction
//! if the parent transaction is deleted, postgres will delete the corresponding
//! entry in the child table for us.
//! Now all we have to do is to unset valid_to columns that point directly to our
//! last reverted block.
//!
//! ### Atomic Transactions
//!
//! In our design, direct connection to the database and consequently beginning,
//! committing, or rolling back transactions isn't handled within these
//! common-purpose implementations. Rather, each operation receives a connection
//! reference which can either be a simple DB connection, or a DB connection
//! within a transactional context.
//!
//! This approach enables us to chain multiple common-purpose CRUD operations
//! into a single transaction. This guarantees preservation of valid state
//! throughout the application lifetime, even if the process panics during
//! database operations.
pub mod chain;
pub mod contract_state;
pub mod extraction_state;
pub mod orm;
pub mod schema;

use std::{collections::HashMap, hash::Hash, i64, marker::PhantomData, str::FromStr, sync::Arc};

use diesel::prelude::*;
use diesel_async::{
    pooled_connection::{bb8::Pool, AsyncDieselConnectionManager},
    AsyncPgConnection, RunQueryDsl,
};
use tracing::info;

use super::{
    ContractDelta, StateGateway, StorableBlock, StorableContract, StorableTransaction, StorageError,
};
use crate::models::Chain;

pub struct EnumTableCache<E> {
    map_id: HashMap<E, i64>,
    map_enum: HashMap<i64, E>,
}

/// Provides caching for enum and its database ID relationships.
///
/// Uses a double sided hash map to provide quick lookups in both directions.
impl<'a, E> EnumTableCache<E>
where
    E: Eq + Hash + Copy + FromStr + std::fmt::Debug,
    <E as FromStr>::Err: std::fmt::Debug,
{
    pub async fn from_pool(pool: Pool<AsyncPgConnection>) -> Result<Self, StorageError> {
        let mut conn = pool
            .get()
            .await
            .map_err(|err| StorageError::Unexpected(format!("{}", err)))?;

        let results: Vec<(i64, String)> = async {
            use schema::chain::dsl::*;
            chain
                .select((id, name))
                .load(&mut conn)
                .await
                .expect("Failed to load chain ids!")
        }
        .await;
        Ok(Self::from_tuples(results))
    }

    /// Creates a new cache from a slice of tuples.
    ///
    /// # Arguments
    ///
    /// * `entries` - A slice of tuples ideally obtained from a database query.
    pub fn from_tuples(entries: Vec<(i64, String)>) -> Self {
        let mut cache = Self { map_id: HashMap::new(), map_enum: HashMap::new() };
        for (id_, name_) in entries {
            let val = E::from_str(&name_).expect("valid enum value");
            cache.map_id.insert(val, id_);
            cache.map_enum.insert(id_, val);
        }
        cache
    }

    /// Fetches the associated database ID for an enum variant. Panics on cache
    /// miss.
    ///
    /// # Arguments
    ///
    /// * `val` - The enum variant to lookup.
    fn get_id(&self, val: E) -> i64 {
        *self
            .map_id
            .get(&val)
            .unwrap_or_else(|| {
                panic!("Unexpected cache miss for enum {:?}, entries: {:?}", val, self.map_id)
            })
    }

    /// Retrieves the corresponding enum variant for a database ID. Panics on
    /// cache miss.
    ///
    /// # Arguments
    ///
    /// * `id` - The database ID to lookup.
    fn get_chain(&self, id: i64) -> E {
        *self
            .map_enum
            .get(&id)
            .unwrap_or_else(|| {
                panic!("Unexpected cache miss for id {}, entries: {:?}", id, self.map_enum)
            })
    }
}

type ChainEnumCache = EnumTableCache<Chain>;

impl From<diesel::result::Error> for StorageError {
    fn from(value: diesel::result::Error) -> Self {
        StorageError::Unexpected(format!("DieselError: {}", value))
    }
}

impl StorageError {
    fn from_diesel(
        err: diesel::result::Error,
        entity: &str,
        id: &str,
        fetch_args: Option<String>,
    ) -> StorageError {
        let err_string = err.to_string();
        match err {
            diesel::result::Error::DatabaseError(
                diesel::result::DatabaseErrorKind::UniqueViolation,
                details,
            ) => {
                if let Some(col) = details.column_name() {
                    if col == "id" {
                        return StorageError::DuplicateEntry(entity.to_owned(), id.to_owned())
                    }
                }
                StorageError::Unexpected(err_string)
            }
            diesel::result::Error::NotFound => {
                if let Some(related_entitiy) = fetch_args {
                    return StorageError::NoRelatedEntity(
                        entity.to_owned(),
                        id.to_owned(),
                        related_entitiy,
                    )
                }
                StorageError::NotFound(entity.to_owned(), id.to_owned())
            }
            _ => StorageError::Unexpected(err_string),
        }
    }
}

pub struct PostgresGateway<B, TX, A, D> {
    chain_id_cache: Arc<ChainEnumCache>,
    _phantom_block: PhantomData<B>,
    _phantom_tx: PhantomData<TX>,
    _phantom_acc: PhantomData<A>,
    _phantom_delta: PhantomData<D>,
}

impl<B, TX, A, D> PostgresGateway<B, TX, A, D>
where
    B: StorableBlock<orm::Block, orm::NewBlock, i64>,
    TX: StorableTransaction<orm::Transaction, orm::NewTransaction, i64>,
    D: ContractDelta,
    A: StorableContract<orm::Contract, orm::NewContract, i64>,
{
    pub fn with_cache(cache: Arc<ChainEnumCache>) -> Self {
        Self {
            chain_id_cache: cache,
            _phantom_block: PhantomData,
            _phantom_tx: PhantomData,
            _phantom_acc: PhantomData,
            _phantom_delta: PhantomData,
        }
    }

    #[cfg(test)]
    #[allow(clippy::needless_pass_by_ref_mut)]
    pub async fn from_connection(conn: &mut AsyncPgConnection) -> Self {
        let results: Vec<(i64, String)> = async {
            use schema::chain::dsl::*;
            chain
                .select((id, name))
                .load(conn)
                .await
                .expect("Failed to load chain ids!")
        }
        .await;
        let cache = Arc::new(ChainEnumCache::from_tuples(results));
        Self::with_cache(cache)
    }

    fn get_chain_id(&self, chain: Chain) -> i64 {
        self.chain_id_cache.get_id(chain)
    }

    fn get_chain(&self, id: i64) -> Chain {
        self.chain_id_cache.get_chain(id)
    }

    pub async fn new(pool: Pool<AsyncPgConnection>) -> Result<Arc<Self>, StorageError> {
        let cache = EnumTableCache::<Chain>::from_pool(pool.clone()).await?;

        let gw = Arc::new(PostgresGateway::<B, TX, A, D>::with_cache(Arc::new(cache)));

        Ok(gw)
    }
}

impl<B, TX, A, D> StateGateway<AsyncPgConnection> for PostgresGateway<B, TX, A, D>
where
    B: StorableBlock<orm::Block, orm::NewBlock, i64>,
    TX: StorableTransaction<orm::Transaction, orm::NewTransaction, i64>,
    D: ContractDelta + From<A>,
    A: StorableContract<orm::Contract, orm::NewContract, i64>,
{
    // No methods in here - this just ties everything together
}

/// Establishes a connection to the database and creates a connection pool.
///
/// This function takes in the URL of the database as an argument and returns a pool
/// of connections that the application can use to interact with the database. If there's
/// any error during the creation of this pool, it is converted into a `StorageError` for
/// uniform error handling across the application.
///
/// # Arguments
///
/// - `db_url`: A string slice that holds the URL of the database to connect to.
///
/// # Returns
///
/// A Result which is either:
///
/// - `Ok`: Contains a `Pool` of `AsyncPgConnection`s if the connection was established
///   successfully.
/// - `Err`: Contains a `StorageError` if there was an issue creating the connection pool.
pub async fn connect(db_url: &str) -> Result<Pool<AsyncPgConnection>, StorageError> {
    let config = AsyncDieselConnectionManager::<AsyncPgConnection>::new(db_url);
    let pool = Pool::builder()
        .build(config)
        .await
        .map_err(|err| StorageError::Unexpected(format!("{}", err)))?;
    Ok(pool)
}

/// Ensures the `Chain` enum is present in the database, if not it inserts it.
///
/// This function serves as a way to ensure all chains found within the `chains`  
/// slice are present within the database. It does this by inserting each chain into
/// the `chain` table. If a conflict arises during this operation (indicating that
/// the chain already exists in the database), it simply does nothing for that
/// specific operation and moves on.
///
/// It uses a connection from the passed in `Pool<AsyncPgConnection>` asynchronously.
/// In case of any error during these operations, the function will panic with an
/// appropriate error message.
///
///
/// # Arguments
///
/// - `chains`: A slice containing chains which need to be ensured in the database.
/// - `pool`: An instance of `Pool` containing `AsyncPgConnection`s used to interact with the
///   database.
///
/// # Panics
///
/// This function will panic under two circumstances:
///
/// - If it failed to get a connection from the provided pool.
/// - If there was an issue ensuring the presence of chains in the database.
pub async fn ensure_chains(chains: &[Chain], pool: Pool<AsyncPgConnection>) {
    info!("Ensured chain enum presence for: {:?}", chains);
    let mut conn = pool.get().await.expect("connection ok");
    diesel::insert_into(schema::chain::table)
        .values(
            chains
                .iter()
                .map(|c| schema::chain::name.eq(c.to_string()))
                .collect::<Vec<_>>(),
        )
        .on_conflict_do_nothing()
        .execute(&mut conn)
        .await
        .expect("chains ensured");
}

#[cfg(test)]
pub mod db_fixtures {
    //! # General Purpose Fixtures for Database State Modification
    //!
    //! The module contains fixtures that are designed to alter the database state
    //! for testing purposes.
    //!
    //! This module doesn't rely on any locally specific code from the Postgres
    //! packages, except for the autogenerated `schema` module. Given that `schema`
    //! is generated by examining our table schema, it's reasonable to assert that
    //! this module belongs to the `schema` and not the package itself.
    //!
    //! A key goal of these fixtures is to prevent reliance on application code when
    //! setting up test data, thereby avoiding cyclical dependencies. For example,
    //! if you're modifying how an entity is inserted, and this change affects the
    //! data setup for other tests, these tests would start failing – a situation we
    //! want to avoid. This could lead to complex, hard-to-resolve issues,
    //! particularly if you're using the insertion method to validate that a second
    //! insertion fails, while simultaneously working on the insertion method. In
    //! such cases, running your tests becomes impossible if the insertion method
    //! encounters bugs.
    //!
    //! # Heads Up
    //! We advise adding only general-purpose methods to this module, such as those
    //! for adding or removing a single row/entry, or maximum entries along with
    //! their child entities. More intricate setups should be localized where they
    //! are explicitly used.
    //!
    //! If you need to share more complex setups and decide to include them here,
    //! please think through whether this is the suitable location, or whether a
    //! local copy might serve your needs better. For instance, if the complete
    //! shared setup isn't necessary for your test case, copy it and keep only
    //! the entries that are crucial to your test case.
    use std::str::FromStr;

    use chrono::NaiveDateTime;
    use diesel::prelude::*;
    use diesel_async::{AsyncPgConnection, RunQueryDsl};
    use ethers::types::{H160, H256, U256};

    use super::schema;

    // Insert a new chain
    pub async fn insert_chain(conn: &mut AsyncPgConnection, name: &str) -> i64 {
        diesel::insert_into(schema::chain::table)
            .values(schema::chain::name.eq(name))
            .returning(schema::chain::id)
            .get_result(conn)
            .await
            .unwrap()
    }

    /// Inserts two sequential blocks
    pub async fn insert_blocks(conn: &mut AsyncPgConnection, chain_id: i64) -> Vec<i64> {
        let block_records = vec![
            (
                schema::block::hash.eq(Vec::from(
                    H256::from_str(
                        "0x88e96d4537bea4d9c05d12549907b32561d3bf31f45aae734cdc119f13406cb6",
                    )
                    .unwrap()
                    .as_bytes(),
                )),
                schema::block::parent_hash.eq(Vec::from(
                    H256::from_str(
                        "0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3",
                    )
                    .unwrap()
                    .as_bytes(),
                )),
                schema::block::number.eq(1),
                schema::block::ts.eq("2020-01-01T00:00:00"
                    .parse::<chrono::NaiveDateTime>()
                    .expect("timestamp")),
                schema::block::chain_id.eq(chain_id),
            ),
            (
                schema::block::hash.eq(Vec::from(
                    H256::from_str(
                        "0xb495a1d7e6663152ae92708da4843337b958146015a2802f4193a410044698c9",
                    )
                    .unwrap()
                    .as_bytes(),
                )),
                schema::block::parent_hash.eq(Vec::from(
                    H256::from_str(
                        "0x88e96d4537bea4d9c05d12549907b32561d3bf31f45aae734cdc119f13406cb6",
                    )
                    .unwrap()
                    .as_bytes(),
                )),
                schema::block::number.eq(2),
                schema::block::ts.eq("2020-01-01T01:00:00"
                    .parse::<chrono::NaiveDateTime>()
                    .unwrap()),
                schema::block::chain_id.eq(chain_id),
            ),
        ];
        diesel::insert_into(schema::block::table)
            .values(&block_records)
            .returning(schema::block::id)
            .get_results(conn)
            .await
            .unwrap()
    }

    /// Insert a bunch of transactions using (block_id, index, hash)
    pub async fn insert_txns(conn: &mut AsyncPgConnection, txns: &[(i64, i64, &str)]) -> Vec<i64> {
        let from_val = H160::from_str("0x4648451b5F87FF8F0F7D622bD40574bb97E25980").unwrap();
        let to_val = H160::from_str("0x6B175474E89094C44Da98b954EedeAC495271d0F").unwrap();
        let data: Vec<_> = txns
            .iter()
            .map(|(b, i, h)| {
                use schema::transaction::dsl::*;
                (
                    block_id.eq(b),
                    index.eq(i),
                    hash.eq(H256::from_str(h)
                        .expect("valid txhash")
                        .as_bytes()
                        .to_owned()),
                    from.eq(from_val.as_bytes()),
                    to.eq(to_val.as_bytes()),
                )
            })
            .collect();
        diesel::insert_into(schema::transaction::table)
            .values(&data)
            .returning(schema::transaction::id)
            .get_results(conn)
            .await
            .unwrap()
    }

    pub async fn insert_account(
        conn: &mut AsyncPgConnection,
        address: &str,
        title: &str,
        chain_id: i64,
        tx_id: Option<i64>,
    ) -> i64 {
        let ts: Option<NaiveDateTime> = if let Some(id) = tx_id {
            Some(
                schema::transaction::table
                    .inner_join(schema::block::table)
                    .filter(schema::transaction::id.eq(id))
                    .select(schema::block::ts)
                    .first::<NaiveDateTime>(conn)
                    .await
                    .expect("setup tx id not found"),
            )
        } else {
            None
        };

        let query = diesel::insert_into(schema::account::table).values((
            schema::account::title.eq(title),
            schema::account::chain_id.eq(chain_id),
            schema::account::creation_tx.eq(tx_id),
            schema::account::created_at.eq(ts),
            schema::account::address.eq(hex::decode(address).unwrap()),
        ));
        query
            .returning(schema::account::id)
            .get_result(conn)
            .await
            .unwrap()
    }

    pub async fn insert_slots(
        conn: &mut AsyncPgConnection,
        contract_id: i64,
        modify_tx: i64,
        valid_from: &str,
        slots: &[(u64, u64)],
    ) -> Vec<i64> {
        let ts = valid_from
            .parse::<chrono::NaiveDateTime>()
            .unwrap();
        let data = slots
            .iter()
            .enumerate()
            .map(|(idx, (k, v))| {
                (
                    schema::contract_storage::slot.eq(hex::decode(format!(
                        "{:064x}",
                        U256::from(*k)
                    ))
                    .unwrap()),
                    schema::contract_storage::value.eq(hex::decode(format!(
                        "{:064x}",
                        U256::from(*v)
                    ))
                    .unwrap()),
                    schema::contract_storage::account_id.eq(contract_id),
                    schema::contract_storage::modify_tx.eq(modify_tx),
                    schema::contract_storage::valid_from.eq(ts),
                    schema::contract_storage::ordinal.eq(idx as i64),
                )
            })
            .collect::<Vec<_>>();

        diesel::insert_into(schema::contract_storage::table)
            .values(&data)
            .returning(schema::contract_storage::id)
            .get_results(conn)
            .await
            .unwrap()
    }

    pub async fn insert_account_balance(
        conn: &mut AsyncPgConnection,
        new_balance: u64,
        tx_id: i64,
        account: i64,
    ) {
        let ts = schema::transaction::table
            .inner_join(schema::block::table)
            .filter(schema::transaction::id.eq(tx_id))
            .select(schema::block::ts)
            .first::<NaiveDateTime>(conn)
            .await
            .expect("setup tx id not found");

        let mut b0 = [0; 32];
        U256::from(new_balance).to_big_endian(&mut b0);
        {
            use schema::account_balance::dsl::*;
            diesel::insert_into(account_balance)
                .values((
                    account_id.eq(account),
                    balance.eq(b0.as_slice()),
                    modify_tx.eq(tx_id),
                    valid_from.eq(ts),
                    valid_to.eq(Option::<NaiveDateTime>::None),
                ))
                .execute(conn)
                .await
                .expect("balance insert ok");
        }
    }

    pub async fn insert_contract_code(
        conn: &mut AsyncPgConnection,
        account_id: i64,
        modify_tx: i64,
        code: Vec<u8>,
    ) -> i64 {
        let ts = schema::transaction::table
            .inner_join(schema::block::table)
            .filter(schema::transaction::id.eq(modify_tx))
            .select(schema::block::ts)
            .first::<NaiveDateTime>(conn)
            .await
            .expect("setup tx id not found");

        let code_hash = H256::from_slice(&ethers::utils::keccak256(&code));
        let data = (
            schema::contract_code::code.eq(code),
            schema::contract_code::hash.eq(code_hash.as_bytes()),
            schema::contract_code::account_id.eq(account_id),
            schema::contract_code::modify_tx.eq(modify_tx),
            schema::contract_code::valid_from.eq(ts),
        );

        diesel::insert_into(schema::contract_code::table)
            .values(data)
            .returning(schema::contract_code::id)
            .get_result(conn)
            .await
            .unwrap()
    }

    pub async fn delete_account(conn: &mut AsyncPgConnection, target_id: i64, ts: &str) {
        let ts = ts
            .parse::<NaiveDateTime>()
            .expect("timestamp valid");
        {
            use schema::account::dsl::*;
            diesel::update(account.filter(id.eq(target_id)))
                .set(deleted_at.eq(ts))
                .execute(conn)
                .await
                .expect("delete account table ok");
        }
        {
            use schema::account_balance::dsl::*;
            diesel::update(account_balance.filter(account_id.eq(target_id)))
                .set(valid_to.eq(ts))
                .execute(conn)
                .await
                .expect("delete balance table ok");
        }
        {
            use schema::contract_code::dsl::*;
            diesel::update(contract_code.filter(account_id.eq(target_id)))
                .set(valid_to.eq(ts))
                .execute(conn)
                .await
                .expect("delete code table ok");
        }
        {
            use schema::contract_storage::dsl::*;
            diesel::update(contract_storage.filter(account_id.eq(target_id)))
                .set(valid_to.eq(ts))
                .execute(conn)
                .await
                .expect("delete storage table ok");
        }
    }
}
