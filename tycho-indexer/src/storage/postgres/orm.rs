use chrono::NaiveDateTime;
use diesel::prelude::*;
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use diesel_derive_enum::DbEnum;

use crate::{
    hex_bytes::Bytes,
    models,
    storage::{Address, Balance, BlockHash, BlockIdentifier, Code, CodeHash, ContractId, TxHash},
};

use super::schema::{
    account, account_balance, block, chain, contract_code, contract_storage, extraction_state,
    protocol_component, protocol_holds_token, protocol_state, protocol_system, protocol_type,
    token, transaction,
};

#[derive(Identifiable, Queryable, Selectable)]
#[diesel(table_name = chain)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Chain {
    pub id: i64,
    pub name: String,
    pub inserted_ts: NaiveDateTime,
    pub modified_ts: NaiveDateTime,
}

/// Represents the state of an extractor.
///
/// Note that static extraction parameters are usually defined through
/// infrastructure configuration tools (e.g., terraform). This struct only
/// maintains dynamic state that changes during runtime and has to be persisted
/// between restarts.
#[derive(Identifiable, Queryable, Associations, Selectable)]
#[diesel(belongs_to(Chain))]
#[diesel(table_name = extraction_state)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct ExtractionState {
    /// Unique identifier for the extraction state.
    pub id: i64,

    /// Name of the extractor.
    pub name: String,

    // Version of the extractor.
    pub version: String,

    /// Chain identifier that the extractor instance is scoped to.
    pub chain_id: i64,

    /// Last fully extracted cursor for the corresponding substream.
    /// Can be null, indicating no cursor has been extracted yet.
    pub cursor: Option<Vec<u8>>,

    /// Additional attributes that the extractor needs to persist.
    /// Stored as a JSON binary object.
    pub attributes: Option<serde_json::Value>,

    /// Timestamp when this entry was inserted into the table.
    pub inserted_ts: NaiveDateTime,

    /// Timestamp when this entry was last modified.
    pub modified_ts: NaiveDateTime,
}

impl ExtractionState {
    /// Retrieves an `ExtractionState` based on the provided extractor name and chain ID.
    ///
    /// This method performs a join operation with the `chain` table and filters the results
    /// based on the given extractor name and chain ID. It then selects the matching
    /// `ExtractionState` and fetches the first result.
    ///
    /// # Parameters
    /// - `extractor`: The name of the extractor to filter by.
    /// - `chain_id`: The ID of the chain to filter by.
    /// - `conn`: A mutable reference to an asynchronous PostgreSQL connection.
    ///
    /// # Returns
    /// - `Ok(Some(ExtractionState))` if a matching `ExtractionState` is found.
    /// - `Ok(None)` if no matching entry is found in the database.
    /// - `Err(DieselError)` if a Diesel error occurs during the query.
    pub async fn by_name(
        extractor: &str,
        chain_id: i64,
        conn: &mut AsyncPgConnection,
    ) -> QueryResult<Option<ExtractionState>> {
        extraction_state::table
            .inner_join(chain::table)
            .filter(extraction_state::name.eq(extractor))
            .filter(chain::id.eq(chain_id))
            .select(ExtractionState::as_select())
            .first::<ExtractionState>(conn)
            .await
            .optional()
    }
}

#[derive(Insertable)]
#[diesel(table_name = extraction_state)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct NewExtractionState<'a> {
    pub name: &'a str,
    pub version: &'a str,
    pub chain_id: i64,
    pub cursor: Option<&'a [u8]>,
    pub attributes: Option<&'a serde_json::Value>,
    pub modified_ts: NaiveDateTime,
}

#[derive(AsChangeset, Debug)]
#[diesel(table_name = extraction_state)]
pub struct ExtractionStateForm<'a> {
    pub cursor: Option<&'a [u8]>,
    pub attributes: Option<&'a serde_json::Value>,
    pub modified_ts: Option<NaiveDateTime>,
}

#[derive(Identifiable, Queryable, Associations, Selectable)]
#[diesel(belongs_to(Chain))]
#[diesel(table_name = block)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Block {
    pub id: i64,
    pub hash: BlockHash,
    pub parent_hash: BlockHash,
    pub chain_id: i64,
    pub main: bool,
    pub number: i64,
    pub ts: NaiveDateTime,
    pub inserted_ts: NaiveDateTime,
    pub modified_ts: NaiveDateTime,
}

impl Block {
    pub async fn by_number(
        chain: models::Chain,
        number: i64,
        conn: &mut AsyncPgConnection,
    ) -> QueryResult<Block> {
        block::table
            .inner_join(chain::table)
            .filter(block::number.eq(number))
            .filter(chain::name.eq(chain.to_string()))
            .select(Block::as_select())
            .first::<Block>(conn)
            .await
    }

    pub async fn by_hash(block_hash: &[u8], conn: &mut AsyncPgConnection) -> QueryResult<Block> {
        block::table
            .filter(block::hash.eq(block_hash))
            .select(Block::as_select())
            .first::<Block>(conn)
            .await
    }

    pub async fn by_id(id: &BlockIdentifier, conn: &mut AsyncPgConnection) -> QueryResult<Block> {
        match id {
            BlockIdentifier::Hash(hash) => Self::by_hash(hash, conn).await,
            BlockIdentifier::Number((chain, number)) => {
                Self::by_number(*chain, *number, conn).await
            }
        }
    }
}

#[derive(Insertable)]
#[diesel(table_name = block)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct NewBlock {
    pub hash: BlockHash,
    pub parent_hash: BlockHash,
    pub chain_id: i64,
    pub main: bool,
    pub number: i64,
    pub ts: NaiveDateTime,
}

#[derive(Identifiable, Queryable, Associations, Selectable, Debug)]
#[diesel(belongs_to(Block))]
#[diesel(table_name = transaction)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Transaction {
    pub id: i64,
    pub hash: TxHash,
    pub block_id: i64,
    pub from: Address,
    pub to: Address,
    pub index: i64,
    pub inserted_ts: NaiveDateTime,
    pub modified_ts: NaiveDateTime,
}

impl Transaction {
    pub async fn by_hash(hash: &[u8], conn: &mut AsyncPgConnection) -> QueryResult<Self> {
        transaction::table
            .filter(transaction::hash.eq(hash))
            .select(Self::as_select())
            .first::<Self>(conn)
            .await
    }
}

#[derive(Insertable)]
#[diesel(table_name = transaction)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct NewTransaction {
    pub hash: TxHash,
    pub block_id: i64,
    pub from: Address,
    pub to: Address,
    pub index: i64,
}

#[derive(Identifiable, Queryable, Selectable)]
#[diesel(table_name = protocol_system)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct ProtocolSystem {
    pub id: i64,
    pub name: String,
    pub inserted_ts: NaiveDateTime,
    pub modified_ts: NaiveDateTime,
}

#[derive(Debug, DbEnum, Clone)]
#[ExistingTypePath = "crate::storage::postgres::schema::sql_types::FinancialProtocolType"]
pub enum FinancialProtocolType {
    Swap,
    Psm,
    Debt,
    Leverage,
}

#[derive(Debug, DbEnum, Clone)]
#[ExistingTypePath = "crate::storage::postgres::schema::sql_types::ProtocolImplementationType"]
pub enum ProtocolImplementationType {
    Custom,
    Vm,
}

#[derive(Identifiable, Queryable, Selectable)]
#[diesel(table_name = protocol_type)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct ProtocolType {
    pub id: i64,
    pub name: String,
    pub financial_type: FinancialProtocolType,
    pub attribute_schema: Option<serde_json::Value>,
    pub implementation: ProtocolImplementationType,
    pub inserted_ts: NaiveDateTime,
    pub modified_ts: NaiveDateTime,
}

#[derive(AsChangeset, Insertable)]
#[diesel(table_name = protocol_type)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct NewProtocolType {
    pub name: String,
    pub financial_type: FinancialProtocolType,
    pub attribute_schema: Option<serde_json::Value>,
    pub implementation: ProtocolImplementationType,
}

#[derive(Identifiable, Queryable, Associations, Selectable)]
#[diesel(belongs_to(Chain))]
#[diesel(belongs_to(ProtocolType))]
#[diesel(belongs_to(ProtocolSystem))]
#[diesel(table_name = protocol_component)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct ProtocolComponent {
    pub id: i64,
    pub external_id: String,
    pub chain_id: i64,
    pub protocol_type_id: i64,
    pub protocol_system_id: i64,
    pub attributes: Option<serde_json::Value>,
    pub created_at: NaiveDateTime,
    pub deleted_at: Option<NaiveDateTime>,
    pub inserted_ts: NaiveDateTime,
    pub modified_ts: NaiveDateTime,
}

#[derive(Identifiable, Queryable, Associations, Selectable)]
#[diesel(belongs_to(ProtocolComponent))]
#[diesel(table_name = protocol_state)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct ProtocolState {
    pub id: i64,
    pub protocol_component_id: i64,
    pub state: Option<serde_json::Value>,
    pub modify_tx: i64,
    pub tvl: Option<i64>,
    pub inertias: Option<Vec<Option<i64>>>,
    pub valid_from: NaiveDateTime,
    pub valid_to: Option<NaiveDateTime>,
    pub inserted_ts: NaiveDateTime,
    pub modified_ts: NaiveDateTime,
}

#[derive(Insertable)]
#[diesel(table_name = protocol_state)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct NewProtocolState {
    pub protocol_component_id: i64,
    pub state: Option<serde_json::Value>,
    pub modify_tx: i64,
    pub tvl: Option<i64>,
    pub inertias: Option<Vec<Option<i64>>>,
    pub valid_from: NaiveDateTime,
    pub valid_to: Option<NaiveDateTime>,
}

#[derive(Identifiable, Queryable, Associations, Selectable, Debug)]
#[diesel(belongs_to(Chain))]
#[diesel(belongs_to(Transaction, foreign_key = creation_tx))]
#[diesel(table_name = account)]
#[diesel(check_for_backend(diesel::pg::Pg))]
/// Represents an account on a blockchain.
///
/// An `Account` is identified by its blockchain (`Chain`) and address (`H160`). It may have a
/// descriptive `title` and contains information about storage slots, balance, associated code
/// (bytecode), code hash, and transaction hashes related to balance modification, code
/// modification, and optional creation. Additional information about accounts.
/// - A Contract is also an Account, but an Account is not necessarily a Contract.
/// - An account is considered a contract if it has associated code.
pub struct Account {
    pub id: i64,
    pub title: String,
    pub address: Address,
    pub chain_id: i64,
    pub creation_tx: Option<i64>,
    pub created_at: Option<NaiveDateTime>,
    pub deleted_at: Option<NaiveDateTime>,
    pub deletion_tx: Option<i64>,
    pub inserted_ts: NaiveDateTime,
    pub modified_ts: NaiveDateTime,
}

impl Account {
    pub async fn by_id(
        account_id: &ContractId,
        conn: &mut AsyncPgConnection,
    ) -> QueryResult<Account> {
        account::table
            .inner_join(chain::table)
            .filter(account::address.eq(&account_id.address))
            .filter(chain::name.eq(account_id.chain.to_string()))
            .select(Account::as_select())
            .first::<Account>(conn)
            .await
    }

    /// retrieves a account by address
    pub async fn by_address(
        address: &[u8],
        conn: &mut AsyncPgConnection,
    ) -> QueryResult<Vec<Self>> {
        account::table
            .filter(account::address.eq(address))
            .select(Self::as_select())
            .get_results::<Self>(conn)
            .await
    }

    pub async fn get_addresses_by_id(
        ids: impl Iterator<Item = &i64>,
        conn: &mut AsyncPgConnection,
    ) -> QueryResult<Vec<(i64, Address)>> {
        account::table
            .filter(account::id.eq_any(ids))
            .select((account::id, account::address))
            .get_results::<(i64, Address)>(conn)
            .await
    }
}

#[derive(Insertable)]
#[diesel(table_name = account)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct NewAccount<'a> {
    pub title: &'a str,
    pub address: &'a [u8],
    pub chain_id: i64,
    pub creation_tx: Option<i64>,
    pub created_at: Option<NaiveDateTime>,
    pub deleted_at: Option<NaiveDateTime>,
}

#[derive(Identifiable, Queryable, Associations, Selectable)]
#[diesel(belongs_to(Account))]
#[diesel(table_name = token)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Token {
    pub id: i64,
    pub account_id: i64,
    pub symbol: String,
    pub decimals: i32,
    pub tax: i64,
    pub gas: Vec<Option<i64>>,
    pub inserted_ts: NaiveDateTime,
    pub modified_ts: NaiveDateTime,
}

#[derive(Insertable)]
#[diesel(table_name = token)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct NewToken {
    pub account_id: i64,
    pub symbol: String,
    pub decimals: i32,
    pub tax: i64,
    pub gas: Vec<Option<i64>>,
}

#[derive(Identifiable, Queryable, Associations, Selectable, Debug)]
#[diesel(belongs_to(Account))]
#[diesel(table_name = account_balance)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct AccountBalance {
    pub id: i64,
    pub balance: Balance,
    pub account_id: i64,
    pub modify_tx: i64,
    pub valid_from: NaiveDateTime,
    pub valid_to: Option<NaiveDateTime>,
    pub inserted_ts: NaiveDateTime,
    pub modified_ts: NaiveDateTime,
}

impl AccountBalance {
    /// retrieves all balances from a certain account
    pub async fn all_versions(
        address: &Address,
        conn: &mut AsyncPgConnection,
    ) -> QueryResult<Vec<Self>> {
        account_balance::table
            .inner_join(account::table)
            .filter(account::address.eq(address))
            .select(Self::as_select())
            .get_results::<Self>(conn)
            .await
    }
}

#[derive(Insertable, Debug)]
#[diesel(table_name = account_balance)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct NewAccountBalance {
    pub balance: Balance,
    pub account_id: i64,
    pub modify_tx: i64,
    pub valid_from: NaiveDateTime,
    pub valid_to: Option<NaiveDateTime>,
}

#[derive(Identifiable, Queryable, Associations, Selectable, Debug)]
#[diesel(belongs_to(Account))]
#[diesel(table_name = contract_code)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct ContractCode {
    pub id: i64,
    pub code: Code,
    pub hash: CodeHash,
    pub account_id: i64,
    pub modify_tx: i64,
    pub valid_from: NaiveDateTime,
    pub valid_to: Option<NaiveDateTime>,
    pub inserted_ts: NaiveDateTime,
    pub modified_ts: NaiveDateTime,
}

impl ContractCode {
    /// retrieves all codes from a certain account
    pub async fn all_versions(
        address: &[u8],
        conn: &mut AsyncPgConnection,
    ) -> QueryResult<Vec<Self>> {
        contract_code::table
            .inner_join(account::table)
            .filter(account::address.eq(address))
            .select(Self::as_select())
            .get_results::<Self>(conn)
            .await
    }
}

#[derive(Insertable, Debug)]
#[diesel(table_name = contract_code)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct NewContractCode<'a> {
    pub code: &'a Code,
    pub hash: CodeHash,
    pub account_id: i64,
    pub modify_tx: i64,
    pub valid_from: NaiveDateTime,
    pub valid_to: Option<NaiveDateTime>,
}

// theoretically this struct could also simply reference the original struct.
// Unfortunately that really doesn't play nicely with async_trait on the Gateway
// and makes the types a lot more complicted. Once the system is up and running
// this could be improved though.
pub struct NewContract {
    pub title: String,
    pub address: Address,
    pub chain_id: i64,
    pub creation_tx: Option<i64>,
    pub created_at: Option<NaiveDateTime>,
    pub deleted_at: Option<NaiveDateTime>,
    pub balance: Balance,
    pub code: Code,
    pub code_hash: CodeHash,
}

impl NewContract {
    pub fn new_account(&self) -> NewAccount {
        NewAccount {
            title: &self.title,
            address: &self.address,
            chain_id: self.chain_id,
            creation_tx: self.creation_tx,
            created_at: self.created_at,
            deleted_at: None,
        }
    }
    pub fn new_balance(
        &self,
        account_id: i64,
        modify_tx: i64,
        modify_ts: NaiveDateTime,
    ) -> NewAccountBalance {
        NewAccountBalance {
            balance: self.balance.clone(),
            account_id,
            modify_tx,
            valid_from: modify_ts,
            valid_to: None,
        }
    }
    pub fn new_code(
        &self,
        account_id: i64,
        modify_tx: i64,
        modify_ts: NaiveDateTime,
    ) -> NewContractCode {
        NewContractCode {
            code: &self.code,
            hash: self.code_hash.clone(),
            account_id,
            modify_tx,
            valid_from: modify_ts,
            valid_to: None,
        }
    }
}

#[derive(Identifiable, Queryable, Associations, Selectable, Debug)]
#[diesel(belongs_to(Account))]
#[diesel(table_name = contract_storage)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct ContractStorage {
    pub id: i64,
    pub slot: Bytes,
    pub value: Option<Bytes>,
    pub previous_value: Option<Bytes>,
    pub account_id: i64,
    pub modify_tx: i64,
    pub ordinal: i64,
    pub valid_from: NaiveDateTime,
    pub valid_to: Option<NaiveDateTime>,
    pub inserted_ts: NaiveDateTime,
    pub modified_ts: NaiveDateTime,
}

#[derive(Insertable)]
#[diesel(table_name = contract_storage)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct NewSlot<'a> {
    pub slot: &'a Bytes,
    pub value: Option<&'a Bytes>,
    pub account_id: i64,
    pub modify_tx: i64,
    pub ordinal: i64,
    pub valid_from: NaiveDateTime,
}

pub struct Contract {
    pub account: Account,
    pub balance: AccountBalance,
    pub code: ContractCode,
}

#[derive(Identifiable, Queryable, Associations, Selectable)]
#[diesel(primary_key(protocol_component_id, token_id))]
#[diesel(belongs_to(ProtocolComponent))]
#[diesel(belongs_to(Token))]
#[diesel(table_name = protocol_holds_token)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct ProtocolHoldsToken {
    protocol_component_id: i64,
    token_id: i64,
    pub inserted_ts: NaiveDateTime,
    pub modified_ts: NaiveDateTime,
}
/*
pub fn get_tokens(protocol: &ProtocolComponent, conn: &mut PgConnection) -> Vec<Token> {
    let token_ids = ProtocolHoldsToken::belonging_to(protocol)
        .select(protocol_holds_token::token_id)
        .distinct();
    token::table
        .filter(token::id.eq_any(token_ids))
        .load::<Token>(conn)
        .expect("Could not load tokens")
}

pub struct ProtocolComponentWithToken {
    pub protocol: ProtocolComponent,
    pub tokens: Vec<Token>,
}

pub fn add_tokens(
    protocols: Vec<ProtocolComponent>,
    conn: &mut PgConnection,
) -> Result<Vec<ProtocolComponentWithToken>, Box<dyn Error + Send + Sync>> {
    let tokens: Vec<(ProtocolHoldsToken, Token)> = ProtocolHoldsToken::belonging_to(&protocols)
        .inner_join(token::table)
        .select((ProtocolHoldsToken::as_select(), Token::as_select()))
        .load(conn)?;

    let res = tokens
        .grouped_by(&protocols)
        .into_iter()
        .zip(protocols)
        .map(|(t, p)| ProtocolComponentWithToken {
            protocol: p,
            tokens: t.into_iter().map(|(_, tok)| tok).collect(),
        })
        .collect();
    Ok(res)
}
 */
