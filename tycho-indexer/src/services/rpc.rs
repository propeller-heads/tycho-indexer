//! This module contains Tycho RPC implementation

use crate::{
    extractor::evm,
    hex_bytes::Bytes,
    models::Chain,
    storage::{
        self, Address, BlockHash, BlockIdentifier, BlockOrTimestamp, ChangeType, ContractId,
        ContractStateGateway, StorageError,
    },
};

use ethers::types::{H160, H256, U256};

use actix_web::{web, HttpResponse};
use chrono::{NaiveDateTime, Utc};
use diesel_async::{
    pooled_connection::deadpool::{self, Pool},
    AsyncPgConnection,
};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc};
use thiserror::Error;
use tracing::{debug, error, info, instrument};
use utoipa::{IntoParams, ToSchema};

use super::EvmPostgresGateway;

#[derive(Error, Debug)]
pub enum RpcError {
    #[error("Failed to parse JSON: {0}")]
    Parse(String),

    #[error("Failed to get storage: {0}")]
    Storage(#[from] StorageError),

    #[error("Failed to get database connection: {0}")]
    Connection(#[from] deadpool::PoolError),
}

// Equivalent to evm::Account. This struct was created to avoid modifying the evm::Account
// struct for RPC purpose.
#[derive(PartialEq, Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct EVMAccount {
    pub chain: Chain,
    #[schema(value_type=String)]
    pub address: H160,
    pub title: String,
    #[schema(value_type=HashMap<String, String>)]
    pub slots: HashMap<U256, U256>,
    #[schema(value_type=String)]
    pub balance: U256,
    #[schema(value_type=String)]
    pub code: Bytes,
    #[schema(value_type=String)]
    pub code_hash: H256,
    #[schema(value_type=String)]
    pub balance_modify_tx: H256,
    #[schema(value_type=String)]
    pub code_modify_tx: H256,
    #[schema(value_type=Option<String>)]
    pub creation_tx: Option<H256>,
}

impl From<evm::Account> for EVMAccount {
    fn from(account: evm::Account) -> Self {
        Self {
            chain: account.chain,
            address: account.address,
            title: account.title,
            slots: account.slots,
            balance: account.balance,
            code: account.code,
            code_hash: account.code_hash,
            balance_modify_tx: account.balance_modify_tx,
            code_modify_tx: account.code_modify_tx,
            creation_tx: account.creation_tx,
        }
    }
}

#[derive(PartialEq, Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct EVMAccountUpdate {
    #[schema(value_type=String)]
    pub address: H160,
    pub chain: Chain,
    #[schema(value_type=HashMap<String, String>)]
    pub slots: HashMap<U256, U256>,
    #[schema(value_type=Option<String>)]
    pub balance: Option<U256>,
    #[schema(value_type=Option<String>)]
    pub code: Option<Bytes>,
    pub change: ChangeType,
}

impl From<evm::AccountUpdate> for EVMAccountUpdate {
    fn from(account_update: evm::AccountUpdate) -> Self {
        Self {
            address: account_update.address,
            chain: account_update.chain,
            slots: account_update.slots,
            balance: account_update.balance,
            code: account_update.code,
            change: account_update.change,
        }
    }
}

#[derive(Serialize, Deserialize, Default, Debug, IntoParams)]
pub(crate) struct RequestParameters {
    #[serde(default = "Chain::default")]
    chain: Chain,
    #[param(default = 0)]
    tvl_gt: Option<u64>,
    #[param(default = 0)]
    intertia_min_gt: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, ToSchema)]
pub(crate) struct ContractStateRequestBody {
    #[serde(rename = "contractIds")]
    contract_ids: Option<Vec<ContractId>>,
    #[serde(default = "Version::default")]
    version: Version,
}
#[derive(Debug, Serialize, Deserialize, PartialEq, ToSchema)]
pub(crate) struct ContractStateRequestResponse {
    accounts: Vec<EVMAccount>,
}

impl ContractStateRequestResponse {
    fn new(accounts: Vec<EVMAccount>) -> Self {
        Self { accounts }
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, ToSchema)]
pub(crate) struct ContractDeltaRequestBody {
    #[serde(rename = "contractIds")]
    contract_ids: Option<Vec<ContractId>>,
    #[serde(default = "Version::default")]
    start: Version,
    #[serde(default = "Version::default")]
    end: Version,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, ToSchema)]
pub(crate) struct ContractDeltaRequestResponse {
    accounts: Vec<EVMAccountUpdate>,
}

impl ContractDeltaRequestResponse {
    fn new(accounts: Vec<EVMAccountUpdate>) -> Self {
        Self { accounts }
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, ToSchema)]
pub(crate) struct Version {
    timestamp: Option<NaiveDateTime>,
    block: Option<Block>,
}

impl Default for Version {
    fn default() -> Self {
        Version { timestamp: Some(Utc::now().naive_utc()), block: None }
    }
}

impl TryFrom<&Version> for BlockOrTimestamp {
    type Error = RpcError;

    fn try_from(version: &Version) -> Result<Self, Self::Error> {
        match (&version.timestamp, &version.block) {
            (_, Some(block)) => {
                // If a full block is provided, we prioritize hash over number and chain
                let block_identifier = match (&block.hash, &block.chain, &block.number) {
                    (Some(hash), _, _) => BlockIdentifier::Hash(hash.clone()),
                    (_, Some(chain), Some(number)) => BlockIdentifier::Number((*chain, *number)),
                    _ => return Err(RpcError::Parse("Insufficient block information".to_owned())),
                };
                Ok(BlockOrTimestamp::Block(block_identifier))
            }
            (Some(timestamp), None) => Ok(BlockOrTimestamp::Timestamp(*timestamp)),
            (None, None) => {
                Err(RpcError::Parse("Missing timestamp or block identifier".to_owned()))
            }
        }
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, ToSchema)]
pub(crate) struct Block {
    #[schema(value_type=Option<String>)]
    hash: Option<BlockHash>,
    chain: Option<Chain>,
    number: Option<i64>,
}
pub struct RpcHandler {
    db_gateway: Arc<EvmPostgresGateway>,
    db_connection_pool: Pool<AsyncPgConnection>,
}

impl RpcHandler {
    pub fn new(
        db_gateway: Arc<EvmPostgresGateway>,
        db_connection_pool: Pool<AsyncPgConnection>,
    ) -> Self {
        Self { db_gateway, db_connection_pool }
    }

    #[instrument(skip(self, request, params))]
    async fn get_contract_state(
        &self,
        request: &ContractStateRequestBody,
        params: &RequestParameters,
    ) -> Result<ContractStateRequestResponse, RpcError> {
        let mut conn = self.db_connection_pool.get().await?;

        info!(?request, ?params, "Getting contract state.");
        self.get_contract_state_inner(request, params, &mut conn)
            .await
    }

    async fn get_contract_state_inner(
        &self,
        request: &ContractStateRequestBody,
        params: &RequestParameters,
        db_connection: &mut AsyncPgConnection,
    ) -> Result<ContractStateRequestResponse, RpcError> {
        //TODO: handle when no contract is specified with filters
        let at = BlockOrTimestamp::try_from(&request.version)?;

        let version = storage::Version(at, storage::VersionKind::Last);

        // Get the contract IDs from the request
        let contract_ids = request.contract_ids.clone();
        let addresses: Option<Vec<Address>> = contract_ids.map(|ids| {
            ids.into_iter()
                .map(|id| id.address)
                .collect::<Vec<Address>>()
        });
        debug!(?addresses, "Getting contract states.");
        let addresses = addresses.as_deref();

        // Get the contract states from the database
        // TODO support additional tvl_gt and intertia_min_gt filters
        match self
            .db_gateway
            .get_contracts(&params.chain, addresses, Some(&version), true, db_connection)
            .await
        {
            Ok(accounts) => Ok(ContractStateRequestResponse::new(
                accounts
                    .into_iter()
                    .map(EVMAccount::from)
                    .collect(),
            )),
            Err(err) => {
                error!(error = %err, "Error while getting contract states.");
                Err(err.into())
            }
        }
    }

    #[instrument(skip(self, request, params))]
    async fn get_contract_delta(
        &self,
        request: &ContractDeltaRequestBody,
        params: &RequestParameters,
    ) -> Result<ContractDeltaRequestResponse, RpcError> {
        let mut conn = self.db_connection_pool.get().await?;

        info!(?request, ?params, "Getting contract state.");
        self.get_contract_delta_inner(request, params, &mut conn)
            .await
    }

    async fn get_contract_delta_inner(
        &self,
        request: &ContractDeltaRequestBody,
        params: &RequestParameters,
        db_connection: &mut AsyncPgConnection,
    ) -> Result<ContractDeltaRequestResponse, RpcError> {
        //TODO: handle when no contract is specified with filters
        let start = BlockOrTimestamp::try_from(&request.start)?;
        let end = BlockOrTimestamp::try_from(&request.end)?;

        // Get the contract IDs from the request
        let contract_ids = request.contract_ids.clone();
        let addresses: Option<Vec<Address>> = contract_ids.map(|ids| {
            ids.into_iter()
                .map(|id| id.address)
                .collect::<Vec<Address>>()
        });
        debug!(?addresses, "Getting contract states.");
        let addresses = addresses.as_deref();

        // Get the contract states from the database
        // TODO support additional tvl_gt and intertia_min_gt filters
        match self
            .db_gateway
            .get_accounts_delta(&params.chain, Some(&start), &end, db_connection)
            .await
        {
            Ok(mut accounts) => {
                // Filter by contract addresses if specified
                // TODO: this is not efficient, we should filter in the database query directly in
                // get_accounts_delta
                if let Some(contract_addrs) = addresses {
                    accounts.retain(|acc| contract_addrs.contains(&acc.address.into()));
                }
                Ok(ContractDeltaRequestResponse::new(
                    accounts
                        .into_iter()
                        .map(EVMAccountUpdate::from)
                        .collect(),
                ))
            }
            Err(err) => {
                error!(error = %err, "Error while getting contract states.");
                Err(err.into())
            }
        }
    }
// Helper function to handle requests
async fn handle_request<ReqBody, ReqParams, Res, F, Fut>(
    query: web::Query<ReqParams>,
    body: web::Json<ReqBody>,
    handler: web::Data<RpcHandler>,
    operation: F,
) -> HttpResponse
where
    F: FnOnce(web::Data<RpcHandler>, web::Json<ReqBody>, web::Query<ReqParams>) -> Fut,
    Fut: Future<Output = Result<Res, RpcError>>,
    ReqBody: Send + 'static,
    ReqParams: Send + 'static,
    Res: serde::Serialize,
{
    let response = operation(handler, body, query).await;

    match response {
        Ok(result) => HttpResponse::Ok().json(result),
        Err(err) => {
            error!(error = %err, "Error while processing request.");
            HttpResponse::InternalServerError().finish()
        }
    }
}

// Endpoint function for contract_state
#[utoipa::path(
    post,
    path = "/v1/contract_state",
    responses(
        (status = 200, description = "OK", body = ContractStateRequestResponse),
    ),
    request_body = ContractStateRequestBody,
    params(RequestParameters),
)]
pub async fn contract_state(
    query: web::Query<RequestParameters>,
    body: web::Json<ContractStateRequestBody>,
    handler: web::Data<RpcHandler>,
) -> HttpResponse {
    handle_request(query, body, handler, |h, b, q| async move {
        // We don't want to directly return the result of the function because we want to
        // ensure the returned type is what we expect. This is because the only constraint in
        // handle_request is that this type implements serde::Serialize, and it's too broad
        let result: Result<ContractStateRequestResponse, RpcError> = h
            .into_inner()
            .get_contract_state(&b, &q)
            .await;
        result
    })
    .await
}

// Endpoint function for contract_delta
#[utoipa::path(
    post,
    path = "/v1/contract_delta",
    responses(
        (status = 200, description = "OK", body = ContractDeltaRequestResponse),
    ),
    request_body = ContractDeltaRequestBody,
    params(RequestParameters),
)]
pub async fn contract_delta(
    query: web::Query<RequestParameters>,
    body: web::Json<ContractDeltaRequestBody>,
    handler: web::Data<RpcHandler>,
) -> HttpResponse {
    handle_request(query, body, handler, |h, b, q| async move {
        // We don't want to directly return the result of the function because we want to
        // ensure the returned type is what we expect. This is because the only constraint in
        // handle_request is that this type implements serde::Serialize, and it's too broad
        let result: Result<ContractDeltaRequestResponse, RpcError> = h
            .into_inner()
            .get_contract_delta(&b, &q)
            .await;
        result
    })
    .await
}

    match response {
        Ok(state) => HttpResponse::Ok().json(state),
        Err(err) => {
            error!(error = %err, ?body, ?query, "Error while getting contract state.");
            HttpResponse::InternalServerError().finish()
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        hex_bytes::Bytes,
        storage::{
            postgres::{self, db_fixtures},
            ChangeType,
        },
    };
    use actix_web::test;
    use diesel_async::AsyncConnection;
    use ethers::types::{H160, U256};

    use std::{collections::HashMap, str::FromStr, sync::Arc};

    use super::*;

    #[test]
    async fn test_parse_state_request() {
        let json_str = r#"
        {
            "contractIds": [
                {
                    "address": "0xb4eccE46b8D4e4abFd03C9B806276A6735C9c092",
                    "chain": "ethereum"
                }
            ],
            "version": {
                "timestamp": "2069-01-01T04:20:00",
                "block": {
                    "hash": "0x24101f9cb26cd09425b52da10e8c2f56ede94089a8bbe0f31f1cda5f4daa52c4",
                    "parentHash": "0x8d75152454e60413efe758cc424bfd339897062d7e658f302765eb7b50971815",
                    "number": 213,
                    "chain": "ethereum"
                }
            }
        }
        "#;

        let result: ContractStateRequestBody = serde_json::from_str(json_str).unwrap();

        let contract0 = "b4eccE46b8D4e4abFd03C9B806276A6735C9c092".into();
        let block_hash = "24101f9cb26cd09425b52da10e8c2f56ede94089a8bbe0f31f1cda5f4daa52c4".into();
        let block_number = 213;

        let expected_timestamp =
            NaiveDateTime::parse_from_str("2069-01-01T04:20:00", "%Y-%m-%dT%H:%M:%S").unwrap();

        let expected = ContractStateRequestBody {
            contract_ids: Some(vec![ContractId::new(Chain::Ethereum, contract0)]),
            version: Version {
                timestamp: Some(expected_timestamp),
                block: Some(Block {
                    hash: Some(block_hash),
                    chain: Some(Chain::Ethereum),
                    number: Some(block_number),
                }),
            },
        };

        assert_eq!(result, expected);
    }

    #[test]
    async fn test_parse_state_request_no_contract_specified() {
        let json_str = r#"
    {
        "version": {
            "timestamp": "2069-01-01T04:20:00",
            "block": {
                "hash": "0x24101f9cb26cd09425b52da10e8c2f56ede94089a8bbe0f31f1cda5f4daa52c4",
                "parentHash": "0x8d75152454e60413efe758cc424bfd339897062d7e658f302765eb7b50971815",
                "number": 213,
                "chain": "ethereum"
            }
        }
    }
    "#;

        let result: ContractStateRequestBody = serde_json::from_str(json_str).unwrap();

        let block_hash = "24101f9cb26cd09425b52da10e8c2f56ede94089a8bbe0f31f1cda5f4daa52c4".into();
        let block_number = 213;
        let expected_timestamp =
            NaiveDateTime::parse_from_str("2069-01-01T04:20:00", "%Y-%m-%dT%H:%M:%S").unwrap();

        let expected = ContractStateRequestBody {
            contract_ids: None,
            version: Version {
                timestamp: Some(expected_timestamp),
                block: Some(Block {
                    hash: Some(block_hash),
                    chain: Some(Chain::Ethereum),
                    number: Some(block_number),
                }),
            },
        };

        assert_eq!(result, expected);
    }

    #[test]
    async fn test_validate_version_priority() {
        let json_str = r#"
    {
        "version": {
            "timestamp": "2069-01-01T04:20:00",
            "block": {
                "hash": "0x24101f9cb26cd09425b52da10e8c2f56ede94089a8bbe0f31f1cda5f4daa52c4",
                "parentHash": "0x8d75152454e60413efe758cc424bfd339897062d7e658f302765eb7b50971815",
                "number": 213,
                "chain": "ethereum"
            }
        }
    }
    "#;

        let body: ContractStateRequestBody = serde_json::from_str(json_str).unwrap();

        let version = BlockOrTimestamp::try_from(&body.version).unwrap();
        assert_eq!(
            version,
            BlockOrTimestamp::Block(BlockIdentifier::Hash(
                Bytes::from_str("24101f9cb26cd09425b52da10e8c2f56ede94089a8bbe0f31f1cda5f4daa52c4")
                    .unwrap()
            ))
        );
    }

    #[test]
    async fn test_validate_version_with_block_number() {
        let json_str = r#"
    {
        "version": {
            "block": {
                "number": 213,
                "chain": "ethereum"
            }
        }
    }
    "#;

        let body: ContractStateRequestBody = serde_json::from_str(json_str).unwrap();

        let version = BlockOrTimestamp::try_from(&body.version).unwrap();
        assert_eq!(
            version,
            BlockOrTimestamp::Block(BlockIdentifier::Number((Chain::Ethereum, 213)))
        );
    }

    #[test]
    async fn test_parse_state_request_no_version_specified() {
        let json_str = r#"
    {
        "contractIds": [
            {
                "address": "0xb4eccE46b8D4e4abFd03C9B806276A6735C9c092",
                "chain": "ethereum"
            }
        ]
    }
    "#;

        let result: ContractStateRequestBody = serde_json::from_str(json_str).unwrap();

        let contract0 = "b4eccE46b8D4e4abFd03C9B806276A6735C9c092".into();

        let expected = ContractStateRequestBody {
            contract_ids: Some(vec![ContractId::new(Chain::Ethereum, contract0)]),
            version: Version { timestamp: Some(Utc::now().naive_utc()), block: None },
        };

        let time_difference = expected
            .version
            .timestamp
            .unwrap()
            .timestamp_millis() -
            result
                .version
                .timestamp
                .unwrap()
                .timestamp_millis();

        // Allowing a small time delta (1 second)
        assert!(time_difference <= 1000);
        assert_eq!(result.contract_ids, expected.contract_ids);
        assert_eq!(result.version.block, expected.version.block);
    }

    pub async fn setup_account(conn: &mut AsyncPgConnection) -> String {
        // Adds fixtures: chain, block, transaction, account, account_balance
        let acc_address = "6B175474E89094C44Da98b954EedeAC495271d0F";
        let chain_id = db_fixtures::insert_chain(conn, "ethereum").await;
        let blk = db_fixtures::insert_blocks(conn, chain_id).await;
        let txn = db_fixtures::insert_txns(
            conn,
            &[
                (
                    // deploy c0
                    blk[0],
                    1i64,
                    "0xbb7e16d797a9e2fbc537e30f91ed3d27a254dd9578aa4c3af3e5f0d3e8130945",
                ),
                (
                    // change c0 state, deploy c2
                    blk[0],
                    2i64,
                    "0x794f7df7a3fe973f1583fbb92536f9a8def3a89902439289315326c04068de54",
                ),
                // ----- Block 01 LAST
                (
                    // deploy c1, delete c2
                    blk[1],
                    1i64,
                    "0x3108322284d0a89a7accb288d1a94384d499504fe7e04441b0706c7628dee7b7",
                ),
                (
                    // change c0 and c1 state
                    blk[1],
                    2i64,
                    "0x50449de1973d86f21bfafa7c72011854a7e33a226709dc3e2e4edcca34188388",
                ),
                // ----- Block 02 LAST
            ],
        )
        .await;
        let c0 = db_fixtures::insert_account(conn, acc_address, "account0", chain_id, Some(txn[0]))
            .await;
        db_fixtures::insert_account_balance(conn, 0, txn[0], c0).await;
        db_fixtures::insert_contract_code(conn, c0, txn[0], Bytes::from_str("C0C0C0").unwrap())
            .await;
        db_fixtures::insert_account_balance(conn, 100, txn[1], c0).await;
        db_fixtures::insert_slots(
            conn,
            c0,
            txn[1],
            "2020-01-01T00:00:00",
            &[(0, 1), (1, 5), (2, 1)],
        )
        .await;
        db_fixtures::insert_account_balance(conn, 101, txn[3], c0).await;
        db_fixtures::insert_slots(
            conn,
            c0,
            txn[3],
            "2020-01-01T01:00:00",
            &[(0, 2), (1, 3), (5, 25), (6, 30)],
        )
        .await;

        let c1 = db_fixtures::insert_account(
            conn,
            "73BcE791c239c8010Cd3C857d96580037CCdd0EE",
            "c1",
            chain_id,
            Some(txn[2]),
        )
        .await;
        db_fixtures::insert_account_balance(conn, 50, txn[2], c1).await;
        db_fixtures::insert_contract_code(conn, c1, txn[2], Bytes::from_str("C1C1C1").unwrap())
            .await;
        db_fixtures::insert_slots(conn, c1, txn[3], "2020-01-01T01:00:00", &[(0, 128), (1, 255)])
            .await;

        let c2 = db_fixtures::insert_account(
            conn,
            "94a3F312366b8D0a32A00986194053C0ed0CdDb1",
            "c2",
            chain_id,
            Some(txn[1]),
        )
        .await;
        db_fixtures::insert_account_balance(conn, 25, txn[1], c2).await;
        db_fixtures::insert_contract_code(conn, c2, txn[1], Bytes::from_str("C2C2C2").unwrap())
            .await;
        db_fixtures::insert_slots(conn, c2, txn[1], "2020-01-01T00:00:00", &[(1, 2), (2, 4)]).await;
        db_fixtures::delete_account(conn, c2, "2020-01-01T01:00:00").await;
        acc_address.to_string()
    }

    fn evm_slots(data: impl IntoIterator<Item = (i32, i32)>) -> HashMap<U256, U256> {
        data.into_iter()
            .map(|(s, v)| (U256::from(s), U256::from(v)))
            .collect()
    }

    #[tokio::test]
    async fn test_get_contract_state() {
        let db_url = std::env::var("DATABASE_URL").unwrap();
        let pool = postgres::connect(&db_url)
            .await
            .unwrap();
        let cloned_pool = pool.clone();
        let mut conn = cloned_pool.get().await.unwrap();
        conn.begin_test_transaction()
            .await
            .unwrap();
        let acc_address = setup_account(&mut conn).await;

        let db_gateway = Arc::new(EvmPostgresGateway::from_connection(&mut conn).await);
        let req_handler = RpcHandler::new(db_gateway, pool);

        let expected = evm::Account {
            chain: Chain::Ethereum,
            address: "0x6b175474e89094c44da98b954eedeac495271d0f"
                .parse()
                .unwrap(),
            title: "account0".to_owned(),
            slots: evm_slots([(6, 30), (5, 25), (1, 3), (2, 1), (0, 2)]),
            balance: U256::from(101),
            code: Bytes::from_str("C0C0C0").unwrap(),
            code_hash: "0x106781541fd1c596ade97569d584baf47e3347d3ac67ce7757d633202061bdc4"
                .parse()
                .unwrap(),
            balance_modify_tx: "0x50449de1973d86f21bfafa7c72011854a7e33a226709dc3e2e4edcca34188388"
                .parse()
                .unwrap(),
            code_modify_tx: "0xbb7e16d797a9e2fbc537e30f91ed3d27a254dd9578aa4c3af3e5f0d3e8130945"
                .parse()
                .unwrap(),
            creation_tx: Some(
                "0xbb7e16d797a9e2fbc537e30f91ed3d27a254dd9578aa4c3af3e5f0d3e8130945"
                    .parse()
                    .unwrap(),
            ),
        };

        let request = ContractStateRequestBody {
            contract_ids: Some(vec![ContractId::new(
                Chain::Ethereum,
                acc_address.parse().unwrap(),
            )]),
            version: Version { timestamp: Some(Utc::now().naive_utc()), block: None },
        };

        let state = req_handler
            .get_contract_state_inner(&request, &RequestParameters::default(), &mut conn)
            .await
            .unwrap();

        assert_eq!(state.accounts.len(), 1);
        assert_eq!(state.accounts[0], expected.into());
    }

    #[tokio::test]
    async fn test_get_contract_delta() {
        // Setup
        let db_url = std::env::var("DATABASE_URL").unwrap();
        let pool = postgres::connect(&db_url)
            .await
            .unwrap();
        let mut conn = pool.get().await.unwrap();
        conn.begin_test_transaction()
            .await
            .unwrap();
        let acc_address = setup_account(&mut conn).await;

        let db_gateway = Arc::new(EvmPostgresGateway::from_connection(&mut conn).await);
        let req_handler = RpcHandler::new(db_gateway, pool);

        let expected = evm::AccountUpdate::new(
            H160::from_str("6B175474E89094C44Da98b954EedeAC495271d0F").unwrap(),
            Chain::Ethereum,
            evm_slots([(6, 30), (5, 25), (1, 3), (0, 2)]),
            Some(U256::from(101)),
            None,
            ChangeType::Update,
        );

        let request = ContractDeltaRequestBody {
            contract_ids: Some(vec![ContractId::new(
                Chain::Ethereum,
                acc_address.parse().unwrap(),
            )]),
            start: Version {
                timestamp: None,
                block: Some(Block {
                    hash: Some(
                        "0x88e96d4537bea4d9c05d12549907b32561d3bf31f45aae734cdc119f13406cb6"
                            .parse()
                            .unwrap(),
                    ),
                    chain: None,
                    number: None,
                }),
            },
            end: Version {
                timestamp: None,
                block: Some(Block {
                    hash: Some(
                        "0xb495a1d7e6663152ae92708da4843337b958146015a2802f4193a410044698c9"
                            .parse()
                            .unwrap(),
                    ),
                    chain: None,
                    number: None,
                }),
            },
        };

        let state = req_handler
            .get_contract_delta_inner(&request, &RequestParameters::default(), &mut conn)
            .await
            .unwrap();

        assert_eq!(state.accounts.len(), 1);
        assert_eq!(state.accounts[0], expected.into());
    }

    #[test]
    async fn test_msg() {
        // Define the contract address and endpoint
        let endpoint = "http://127.0.0.1:4242/v1/contract_state";

        // Create the request body using the ContractStateRequestBody struct
        let request_body = ContractStateRequestBody {
            contract_ids: Some(vec![ContractId::new(
                Chain::Ethereum,
                Bytes::from_str("b4eccE46b8D4e4abFd03C9B806276A6735C9c092").unwrap(),
            )]),
            version: Version::default(),
        };

        // Serialize the request body to JSON
        let json_data = serde_json::to_string(&request_body).expect("Failed to serialize to JSON");

        // Print the curl command
        println!(
            "curl -X POST -H \"Content-Type: application/json\" -d '{}' {}",
            json_data, endpoint
        );
    }
}
