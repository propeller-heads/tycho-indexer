//! This module contains Tycho RPC implementation

use crate::{
    extractor::evm::{self, Account},
    models::Chain,
    serde_helpers::{deserialize_hex, serialize_hex},
    storage::{
        self, postgres::PostgresGateway, BlockIdentifier, BlockOrTimestamp, ContractId,
        ContractStateGateway, StorageError,
    },
};
use actix_web::{post, web, HttpResponse, Responder};
use chrono::{NaiveDateTime, Utc};
use diesel_async::{pooled_connection::bb8::Pool, AsyncPgConnection};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::error;

struct RequestHandler {
    db_gw: PostgresGateway<evm::Block, evm::Transaction, evm::Account, evm::AccountUpdate>,
    pool: Pool<AsyncPgConnection>,
}

impl RequestHandler {
    pub fn new(
        db_gw: PostgresGateway<evm::Block, evm::Transaction, evm::Account, evm::AccountUpdate>,
        pool: Pool<AsyncPgConnection>,
    ) -> Self {
        Self { db_gw, pool }
    }

    async fn get_state(
        &self,
        request: &StateRequestBody,
        params: &QueryParameters,
    ) -> Result<StateRequestResponse, RpcError> {
        let mut db_conn = self.pool.get().await.unwrap();
        self.get_state_with_conn(request, params, &mut db_conn)
            .await
    }

    async fn get_state_with_conn(
        &self,
        request: &StateRequestBody,
        params: &QueryParameters,
        db_conn: &mut AsyncPgConnection,
    ) -> Result<StateRequestResponse, RpcError> {
        //TODO: handle when no contract is specified with filters
        let at = match &request.version.block {
            Some(b) => BlockOrTimestamp::Block(BlockIdentifier::Hash(b.hash.clone())),
            None => BlockOrTimestamp::Timestamp(request.version.timestamp),
        };

        let version = storage::Version(at, storage::VersionKind::Last);

        // Get the contract IDs from the request
        let contract_ids = request.contract_ids.clone();
        let address_slices: Option<Vec<&[u8]>> = contract_ids.as_ref().map(|ids| {
            ids.iter()
                .map(|id| id.address.as_slice())
                .collect()
        });
        let addresses: Option<&[&[u8]]> = address_slices.as_deref();

        // Get the contract states from the database
        // TODO support additional tvl_gt and intertia_min_gt filters
        match self
            .db_gw
            .get_contracts(params.chain, addresses, Some(&version), false, db_conn)
            .await
        {
            Ok(accounts) => Ok(StateRequestResponse::new(accounts)),
            Err(e) => {
                error!("Error while getting contract states: {}", e);
                Err(RpcError::StorageError(e))
            }
        }
    }
}

#[post("/contract_state")]
async fn contract_state(
    query: web::Query<QueryParameters>,
    body: web::Json<StateRequestBody>,
    handler: web::Data<RequestHandler>,
) -> impl Responder {
    // Call the handler to get the state
    let response = handler
        .into_inner()
        .get_state(&body, &query)
        .await;

    match response {
        Ok(state) => HttpResponse::Ok().json(state),
        Err(e) => {
            error!("Error while getting contract state: request body: {:?}, query parameters: {:?}, error: {}", body, query, e);
            HttpResponse::InternalServerError().finish()
        }
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct StateRequestResponse {
    accounts: Vec<Account>,
}

impl StateRequestResponse {
    fn new(accounts: Vec<Account>) -> Self {
        Self { accounts }
    }
}

#[derive(Error, Debug)]
pub enum RpcError {
    #[error("Failed to parse JSON: {0}")]
    ParseError(#[from] serde_json::Error),

    #[error("Failed to get storage: {0}")]
    StorageError(#[from] StorageError),
}

#[derive(Serialize, Deserialize, Default, Debug)]
struct QueryParameters {
    #[serde(default = "Chain::default")]
    chain: Chain,
    tvl_gt: Option<f64>,
    intertia_min_gt: Option<f64>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct StateRequestBody {
    #[serde(rename = "contractIds")]
    contract_ids: Option<Vec<ContractId>>,
    #[serde(default = "Version::default")]
    version: Version,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct Version {
    timestamp: NaiveDateTime,
    block: Option<Block>,
}

impl Default for Version {
    fn default() -> Self {
        Version { timestamp: Utc::now().naive_utc(), block: None }
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct Block {
    #[serde(serialize_with = "serialize_hex", deserialize_with = "deserialize_hex")]
    hash: Vec<u8>,
    #[serde(
        rename = "parentHash",
        serialize_with = "serialize_hex",
        deserialize_with = "deserialize_hex"
    )]
    parent_hash: Vec<u8>,
    chain: Chain,
    number: i64,
}

#[cfg(test)]
mod tests {
    use crate::storage::postgres::{connect, db_fixtures};
    use actix_web::test;
    use diesel_async::AsyncConnection;
    use ethers::types::{H160, H256, U256};
    use std::{collections::HashMap, str::FromStr};

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

        let result: StateRequestBody = serde_json::from_str(json_str).unwrap();

        let contract0 = hex::decode("b4eccE46b8D4e4abFd03C9B806276A6735C9c092").unwrap();
        let block_hash =
            hex::decode("24101f9cb26cd09425b52da10e8c2f56ede94089a8bbe0f31f1cda5f4daa52c4")
                .unwrap();
        let parent_block_hash =
            hex::decode("8d75152454e60413efe758cc424bfd339897062d7e658f302765eb7b50971815")
                .unwrap();
        let block_number = 213;

        let expected_timestamp =
            NaiveDateTime::parse_from_str("2069-01-01T04:20:00", "%Y-%m-%dT%H:%M:%S").unwrap();

        let expected = StateRequestBody {
            contract_ids: Some(vec![ContractId::new(Chain::Ethereum, contract0)]),
            version: Version {
                timestamp: expected_timestamp,
                block: Some(Block {
                    hash: block_hash,
                    parent_hash: parent_block_hash,
                    chain: Chain::Ethereum,
                    number: block_number,
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

        let result: StateRequestBody = serde_json::from_str(json_str).unwrap();

        let block_hash =
            hex::decode("24101f9cb26cd09425b52da10e8c2f56ede94089a8bbe0f31f1cda5f4daa52c4")
                .unwrap();
        let parent_block_hash =
            hex::decode("8d75152454e60413efe758cc424bfd339897062d7e658f302765eb7b50971815")
                .unwrap();
        let block_number = 213;
        let expected_timestamp =
            NaiveDateTime::parse_from_str("2069-01-01T04:20:00", "%Y-%m-%dT%H:%M:%S").unwrap();

        let expected = StateRequestBody {
            contract_ids: None,
            version: Version {
                timestamp: expected_timestamp,
                block: Some(Block {
                    hash: block_hash,
                    parent_hash: parent_block_hash,
                    chain: Chain::Ethereum,
                    number: block_number,
                }),
            },
        };

        assert_eq!(result, expected);
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

        let result: StateRequestBody = serde_json::from_str(json_str).unwrap();

        let contract0 = hex::decode("b4eccE46b8D4e4abFd03C9B806276A6735C9c092").unwrap();

        let expected = StateRequestBody {
            contract_ids: Some(vec![ContractId::new(Chain::Ethereum, contract0)]),
            version: Version { timestamp: Utc::now().naive_utc(), block: None },
        };

        let time_difference = expected
            .version
            .timestamp
            .timestamp_millis() -
            result
                .version
                .timestamp
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
        let tid = db_fixtures::insert_txns(
            conn,
            &[
                (
                    blk[0],
                    1i64,
                    "0xbb7e16d797a9e2fbc537e30f91ed3d27a254dd9578aa4c3af3e5f0d3e8130945",
                ),
                (
                    blk[1],
                    1i64,
                    "0x3108322284d0a89a7accb288d1a94384d499504fe7e04441b0706c7628dee7b7",
                ),
            ],
        )
        .await;
        // Insert account and balances
        let acc_id =
            db_fixtures::insert_account(conn, acc_address, "account0", chain_id, Some(tid[0]))
                .await;

        db_fixtures::insert_account_balance(conn, 100, tid[0], acc_id).await;
        let contract_code = hex::decode("1234").unwrap();
        db_fixtures::insert_contract_code(conn, acc_id, tid[0], contract_code).await;
        acc_address.to_string()
    }

    #[tokio::test]
    async fn test_get_state() {
        let db_url = std::env::var("DATABASE_URL").unwrap();
        let pool = connect(&db_url).await.unwrap();
        let mut conn = pool.get().await.unwrap();

        conn.begin_test_transaction()
            .await
            .unwrap();

        let acc_address = setup_account(&mut conn).await;

        let db_gw = PostgresGateway::<
            evm::Block,
            evm::Transaction,
            evm::Account,
            evm::AccountUpdate,
        >::from_connection(&mut conn)
        .await;
        // Initiate with a new pool, but which will not be used in the test
        let req_handler = RequestHandler::new(db_gw, connect(&db_url).await.unwrap());

        let code = hex::decode("1234").unwrap();
        let code_hash = H256::from_slice(&ethers::utils::keccak256(&code));
        let expected = Account::new(
            Chain::Ethereum,
            H160::from_str("6B175474E89094C44Da98b954EedeAC495271d0F").unwrap(),
            "account0".to_owned(),
            HashMap::new(),
            U256::from(100),
            code,
            code_hash,
            "0xbb7e16d797a9e2fbc537e30f91ed3d27a254dd9578aa4c3af3e5f0d3e8130945"
                .parse()
                .unwrap(),
            "0xbb7e16d797a9e2fbc537e30f91ed3d27a254dd9578aa4c3af3e5f0d3e8130945"
                .parse()
                .unwrap(),
            Some(
                "0xbb7e16d797a9e2fbc537e30f91ed3d27a254dd9578aa4c3af3e5f0d3e8130945"
                    .parse()
                    .unwrap(),
            ),
        );

        let request = StateRequestBody {
            contract_ids: Some(vec![ContractId::new(
                Chain::Ethereum,
                hex::decode(acc_address).unwrap(),
            )]),
            version: Version { timestamp: Utc::now().naive_utc(), block: None },
        };

        let state = req_handler
            .get_state_with_conn(&request, &QueryParameters::default(), &mut conn)
            .await
            .unwrap();

        assert_eq!(state.accounts.len(), 1);
        assert_eq!(state.accounts[0], expected);
    }
}
