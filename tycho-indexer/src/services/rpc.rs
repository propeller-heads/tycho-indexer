//! This module contains Tycho RPC implementation

use std::sync::Arc;

use crate::{
    extractor::evm::Account,
    models::Chain,
    storage::{
        self, Address, BlockHash, BlockIdentifier, BlockOrTimestamp, ContractId,
        ContractStateGateway, StorageError,
    },
};
use actix_web::{web, HttpResponse};
use chrono::{NaiveDateTime, Utc};
use diesel_async::{
    pooled_connection::bb8::{self, Pool},
    AsyncPgConnection,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::error;

use super::EvmPostgresGateway;

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

    async fn get_state(
        &self,
        request: &StateRequestBody,
        params: &StateRequestParameters,
    ) -> Result<StateRequestResponse, RpcError> {
        let mut conn = self.db_connection_pool.get().await?;
        self.get_state_inner(request, params, &mut conn)
            .await
    }

    async fn get_state_inner(
        &self,
        request: &StateRequestBody,
        params: &StateRequestParameters,
        db_connection: &mut AsyncPgConnection,
    ) -> Result<StateRequestResponse, RpcError> {
        //TODO: handle when no contract is specified with filters
        let at = match &request.version.block {
            Some(b) => BlockOrTimestamp::Block(BlockIdentifier::Hash(b.hash.clone())),
            None => BlockOrTimestamp::Timestamp(request.version.timestamp),
        };

        let version = storage::Version(at, storage::VersionKind::Last);

        // Get the contract IDs from the request
        let contract_ids = request.contract_ids.clone();
        let addresses: Option<Vec<Address>> = contract_ids.map(|ids| {
            ids.into_iter()
                .map(|id| id.address)
                .collect::<Vec<Address>>()
        });
        let addresses = addresses.as_deref();

        // Get the contract states from the database
        // TODO support additional tvl_gt and intertia_min_gt filters
        match self
            .db_gateway
            .get_contracts(&params.chain, addresses, Some(&version), false, db_connection)
            .await
        {
            Ok(accounts) => Ok(StateRequestResponse::new(accounts)),
            Err(err) => {
                error!(error = %err, "Error while getting contract states.");
                Err(err.into())
            }
        }
    }
}

pub async fn contract_state(
    query: web::Query<StateRequestParameters>,
    body: web::Json<StateRequestBody>,
    handler: web::Data<RpcHandler>,
) -> HttpResponse {
    // Call the handler to get the state
    let response = handler
        .into_inner()
        .get_state(&body, &query)
        .await;

    match response {
        Ok(state) => HttpResponse::Ok().json(state),
        Err(err) => {
            error!(error = %err, ?body, ?query, "Error while getting contract state.");
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
    Parse(#[from] serde_json::Error),

    #[error("Failed to get storage: {0}")]
    Storage(#[from] StorageError),

    #[error("Failed to get database connection: {0}")]
    Connection(#[from] bb8::RunError),
}

#[derive(Serialize, Deserialize, Default, Debug)]
pub struct StateRequestParameters {
    #[serde(default = "Chain::default")]
    chain: Chain,
    tvl_gt: Option<u64>,
    intertia_min_gt: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct StateRequestBody {
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
    hash: BlockHash,
    #[serde(rename = "parentHash")]
    parent_hash: BlockHash,
    chain: Chain,
    number: i64,
}

#[cfg(test)]
mod tests {
    use crate::{
        hex_bytes::Bytes,
        storage::{
            postgres::{self, db_fixtures},
            Code,
        },
    };
    use actix_web::test;
    use diesel_async::AsyncConnection;
    use ethers::types::{H160, H256, U256};

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

        let result: StateRequestBody = serde_json::from_str(json_str).unwrap();

        let contract0 = "b4eccE46b8D4e4abFd03C9B806276A6735C9c092".into();
        let block_hash = "24101f9cb26cd09425b52da10e8c2f56ede94089a8bbe0f31f1cda5f4daa52c4".into();
        let parent_block_hash =
            "8d75152454e60413efe758cc424bfd339897062d7e658f302765eb7b50971815".into();
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

        let block_hash = "24101f9cb26cd09425b52da10e8c2f56ede94089a8bbe0f31f1cda5f4daa52c4".into();
        let parent_block_hash =
            "8d75152454e60413efe758cc424bfd339897062d7e658f302765eb7b50971815".into();
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

        let contract0 = "b4eccE46b8D4e4abFd03C9B806276A6735C9c092".into();

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
        let contract_code = Code::from("1234");
        db_fixtures::insert_contract_code(conn, acc_id, tid[0], contract_code).await;
        acc_address.to_string()
    }

    #[tokio::test]
    async fn test_get_state() {
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

        let code = Code::from("1234");
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
                acc_address.parse().unwrap(),
            )]),
            version: Version { timestamp: Utc::now().naive_utc(), block: None },
        };

        let state = req_handler
            .get_state_inner(&request, &StateRequestParameters::default(), &mut conn)
            .await
            .unwrap();

        assert_eq!(state.accounts.len(), 1);
        assert_eq!(state.accounts[0], expected);
    }

    #[test]
    async fn test_msg() {
        // Define the contract address and endpoint
        let endpoint = "http://127.0.0.1:4242/v1/contract_state";

        // Create the request body using the StateRequestBody struct
        let request_body = StateRequestBody {
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
