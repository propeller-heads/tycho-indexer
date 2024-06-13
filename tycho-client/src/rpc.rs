//! # Tycho RPC Client
//!
//! The objective of this module is to provide swift and simplified access to the Remote Procedure
//! Call (RPC) endpoints of Tycho. These endpoints are chiefly responsible for facilitating data
//! queries, especially querying snapshots of data.
//!
//! Currently we provide only a HTTP implementation.
use hyper::{client::HttpConnector, Body, Client, Request, Uri};
#[cfg(test)]
use mockall::automock;
use std::sync::Arc;
use thiserror::Error;
use tracing::{debug, error, instrument, trace, warn};

use async_trait::async_trait;
use futures03::future::try_join_all;

use tycho_core::dto::{
    Chain, PaginationParams, ProtocolComponentRequestParameters, ProtocolComponentRequestResponse,
    ProtocolComponentsRequestBody, ProtocolId, ProtocolStateRequestBody,
    ProtocolStateRequestResponse, ResponseToken, StateRequestBody, StateRequestParameters,
    StateRequestResponse, TokensRequestBody, TokensRequestResponse, VersionParam,
};

use tokio::sync::Semaphore;

use crate::TYCHO_SERVER_VERSION;

#[derive(Error, Debug)]
pub enum RPCError {
    /// The passed tycho url failed to parse.
    #[error("Failed to parse URI: {0}. Error: {1}")]
    UriParsing(String, String),
    /// The request data is not correctly formed.
    #[error("Failed to format request: {0}")]
    FormatRequest(String),
    /// Errors forwarded from the HTTP protocol.
    #[error("Unexpected HTTP client error: {0}")]
    HttpClient(String),
    /// The response from the server could not be parsed correctly.
    #[error("Failed to parse response: {0}")]
    ParseResponse(String),
    #[error("Fatal error: {0}")]
    Fatal(String),
}

#[cfg_attr(test, automock)]
#[async_trait]
pub trait RPCClient {
    /// Retrieves a snapshot of contract state.
    async fn get_contract_state(
        &self,
        chain: Chain,
        filters: &StateRequestParameters,
        request: &StateRequestBody,
    ) -> Result<StateRequestResponse, RPCError>;

    async fn get_protocol_components(
        &self,
        chain: Chain,
        filters: &ProtocolComponentRequestParameters,
        request: &ProtocolComponentsRequestBody,
    ) -> Result<ProtocolComponentRequestResponse, RPCError>;

    async fn get_protocol_states(
        &self,
        chain: Chain,
        filters: &StateRequestParameters,
        request: &ProtocolStateRequestBody,
    ) -> Result<ProtocolStateRequestResponse, RPCError>;

    async fn get_protocol_states_paginated(
        &self,
        chain: Chain,
        filters: &StateRequestParameters,
        ids: &[ProtocolId],
        version: &VersionParam,
        chunk_size: usize,
        concurrency: usize,
    ) -> Result<ProtocolStateRequestResponse, RPCError> {
        let semaphore = Arc::new(Semaphore::new(concurrency));
        let chunked_bodies = ids
            .chunks(chunk_size)
            .map(|c| ProtocolStateRequestBody {
                protocol_ids: Some(c.to_vec()),
                protocol_system: None,
                version: version.clone(),
            })
            .collect::<Vec<_>>();

        let mut tasks = Vec::new();
        for body in chunked_bodies.iter() {
            let sem = semaphore.clone();
            tasks.push(async move {
                let _permit = sem
                    .acquire()
                    .await
                    .map_err(|_| RPCError::Fatal("Semaphore dropped".to_string()))?;
                self.get_protocol_states(chain, filters, body)
                    .await
            });
        }

        try_join_all(tasks)
            .await
            .map(|responses| ProtocolStateRequestResponse {
                states: responses
                    .into_iter()
                    .flat_map(|r| r.states.into_iter())
                    .collect(),
            })
    }

    /// This function returns only one chunk of tokens. To get all tokens please call
    /// get_all_tokens.
    async fn get_tokens(
        &self,
        chain: &Chain,
        request: &TokensRequestBody,
    ) -> Result<TokensRequestResponse, RPCError>;

    async fn get_all_tokens(
        &self,
        chain: Chain,
        min_quality: Option<i32>,
        traded_n_days_ago: Option<u64>,
        chunk_size: usize,
    ) -> Result<Vec<ResponseToken>, RPCError> {
        let mut request_page = 0;
        let mut all_tokens = Vec::new();
        loop {
            let mut response = self
                .get_tokens(
                    &chain,
                    &TokensRequestBody {
                        token_addresses: None,
                        min_quality,
                        traded_n_days_ago,
                        pagination: PaginationParams {
                            page: request_page,
                            page_size: chunk_size.try_into().map_err(|_| {
                                RPCError::FormatRequest(
                                    "Failed to convert chunk_size into i64".to_string(),
                                )
                            })?,
                        },
                    },
                )
                .await?;

            let num_tokens = response.tokens.len();
            all_tokens.append(&mut response.tokens);
            request_page += 1;

            if num_tokens < chunk_size {
                break;
            }
        }
        Ok(all_tokens)
    }
}

#[derive(Debug, Clone)]
pub struct HttpRPCClient {
    http_client: Client<HttpConnector>,
    uri: Uri,
}

impl HttpRPCClient {
    pub fn new(base_uri: &str) -> Result<Self, RPCError> {
        let uri = base_uri
            .parse::<Uri>()
            .map_err(|e| RPCError::UriParsing(base_uri.to_string(), e.to_string()))?;

        Ok(Self { http_client: Client::new(), uri })
    }
}

#[async_trait]
impl RPCClient for HttpRPCClient {
    #[instrument(skip(self, filters, request))]
    async fn get_contract_state(
        &self,
        chain: Chain,
        filters: &StateRequestParameters,
        request: &StateRequestBody,
    ) -> Result<StateRequestResponse, RPCError> {
        // Check if contract ids are specified
        if request.contract_ids.is_none() ||
            request
                .contract_ids
                .as_ref()
                .unwrap()
                .is_empty()
        {
            warn!("No contract ids specified in request.");
        }

        let uri = format!(
            "{}/{}/{}/contract_state{}",
            self.uri
                .to_string()
                .trim_end_matches('/'),
            TYCHO_SERVER_VERSION,
            chain,
            filters.to_query_string()
        );
        debug!(%uri, "Sending contract_state request to Tycho server");
        let body =
            serde_json::to_string(&request).map_err(|e| RPCError::FormatRequest(e.to_string()))?;

        let header = hyper::header::HeaderValue::from_str("application/json")
            .map_err(|e| RPCError::FormatRequest(e.to_string()))?;

        let req = Request::post(uri)
            .header(hyper::header::CONTENT_TYPE, header)
            .body(Body::from(body))
            .map_err(|e| RPCError::FormatRequest(e.to_string()))?;
        trace!(?req, "Sending request to Tycho server");

        let response = self
            .http_client
            .request(req)
            .await
            .map_err(|e| RPCError::HttpClient(e.to_string()))?;
        trace!(?response, "Received response from Tycho server");

        let body = hyper::body::to_bytes(response.into_body())
            .await
            .map_err(|e| RPCError::ParseResponse(e.to_string()))?;
        let accounts: StateRequestResponse =
            serde_json::from_slice(&body).map_err(|e| RPCError::ParseResponse(e.to_string()))?;
        trace!(?accounts, "Received contract_state response from Tycho server");

        Ok(accounts)
    }

    async fn get_protocol_components(
        &self,
        chain: Chain,
        filters: &ProtocolComponentRequestParameters,
        request: &ProtocolComponentsRequestBody,
    ) -> Result<ProtocolComponentRequestResponse, RPCError> {
        let uri = format!(
            "{}/{}/{}/protocol_components{}",
            self.uri
                .to_string()
                .trim_end_matches('/'),
            TYCHO_SERVER_VERSION,
            chain,
            filters.to_query_string()
        );
        debug!(%uri, "Sending protocol_components request to Tycho server");

        let body =
            serde_json::to_string(&request).map_err(|e| RPCError::FormatRequest(e.to_string()))?;
        let header = hyper::header::HeaderValue::from_str("application/json")
            .map_err(|e| RPCError::FormatRequest(e.to_string()))?;

        let req = Request::post(uri)
            .header(hyper::header::CONTENT_TYPE, header)
            .body(Body::from(body))
            .map_err(|e| RPCError::FormatRequest(e.to_string()))?;
        trace!(?req, "Sending request to Tycho server");

        let response = self
            .http_client
            .request(req)
            .await
            .map_err(|e| RPCError::HttpClient(e.to_string()))?;
        trace!(?response, "Received response from Tycho server");

        let body = hyper::body::to_bytes(response.into_body())
            .await
            .map_err(|e| RPCError::ParseResponse(e.to_string()))?;
        let components: ProtocolComponentRequestResponse =
            serde_json::from_slice(&body).map_err(|e| RPCError::ParseResponse(e.to_string()))?;
        trace!(?components, "Received protocol_components response from Tycho server");

        Ok(components)
    }

    async fn get_protocol_states(
        &self,
        chain: Chain,
        filters: &StateRequestParameters,
        request: &ProtocolStateRequestBody,
    ) -> Result<ProtocolStateRequestResponse, RPCError> {
        // Check if contract ids are specified
        if request.protocol_ids.is_none() ||
            request
                .protocol_ids
                .as_ref()
                .unwrap()
                .is_empty()
        {
            warn!("No protocol ids specified in request.");
        }

        let uri = format!(
            "{}/{}/{}/protocol_state{}",
            self.uri
                .to_string()
                .trim_end_matches('/'),
            TYCHO_SERVER_VERSION,
            chain,
            filters.to_query_string()
        );
        debug!(%uri, "Sending protocol_states request to Tycho server");

        let body =
            serde_json::to_string(&request).map_err(|e| RPCError::FormatRequest(e.to_string()))?;
        let header = hyper::header::HeaderValue::from_str("application/json")
            .map_err(|e| RPCError::FormatRequest(e.to_string()))?;

        let req = Request::post(uri)
            .header(hyper::header::CONTENT_TYPE, header)
            .body(Body::from(body))
            .map_err(|e| RPCError::FormatRequest(e.to_string()))?;
        trace!(?req, "Sending request to Tycho server");

        let response = self
            .http_client
            .request(req)
            .await
            .map_err(|e| RPCError::HttpClient(e.to_string()))?;
        trace!(?response, "Received response from Tycho server");

        let body = hyper::body::to_bytes(response.into_body())
            .await
            .map_err(|e| RPCError::ParseResponse(e.to_string()))?;
        let states: ProtocolStateRequestResponse =
            serde_json::from_slice(&body).map_err(|e| RPCError::ParseResponse(e.to_string()))?;
        trace!(?states, "Received protocol_states response from Tycho server");

        Ok(states)
    }

    async fn get_tokens(
        &self,
        chain: &Chain,
        request: &TokensRequestBody,
    ) -> Result<TokensRequestResponse, RPCError> {
        let uri = format!(
            "{}/{}/{}/tokens",
            self.uri
                .to_string()
                .trim_end_matches('/'),
            TYCHO_SERVER_VERSION,
            chain,
        );
        debug!(%uri, "Sending token request to Tycho server");

        let body =
            serde_json::to_string(&request).map_err(|e| RPCError::FormatRequest(e.to_string()))?;
        let header = hyper::header::HeaderValue::from_str("application/json")
            .map_err(|e| RPCError::FormatRequest(e.to_string()))?;

        let req = Request::post(uri)
            .header(hyper::header::CONTENT_TYPE, header)
            .body(Body::from(body))
            .map_err(|e| RPCError::FormatRequest(e.to_string()))?;
        trace!(?req, "Sending request to Tycho server");

        let response = self
            .http_client
            .request(req)
            .await
            .map_err(|e| RPCError::HttpClient(e.to_string()))?;
        trace!(?response, "Received response from Tycho server");

        let body = hyper::body::to_bytes(response.into_body())
            .await
            .map_err(|e| RPCError::ParseResponse(e.to_string()))?;
        let states: TokensRequestResponse =
            serde_json::from_slice(&body).map_err(|e| RPCError::ParseResponse(e.to_string()))?;
        trace!(?states, "Received tokens response from Tycho server");

        Ok(states)
    }
}

#[cfg(test)]
mod tests {
    use tycho_core::Bytes;

    use super::*;

    use mockito::Server;

    use std::{collections::HashMap, str::FromStr};

    #[tokio::test]
    async fn test_get_contract_state() {
        let mut server = Server::new_async().await;
        let server_resp = r#"
        {
            "accounts": [
                {
                    "chain": "ethereum",
                    "address": "0x0000000000000000000000000000000000000000",
                    "title": "",
                    "slots": {},
                    "native_balance": "0x01f4",
                    "balances": {
                        "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2": "0x01f4"
                    },
                    "code": "0x00",
                    "code_hash": "0x5c06b7c5b3d910fd33bc2229846f9ddaf91d584d9b196e16636901ac3a77077e",
                    "balance_modify_tx": "0x0000000000000000000000000000000000000000000000000000000000000000",
                    "code_modify_tx": "0x0000000000000000000000000000000000000000000000000000000000000000",
                    "creation_tx": null
                }
            ]
        }
        "#;
        // test that the response is deserialized correctly
        serde_json::from_str::<StateRequestResponse>(server_resp).expect("deserialize");

        let mocked_server = server
            .mock("POST", "/v1/ethereum/contract_state?include_balances=false")
            .expect(1)
            .with_body(server_resp)
            .create_async()
            .await;

        let client = HttpRPCClient::new(server.url().as_str()).expect("create client");

        let response = client
            .get_contract_state(Chain::Ethereum, &Default::default(), &Default::default())
            .await
            .expect("get state");
        let accounts = response.accounts;

        mocked_server.assert();
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].slots, HashMap::new());
        assert_eq!(accounts[0].native_balance, Bytes::from(500u16.to_be_bytes()));
        assert_eq!(accounts[0].code, [0].to_vec());
        assert_eq!(
            accounts[0].code_hash,
            hex::decode("5c06b7c5b3d910fd33bc2229846f9ddaf91d584d9b196e16636901ac3a77077e")
                .unwrap()
        );
        assert_eq!(
            accounts[0].balances.get(
                &Bytes::from_str("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2")
                    .expect("Missing balance!")
            ),
            Some(&Bytes::from_str("0x01f4").unwrap())
        );
    }

    #[tokio::test]
    async fn test_get_protocol_components() {
        let mut server = Server::new_async().await;
        let server_resp = r#"
        {
            "protocol_components": [
                {
                    "id": "State1",
                    "protocol_system": "ambient",
                    "protocol_type_name": "Pool",
                    "chain": "ethereum",
                    "tokens": [
                        "0x0000000000000000000000000000000000000000",
                        "0x0000000000000000000000000000000000000001"
                    ],
                    "contract_ids": [
                        "0x0000000000000000000000000000000000000000"
                    ],
                    "static_attributes": {
                        "attribute_1": "0xe803000000000000"
                    },
                    "change": "Creation",
                    "creation_tx": "0x0000000000000000000000000000000000000000000000000000000000000000",
                    "created_at": "2022-01-01T00:00:00"
                }
            ]
        }
        "#;
        // test that the response is deserialized correctly
        serde_json::from_str::<ProtocolComponentRequestResponse>(server_resp).expect("deserialize");

        let mocked_server = server
            .mock("POST", "/v1/ethereum/protocol_components")
            .expect(1)
            .with_body(server_resp)
            .create_async()
            .await;

        let client = HttpRPCClient::new(server.url().as_str()).expect("create client");

        let response = client
            .get_protocol_components(Chain::Ethereum, &Default::default(), &Default::default())
            .await
            .expect("get state");
        let components = response.protocol_components;

        mocked_server.assert();
        assert_eq!(components.len(), 1);
        assert_eq!(components[0].id, "State1");
        assert_eq!(components[0].protocol_system, "ambient");
        assert_eq!(components[0].protocol_type_name, "Pool");
        assert_eq!(components[0].tokens.len(), 2);
        let expected_attributes =
            [("attribute_1".to_string(), Bytes::from(1000_u64.to_le_bytes()))]
                .iter()
                .cloned()
                .collect::<HashMap<String, Bytes>>();
        assert_eq!(components[0].static_attributes, expected_attributes);
    }

    #[tokio::test]
    async fn test_get_protocol_states() {
        let mut server = Server::new_async().await;
        let server_resp = r#"
        {
            "states": [
                {
                    "component_id": "State1",
                    "attributes": {
                        "attribute_1": "0xe803000000000000"
                    },
                    "balances": {
                        "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2": "0x01f4"
                    }
                }
            ]
        }
        "#;
        // test that the response is deserialized correctly
        serde_json::from_str::<ProtocolStateRequestResponse>(server_resp).expect("deserialize");

        let mocked_server = server
            .mock("POST", "/v1/ethereum/protocol_state?include_balances=false")
            .expect(1)
            .with_body(server_resp)
            .create_async()
            .await;
        let client = HttpRPCClient::new(server.url().as_str()).expect("create client");

        let response = client
            .get_protocol_states(Chain::Ethereum, &Default::default(), &Default::default())
            .await
            .expect("get state");
        let states = response.states;

        mocked_server.assert();
        assert_eq!(states.len(), 1);
        assert_eq!(states[0].component_id, "State1");
        let expected_attributes =
            [("attribute_1".to_string(), Bytes::from(1000_u64.to_le_bytes()))]
                .iter()
                .cloned()
                .collect::<HashMap<String, Bytes>>();
        assert_eq!(states[0].attributes, expected_attributes);
        let expected_balances = [(
            Bytes::from_str("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2")
                .expect("Unsupported address format"),
            Bytes::from_str("0x01f4").unwrap(),
        )]
        .iter()
        .cloned()
        .collect::<HashMap<Bytes, Bytes>>();
        assert_eq!(states[0].balances, expected_balances);
    }

    #[tokio::test]
    async fn test_get_tokens() {
        let mut server = Server::new_async().await;
        let server_resp = r#"
        {
            "tokens": [
              {
                "chain": "ethereum",
                "address": "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
                "symbol": "WETH",
                "decimals": 18,
                "tax": 0,
                "gas": [
                  29962
                ],
                "quality": 100
              },
              {
                "chain": "ethereum",
                "address": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
                "symbol": "USDC",
                "decimals": 6,
                "tax": 0,
                "gas": [
                  40652
                ],
                "quality": 100
              }
            ],
            "pagination": {
              "page": 0,
              "page_size": 2
            }
          }
        "#;
        // test that the response is deserialized correctly
        serde_json::from_str::<TokensRequestResponse>(server_resp).expect("deserialize");

        let mocked_server = server
            .mock("POST", "/v1/ethereum/tokens")
            .expect(1)
            .with_body(server_resp)
            .create_async()
            .await;
        let client = HttpRPCClient::new(server.url().as_str()).expect("create client");

        let response = client
            .get_tokens(&Chain::Ethereum, &Default::default())
            .await
            .expect("get state");

        let expected = vec![
            ResponseToken {
                chain: Chain::Ethereum,
                address: Bytes::from_str("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2").unwrap(),
                symbol: "WETH".to_string(),
                decimals: 18,
                tax: 0,
                gas: vec![Some(29962)],
                quality: 100,
            },
            ResponseToken {
                chain: Chain::Ethereum,
                address: Bytes::from_str("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48").unwrap(),
                symbol: "USDC".to_string(),
                decimals: 6,
                tax: 0,
                gas: vec![Some(40652)],
                quality: 100,
            },
        ];

        mocked_server.assert();
        assert_eq!(response.tokens, expected);
        assert_eq!(response.pagination, PaginationParams { page: 0, page_size: 2 });
    }
}
