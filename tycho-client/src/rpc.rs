//! # Tycho RPC Client
//!
//! The objective of this module is to provide swift and simplified access to the Remote Procedure
//! Call (RPC) endpoints of Tycho. These endpoints are chiefly responsible for facilitating data
//! queries, especially querying snapshots of data.
#[cfg(test)]
use mockall::automock;
use std::sync::Arc;
use thiserror::Error;
use tracing::{debug, error, instrument, trace, warn};

use async_trait::async_trait;
use futures03::future::try_join_all;

use tycho_core::dto::{
    Chain, PaginationParams, ProtocolComponentRequestResponse, ProtocolComponentsRequestBody,
    ProtocolId, ProtocolStateRequestBody, ProtocolStateRequestResponse, ResponseToken,
    StateRequestBody, StateRequestResponse, TokensRequestBody, TokensRequestResponse, VersionParam,
};

use reqwest::{
    header::{self, CONTENT_TYPE, USER_AGENT},
    Client, ClientBuilder, Url,
};
use tokio::sync::Semaphore;

use crate::TYCHO_SERVER_VERSION;
use tokio::sync::Semaphore;
use tycho_core::Bytes;

#[derive(Error, Debug)]
pub enum RPCError {
    /// The passed tycho url failed to parse.
    #[error("Failed to parse URL: {0}. Error: {1}")]
    UrlParsing(String, String),
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
        request: &StateRequestBody,
    ) -> Result<StateRequestResponse, RPCError>;

    #[allow(clippy::too_many_arguments)]
    async fn get_contract_state_paginated(
        &self,
        chain: Chain,
        ids: &[Bytes],
        protocol_system: &Option<String>,
        version: &VersionParam,
        chunk_size: usize,
        concurrency: usize,
    ) -> Result<StateRequestResponse, RPCError> {
        let semaphore = Arc::new(Semaphore::new(concurrency));
        let chunked_bodies = ids
            .chunks(chunk_size)
            .map(|_| StateRequestBody {
                contract_ids: Some(ids.to_vec()),
                protocol_system: protocol_system.clone(),
                chain,
                version: version.clone(),
                pagination: PaginationParams { page: 0, page_size: chunk_size as i64 },
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
                self.get_contract_state(body).await
            });
        }

        try_join_all(tasks)
            .await
            .map(|responses| StateRequestResponse {
                accounts: responses
                    .into_iter()
                    .flat_map(|r| r.accounts.into_iter())
                    .collect(),
                // TODO: Should use the response from the task
                pagination: PaginationParams { page: 0, page_size: chunk_size as i64 },
            })
    }

    async fn get_protocol_components(
        &self,
        request: &ProtocolComponentsRequestBody,
    ) -> Result<ProtocolComponentRequestResponse, RPCError>;

    async fn get_protocol_states(
        &self,
        request: &ProtocolStateRequestBody,
    ) -> Result<ProtocolStateRequestResponse, RPCError>;

    #[allow(clippy::too_many_arguments)]
    async fn get_protocol_states_paginated(
        &self,
        chain: Chain,
        ids: &[ProtocolId],
        protocol_system: &Option<String>,
        include_balances: bool,
        version: &VersionParam,
        chunk_size: usize,
        concurrency: usize,
    ) -> Result<ProtocolStateRequestResponse, RPCError> {
        let semaphore = Arc::new(Semaphore::new(concurrency));
        let chunked_bodies = ids
            .chunks(chunk_size)
            .map(|_| ProtocolStateRequestBody {
                protocol_ids: Some(ids.to_vec()),
                protocol_system: protocol_system.clone(),
                chain,
                include_balances,
                version: version.clone(),
                pagination: PaginationParams { page: 0, page_size: chunk_size as i64 },
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
                self.get_protocol_states(body).await
            });
        }

        try_join_all(tasks)
            .await
            .map(|responses| ProtocolStateRequestResponse {
                states: responses
                    .into_iter()
                    .flat_map(|r| r.states.into_iter())
                    .collect(),
                // TODO: Should use the response from the task
                pagination: PaginationParams { page: 0, page_size: chunk_size as i64 },
            })
    }

    /// This function returns only one chunk of tokens. To get all tokens please call
    /// get_all_tokens.
    async fn get_tokens(
        &self,
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
                .get_tokens(&TokensRequestBody {
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
                    chain,
                })
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
    http_client: Client,
    url: Url,
}

impl HttpRPCClient {
    pub fn new(base_uri: &str, auth_key: Option<&str>) -> Result<Self, RPCError> {
        let uri = base_uri
            .parse::<Url>()
            .map_err(|e| RPCError::UrlParsing(base_uri.to_string(), e.to_string()))?;

        // Add default headers
        let mut headers = header::HeaderMap::new();
        headers.insert(header::CONTENT_TYPE, header::HeaderValue::from_static("application/json"));
        let user_agent = format!("tycho-client-{}", env!("CARGO_PKG_VERSION"));
        headers.insert(
            USER_AGENT,
            header::HeaderValue::from_str(&user_agent).expect("invalid user agent format"),
        );

        // Add Authorization if one is given
        if let Some(key) = auth_key {
            let mut auth_value = header::HeaderValue::from_str(key).expect("invalid key format");
            auth_value.set_sensitive(true);
            headers.insert(header::AUTHORIZATION, auth_value);
        }

        let client = ClientBuilder::new()
            .default_headers(headers)
            .build()
            .map_err(|e| RPCError::HttpClient(e.to_string()))?;
        Ok(Self { http_client: client, url: uri })
    }
}

#[async_trait]
impl RPCClient for HttpRPCClient {
    #[instrument(skip(self, request))]
    async fn get_contract_state(
        &self,
        request: &StateRequestBody,
    ) -> Result<StateRequestResponse, RPCError> {
        // Check if contract ids are specified
        if request.contract_ids.is_none()
            || request
                .contract_ids
                .as_ref()
                .unwrap()
                .is_empty()
        {
            warn!("No contract ids specified in request.");
        }

        let uri = format!(
            "{}/{}/contract_state",
            self.url
                .to_string()
                .trim_end_matches('/'),
            TYCHO_SERVER_VERSION
        );
        debug!(%uri, "Sending contract_state request to Tycho server");
        trace!(?request, "Sending request to Tycho server");

        let response = self
            .http_client
            .post(&uri)
            .json(request)
            .send()
            .await
            .map_err(|e| RPCError::HttpClient(e.to_string()))?;
        trace!(?response, "Received response from Tycho server");

        let body = response
            .text()
            .await
            .map_err(|e| RPCError::ParseResponse(e.to_string()))?;
        if body.is_empty() {
            // Pure native protocols will return empty contract states
            return Ok(StateRequestResponse { accounts: vec![], pagination: Default::default() });
        }

        let accounts = serde_json::from_str::<StateRequestResponse>(&body)
            .map_err(|e| RPCError::ParseResponse(e.to_string()))?;
        trace!(?accounts, "Received contract_state response from Tycho server");

        Ok(accounts)
    }

    async fn get_protocol_components(
        &self,
        request: &ProtocolComponentsRequestBody,
    ) -> Result<ProtocolComponentRequestResponse, RPCError> {
        let uri = format!(
            "{}/{}/protocol_components",
            self.url
                .to_string()
                .trim_end_matches('/'),
            TYCHO_SERVER_VERSION,
        );
        debug!(%uri, "Sending protocol_components request to Tycho server");
        trace!(?request, "Sending request to Tycho server");

        let response = self
            .http_client
            .post(uri)
            .header(CONTENT_TYPE, "application/json")
            .json(request)
            .send()
            .await
            .map_err(|e| RPCError::HttpClient(e.to_string()))?;

        trace!(?response, "Received response from Tycho server");

        let body = response
            .text()
            .await
            .map_err(|e| RPCError::ParseResponse(e.to_string()))?;
        let components = serde_json::from_str::<ProtocolComponentRequestResponse>(&body)
            .map_err(|e| RPCError::ParseResponse(e.to_string()))?;
        trace!(?components, "Received protocol_components response from Tycho server");

        Ok(components)
    }

    async fn get_protocol_states(
        &self,
        request: &ProtocolStateRequestBody,
    ) -> Result<ProtocolStateRequestResponse, RPCError> {
        // Check if contract ids are specified
        if request.protocol_ids.is_none()
            || request
                .protocol_ids
                .as_ref()
                .unwrap()
                .is_empty()
        {
            warn!("No protocol ids specified in request.");
        }

        let uri = format!(
            "{}/{}/protocol_state",
            self.url
                .to_string()
                .trim_end_matches('/'),
            TYCHO_SERVER_VERSION
        );
        debug!(%uri, "Sending protocol_states request to Tycho server");
        trace!(?request, "Sending request to Tycho server");

        let response = self
            .http_client
            .post(&uri)
            .json(request)
            .send()
            .await
            .map_err(|e| RPCError::HttpClient(e.to_string()))?;
        trace!(?response, "Received response from Tycho server");

        let body = response
            .text()
            .await
            .map_err(|e| RPCError::ParseResponse(e.to_string()))?;

        if body.is_empty() {
            // Pure VM protocols will return empty states
            return Ok(ProtocolStateRequestResponse {
                states: vec![],
                pagination: Default::default(),
            });
        }

        let states = serde_json::from_str::<ProtocolStateRequestResponse>(&body)
            .map_err(|e| RPCError::ParseResponse(e.to_string()))?;
        trace!(?states, "Received protocol_states response from Tycho server");

        Ok(states)
    }

    async fn get_tokens(
        &self,
        request: &TokensRequestBody,
    ) -> Result<TokensRequestResponse, RPCError> {
        let uri = format!(
            "{}/{}/tokens",
            self.url
                .to_string()
                .trim_end_matches('/'),
            TYCHO_SERVER_VERSION
        );
        debug!(%uri, "Sending tokens request to Tycho server");

        let response = self
            .http_client
            .post(&uri)
            .json(request)
            .send()
            .await
            .map_err(|e| RPCError::HttpClient(e.to_string()))?;

        let body = response
            .text()
            .await
            .map_err(|e| RPCError::ParseResponse(e.to_string()))?;
        let tokens = serde_json::from_str::<TokensRequestResponse>(&body)
            .map_err(|e| RPCError::ParseResponse(e.to_string()))?;

        Ok(tokens)
    }
}

#[cfg(test)]
mod tests {
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
                    "code": "0x00",
                    "code_hash": "0x5c06b7c5b3d910fd33bc2229846f9ddaf91d584d9b196e16636901ac3a77077e",
                    "balance_modify_tx": "0x0000000000000000000000000000000000000000000000000000000000000000",
                    "code_modify_tx": "0x0000000000000000000000000000000000000000000000000000000000000000",
                    "creation_tx": null
                }
            ],
            "pagination": {
                "page": 0,
                "page_size": 20
            }
        }
        "#;
        // test that the response is deserialized correctly
        serde_json::from_str::<StateRequestResponse>(server_resp).expect("deserialize");

        let mocked_server = server
            .mock("POST", "/v1/contract_state")
            .expect(1)
            .with_body(server_resp)
            .create_async()
            .await;

        let client = HttpRPCClient::new(server.url().as_str(), None).expect("create client");

        let response = client
            .get_contract_state(&Default::default())
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
            ],
            "pagination": {
                "page": 0,
                "page_size": 20
            }
        }
        "#;
        // test that the response is deserialized correctly
        serde_json::from_str::<ProtocolComponentRequestResponse>(server_resp).expect("deserialize");

        let mocked_server = server
            .mock("POST", "/v1/protocol_components")
            .expect(1)
            .with_body(server_resp)
            .create_async()
            .await;

        let client = HttpRPCClient::new(server.url().as_str(), None).expect("create client");

        let response = client
            .get_protocol_components(&Default::default())
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
            ],
            "pagination": {
                "page": 0,
                "page_size": 20
            }
        }
        "#;
        // test that the response is deserialized correctly
        serde_json::from_str::<ProtocolStateRequestResponse>(server_resp).expect("deserialize");

        let mocked_server = server
            .mock("POST", "/v1/protocol_state")
            .expect(1)
            .with_body(server_resp)
            .create_async()
            .await;
        let client = HttpRPCClient::new(server.url().as_str(), None).expect("create client");

        let response = client
            .get_protocol_states(&Default::default())
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
            .mock("POST", "/v1/tokens")
            .expect(1)
            .with_body(server_resp)
            .create_async()
            .await;
        let client = HttpRPCClient::new(server.url().as_str(), None).expect("create client");

        let response = client
            .get_tokens(&Default::default())
            .await
            .expect("get tokens");

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
