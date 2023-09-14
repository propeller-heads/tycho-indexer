use chrono::NaiveDateTime;
use futures::StreamExt;
use hyper::{client::HttpConnector, Body, Client, Request, Uri};
use log::{error, info};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

use super::tycho_models::Chain;
use super::tycho_models::{Block, BlockStateChanges};
use revm::primitives::{B160, B256, U256 as rU256};
use tokio::sync::mpsc::{self, Receiver};
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::protocol::Message;

#[derive(Error, Debug)]
pub enum TychoClientError {
    #[error("Failed to parse URI: {0}. Error: {1}")]
    UriParsing(String, String),
    #[error("Failed to format request: {0}")]
    FormatRequest(String),
    #[error("Unexpected HTTP client error: {0}")]
    HttpClient(String),
    #[error("Failed to parse response: {0}")]
    ParseResponse(String),
}
#[derive(Serialize, Debug)]
pub struct StateRequestBody {
    contract_ids: Option<Vec<B160>>,
    version: Option<Version>,
}

impl StateRequestBody {
    pub fn from_block(block: Block) -> Self {
        Self {
            contract_ids: None,
            version: Some(Version {
                timestamp: None,
                block: Some(RequestBlock {
                    hash: block.hash,
                    number: block.number,
                    chain: block.chain,
                }),
            }),
        }
    }
}
#[derive(Serialize, Debug)]
pub struct Version {
    timestamp: Option<NaiveDateTime>,
    block: Option<RequestBlock>,
}

#[derive(Serialize, Debug)]
struct RequestBlock {
    hash: B256,
    number: u64,
    chain: Chain,
}
#[derive(Default)]
pub struct GetStateFilters {
    tvl_gt: Option<u64>,
    intertia_min_gt: Option<u64>,
}

impl GetStateFilters {
    fn to_query_string(&self) -> String {
        let mut parts = Vec::new();

        parts.push(format!("chain={}", Chain::Ethereum.to_string()));

        if let Some(tvl_gt) = self.tvl_gt {
            parts.push(format!("tvl_gt={}", tvl_gt));
        }

        if let Some(intertia_min_gt) = self.intertia_min_gt {
            parts.push(format!("intertia_min_gt={}", intertia_min_gt));
        }

        parts.join("&")
    }
}
#[derive(Deserialize)]
pub struct ResponseAccount {
    pub address: B160,
    pub slots: HashMap<rU256, rU256>,
    pub balance: rU256,
    pub code: Vec<u8>,
    pub code_hash: B256,
}

pub struct TychoVmStateClient {
    http_client: Client<HttpConnector>,
    base_uri: Uri,
}

impl TychoVmStateClient {
    pub fn new(base_url: &str) -> Result<Self, TychoClientError> {
        let base_uri = base_url
            .parse::<Uri>()
            .map_err(|e| TychoClientError::UriParsing(base_url.to_string(), e.to_string()))?;

        // No need for references anymore
        Ok(Self {
            http_client: Client::new(),
            base_uri,
        })
    }

    pub async fn get_state(
        &self,
        filters: Option<&GetStateFilters>,
        request: Option<&StateRequestBody>,
    ) -> Result<Vec<ResponseAccount>, TychoClientError> {
        let mut url = format!("{}/{}", self.base_uri, "contract_state");
        let mut body = Body::empty();

        if let Some(filters) = filters {
            let query_string = filters.to_query_string();
            if !query_string.is_empty() {
                url = format!("{}?{}", url, query_string);
            }
        }
        if let Some(request) = request {
            if request.to_owned().contract_ids.is_some() || request.to_owned().version.is_some() {
                let serialized = serde_json::to_string(&request).unwrap();
                body = Body::from(serialized);
            }
        }

        let req = Request::get(url)
            .body(body)
            .map_err(|e| TychoClientError::FormatRequest(e.to_string()))?;

        let response = self
            .http_client
            .request(req)
            .await
            .map_err(|e| TychoClientError::HttpClient(e.to_string()))?;

        let body = hyper::body::to_bytes(response.into_body())
            .await
            .map_err(|e| TychoClientError::ParseResponse(e.to_string()))?;
        let accounts: Vec<ResponseAccount> = serde_json::from_slice(&body)
            .map_err(|e| TychoClientError::ParseResponse(e.to_string()))?;

        Ok(accounts)
    }
