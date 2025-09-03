use std::{collections::HashMap, error::Error as StdError, fmt};

use tracing::info;
use tycho_client::{rpc::RPCClient, HttpRPCClient};
use tycho_common::{
    dto::{
        Chain, PaginationParams, ProtocolComponent, ProtocolComponentsRequestBody, ResponseAccount,
        ResponseProtocolState, ResponseToken, StateRequestBody, VersionParam,
    },
    models::token::Token,
    Bytes,
};

/// Custom error type for RPC operations
#[derive(Debug)]
pub enum RpcError {
    ClientError(String),
    ResponseError(String),
}

impl fmt::Display for RpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RpcError::ClientError(msg) => write!(f, "RPC client error: {}", msg),
            RpcError::ResponseError(msg) => write!(f, "RPC response error: {}", msg),
        }
    }
}

impl StdError for RpcError {}

impl From<Box<dyn StdError>> for RpcError {
    fn from(error: Box<dyn StdError>) -> Self {
        RpcError::ClientError(error.to_string())
    }
}

impl From<tycho_client::RPCError> for RpcError {
    fn from(error: tycho_client::RPCError) -> Self {
        RpcError::ClientError(error.to_string())
    }
}

/// Client for interacting with the Tycho RPC server
pub struct TychoClient {
    http_client: HttpRPCClient,
}

impl TychoClient {
    pub fn new(host: &str) -> Result<Self, RpcError> {
        let http_client =
            HttpRPCClient::new(host, None).map_err(|e| RpcError::ClientError(e.to_string()))?;
        Ok(Self { http_client })
    }

    /// Gets protocol components from the RPC server
    pub async fn get_protocol_components(
        &self,
        protocol_system: &str,
        chain: Chain,
    ) -> Result<Vec<ProtocolComponent>, RpcError> {
        let request = ProtocolComponentsRequestBody::system_filtered(protocol_system, None, chain);

        let chunk_size = 100;
        let concurrency = 1;

        let response = self
            .http_client
            .get_protocol_components_paginated(&request, chunk_size, concurrency)
            .await?;

        Ok(response.protocol_components)
    }

    /// Gets protocol state from the RPC server
    pub async fn get_protocol_state(
        &self,
        protocol_system: &str,
        component_ids: Vec<String>,
        chain: Chain,
    ) -> Result<Vec<ResponseProtocolState>, RpcError> {
        let chunk_size = 100;
        let concurrency = 1;
        let version: tycho_common::dto::VersionParam = VersionParam::default();

        let protocol_states = self
            .http_client
            .get_protocol_states_paginated(
                chain,
                &component_ids,
                protocol_system,
                true,
                &version,
                chunk_size,
                concurrency,
            )
            .await?;

        Ok(protocol_states.states)
    }

    /// Gets contract state from the RPC server
    pub async fn get_contract_state(
        &self,
        protocol_system: &str,
        chain: Chain,
    ) -> Result<Vec<ResponseAccount>, RpcError> {
        let request_body = StateRequestBody {
            contract_ids: None,
            protocol_system: protocol_system.to_string(),
            version: Default::default(),
            chain,
            pagination: PaginationParams { page: 0, page_size: 100 },
        };

        let contract_states = self
            .http_client
            .get_contract_state(&request_body)
            .await?;

        Ok(contract_states.accounts)
    }

    pub async fn get_tokens(
        &self,
        chain: Chain,
        min_quality: Option<i32>,
        max_days_since_last_trade: Option<u64>,
    ) -> Result<HashMap<Bytes, Token>, RpcError> {
        info!("Loading tokens from Tycho...");

        #[allow(clippy::mutable_key_type)]
        let res = self
            .http_client
            .get_all_tokens(chain, min_quality, max_days_since_last_trade, 3_000)
            .await?
            .into_iter()
            .map(|token| {
                let mut token_clone: ResponseToken = token.clone();
                // Set default gas if empty
                // TODO: Check if this interferes with simulation logic
                if token_clone.gas.is_empty() {
                    token_clone.gas = vec![Some(44000_u64)];
                }
                (
                    token_clone.address.clone(),
                    token_clone
                        .try_into()
                        .expect("Failed to convert token"),
                )
            })
            .collect::<HashMap<_, Token>>();

        Ok(res)
    }
}
