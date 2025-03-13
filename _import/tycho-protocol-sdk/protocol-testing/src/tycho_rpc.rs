use std::{error::Error as StdError, fmt};

use tycho_client::{rpc::RPCClient, HttpRPCClient};
use tycho_core::{
    dto::{
        Chain, ProtocolComponent, ProtocolComponentsRequestBody, ResponseAccount,
        ResponseProtocolState, VersionParam,
    },
    models::Address,
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
        chain: Chain,
    ) -> Result<Vec<ResponseProtocolState>, RpcError> {
        let chunk_size = 100;
        let concurrency = 1;
        let ids: &[String] = &[];
        let version: tycho_core::dto::VersionParam = VersionParam::default();

        let protocol_states = self
            .http_client
            .get_protocol_states_paginated(
                chain,
                ids,
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
        contract_ids: Vec<Address>,
        protocol_system: &str,
        chain: Chain,
    ) -> Result<Vec<ResponseAccount>, RpcError> {
        // Pagination parameters
        let chunk_size = 100;
        let concurrency = 1;
        let version: tycho_core::dto::VersionParam = VersionParam::default();

        let contract_states = self
            .http_client
            .get_contract_state_paginated(
                chain,
                &contract_ids,
                protocol_system,
                &version,
                chunk_size,
                concurrency,
            )
            .await?;

        Ok(contract_states.accounts)
    }
}
