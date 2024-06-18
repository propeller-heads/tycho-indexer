//! This module contains Tycho RPC implementation
use std::collections::HashSet;

use actix_web::{web, HttpResponse};
use anyhow::Error;
use chrono::{Duration, Utc};
use diesel_async::pooled_connection::deadpool;
use thiserror::Error;
use tracing::{debug, error, info, instrument, warn};

use tycho_core::{
    dto::{self, ProtocolComponentRequestParameters, ResponseToken, StateRequestParameters},
    models::{Address, Chain, PaginationParams},
    storage::{BlockIdentifier, BlockOrTimestamp, Gateway, StorageError, Version, VersionKind},
    Bytes,
};

use crate::{
    extractor::{
        evm,
        revert_buffer::{BlockNumberOrTimestamp, FinalityStatus},
    },
    services::deltas_buffer::{PendingDeltas, PendingDeltasError},
};

#[derive(Error, Debug)]
pub enum RpcError {
    #[error("Failed to parse JSON: {0}")]
    Parse(String),

    #[error("Failed to get storage: {0}")]
    Storage(#[from] StorageError),

    #[error("Failed to get database connection: {0}")]
    Connection(#[from] deadpool::PoolError),

    #[error("Failed to apply pending deltas: {0}")]
    DeltasError(#[from] PendingDeltasError),
}

impl From<anyhow::Error> for RpcError {
    fn from(value: Error) -> Self {
        Self::Parse(value.to_string())
    }
}

impl From<evm::ProtocolStateDelta> for dto::ProtocolStateDelta {
    fn from(protocol_state: evm::ProtocolStateDelta) -> Self {
        Self {
            component_id: protocol_state.component_id,
            updated_attributes: protocol_state.updated_attributes,
            deleted_attributes: protocol_state.deleted_attributes,
        }
    }
}

impl From<evm::AccountUpdate> for dto::AccountUpdate {
    fn from(account_update: evm::AccountUpdate) -> Self {
        Self {
            address: account_update.address.into(),
            chain: account_update.chain.into(),
            slots: account_update
                .slots
                .into_iter()
                .map(|(k, v)| (Bytes::from(k), Bytes::from(v)))
                .collect(),
            balance: account_update.balance.map(Bytes::from),
            code: account_update.code,
            change: account_update.change.into(),
        }
    }
}

impl From<evm::ERC20Token> for ResponseToken {
    fn from(token: evm::ERC20Token) -> Self {
        Self {
            address: token.address.into(),
            symbol: token.symbol,
            decimals: token.decimals,
            tax: token.tax,
            chain: token.chain.into(),
            gas: token.gas,
            quality: token.quality,
        }
    }
}

impl From<evm::ProtocolComponent> for dto::ProtocolComponent {
    fn from(protocol_component: evm::ProtocolComponent) -> Self {
        Self {
            chain: protocol_component.chain.into(),
            id: protocol_component.id,
            protocol_system: protocol_component.protocol_system,
            protocol_type_name: protocol_component.protocol_type_name,
            tokens: protocol_component
                .tokens
                .into_iter()
                .map(|token| {
                    let bytes = token.as_bytes().to_vec();
                    Bytes::from(bytes)
                })
                .collect(),
            contract_ids: protocol_component
                .contract_ids
                .into_iter()
                .map(|h| {
                    let bytes = h.as_bytes().to_vec();
                    Bytes::from(bytes)
                })
                .collect(),
            static_attributes: protocol_component.static_attributes,
            creation_tx: protocol_component.creation_tx.into(),
            created_at: protocol_component.created_at,
            change: protocol_component.change.into(),
        }
    }
}

pub struct RpcHandler<G> {
    db_gateway: G,
    pending_deltas: PendingDeltas,
}

impl<G> RpcHandler<G>
where
    G: Gateway,
{
    pub fn new(db_gateway: G, pending_deltas: PendingDeltas) -> Self {
        Self { db_gateway, pending_deltas }
    }

    #[instrument(skip(self, chain, request, params))]
    async fn get_contract_state(
        &self,
        chain: &Chain,
        request: &dto::StateRequestBody,
        params: &dto::StateRequestParameters,
    ) -> Result<dto::StateRequestResponse, RpcError> {
        info!(?chain, ?request, ?params, "Getting contract state.");
        self.get_contract_state_inner(chain, request, params)
            .await
    }

    async fn get_contract_state_inner(
        &self,
        chain: &Chain,
        request: &dto::StateRequestBody,
        params: &dto::StateRequestParameters,
    ) -> Result<dto::StateRequestResponse, RpcError> {
        //TODO: set version to latest if we are targeting a version within pending deltas
        let at = BlockOrTimestamp::try_from(&request.version)?;
        let (db_version, deltas_version) = self
            .calculate_versions(&at, *chain)
            .await?;

        // Get the contract IDs from the request
        let contract_ids = request.contract_ids.clone();
        let addresses: Option<Vec<Address>> = contract_ids.map(|ids| {
            ids.into_iter()
                .map(|id| Address::from(id.address))
                .collect::<Vec<Address>>()
        });
        debug!(?addresses, "Getting contract states.");
        let addresses = addresses.as_deref();

        // Get the contract states from the database
        let mut accounts = self
            .db_gateway
            .get_contracts(chain, addresses, Some(&db_version), true, params.include_balances)
            .await
            .map_err(|err| {
                error!(error = %err, "Error while getting contract states.");
                err
            })?;

        if let Some(at) = deltas_version {
            self.pending_deltas
                .update_vm_states(&mut accounts, Some(at))?;
        }
        Ok(dto::StateRequestResponse::new(
            accounts
                .into_iter()
                .map(dto::ResponseAccount::from)
                .collect(),
        ))
    }

    /// Calculates versions for state retrieval.
    ///
    /// This method will calculate:
    /// - The finalized version to be retrieved from the database.
    /// - An "ordered" version to be retrieved from the pending deltas buffer.
    ///
    /// To calculate the finalized version, it queries the pending deltas buffer for the requested
    /// version's finality. If the version is already finalized, it can be simply passed on to
    /// the db, no deltas version is required. In case it is an unfinalized version, we downgrade
    /// the db version to the latest available version and will later apply any pending
    /// changes from the buffer on top of the retrieved version. We also return a deltas
    /// version which must be either block number or timestamps based.
    async fn calculate_versions(
        &self,
        request_version: &BlockOrTimestamp,
        chain: Chain,
    ) -> Result<(Version, Option<BlockNumberOrTimestamp>), RpcError> {
        let ordered_version = match request_version {
            BlockOrTimestamp::Block(BlockIdentifier::Number((_, no))) => {
                BlockNumberOrTimestamp::Number(*no as u64)
            }
            BlockOrTimestamp::Timestamp(ts) => BlockNumberOrTimestamp::Timestamp(*ts),
            BlockOrTimestamp::Block(block_id) => BlockNumberOrTimestamp::Number(
                self.db_gateway
                    .get_block(block_id)
                    .await?
                    .number,
            ),
        };
        let request_version_finality = self
            .pending_deltas
            .get_block_finality(ordered_version)?
            .unwrap_or_else(|| {
                warn!(?ordered_version, "No finality found for version.");
                FinalityStatus::Finalized
            });
        debug!(
            ?request_version_finality,
            ?request_version,
            ?ordered_version,
            "Version finality calculated!"
        );
        match request_version_finality {
            FinalityStatus::Finalized => {
                Ok((Version(request_version.clone(), VersionKind::Last), None))
            }
            FinalityStatus::Unfinalized => Ok((
                Version(BlockOrTimestamp::Block(BlockIdentifier::Latest(chain)), VersionKind::Last),
                Some(ordered_version),
            )),
            FinalityStatus::Unseen => Err(RpcError::Storage(StorageError::NotFound(
                "Version".to_string(),
                format!("{:?}", request_version),
            ))),
        }
    }

    #[instrument(skip(self, chain, request, params))]
    async fn get_contract_delta(
        &self,
        chain: &Chain,
        request: &dto::ContractDeltaRequestBody,
        params: &dto::StateRequestParameters,
    ) -> Result<dto::ContractDeltaRequestResponse, RpcError> {
        info!(?request, ?params, "Getting contract delta.");
        self.get_contract_delta_inner(chain, request, params)
            .await
    }

    async fn get_contract_delta_inner(
        &self,
        chain: &Chain,
        request: &dto::ContractDeltaRequestBody,
        params: &dto::StateRequestParameters,
    ) -> Result<dto::ContractDeltaRequestResponse, RpcError> {
        #![allow(unused_variables)]
        //TODO: handle when no contract is specified with filters
        let start = BlockOrTimestamp::try_from(&request.start)?;
        let end = BlockOrTimestamp::try_from(&request.end)?;

        // Get the contract IDs from the request
        let contract_ids = request.contract_ids.clone();
        let addresses: Option<HashSet<Address>> = contract_ids.map(|ids| {
            ids.into_iter()
                .map(|id| id.address)
                .collect::<HashSet<Address>>()
        });
        debug!(?addresses, "Getting contract states.");
        let addresses: Option<&HashSet<Address>> = addresses.as_ref();

        // Get the contract deltas from the database
        match self
            .db_gateway
            .get_accounts_delta(chain, Some(&start), &end)
            .await
        {
            Ok(mut accounts) => {
                // Filter by contract addresses if specified in the request
                // PERF: This is not efficient, we should filter in the query
                if let Some(contract_addrs) = addresses {
                    accounts.retain(|acc| contract_addrs.contains(&acc.address));
                }
                Ok(dto::ContractDeltaRequestResponse::new(
                    accounts
                        .into_iter()
                        .map(dto::AccountUpdate::from)
                        .collect(),
                ))
            }
            Err(err) => {
                error!(error = %err, "Error while getting contract delta.");
                Err(err.into())
            }
        }
    }

    #[instrument(skip(self, request, params))]
    async fn get_protocol_state(
        &self,
        chain: &Chain,
        request: &dto::ProtocolStateRequestBody,
        params: &dto::StateRequestParameters,
    ) -> Result<dto::ProtocolStateRequestResponse, RpcError> {
        info!(?request, ?params, "Getting protocol state.");
        self.get_protocol_state_inner(chain, request, params)
            .await
    }

    #[allow(unused_variables)]
    async fn get_protocol_state_inner(
        &self,
        chain: &Chain,
        request: &dto::ProtocolStateRequestBody,
        params: &dto::StateRequestParameters,
    ) -> Result<dto::ProtocolStateRequestResponse, RpcError> {
        //TODO: handle when no id is specified with filters
        let at = BlockOrTimestamp::try_from(&request.version)?;
        let (db_version, deltas_version) = self
            .calculate_versions(&at, *chain)
            .await?;

        // Get the protocol IDs from the request
        let protocol_ids: Option<Vec<dto::ProtocolId>> = request.protocol_ids.clone();
        let ids: Option<Vec<&str>> = protocol_ids.as_ref().map(|ids| {
            ids.iter()
                .map(|id| id.id.as_str())
                .collect::<Vec<&str>>()
        });
        debug!(?ids, "Getting protocol states.");
        let ids = ids.as_deref();

        // Get the protocol states from the database
        let mut states = self
            .db_gateway
            .get_protocol_states(
                chain,
                Some(db_version),
                request.protocol_system.clone(),
                ids,
                params.include_balances,
            )
            .await
            .map_err(|err| {
                error!(error = %err, "Error while getting protocol states.");
                err
            })?;

        if let Some(at) = deltas_version {
            self.pending_deltas
                .update_native_states(&mut states, Some(at))?;
        }
        Ok(dto::ProtocolStateRequestResponse::new(
            states
                .into_iter()
                .map(dto::ResponseProtocolState::from)
                .collect(),
        ))
    }

    async fn get_tokens(
        &self,
        chain: &Chain,
        request: &dto::TokensRequestBody,
    ) -> Result<dto::TokensRequestResponse, RpcError> {
        info!(?chain, ?request, "Getting tokens.");
        self.get_tokens_inner(chain, request)
            .await
    }

    async fn get_tokens_inner(
        &self,
        chain: &Chain,
        request: &dto::TokensRequestBody,
    ) -> Result<dto::TokensRequestResponse, RpcError> {
        let address_refs: Option<Vec<&Address>> = request
            .token_addresses
            .as_ref()
            .map(|vec| vec.iter().collect());
        let addresses_slice = address_refs.as_deref();
        debug!(?addresses_slice, "Getting tokens.");

        let converted_params: PaginationParams = (&request.pagination).into();
        let min_quality = request.min_quality;

        let traded_n_days_ago = request.traded_n_days_ago;

        let n_days_ago = if let Some(days) = traded_n_days_ago {
            i64::try_from(days)
                .map(|days| Some(Utc::now().naive_utc() - Duration::days(days)))
                .map_err(|_| RpcError::Parse("traded_n_days_ago is too big.".to_string()))?
        } else {
            None
        };

        match self
            .db_gateway
            .get_tokens(*chain, addresses_slice, min_quality, n_days_ago, Some(&converted_params))
            .await
        {
            Ok(tokens) => Ok(dto::TokensRequestResponse::new(
                tokens
                    .into_iter()
                    .map(dto::ResponseToken::from)
                    .collect(),
                &request.pagination,
            )),
            Err(err) => {
                error!(error = %err, "Error while getting tokens.");
                Err(err.into())
            }
        }
    }

    async fn get_protocol_components(
        &self,
        chain: &Chain,
        request: &dto::ProtocolComponentsRequestBody,
        params: &dto::ProtocolComponentRequestParameters,
    ) -> Result<dto::ProtocolComponentRequestResponse, RpcError> {
        info!(?chain, ?request, "Getting protocol components.");
        self.get_protocol_components_inner(chain, request, params)
            .await
    }

    async fn get_protocol_components_inner(
        &self,
        chain: &Chain,
        request: &dto::ProtocolComponentsRequestBody,
        params: &dto::ProtocolComponentRequestParameters,
    ) -> Result<dto::ProtocolComponentRequestResponse, RpcError> {
        let system = request.protocol_system.clone();
        let ids_strs: Option<Vec<&str>> = request
            .component_ids
            .as_ref()
            .map(|vec| vec.iter().map(String::as_str).collect());

        let ids_slice = ids_strs.as_deref();

        let mut new_components = self
            .pending_deltas
            .get_new_components(ids_slice)?;

        match self
            .db_gateway
            .get_protocol_components(chain, system, ids_slice, params.tvl_gt)
            .await
        {
            Ok(comps) => {
                new_components.extend(comps);
                let components = new_components
                    .into_iter()
                    .map(dto::ProtocolComponent::from)
                    .collect::<Vec<dto::ProtocolComponent>>();
                Ok(dto::ProtocolComponentRequestResponse::new(components))
            }
            Err(err) => {
                error!(error = %err, "Error while getting protocol components.");
                Err(err.into())
            }
        }
    }

    #[instrument(skip(self, chain, request))]
    async fn get_protocol_delta(
        &self,
        chain: &Chain,
        request: &dto::ProtocolDeltaRequestBody,
    ) -> Result<dto::ProtocolDeltaRequestResponse, RpcError> {
        info!(?request, "Getting protocol delta.");
        self.get_protocol_delta_inner(chain, request)
            .await
    }

    async fn get_protocol_delta_inner(
        &self,
        chain: &Chain,
        request: &dto::ProtocolDeltaRequestBody,
    ) -> Result<dto::ProtocolDeltaRequestResponse, RpcError> {
        let start = BlockOrTimestamp::try_from(&request.start)?;
        let end = BlockOrTimestamp::try_from(&request.end)?;

        // Get the components IDs from the request
        let ids = request.component_ids.clone();
        let component_ids: Option<HashSet<String>> = ids.map(|ids| {
            ids.into_iter()
                .collect::<HashSet<String>>()
        });
        debug!(?component_ids, "Getting protocol states delta.");
        let component_ids: Option<&HashSet<String>> = component_ids.as_ref();

        // Get the protocol state deltas from the database
        match self
            .db_gateway
            .get_protocol_states_delta(chain, Some(&start), &end)
            .await
        {
            Ok(mut components) => {
                // Filter by component id if specified in the request
                // PERF: This is not efficient, we should filter in the query
                if let Some(component_ids) = component_ids {
                    components.retain(|acc| {
                        let id: String = acc.component_id.clone();
                        component_ids.contains(&id)
                    });
                }
                Ok(dto::ProtocolDeltaRequestResponse::new(
                    components
                        .into_iter()
                        .map(dto::ProtocolStateDelta::from)
                        .collect(),
                ))
            }
            Err(err) => {
                error!(error = %err, "Error while getting protocol state delta.");
                Err(err.into())
            }
        }
    }
}

#[utoipa::path(
    post,
    path = "/v1/{execution_env}/contract_state",
    responses(
        (status = 200, description = "OK", body = StateRequestResponse),
    ),
    request_body = StateRequestBody,
    params(
        ("execution_env" = Chain, description = "Execution environment"),
        StateRequestParameters
    ),
)]
pub async fn contract_state<G: Gateway>(
    execution_env: web::Path<Chain>,
    query: web::Query<dto::StateRequestParameters>,
    body: web::Json<dto::StateRequestBody>,
    handler: web::Data<RpcHandler<G>>,
) -> HttpResponse {
    // Call the handler to get the state
    let response = handler
        .into_inner()
        .get_contract_state(&execution_env, &body, &query)
        .await;

    match response {
        Ok(state) => HttpResponse::Ok().json(state),
        Err(err) => {
            error!(error = %err, ?body, ?query, "Error while getting contract state.");
            HttpResponse::InternalServerError().finish()
        }
    }
}

#[utoipa::path(
    post,
    path = "/v1/{execution_env}/contract_delta",
    responses(
        (status = 200, description = "OK", body = ContractDeltaRequestResponse),
    ),
    request_body = ContractDeltaRequestBody,
    params(
        ("execution_env" = Chain, description = "Execution environment"),
        StateRequestParameters
    ),
)]
pub async fn contract_delta<G: Gateway>(
    execution_env: web::Path<Chain>,
    params: web::Query<dto::StateRequestParameters>,
    body: web::Json<dto::ContractDeltaRequestBody>,
    handler: web::Data<RpcHandler<G>>,
) -> HttpResponse {
    // Call the handler to get the state delta
    let response = handler
        .into_inner()
        .get_contract_delta(&execution_env, &body, &params)
        .await;

    match response {
        Ok(state) => HttpResponse::Ok().json(state),
        Err(err) => {
            error!(error = %err, ?body, "Error while getting contract state delta.");
            HttpResponse::InternalServerError().finish()
        }
    }
}

#[utoipa::path(
    post,
    path = "/v1/{execution_env}/tokens",
    responses(
        (status = 200, description = "OK", body = TokensRequestResponse),
    ),
    request_body = TokensRequestBody,
    params(
        ("execution_env" = Chain, description = "Execution environment"),
    ),
)]
pub async fn tokens<G: Gateway>(
    execution_env: web::Path<Chain>,
    body: web::Json<dto::TokensRequestBody>,
    handler: web::Data<RpcHandler<G>>,
) -> HttpResponse {
    // Call the handler to get tokens
    let response = handler
        .into_inner()
        .get_tokens(&execution_env, &body)
        .await;

    match response {
        Ok(state) => HttpResponse::Ok().json(state),
        Err(err) => {
            error!(error = %err, ?body, "Error while getting tokens.");
            HttpResponse::InternalServerError().finish()
        }
    }
}

#[utoipa::path(
    post,
    path = "/v1/{execution_env}/protocol_components",
    responses(
        (status = 200, description = "OK", body = ProtocolComponentRequestResponse),
    ),
    request_body = ProtocolComponentsRequestBody,
    params(
        ("execution_env" = Chain, description = "Execution environment"),
        ProtocolComponentRequestParameters
    ),
)]
pub async fn protocol_components<G: Gateway>(
    execution_env: web::Path<Chain>,
    body: web::Json<dto::ProtocolComponentsRequestBody>,
    params: web::Query<dto::ProtocolComponentRequestParameters>,
    handler: web::Data<RpcHandler<G>>,
) -> HttpResponse {
    // Call the handler to get tokens
    let response = handler
        .into_inner()
        .get_protocol_components(&execution_env, &body, &params)
        .await;

    match response {
        Ok(state) => HttpResponse::Ok().json(state),
        Err(err) => {
            error!(error = %err, ?body, "Error while getting tokens.");
            HttpResponse::InternalServerError().finish()
        }
    }
}

#[utoipa::path(
    post,
    path = "/v1/{execution_env}/protocol_state",
    responses(
        (status = 200, description = "OK", body = ProtocolStateRequestResponse),
    ),
    request_body = ProtocolStateRequestBody,
    params(
        ("execution_env" = Chain, description = "Execution environment"),
        StateRequestParameters
    ),
)]
pub async fn protocol_state<G: Gateway>(
    execution_env: web::Path<Chain>,
    body: web::Json<dto::ProtocolStateRequestBody>,
    params: web::Query<dto::StateRequestParameters>,
    handler: web::Data<RpcHandler<G>>,
) -> HttpResponse {
    // Call the handler to get protocol states
    let response = handler
        .into_inner()
        .get_protocol_state(&execution_env, &body, &params)
        .await;

    match response {
        Ok(state) => HttpResponse::Ok().json(state),
        Err(err) => {
            error!(error = %err, ?body, "Error while getting protocol states.");
            HttpResponse::InternalServerError().finish()
        }
    }
}

#[utoipa::path(
    post,
    path = "/v1/{execution_env}/protocol_delta",
    responses(
        (status = 200, description = "OK", body = ProtocolDeltaRequestResponse),
    ),
    request_body = ProtocolDeltaRequestBody,
    params(
        ("execution_env" = Chain, description = "Execution environment"),
        StateRequestParameters
    ),
)]
pub async fn protocol_delta<G: Gateway>(
    execution_env: web::Path<Chain>,
    body: web::Json<dto::ProtocolDeltaRequestBody>,
    handler: web::Data<RpcHandler<G>>,
) -> HttpResponse {
    // Call the handler to get protocol deltas
    let response = handler
        .into_inner()
        .get_protocol_delta(&execution_env, &body)
        .await;

    match response {
        Ok(state) => HttpResponse::Ok().json(state),
        Err(err) => {
            error!(error = %err, ?body, "Error while getting protocol deltas.");
            HttpResponse::InternalServerError().finish()
        }
    }
}

#[utoipa::path(
    get,
    path="/v1/health",
    responses(
        (status = 200, description = "OK", body=Health),
    ),
)]
pub async fn health() -> HttpResponse {
    HttpResponse::Ok().json(dto::Health::Ready)
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, str::FromStr};

    use actix_web::test;
    use chrono::NaiveDateTime;
    use ethers::types::U256;

    use tycho_core::models::{
        contract::{Contract, ContractDelta},
        protocol::{ProtocolComponent, ProtocolComponentState, ProtocolComponentStateDelta},
        token::CurrencyToken,
        ChangeType,
    };

    use crate::testing::{evm_contract_slots, MockGateway};

    use super::*;

    const WETH: &str = "C02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2";
    const USDC: &str = "A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";

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

        let body: dto::StateRequestBody = serde_json::from_str(json_str).unwrap();

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

        let body: dto::StateRequestBody =
            serde_json::from_str(json_str).expect("serde parsing error");

        let version = BlockOrTimestamp::try_from(&body.version).expect("nor block nor timestamp");
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

        let result: dto::StateRequestBody = serde_json::from_str(json_str).unwrap();

        let contract0 = "b4eccE46b8D4e4abFd03C9B806276A6735C9c092".into();

        let expected = dto::StateRequestBody {
            contract_ids: Some(vec![dto::ContractId::new(dto::Chain::Ethereum, contract0)]),
            version: dto::VersionParam { timestamp: Some(Utc::now().naive_utc()), block: None },
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

    #[tokio::test]
    async fn test_get_state() {
        let expected = Contract::new(
            Chain::Ethereum,
            "0x6b175474e89094c44da98b954eedeac495271d0f"
                .parse()
                .unwrap(),
            "account0".to_owned(),
            evm_contract_slots([(6, 30), (5, 25), (1, 3), (2, 1), (0, 2)]),
            Bytes::from(U256::from(101)),
            HashMap::new(),
            Bytes::from("C0C0C0"),
            "0x106781541fd1c596ade97569d584baf47e3347d3ac67ce7757d633202061bdc4"
                .parse()
                .unwrap(),
            "0x50449de1973d86f21bfafa7c72011854a7e33a226709dc3e2e4edcca34188388"
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
        let mut gw = MockGateway::new();
        let mock_response = Ok(vec![expected.clone()]);
        gw.expect_get_contracts()
            .return_once(|_, _, _, _, _| Box::pin(async move { mock_response }));
        let req_handler = RpcHandler::new(gw, PendingDeltas::new([], []));

        let request = dto::StateRequestBody {
            contract_ids: Some(vec![dto::ContractId::new(
                dto::Chain::Ethereum,
                "6B175474E89094C44Da98b954EedeAC495271d0F"
                    .parse::<Bytes>()
                    .unwrap(),
            )]),
            version: dto::VersionParam { timestamp: Some(Utc::now().naive_utc()), block: None },
        };
        let state = req_handler
            .get_contract_state_inner(
                &Chain::Ethereum,
                &request,
                &dto::StateRequestParameters::default(),
            )
            .await
            .unwrap();

        assert_eq!(state.accounts.len(), 1);
        assert_eq!(state.accounts[0], expected.into());
    }

    #[test]
    async fn test_msg() {
        // Define the contract address and endpoint
        let endpoint = "http://127.0.0.1:4242/v1/ethereum/contract_state";

        // Create the request body using the dto::StateRequestBody struct
        let request_body = dto::StateRequestBody {
            contract_ids: Some(vec![dto::ContractId::new(
                dto::Chain::Ethereum,
                Bytes::from_str("b4eccE46b8D4e4abFd03C9B806276A6735C9c092").unwrap(),
            )]),
            version: dto::VersionParam::default(),
        };

        // Serialize the request body to JSON
        let json_data = serde_json::to_string(&request_body).expect("Failed to serialize to JSON");

        // Print the curl command
        println!(
            "curl -X POST -H \"Content-Type: application/json\" -d '{}' {}",
            json_data, endpoint
        );
    }

    #[tokio::test]
    async fn test_get_tokens() {
        let expected = vec![
            CurrencyToken::new(&(USDC.parse().unwrap()), "USDC", 6, 0, &[], Chain::Ethereum, 100),
            CurrencyToken::new(&(WETH.parse().unwrap()), "WETH", 18, 0, &[], Chain::Ethereum, 100),
        ];
        let mut gw = MockGateway::new();
        let mock_response = Ok(expected.clone());
        gw.expect_get_tokens()
            .return_once(|_, _, _, _, _| Box::pin(async move { mock_response }));
        let req_handler = RpcHandler::new(gw, PendingDeltas::new([], []));

        // request for 2 tokens that are in the DB (WETH and USDC)
        let request = dto::TokensRequestBody {
            token_addresses: Some(vec![
                USDC.parse::<Bytes>().unwrap(),
                WETH.parse::<Bytes>().unwrap(),
            ]),
            min_quality: None,
            traded_n_days_ago: None,
            pagination: dto::PaginationParams::default(),
        };

        let tokens = req_handler
            .get_tokens_inner(&Chain::Ethereum, &request)
            .await
            .unwrap();

        assert_eq!(tokens.tokens.len(), 2);
        assert_eq!(tokens.tokens[0].symbol, "USDC");
        assert_eq!(tokens.tokens[1].symbol, "WETH");
    }

    #[tokio::test]
    async fn test_get_protocol_state() {
        let mut gw = MockGateway::new();
        let expected = ProtocolComponentState::new(
            "state1",
            protocol_attributes([("reserve1", 1000), ("reserve2", 500)]),
            HashMap::new(),
        );
        let mock_response = Ok(vec![expected.clone()]);
        gw.expect_get_protocol_states()
            .return_once(|_, _, _, _, _| Box::pin(async move { mock_response }));
        let req_handler = RpcHandler::new(gw, PendingDeltas::new([], []));

        let request = dto::ProtocolStateRequestBody {
            protocol_ids: Some(vec![dto::ProtocolId {
                id: "state1".to_owned(),
                chain: dto::Chain::Ethereum,
            }]),
            protocol_system: None,
            version: dto::VersionParam { timestamp: Some(Utc::now().naive_utc()), block: None },
        };
        let params =
            StateRequestParameters { tvl_gt: None, inertia_min_gt: None, include_balances: true };
        let res = req_handler
            .get_protocol_state_inner(&Chain::Ethereum, &request, &params)
            .await
            .unwrap();

        assert_eq!(res.states.len(), 1);
        assert_eq!(res.states[0], expected.into());
    }

    fn protocol_attributes<'a>(
        data: impl IntoIterator<Item = (&'a str, i32)>,
    ) -> HashMap<String, Bytes> {
        data.into_iter()
            .map(|(s, v)| (s.to_owned(), Bytes::from(U256::from(v))))
            .collect()
    }

    #[tokio::test]
    async fn test_get_protocol_components() {
        let mut gw = MockGateway::new();
        let expected = ProtocolComponent::new(
            "comp1",
            "ambient",
            "pool",
            Chain::Ethereum,
            vec![],
            vec![],
            HashMap::new(),
            ChangeType::Creation,
            "0x50449de1973d86f21bfafa7c72011854a7e33a226709dc3e2e4edcca34"
                .parse()
                .unwrap(),
            NaiveDateTime::default(),
        );
        let mock_response = Ok(vec![expected.clone()]);
        gw.expect_get_protocol_components()
            .return_once(|_, _, _, _| Box::pin(async move { mock_response }));
        let req_handler = RpcHandler::new(gw, PendingDeltas::new([], []));

        let request = dto::ProtocolComponentsRequestBody {
            protocol_system: Option::from("ambient".to_string()),
            component_ids: None,
        };
        let params = dto::ProtocolComponentRequestParameters::default();

        let components = req_handler
            .get_protocol_components_inner(&Chain::Ethereum, &request, &params)
            .await
            .unwrap();

        assert_eq!(components.protocol_components[0], expected.into());
    }

    #[tokio::test]
    async fn test_get_contract_delta() {
        // Setup
        let mut gw = MockGateway::new();
        let expected = ContractDelta::new(
            &Chain::Ethereum,
            &("6B175474E89094C44Da98b954EedeAC495271d0F"
                .parse()
                .unwrap()),
            Some(
                evm_contract_slots([(6, 30), (5, 25), (1, 3), (0, 2)])
                    .into_iter()
                    .map(|(k, v)| (k, Some(v)))
                    .collect(),
            )
            .as_ref(),
            Some(&Bytes::from(U256::from(101))),
            None,
            ChangeType::Update,
        );
        let mock_response = Ok(vec![expected.clone()]);
        gw.expect_get_accounts_delta()
            .return_once(|_, _, _| Box::pin(async move { mock_response }));
        let req_handler = RpcHandler::new(gw, PendingDeltas::new([], []));
        let request = dto::ContractDeltaRequestBody {
            contract_ids: Some(vec![dto::ContractId::new(
                Chain::Ethereum.into(),
                "6B175474E89094C44Da98b954EedeAC495271d0F"
                    .parse()
                    .unwrap(),
            )]),
            start: dto::VersionParam {
                timestamp: None,
                block: Some(dto::BlockParam {
                    hash: Some(
                        "0x88e96d4537bea4d9c05d12549907b32561d3bf31f45aae734cdc119f13406cb6"
                            .parse()
                            .unwrap(),
                    ),
                    chain: None,
                    number: None,
                }),
            },
            end: dto::VersionParam {
                timestamp: None,
                block: Some(dto::BlockParam {
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

        let delta = req_handler
            .get_contract_delta_inner(
                &Chain::Ethereum,
                &request,
                &StateRequestParameters::default(),
            )
            .await
            .unwrap();

        assert_eq!(delta.accounts.len(), 1);
        assert_eq!(delta.accounts[0], expected.into());
    }

    #[tokio::test]
    async fn test_get_protocol_delta() {
        // Setup
        let mut gw = MockGateway::new();
        let expected = ProtocolComponentStateDelta::new(
            "state3",
            HashMap::new(),
            vec!["deleted2".to_owned()]
                .into_iter()
                .collect(),
        );
        let mock_response = Ok(vec![expected.clone()]);
        gw.expect_get_protocol_states_delta()
            .return_once(|_, _, _| Box::pin(async move { mock_response }));
        let req_handler = RpcHandler::new(gw, PendingDeltas::new([], []));
        let request = dto::ProtocolDeltaRequestBody {
            component_ids: Some(vec!["state3".to_owned()]), // Filter to only "state3"
            start: dto::VersionParam {
                timestamp: None,
                block: Some(dto::BlockParam {
                    hash: None,
                    chain: Some(dto::Chain::Ethereum),
                    number: Some(1),
                }),
            },
            end: dto::VersionParam {
                timestamp: None,
                block: Some(dto::BlockParam {
                    hash: None,
                    chain: Some(dto::Chain::Ethereum),
                    number: Some(2),
                }),
            },
        };

        let delta = req_handler
            .get_protocol_delta_inner(&Chain::Ethereum, &request)
            .await
            .unwrap();

        assert_eq!(delta.protocols.len(), 1);
        assert_eq!(delta.protocols[0], expected.into());
    }
}
