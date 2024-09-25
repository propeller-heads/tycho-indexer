//! This module contains Tycho RPC implementation
#![allow(deprecated)]
use mini_moka::sync::Cache;
use std::{collections::HashSet, sync::Arc};
use tokio::sync::RwLock;

use actix_web::{web, HttpResponse};
use anyhow::Error;
use chrono::{Duration, Utc};
use diesel_async::pooled_connection::deadpool;
use thiserror::Error;
use tracing::{debug, error, info, instrument, trace, warn};

use crate::{
    extractor::reorg_buffer::{BlockNumberOrTimestamp, FinalityStatus},
    services::deltas_buffer::{PendingDeltasBuffer, PendingDeltasError},
};
use tycho_core::{
    dto::{self, PaginationResponse},
    models::{Address, Chain, PaginationParams},
    storage::{BlockIdentifier, BlockOrTimestamp, Gateway, StorageError, Version, VersionKind},
    Bytes,
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

pub struct RpcHandler<G> {
    db_gateway: G,
    pending_deltas: Arc<dyn PendingDeltasBuffer + Send + Sync>,
    token_cache: Arc<RwLock<Cache<String, dto::TokensRequestResponse>>>,
}

impl<G> RpcHandler<G>
where
    G: Gateway,
{
    pub fn new(db_gateway: G, pending_deltas: Arc<dyn PendingDeltasBuffer + Send + Sync>) -> Self {
        let token_cache = Cache::builder()
            .max_capacity(50)
            .time_to_live(std::time::Duration::from_secs(7 * 60))
            .build();

        Self { db_gateway, pending_deltas, token_cache: Arc::new(RwLock::new(token_cache)) }
    }

    #[instrument(skip(self, request))]
    async fn get_contract_state(
        &self,
        request: &dto::StateRequestBody,
    ) -> Result<dto::StateRequestResponse, RpcError> {
        info!(?request, "Getting contract state.");
        self.get_contract_state_inner(request)
            .await
    }

    async fn get_contract_state_inner(
        &self,
        request: &dto::StateRequestBody,
    ) -> Result<dto::StateRequestResponse, RpcError> {
        let at = BlockOrTimestamp::try_from(&request.version)?;
        let chain = request.chain.into();
        let (db_version, deltas_version) = self
            .calculate_versions(&at, &request.protocol_system.clone(), chain)
            .await?;

        let pagination_params: PaginationParams = (&request.pagination).into();

        // Get the contract IDs from the request
        let addresses = request.contract_ids.clone();
        debug!(?addresses, "Getting contract states.");
        let addresses = addresses.as_deref();

        // Apply pagination to the contract addresses. This is done so that we can determine which
        // contracts were not returned from the db and get them from the buffer instead.
        let mut paginated_addrs: Vec<Bytes> = Vec::new();
        if let Some(adrs) = addresses {
            paginated_addrs = adrs
                .iter()
                .skip(pagination_params.offset() as usize)
                .take(pagination_params.page_size as usize)
                .cloned()
                .collect();
        }

        // Get the contract states from the database
        let (db_total, mut accounts) = self
            .db_gateway
            .get_contracts(
                &chain,
                Some(&paginated_addrs),
                Some(&db_version),
                true,
                Some(&pagination_params),
            )
            .await
            .map_err(|err| {
                error!(error = %err, "Error while getting contract states.");
                err
            })?;

        if let Some(at) = deltas_version {
            self.pending_deltas.update_vm_states(
                Some(&paginated_addrs),
                &mut accounts,
                Some(at),
            )?;
        }

        let total = match addresses {
            Some(adrs) => {
                // If contract addresses are specified, the total count is the number of addresses
                adrs.len() as i64
            }
            None => db_total, // TODO: handle case where contract addresses are not specified
        };

        Ok(dto::StateRequestResponse::new(
            accounts
                .into_iter()
                .map(dto::ResponseAccount::from)
                .collect(),
            PaginationResponse::new(pagination_params.page, pagination_params.page_size, total),
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
        protocol_system: &Option<String>,
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
            .get_block_finality(ordered_version, protocol_system.clone())
            .unwrap_or(None)
            .unwrap_or_else(|| {
                warn!(?ordered_version, ?protocol_system, "No finality found for version.");
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
            FinalityStatus::Unseen => {
                match request_version {
                    BlockOrTimestamp::Timestamp(_) => {
                        // If the request is based on a timestamp, return the latest valid version
                        Ok((
                            Version(
                                BlockOrTimestamp::Block(BlockIdentifier::Latest(chain)),
                                VersionKind::Last,
                            ),
                            Some(ordered_version),
                        ))
                    }
                    BlockOrTimestamp::Block(_) => {
                        // If the request is based on a block and it's unseen, return an error
                        Err(RpcError::Storage(StorageError::NotFound(
                            "Version".to_string(),
                            format!("{:?}", request_version),
                        )))
                    }
                }
            }
        }
    }

    #[instrument(skip(self, request))]
    async fn get_protocol_state(
        &self,
        request: &dto::ProtocolStateRequestBody,
    ) -> Result<dto::ProtocolStateRequestResponse, RpcError> {
        debug!(?request, "Getting protocol state.");
        self.get_protocol_state_inner(request)
            .await
    }

    async fn get_protocol_state_inner(
        &self,
        request: &dto::ProtocolStateRequestBody,
    ) -> Result<dto::ProtocolStateRequestResponse, RpcError> {
        //TODO: handle when no id is specified with filters
        let at = BlockOrTimestamp::try_from(&request.version)?;
        let chain = request.chain.into();
        let (db_version, deltas_version) = self
            .calculate_versions(&at, &request.protocol_system.clone(), chain)
            .await?;

        let pagination_params: PaginationParams = (&request.pagination).into();

        // Get the protocol IDs from the request
        let protocol_ids: Option<Vec<dto::ProtocolId>> = request.protocol_ids.clone();
        let ids: Option<Vec<&str>> = protocol_ids.as_ref().map(|ids| {
            ids.iter()
                .map(|id| id.id.as_str())
                .collect::<Vec<&str>>()
        });
        debug!(?ids, "Getting protocol states.");
        let ids = ids.as_deref();

        // Apply pagination to the protocol ids. This is done so that we can determine which ids
        // were not returned from the db and get them from the buffer instead. For component ids
        // that do not exist in either the db or the buffer, we will return an empty state.
        let mut paginated_ids: Vec<&str> = Vec::new();
        if let Some(ids) = ids {
            paginated_ids = ids
                .iter()
                .skip(pagination_params.offset() as usize)
                .take(pagination_params.page_size as usize)
                .cloned()
                .collect();
        }

        // Get the protocol states from the database
        let (db_total, mut states) = self
            .db_gateway
            .get_protocol_states(
                &chain,
                Some(db_version),
                request.protocol_system.clone(),
                Some(&paginated_ids),
                request.include_balances,
                Some(&pagination_params),
            )
            .await
            .map_err(|err| {
                error!(error = %err, "Error while getting protocol states.");
                err
            })?;

        // merge db states with pending deltas
        if let Some(at) = deltas_version {
            self.pending_deltas
                .merge_native_states(Some(&paginated_ids), &mut states, Some(at))?;
        }

        let total = match ids {
            Some(ids) => {
                // If protocol IDs are specified, the total count is the number of IDs
                ids.len() as i64
            }
            None => db_total, // TODO: handle case where protocol ids are not specified
        };

        Ok(dto::ProtocolStateRequestResponse::new(
            states
                .into_iter()
                .map(dto::ResponseProtocolState::from)
                .collect(),
            PaginationResponse::new(pagination_params.page, pagination_params.page_size, total),
        ))
    }

    async fn get_tokens(
        &self,
        request: &dto::TokensRequestBody,
    ) -> Result<dto::TokensRequestResponse, RpcError> {
        info!(?request, "Getting tokens.");

        let cache_key = format!("{:?}", request);

        // Cache entry count is only used for logging purposes
        #[allow(unused_assignments)]
        let mut cache_entry_count: u64 = 0;

        // Check the cache for a cached response
        {
            let read_lock = self.token_cache.read().await;
            cache_entry_count = read_lock.entry_count();
            if let Some(cached_response) = read_lock.get(&cache_key) {
                trace!("Returning cached response");
                return Ok(cached_response);
            }
        }

        trace!(
            ?cache_key,
            "Token cache missed. Cache size: {cache_size}",
            cache_size = cache_entry_count
        );
        // Acquire a write lock before querying the database (prevents concurrent db queries)
        let write_lock = self.token_cache.write().await;

        // Double-check if another thread has already fetched and cached the data
        if let Some(cached_response) = write_lock.get(&cache_key) {
            trace!("Returning cached response after re-check");
            return Ok(cached_response);
        }

        let response = self.get_tokens_inner(request).await?;

        trace!(n_tokens_received=?response.tokens.len(), "Retrieved tokens from DB");

        // Cache the response if it contains a full page of tokens
        if response.tokens.len() == request.pagination.page_size as usize {
            trace!("Caching response");
            write_lock.insert(cache_key, response.clone());
        };

        Ok(response)
    }

    async fn get_tokens_inner(
        &self,
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
            .get_tokens(
                request.chain.into(),
                addresses_slice,
                min_quality,
                n_days_ago,
                Some(&converted_params),
            )
            .await
        {
            Ok((total, tokens)) => Ok(dto::TokensRequestResponse::new(
                tokens
                    .into_iter()
                    .map(dto::ResponseToken::from)
                    .collect(),
                &PaginationResponse::new(
                    request.pagination.page,
                    request.pagination.page_size,
                    total,
                ),
            )),
            Err(err) => {
                error!(error = %err, "Error while getting tokens.");
                Err(err.into())
            }
        }
    }

    async fn get_protocol_components(
        &self,
        request: &dto::ProtocolComponentsRequestBody,
    ) -> Result<dto::ProtocolComponentRequestResponse, RpcError> {
        info!(?request, "Getting protocol components.");
        self.get_protocol_components_inner(request)
            .await
    }

    async fn get_protocol_components_inner(
        &self,
        request: &dto::ProtocolComponentsRequestBody,
    ) -> Result<dto::ProtocolComponentRequestResponse, RpcError> {
        let system = request.protocol_system.clone();
        let pagination_params: PaginationParams = (&request.pagination).into();

        let ids_strs: Option<Vec<&str>> = request
            .component_ids
            .as_ref()
            .map(|vec| vec.iter().map(String::as_str).collect());

        let ids_slice = ids_strs.as_deref();

        let buffered_components = self
            .pending_deltas
            .get_new_components(ids_slice, system.as_deref())?;

        // Check if we have all requested components in the cache
        if let Some(requested_ids) = ids_slice {
            let fetched_ids: HashSet<_> = buffered_components
                .iter()
                .map(|comp| comp.id.as_str())
                .collect();

            let total = buffered_components.len() as i64;

            if requested_ids.len() == fetched_ids.len() {
                let response_components: Vec<dto::ProtocolComponent> = buffered_components
                    .into_iter()
                    .skip(
                        ((pagination_params.page * pagination_params.page_size) as usize)
                            .min(total as usize),
                    )
                    .take(pagination_params.page_size as usize)
                    .map(dto::ProtocolComponent::from)
                    .collect();

                return Ok(dto::ProtocolComponentRequestResponse::new(
                    response_components,
                    PaginationResponse::new(
                        pagination_params.page,
                        pagination_params.page_size,
                        total,
                    ),
                ));
            }
        }

        match self
            .db_gateway
            .get_protocol_components(
                &request.chain.into(),
                system,
                ids_slice,
                request.tvl_gt,
                Some(&pagination_params),
            )
            .await
        {
            Ok((db_total, mut components)) => {
                let total = db_total + buffered_components.len() as i64;

                // Handle adding buffered components to the response
                let buffer_offset = pagination_params.offset() - db_total;
                if buffer_offset > 0 {
                    // Pagination page is greater than that provided by the db query - respond with
                    // buffered data only
                    components = buffered_components
                        .into_iter()
                        .skip(buffer_offset as usize)
                        .take(pagination_params.page_size as usize)
                        .collect();
                } else {
                    let remaining_capacity =
                        pagination_params.page_size as usize - components.len();
                    if remaining_capacity > 0 {
                        // The db response does not fill a page - add buffered components to the
                        // response
                        let buf_comps = buffered_components
                            .into_iter()
                            .take(remaining_capacity);
                        components.extend(buf_comps);
                    }
                }

                let response_components = components
                    .into_iter()
                    .map(dto::ProtocolComponent::from)
                    .collect::<Vec<dto::ProtocolComponent>>();
                Ok(dto::ProtocolComponentRequestResponse::new(
                    response_components,
                    PaginationResponse::new(
                        pagination_params.page,
                        pagination_params.page_size,
                        total,
                    ),
                ))
            }
            Err(err) => {
                error!(error = %err, "Error while getting protocol components.");
                Err(err.into())
            }
        }
    }
}

/// Deprecated endpoint
///
/// Path params will override the request body.
#[utoipa::path(
    post,
    path = "/v1/{execution_env}/contract_state",
    responses(
        (status = 200, description = "OK", body = StateRequestResponse),
    ),
    request_body = StateRequestBody,
    params(
        ("execution_env" = Chain, description = "Execution environment")
    ),
)]
pub async fn contract_state_deprecated<G: Gateway>(
    execution_env: web::Path<dto::Chain>,
    body: web::Json<dto::StateRequestBody>,
    handler: web::Data<RpcHandler<G>>,
) -> HttpResponse {
    let mut request = body.into_inner();
    request.chain = execution_env.into_inner();

    // Call the handler to get the state
    let response = handler
        .into_inner()
        .get_contract_state(&request)
        .await;

    match response {
        Ok(state) => HttpResponse::Ok().json(state),
        Err(err) => {
            error!(error = %err, ?request, "Error while getting contract state.");
            HttpResponse::InternalServerError().finish()
        }
    }
}

/// Retrieve contract states
///
/// This endpoint retrieves the state of contracts within a specific execution environment. If no
/// contract ids are given, all contracts are returned. Note that `protocol_system` is not a filter;
/// it's a way to specify the protocol system associated with the contracts requested and is used to
/// ensure that the correct extractor's block status is used when querying the database. If omitted,
/// the block status will be determined by a random extractor, which could be risky if the extractor
/// is out of sync. Filtering by protocol system is not currently supported on this endpoint and
/// should be done client side.
#[utoipa::path(
    post,
    path = "/v1/contract_state",
    responses(
        (status = 200, description = "OK", body = StateRequestResponse),
    ),
    request_body = StateRequestBody,
)]
pub async fn contract_state<G: Gateway>(
    body: web::Json<dto::StateRequestBody>,
    handler: web::Data<RpcHandler<G>>,
) -> HttpResponse {
    // Note - filtering by protocol system is not supported on this endpoint. This is due to the
    // complexity of paginating this endpoint with the current design.
    if body.pagination.page_size > 100 {
        return HttpResponse::BadRequest().body("Page size must be less than or equal to 100.");
    }

    // Call the handler to get the state
    let response = handler
        .into_inner()
        .get_contract_state(&body)
        .await;

    match response {
        Ok(state) => HttpResponse::Ok().json(state),
        Err(err) => {
            error!(error = %err, ?body, "Error while getting contract state.");
            HttpResponse::InternalServerError().finish()
        }
    }
}

/// Deprecated endpoint
///
/// Path params will override the request body.
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
pub async fn tokens_deprecated<G: Gateway>(
    execution_env: web::Path<Chain>,
    body: web::Json<dto::TokensRequestBody>,
    handler: web::Data<RpcHandler<G>>,
) -> HttpResponse {
    let mut request = body.into_inner();
    request.chain = execution_env.into_inner().into();

    // Call the handler to get tokens
    let response = handler
        .into_inner()
        .get_tokens(&request)
        .await;

    match response {
        Ok(state) => HttpResponse::Ok().json(state),
        Err(err) => {
            error!(error = %err, ?request, "Error while getting tokens.");
            HttpResponse::InternalServerError().finish()
        }
    }
}

/// Retrieve tokens
///
/// This endpoint retrieves tokens for a specific execution environment, filtered by various
/// criteria. The tokens are returned in a paginated format.
#[utoipa::path(
    post,
    path = "/v1/tokens",
    responses(
        (status = 200, description = "OK", body = TokensRequestResponse),
    ),
    request_body = TokensRequestBody,
)]
pub async fn tokens<G: Gateway>(
    body: web::Json<dto::TokensRequestBody>,
    handler: web::Data<RpcHandler<G>>,
) -> HttpResponse {
    if body.pagination.page_size > 3000 {
        return HttpResponse::BadRequest().body("Page size must be less than or equal to 3000.");
    }

    // Call the handler to get tokens
    let response = handler
        .into_inner()
        .get_tokens(&body)
        .await;

    match response {
        Ok(state) => HttpResponse::Ok().json(state),
        Err(err) => {
            error!(error = %err, ?body, "Error while getting tokens.");
            HttpResponse::InternalServerError().finish()
        }
    }
}

/// Deprecated endpoint
///
/// Path params will override the request body.
#[utoipa::path(
    post,
    path = "/v1/{execution_env}/protocol_components",
    responses(
        (status = 200, description = "OK", body = ProtocolComponentRequestResponse),
    ),
    request_body = ProtocolComponentsRequestBody,
    params(
        ("execution_env" = Chain, description = "Execution environment"),
        ("tvl_gt" = Option<f64>, Query, description = "Filter components by TVL greater than this value")
    ),
)]
pub async fn protocol_components_deprecated<G: Gateway>(
    execution_env: web::Path<dto::Chain>,
    body: web::Json<dto::ProtocolComponentsRequestBody>,
    params: web::Query<dto::ProtocolComponentRequestParameters>,
    handler: web::Data<RpcHandler<G>>,
) -> HttpResponse {
    let mut request = body.into_inner();
    request.chain = execution_env.into_inner();
    request.tvl_gt = params.tvl_gt.or(request.tvl_gt);

    // Call the handler to get tokens
    let response = handler
        .into_inner()
        .get_protocol_components(&request)
        .await;

    match response {
        Ok(state) => HttpResponse::Ok().json(state),
        Err(err) => {
            error!(error = %err, ?request, "Error while getting tokens.");
            HttpResponse::InternalServerError().finish()
        }
    }
}

/// Retrieve protocol components
///
/// This endpoint retrieves components within a specific execution environment, filtered by various
/// criteria.
#[utoipa::path(
    post,
    path = "/v1/protocol_components",
    responses(
        (status = 200, description = "OK", body = ProtocolComponentRequestResponse),
    ),
    request_body = ProtocolComponentsRequestBody,
)]
pub async fn protocol_components<G: Gateway>(
    body: web::Json<dto::ProtocolComponentsRequestBody>,
    handler: web::Data<RpcHandler<G>>,
) -> HttpResponse {
    if body.pagination.page_size > 100 {
        return HttpResponse::BadRequest().body("Page size must be less than or equal to 100.");
    }

    // Call the handler to get tokens
    let response = handler
        .into_inner()
        .get_protocol_components(&body)
        .await;

    match response {
        Ok(state) => HttpResponse::Ok().json(state),
        Err(err) => {
            error!(error = %err, ?body, "Error while getting tokens.");
            HttpResponse::InternalServerError().finish()
        }
    }
}

/// Deprecated endpoint
///
/// Path params will override the request body.
#[utoipa::path(
    post,
    path = "/v1/{execution_env}/protocol_state",
    responses(
        (status = 200, description = "OK", body = ProtocolStateRequestResponse),
    ),
    request_body = ProtocolStateRequestBody,
    params(
        ("execution_env" = Chain, description = "Execution environment"),
        ("include_balances" = Option<bool>, Query, description = "Include account balances in the response", example=true),
        ("tvl_gt" = Option<f64>, Query, description = "Note - not supported."),
        ("inertia_min_gt" = Option<f64>, Query, description = "Note - not supported.")
    ),
)]
pub async fn protocol_state_deprecated<G: Gateway>(
    execution_env: web::Path<dto::Chain>,
    body: web::Json<dto::ProtocolStateRequestBody>,
    params: web::Query<dto::StateRequestParameters>,
    handler: web::Data<RpcHandler<G>>,
) -> HttpResponse {
    let mut request = body.into_inner();
    request.chain = execution_env.into_inner();
    request.include_balances = params.include_balances;

    info!(?request, "Getting protocol state.");

    // Call the handler to get protocol states
    let response = handler
        .into_inner()
        .get_protocol_state(&request)
        .await;

    match response {
        Ok(state) => HttpResponse::Ok().json(state),
        Err(err) => {
            error!(error = %err, ?request, "Error while getting protocol states.");
            HttpResponse::InternalServerError().finish()
        }
    }
}

/// Retrieve protocol states
///
/// This endpoint retrieves the state of protocols within a specific execution environment.
/// Currently, the filters are not compounded, meaning that if multiple filters are provided, one
/// will be prioritised. The priority from highest to lowest is as follows: 'protocol_ids',
/// 'protocol_system', 'chain'. Note that 'protocol_system' serves as both a filter and as a way
/// to specify the protocol system associated with the components requested. This is used to ensure
/// that the correct extractor's block status is used when querying the database. If omitted, the
/// block status will be determined by a random extractor, which could be risky if the extractor is
/// out of sync.
#[utoipa::path(
    post,
    path = "/v1/protocol_state",
    responses(
        (status = 200, description = "OK", body = ProtocolStateRequestResponse),
    ),
    request_body = ProtocolStateRequestBody,
)]
pub async fn protocol_state<G: Gateway>(
    body: web::Json<dto::ProtocolStateRequestBody>,
    handler: web::Data<RpcHandler<G>>,
) -> HttpResponse {
    if body.pagination.page_size > 100 {
        return HttpResponse::BadRequest().body("Page size must be less than or equal to 100.");
    }

    // Call the handler to get protocol states
    let response = handler
        .into_inner()
        .get_protocol_state(&body)
        .await;

    match response {
        Ok(state) => HttpResponse::Ok().json(state),
        Err(err) => {
            error!(error = %err, ?body, "Error while getting protocol states.");
            HttpResponse::InternalServerError().finish()
        }
    }
}

/// Health check endpoint
///
/// This endpoint is used to check the health of the service.
#[utoipa::path(
    get,
    path = "/v1/health",
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

    use mockall::mock;
    use tycho_core::{
        models::{
            contract::Account,
            protocol::{ProtocolComponent, ProtocolComponentState},
            token::CurrencyToken,
            ChangeType,
        },
        Bytes,
    };

    use crate::{
        services::deltas_buffer::PendingDeltas,
        testing::{evm_contract_slots, MockGateway},
    };

    use super::*;

    const WETH: &str = "C02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2";
    const USDC: &str = "A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";

    mock! {
        pub PendingDeltas {}

        impl PendingDeltasBuffer for PendingDeltas {
            fn merge_native_states<'a>(
                &self,
                protocol_ids: Option<&'a [&'a str]>,
                db_states: &mut Vec<ProtocolComponentState>,
                version: Option<BlockNumberOrTimestamp>,
            ) -> Result<(), PendingDeltasError>;

            fn update_vm_states<'a>(
                &self,
                addresses: Option<&'a [Bytes]>,
                db_states: &mut Vec<Account>,
                version: Option<BlockNumberOrTimestamp>,
            ) -> Result<(), PendingDeltasError>;

            fn get_new_components<'a>(
                &self,
                ids: Option<&'a [&'a str]>,
                protocol_system: Option<&'a str>,
            ) -> Result<Vec<ProtocolComponent>, PendingDeltasError>;

            fn get_block_finality(
                &self,
                version: BlockNumberOrTimestamp,
                protocol_system: Option<String>,
            ) -> Result<Option<FinalityStatus>, PendingDeltasError>;
        }
    }

    #[test]
    async fn test_validate_version_priority() {
        let json_str = r#"
    {
        "version": {
            "timestamp": "2069-01-01T04:20:00",
            "block": {
                "hash": "0x24101f9cb26cd09425b52da10e8c2f56ede94089a8bbe0f31f1cda5f4daa52c4",
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
            "0xb4eccE46b8D4e4abFd03C9B806276A6735C9c092"
        ]
    }
    "#;

        let result: dto::StateRequestBody = serde_json::from_str(json_str).unwrap();

        let contract0 = "b4eccE46b8D4e4abFd03C9B806276A6735C9c092".into();

        let expected = dto::StateRequestBody {
            contract_ids: Some(vec![contract0]),
            protocol_system: None,
            version: dto::VersionParam { timestamp: Some(Utc::now().naive_utc()), block: None },
            chain: dto::Chain::Ethereum,
            pagination: dto::PaginationParams::default(),
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
        let expected = Account::new(
            Chain::Ethereum,
            "0x6b175474e89094c44da98b954eedeac495271d0f"
                .parse()
                .unwrap(),
            "account0".to_owned(),
            evm_contract_slots([(6, 30), (5, 25), (1, 3), (2, 1), (0, 2)]),
            Bytes::from(101u8).lpad(32, 0),
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
        let mock_response = Ok((10_i64, vec![expected.clone()]));
        gw.expect_get_contracts()
            .return_once(|_, _, _, _, _| Box::pin(async move { mock_response }));
        let req_handler = RpcHandler::new(gw, Arc::new(PendingDeltas::new([])));

        let request = dto::StateRequestBody {
            contract_ids: Some(vec![
                Bytes::from_str("6B175474E89094C44Da98b954EedeAC495271d0F").unwrap()
            ]),
            protocol_system: None,
            version: dto::VersionParam { timestamp: Some(Utc::now().naive_utc()), block: None },
            chain: dto::Chain::Ethereum,
            pagination: dto::PaginationParams::default(),
        };
        let state = req_handler
            .get_contract_state_inner(&request)
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
            contract_ids: Some(vec![
                Bytes::from_str("b4eccE46b8D4e4abFd03C9B806276A6735C9c092").unwrap()
            ]),
            protocol_system: None,
            version: dto::VersionParam::default(),
            chain: dto::Chain::Ethereum,
            pagination: dto::PaginationParams::default(),
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
        let mock_response = Ok((2, expected.clone()));
        // ensure the gateway is only accessed once - the second request should hit cache
        gw.expect_get_tokens()
            .return_once(|_, _, _, _, _| Box::pin(async move { mock_response }));
        let req_handler = RpcHandler::new(gw, Arc::new(PendingDeltas::new([])));

        // request for 2 tokens that are in the DB (WETH and USDC)
        let request = dto::TokensRequestBody {
            token_addresses: Some(vec![
                USDC.parse::<Bytes>().unwrap(),
                WETH.parse::<Bytes>().unwrap(),
            ]),
            min_quality: None,
            traded_n_days_ago: None,
            pagination: dto::PaginationParams { page: 0, page_size: 2 },
            chain: dto::Chain::Ethereum,
        };

        // First request

        let tokens = req_handler
            .get_tokens(&request)
            .await
            .unwrap();

        assert_eq!(tokens.tokens.len(), 2);
        assert_eq!(tokens.tokens[0].symbol, "USDC");
        assert_eq!(tokens.tokens[1].symbol, "WETH");

        // Second request (should hit cache and not increase gateway access count)

        let tokens = req_handler
            .get_tokens(&request)
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
        let mock_response = Ok((1, vec![expected.clone()]));
        gw.expect_get_protocol_states()
            .return_once(|_, _, _, _, _, _| Box::pin(async move { mock_response }));

        let mut mock_buffer = MockPendingDeltas::new();
        let buf_expected = ProtocolComponentState::new(
            "state_buff",
            protocol_attributes([("reserve1", 100), ("reserve2", 200)]),
            HashMap::new(),
        );
        mock_buffer
            .expect_merge_native_states()
            .return_once({
                let buf_expected_clone = buf_expected.clone();
                move |_, db_states: &mut Vec<ProtocolComponentState>, _| {
                    db_states.push(buf_expected_clone);
                    Ok(())
                }
            });
        mock_buffer
            .expect_get_block_finality()
            .return_once(|_, _| Ok(Some(FinalityStatus::Unfinalized)));

        let req_handler = RpcHandler::new(gw, Arc::new(mock_buffer));

        let request = dto::ProtocolStateRequestBody {
            protocol_ids: Some(vec![
                dto::ProtocolId { id: "state1".to_owned(), chain: dto::Chain::Ethereum },
                dto::ProtocolId { id: "state_buff".to_owned(), chain: dto::Chain::Ethereum },
            ]),
            protocol_system: None,
            chain: dto::Chain::Ethereum,
            include_balances: true,
            version: dto::VersionParam { timestamp: Some(Utc::now().naive_utc()), block: None },
            pagination: dto::PaginationParams::default(),
        };
        let res = req_handler
            .get_protocol_state_inner(&request)
            .await
            .unwrap();

        assert_eq!(res.states.len(), 2);
        assert_eq!(res.states[0], expected.into());
        assert_eq!(res.states[1], buf_expected.into());
        assert_eq!(res.pagination.total, 2);
    }

    fn protocol_attributes<'a>(
        data: impl IntoIterator<Item = (&'a str, i32)>,
    ) -> HashMap<String, Bytes> {
        data.into_iter()
            .map(|(s, v)| (s.to_owned(), Bytes::from(u32::try_from(v).unwrap()).lpad(32, 0)))
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
        let mock_response = Ok((1, vec![expected.clone()]));
        gw.expect_get_protocol_components()
            .return_once(|_, _, _, _, _| Box::pin(async move { mock_response }));

        let mut mock_buffer = MockPendingDeltas::new();
        let buf_expected = ProtocolComponent::new(
            "comp_buff",
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
        mock_buffer
            .expect_get_new_components()
            .return_once({
                let buf_expected_clone = buf_expected.clone();
                move |_, _| Ok(vec![buf_expected_clone])
            });

        let req_handler = RpcHandler::new(gw, Arc::new(mock_buffer));

        let request = dto::ProtocolComponentsRequestBody {
            protocol_system: Option::from("ambient".to_string()),
            component_ids: None,
            tvl_gt: None,
            chain: dto::Chain::Ethereum,
            pagination: dto::PaginationParams::new(0, 2),
        };

        let components = req_handler
            .get_protocol_components_inner(&request)
            .await
            .unwrap();

        assert_eq!(components.protocol_components.len(), 2);
        assert_eq!(components.protocol_components[0], expected.into());
        assert_eq!(components.protocol_components[1], buf_expected.into());
        assert_eq!(components.pagination.total, 2);
        assert_eq!(components.pagination.page, 0);
        assert_eq!(components.pagination.page_size, 2);
    }

    #[tokio::test]
    async fn test_get_protocol_components_pagination() {
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
        gw.expect_get_protocol_components()
            .returning({
                let mock_response: Result<(i64, Vec<ProtocolComponent>), StorageError> =
                    Ok((1, vec![expected.clone()]));
                move |_, _, _, _, _| {
                    let mock_response_clone = match &mock_response {
                        Ok((num, components)) => Ok((*num, components.clone())),
                        Err(_) => Err(StorageError::Unexpected("Mock Error".to_string())),
                    };
                    Box::pin(async move { mock_response_clone })
                }
            });

        let mut mock_buffer = MockPendingDeltas::new();
        let buf_expected1 = ProtocolComponent::new(
            "comp_buff1",
            "ambient",
            "pool",
            Chain::Ethereum,
            vec![],
            vec![],
            HashMap::new(),
            ChangeType::Creation,
            "0x2b493d2596845046d3769c6a9c763a6f983efdbd4209c62be1d024d564aa4df7"
                .parse()
                .unwrap(),
            NaiveDateTime::default(),
        );
        let buf_expected2 = ProtocolComponent::new(
            "comp_buff2",
            "ambient",
            "pool",
            Chain::Ethereum,
            vec![],
            vec![],
            HashMap::new(),
            ChangeType::Creation,
            "0x2b493d2596845046d3769c6a9c763a6f983efdbd4209c62be1d024d564aa4df7"
                .parse()
                .unwrap(),
            NaiveDateTime::default(),
        );

        mock_buffer
            .expect_get_new_components()
            .returning({
                let buf_expected1_clone = buf_expected1.clone();
                let buf_expected2_clone = buf_expected2.clone();
                move |_, _| Ok(vec![buf_expected1_clone.clone(), buf_expected2_clone.clone()])
            });

        let req_handler = RpcHandler::new(gw, Arc::new(mock_buffer));

        let request = dto::ProtocolComponentsRequestBody {
            protocol_system: Option::from("ambient".to_string()),
            component_ids: None,
            tvl_gt: None,
            chain: dto::Chain::Ethereum,
            pagination: dto::PaginationParams::new(0, 2),
        };

        let response1 = req_handler
            .get_protocol_components_inner(&request)
            .await
            .unwrap();

        assert_eq!(response1.protocol_components.len(), 2);
        assert_eq!(response1.protocol_components[0], expected.into());
        assert_eq!(response1.protocol_components[1], buf_expected1.into());
        assert_eq!(response1.pagination.total, 3);

        let request = dto::ProtocolComponentsRequestBody {
            protocol_system: Option::from("ambient".to_string()),
            component_ids: None,
            tvl_gt: None,
            chain: dto::Chain::Ethereum,
            pagination: dto::PaginationParams::new(1, 2),
        };

        let response2 = req_handler
            .get_protocol_components_inner(&request)
            .await
            .unwrap();

        assert_eq!(response2.protocol_components.len(), 1);
        assert_eq!(response2.protocol_components[0], buf_expected2.into());
        assert_eq!(response2.pagination.total, 3);
    }
}
