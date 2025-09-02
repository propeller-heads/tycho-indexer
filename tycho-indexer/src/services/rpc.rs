//! This module contains Tycho RPC implementation
#![allow(deprecated)]
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use actix_web::{web, HttpRequest, HttpResponse, ResponseError};
use anyhow::Error;
use chrono::{Duration, Utc};
use diesel_async::pooled_connection::deadpool;
use metrics::counter;
use reqwest::StatusCode;
use thiserror::Error;
use tracing::{debug, error, info, instrument, trace, warn};
use tycho_common::{
    dto::{self, PaginationResponse},
    models::{
        blockchain::{BlockAggregatedChanges, EntryPoint, TracedEntryPoint, TracingParams},
        protocol::QualityRange,
        Address, Chain, ComponentId, EntryPointId, PaginationParams,
    },
    storage::{
        BlockIdentifier, BlockOrTimestamp, EntryPointFilter, Gateway, StorageError, Version,
        VersionKind,
    },
    traits::EntryPointTracer,
    Bytes,
};

use crate::{
    extractor::reorg_buffer::{BlockNumberOrTimestamp, FinalityStatus},
    services::{
        cache::RpcCache,
        deltas_buffer::{PendingDeltasBuffer, PendingDeltasError},
    },
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

    #[error("Unknown error: {0}")]
    Unknown(String),
}

impl From<anyhow::Error> for RpcError {
    fn from(value: Error) -> Self {
        Self::Parse(value.to_string())
    }
}

impl ResponseError for RpcError {
    fn error_response(&self) -> HttpResponse {
        match self {
            RpcError::Storage(e) => HttpResponse::NotFound().body(e.to_string()),
            RpcError::Parse(e) => HttpResponse::BadRequest().body(e.to_string()),
            RpcError::Connection(e) => HttpResponse::InternalServerError().body(e.to_string()),
            RpcError::DeltasError(e) => HttpResponse::InternalServerError().body(e.to_string()),
            RpcError::Unknown(e) => HttpResponse::InternalServerError().body(e.to_string()),
        }
    }

    fn status_code(&self) -> StatusCode {
        match self {
            RpcError::Storage(_) => StatusCode::NOT_FOUND,
            RpcError::Parse(_) => StatusCode::BAD_REQUEST,
            RpcError::Connection(_) => StatusCode::INTERNAL_SERVER_ERROR,
            RpcError::DeltasError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            RpcError::Unknown(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

pub struct RpcHandler<G, T> {
    db_gateway: G,
    // TODO: remove use of Arc. It was introduced for ease of testing this deltas buffer, however
    // it potentially could make this slow. We should consider refactoring this and maybe use
    // generics
    pending_deltas: Option<Arc<dyn PendingDeltasBuffer + Send + Sync>>,
    token_cache: RpcCache<dto::TokensRequestBody, dto::TokensRequestResponse>,
    contract_storage_cache: RpcCache<dto::StateRequestBody, dto::StateRequestResponse>,
    protocol_state_cache:
        RpcCache<dto::ProtocolStateRequestBody, dto::ProtocolStateRequestResponse>,
    component_cache:
        RpcCache<dto::ProtocolComponentsRequestBody, dto::ProtocolComponentRequestResponse>,
    traced_entry_point_cache:
        RpcCache<dto::TracedEntryPointRequestBody, dto::TracedEntryPointRequestResponse>,
    #[allow(dead_code)]
    tracer: T,
}

impl<G, T> RpcHandler<G, T>
where
    G: Gateway,
    T: EntryPointTracer + Sync,
{
    pub fn new(
        db_gateway: G,
        pending_deltas: Option<Arc<dyn PendingDeltasBuffer + Send + Sync>>,
        tracer: T,
    ) -> Self {
        let token_cache = RpcCache::<dto::TokensRequestBody, dto::TokensRequestResponse>::new(
            "token",
            50,
            7 * 60,
        );

        let contract_storage_cache =
            RpcCache::<dto::StateRequestBody, dto::StateRequestResponse>::new(
                "contract_storage",
                50,
                7 * 60,
            );

        let protocol_state_cache = RpcCache::<
            dto::ProtocolStateRequestBody,
            dto::ProtocolStateRequestResponse,
        >::new("protocol_state", 50, 7 * 60);

        let component_cache = RpcCache::<
            dto::ProtocolComponentsRequestBody,
            dto::ProtocolComponentRequestResponse,
        >::new("protocol_components", 500, 7 * 60);

        let traced_entry_point_cache = RpcCache::<
            dto::TracedEntryPointRequestBody,
            dto::TracedEntryPointRequestResponse,
        >::new("traced_entry_points", 500, 7 * 60);

        Self {
            db_gateway,
            pending_deltas,
            token_cache,
            contract_storage_cache,
            protocol_state_cache,
            component_cache,
            traced_entry_point_cache,
            tracer,
        }
    }

    #[instrument(skip(self, request))]
    async fn get_contract_state(
        &self,
        request: &dto::StateRequestBody,
    ) -> Result<dto::StateRequestResponse, RpcError> {
        info!(?request, "Getting contract state.");
        self.contract_storage_cache
            .get(request.clone(), |r| async {
                self.get_contract_state_inner(r)
                    .await
                    .map(|res| (res, true))
            })
            .await
    }

    async fn get_contract_state_inner(
        &self,
        request: dto::StateRequestBody,
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
        let mut paginated_addrs: Option<Vec<Bytes>> = None;
        if let Some(addrs) = addresses {
            paginated_addrs = Some(
                addrs
                    .iter()
                    .skip(pagination_params.offset() as usize)
                    .take(pagination_params.page_size as usize)
                    .cloned()
                    .collect(),
            );
        }

        // Get the contract states from the database
        let account_data = self
            .db_gateway
            .get_contracts(
                &chain,
                paginated_addrs.as_deref(),
                Some(&db_version),
                true,
                Some(&pagination_params),
            )
            .await
            .map_err(|err| {
                error!(error = %err, "Error while getting contract states.");
                err
            })?;
        let mut accounts = account_data.entity;

        if let Some(at) = deltas_version {
            if let Some(pending_deltas) = &self.pending_deltas {
                pending_deltas.update_vm_states(
                    paginated_addrs.as_deref(),
                    &mut accounts,
                    Some(at),
                    &request.protocol_system,
                )?;
            }
        }

        let total = match addresses {
            Some(adrs) => {
                // If contract addresses are specified, the total count is the number of addresses
                adrs.len() as i64
            }
            None => account_data.total.unwrap_or_default(), /* TODO: handle case where contract
                                                             * addresses are not specified */
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
        protocol_system: &str,
        chain: Chain,
    ) -> Result<(Version, Option<BlockNumberOrTimestamp>), RpcError> {
        let ordered_version = match request_version {
            BlockOrTimestamp::Block(BlockIdentifier::Number((_, no))) => {
                BlockNumberOrTimestamp::Number(*no as u64)
            }
            BlockOrTimestamp::Block(BlockIdentifier::Hash(hash)) => {
                let block_number = if let Some(block_number) = self
                    .pending_deltas
                    .as_ref()
                    .and_then(|pending| {
                        pending
                            .search_block(
                                &|b: &BlockAggregatedChanges| &b.block.hash == hash,
                                protocol_system,
                            )
                            .ok()
                    })
                    .and_then(|block| block.map(|b| b.block.number))
                {
                    Some(block_number)
                } else {
                    self.db_gateway
                        .get_block(&BlockIdentifier::Hash(hash.clone()))
                        .await
                        .ok()
                        .map(|block| block.number)
                }
                .ok_or_else(|| {
                    RpcError::Storage(StorageError::NotFound(
                        "Version".to_string(),
                        format!("{request_version:?}",),
                    ))
                })?;

                BlockNumberOrTimestamp::Number(block_number)
            }
            BlockOrTimestamp::Timestamp(ts) => BlockNumberOrTimestamp::Timestamp(*ts),
            BlockOrTimestamp::Block(block_id) => BlockNumberOrTimestamp::Number(
                self.db_gateway
                    .get_block(block_id)
                    .await?
                    .number,
            ),
        };
        let request_version_finality =
            self.pending_deltas
                .as_ref()
                .map_or(FinalityStatus::Finalized, |pending| {
                    pending
                        .get_block_finality(ordered_version, protocol_system)
                        .ok()
                        .and_then(|finality| finality)
                        .unwrap_or_else(|| {
                            warn!(
                                ?ordered_version,
                                ?protocol_system,
                                "No finality found for version."
                            );
                            FinalityStatus::Finalized
                        })
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
                            format!("{request_version:?}",),
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
        self.protocol_state_cache
            .get(request.clone(), |r| async {
                self.get_protocol_state_inner(r)
                    .await
                    .map(|res| (res, true))
            })
            .await
    }

    async fn get_protocol_state_inner(
        &self,
        request: dto::ProtocolStateRequestBody,
    ) -> Result<dto::ProtocolStateRequestResponse, RpcError> {
        let at = BlockOrTimestamp::try_from(&request.version)?;
        let chain = request.chain.into();
        let (db_version, deltas_version) = self
            .calculate_versions(&at, &request.protocol_system.clone(), chain)
            .await?;

        let pagination_params: PaginationParams = (&request.pagination).into();

        // Get the protocol IDs from the request
        let protocol_ids = request.protocol_ids.clone();
        debug!(?protocol_ids, "Getting protocol states.");
        let ids = protocol_ids.as_deref();

        // Apply pagination to the protocol ids. This is done so that we can determine which ids
        // were not returned from the db and get them from the buffer instead. For component ids
        // that do not exist in either the db or the buffer, we will return an empty state.
        // By precomputing the paginated IDs we also ensure that the fetched balances and
        // protocol state are paginated in the same way.
        // Also, by doing this in a single point prevents failures and increases performance.
        let (paginated_ids, total): (Vec<String>, i64) = match ids {
            Some(ids) => (
                ids.iter()
                    .skip(pagination_params.offset() as usize)
                    .take(pagination_params.page_size as usize)
                    .cloned()
                    .map(|s| s.to_string())
                    .collect(),
                ids.len() as i64,
            ),
            None => {
                let req = dto::ProtocolComponentsRequestBody {
                    chain: request.chain,
                    protocol_system: request.protocol_system.clone(),
                    component_ids: None,
                    tvl_gt: None,
                    pagination: request.pagination.clone(),
                };
                let protocol_components = self
                    .get_protocol_components_inner(req)
                    .await
                    .expect("Failed to get protocol component IDs");
                let total_components = protocol_components.pagination.total;
                (
                    protocol_components
                        .protocol_components
                        .into_iter()
                        .map(|c| c.id)
                        .collect(),
                    total_components,
                )
            }
        };
        let paginated_ids: Vec<&str> = paginated_ids
            .iter()
            .map(AsRef::as_ref)
            .collect();

        debug!(n_ids = paginated_ids.len(), "Getting protocol states for paginated IDs.");

        // Get the protocol states from the database. We skip pagination because we have already
        // paginated the protocol IDs.
        let state_data = self
            .db_gateway
            .get_protocol_states(
                &chain,
                Some(db_version),
                Some(request.protocol_system.clone()),
                Some(paginated_ids.as_slice()),
                request.include_balances,
                None,
            )
            .await
            .map_err(|err| {
                error!(error = %err, "Error while getting protocol states.");
                err
            })?;
        let mut states = state_data.entity;

        trace!(db_state = ?states, "Retrieved states from database.");

        // merge db states with pending deltas
        if let Some(at) = deltas_version {
            if let Some(pending_deltas) = &self.pending_deltas {
                pending_deltas.merge_native_states(
                    Some(paginated_ids.as_slice()),
                    &mut states,
                    Some(at),
                    &request.protocol_system,
                )?;
            }
        }

        trace!(db_state = ?states, "Updated states with buffer.");

        Ok(dto::ProtocolStateRequestResponse::new(
            states
                .into_iter()
                .map(dto::ResponseProtocolState::from)
                .collect(),
            PaginationResponse::new(pagination_params.page, pagination_params.page_size, total),
        ))
    }

    #[instrument(skip(self, request))]
    async fn get_protocol_systems(
        &self,
        request: &dto::ProtocolSystemsRequestBody,
    ) -> Result<dto::ProtocolSystemsRequestResponse, RpcError> {
        info!(?request, "Getting protocol systems.");
        let chain = request.chain.into();
        let pagination_params: PaginationParams = (&request.pagination).into();
        match self
            .db_gateway
            .get_protocol_systems(&chain, Some(&pagination_params))
            .await
        {
            Ok(protocol_systems) => Ok(dto::ProtocolSystemsRequestResponse::new(
                protocol_systems
                    .entity
                    .into_iter()
                    .collect(),
                PaginationResponse::new(
                    request.pagination.page,
                    request.pagination.page_size,
                    protocol_systems
                        .total
                        .unwrap_or_default(),
                ),
            )),
            Err(err) => {
                error!(error = %err, "Error while getting protocol systems.");
                Err(err.into())
            }
        }
    }

    #[instrument(skip(self, request))]
    async fn get_component_tvls(
        &self,
        request: &dto::ComponentTvlRequestBody,
    ) -> Result<dto::ComponentTvlRequestResponse, RpcError> {
        info!(?request, "Getting protocol component tvl.");
        let chain = request.chain.into();
        let pagination_params: PaginationParams = (&request.pagination).into();
        let ids_strs: Option<Vec<&str>> = request
            .component_ids
            .as_ref()
            .map(|vec| vec.iter().map(String::as_str).collect());

        let ids_slice = ids_strs.as_deref();

        let tvl_result = self
            .db_gateway
            .get_component_tvls(
                &chain,
                request.protocol_system.clone(),
                ids_slice,
                Some(&pagination_params),
            )
            .await;

        match tvl_result {
            Ok(tvl) => Ok(dto::ComponentTvlRequestResponse::new(
                tvl.entity,
                PaginationResponse::new(
                    pagination_params.page,
                    pagination_params.page_size,
                    tvl.total.unwrap_or_default(),
                ),
            )),
            Err(err) => {
                error!(error = %err, "Error while getting component tvls.");
                Err(err.into())
            }
        }
    }

    #[instrument(skip(self, request))]
    async fn get_tokens(
        &self,
        request: &dto::TokensRequestBody,
    ) -> Result<dto::TokensRequestResponse, RpcError> {
        let response = self
            .token_cache
            .get(request.clone(), |r: dto::TokensRequestBody| async {
                self.get_tokens_inner(r)
                    .await
                    .map(|res| {
                        let last_page = res.pagination.total_pages() - 1;
                        (res, request.pagination.page < last_page)
                    })
            })
            .await?;

        trace!(n_tokens_received=?response.tokens.len(), "Retrieved tokens from DB");

        Ok(response)
    }

    async fn get_tokens_inner(
        &self,
        request: dto::TokensRequestBody,
    ) -> Result<dto::TokensRequestResponse, RpcError> {
        let address_refs: Option<Vec<&Address>> = request
            .token_addresses
            .as_ref()
            .map(|vec| vec.iter().collect());
        let addresses_slice = address_refs.as_deref();
        debug!(?addresses_slice, "Getting tokens.");

        let converted_params: PaginationParams = (&request.pagination).into();
        let quality = if let Some(min_quality) = request.min_quality {
            QualityRange::min_only(min_quality)
        } else {
            QualityRange::None()
        };

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
                quality,
                n_days_ago,
                Some(&converted_params),
            )
            .await
        {
            Ok(token_data) => Ok(dto::TokensRequestResponse::new(
                token_data
                    .entity
                    .into_iter()
                    .map(dto::ResponseToken::from)
                    .collect(),
                &PaginationResponse::new(
                    request.pagination.page,
                    request.pagination.page_size,
                    token_data.total.unwrap_or_default(),
                ),
            )),
            Err(err) => {
                error!(error = %err, "Error while getting tokens.");
                Err(err.into())
            }
        }
    }

    #[instrument(skip(self, request))]
    async fn get_protocol_components(
        &self,
        request: &dto::ProtocolComponentsRequestBody,
    ) -> Result<dto::ProtocolComponentRequestResponse, RpcError> {
        info!(?request, "Getting protocol components.");
        self.component_cache
            .get(request.clone(), |r| async {
                self.get_protocol_components_inner(r)
                    .await
                    .map(|res| {
                        // If component ids were specified, check if we have all requested
                        // components are in the response (should cache)
                        if let Some(component_ids) = &request.component_ids {
                            let all_found = component_ids.len() == res.pagination.total as usize;
                            if all_found {
                                return (res, true);
                            } else {
                                return (res, false);
                            }
                        }
                        // Otherwise check if request is for the last page (shouldn't cache)
                        let last_page = res.pagination.total_pages() - 1;
                        (res, request.pagination.page < last_page)
                    })
            })
            .await
    }

    async fn get_protocol_components_inner(
        &self,
        request: dto::ProtocolComponentsRequestBody,
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
            .as_ref()
            .map_or(Ok(Vec::new()), |pending_delta| {
                pending_delta.get_new_components(ids_slice, &system, request.tvl_gt)
            })?;

        debug!(n_components = buffered_components.len(), "RetrievedBufferedComponents");

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
                    .map(|c| {
                        let mut pc = dto::ProtocolComponent::from(c);
                        pc.tokens.sort_unstable();
                        pc
                    })
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
                Some(system),
                ids_slice,
                request.tvl_gt,
                Some(&pagination_params),
            )
            .await
        {
            Ok(component_data) => {
                let db_total = component_data.total.unwrap_or_default();
                let total = db_total + buffered_components.len() as i64;
                let mut components = component_data.entity;

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
                    .map(|c| {
                        let mut pc = dto::ProtocolComponent::from(c);
                        pc.tokens.sort_unstable();
                        pc
                    })
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

    #[instrument(skip(self, request))]
    async fn get_traced_entry_points(
        &self,
        request: &dto::TracedEntryPointRequestBody,
    ) -> Result<dto::TracedEntryPointRequestResponse, RpcError> {
        info!(?request, "Getting traced entry points.");

        self.traced_entry_point_cache
            .get(request.clone(), |r| async {
                self.get_traced_entry_points_inner(r)
                    .await
                    .map(|res| {
                        let last_page = res.pagination.total_pages() - 1;
                        (res, request.pagination.page < last_page)
                    })
            })
            .await
    }

    async fn get_traced_entry_points_inner(
        &self,
        request: dto::TracedEntryPointRequestBody,
    ) -> Result<dto::TracedEntryPointRequestResponse, RpcError> {
        let pagination_params: PaginationParams = (&request.pagination).into();

        // For consistency, we pre-apply pagination to the component ids to ensure it's
        // predetermined which components will appear on which page.
        let mut paginated_component_ids: Option<Vec<String>> = None;
        if let Some(component_ids) = request.component_ids {
            paginated_component_ids = Some(
                component_ids
                    .iter()
                    .skip(pagination_params.offset() as usize)
                    .take(pagination_params.page_size as usize)
                    .cloned()
                    .collect(),
            );
        }

        let filter = EntryPointFilter {
            protocol_system: request.protocol_system,
            component_ids: paginated_component_ids,
        };

        let entry_points_tracing_params_data = self
            .db_gateway
            .get_entry_points_tracing_params(filter, Some(&pagination_params))
            .await
            .map_err(|err| {
                error!(error = %err, "Error while getting entry points with tracing params.");
                err
            })?;

        trace!(
            entry_points_tracing_params = ?entry_points_tracing_params_data,
            "Retrieved entry points with tracing params from database."
        );

        // Flatten the ID lists, throwing away component ids, to avoid making duplicate db calls
        // when getting traced entry points.
        let entry_point_ids: HashSet<EntryPointId> = entry_points_tracing_params_data
            .entity
            .values()
            .flat_map(|entry_points_with_tracing_params| {
                entry_points_with_tracing_params
                    .iter()
                    .map(|entry_point| {
                        entry_point
                            .entry_point
                            .external_id
                            .clone()
                    })
            })
            .collect();

        let traced_entry_points = self
            .db_gateway
            .get_traced_entry_points(&entry_point_ids)
            .await
            .map_err(|err| {
                error!(error = %err, "Error while getting traced entry points.");
                err
            })?;

        trace!(
            traced_entry_points = ?traced_entry_points,
            "Retrieved traced entry points from database."
        );

        let mut traced_entry_points_by_component = HashMap::new();

        for (component_id, entry_points_set) in entry_points_tracing_params_data.entity {
            let mut pairs = Vec::with_capacity(entry_points_set.len());

            for entry_point_with_params in entry_points_set {
                let entry_point_id = entry_point_with_params
                    .entry_point
                    .external_id
                    .as_str();
                let tracing_param = &entry_point_with_params.params;

                if let Some(results_for_entry_point) = traced_entry_points.get(entry_point_id) {
                    if let Some(result_for_param) = results_for_entry_point.get(tracing_param) {
                        pairs.push((
                            entry_point_with_params.into(),
                            result_for_param.clone().into(),
                        ));
                    } else {
                        warn!(
                            ?entry_point_id,
                            ?tracing_param,
                            "No tracing results found for entry point with params."
                        );
                    }
                } else {
                    warn!(?entry_point_id, "No tracing results found for entry point.");
                }
            }

            traced_entry_points_by_component.insert(component_id, pairs);
        }

        Ok(dto::TracedEntryPointRequestResponse {
            traced_entry_points: traced_entry_points_by_component,
            pagination: PaginationResponse::new(
                request.pagination.page,
                request.pagination.page_size,
                entry_points_tracing_params_data
                    .total
                    .unwrap_or_default(),
            ),
        })
    }

    #[allow(dead_code)]
    async fn add_entry_points(
        &self,
        request: &dto::AddEntryPointRequestBody,
    ) -> Result<dto::AddEntryPointRequestResponse, RpcError> {
        let tracing_result = self.trace_entry_points(request).await?;
        let mut entry_points: HashMap<ComponentId, HashSet<EntryPoint>> = HashMap::new();
        let mut entry_points_params: HashMap<
            EntryPointId,
            HashSet<(TracingParams, Option<ComponentId>)>,
        > = HashMap::new();
        for (component_id, components_and_params) in &request.entry_points_with_tracing_data {
            for params in components_and_params {
                entry_points
                    .entry(component_id.into())
                    .or_default()
                    .insert(params.entry_point.clone().into());
                entry_points_params
                    .entry(params.entry_point.external_id.clone())
                    .or_default()
                    .insert((params.params.clone().into(), Some(component_id.into())));
            }
        }
        self.db_gateway
            .insert_entry_points(&entry_points)
            .await?;
        self.db_gateway
            .insert_entry_point_tracing_params(&entry_points_params)
            .await?;
        self.db_gateway
            .upsert_traced_entry_points(&tracing_result)
            .await?;

        let mut traced_entry_points: HashMap<
            String,
            Vec<(dto::EntryPointWithTracingParams, dto::TracingResult)>,
        > = HashMap::new();
        let mut entry_point_to_component: HashMap<EntryPoint, ComponentId> = HashMap::new();
        for (component_id, entry_point_set) in &entry_points {
            for entry_point in entry_point_set {
                entry_point_to_component.insert(entry_point.clone(), component_id.clone());
            }
        }
        for traced_entry_point in tracing_result {
            let entry_point_with_tracing_params: dto::EntryPointWithTracingParams =
                traced_entry_point
                    .entry_point_with_params
                    .clone()
                    .into();
            let tracing_result: dto::TracingResult = traced_entry_point
                .tracing_result
                .clone()
                .into();
            let component_id = entry_point_to_component
                .get(
                    &entry_point_with_tracing_params
                        .entry_point
                        .clone()
                        .into(),
                )
                .cloned()
                .unwrap_or_default();
            traced_entry_points.insert(
                component_id.to_string(),
                vec![(entry_point_with_tracing_params, tracing_result)],
            );
        }
        Ok(dto::AddEntryPointRequestResponse { traced_entry_points })
    }

    async fn trace_entry_points(
        &self,
        request: &dto::AddEntryPointRequestBody,
    ) -> Result<Vec<TracedEntryPoint>, RpcError> {
        let entry_points_with_params: Vec<_> = request
            .entry_points_with_tracing_data
            .iter()
            .flat_map(|(_, params)| params.iter().cloned().map(Into::into))
            .collect();
        let trace_results = self
            .tracer
            .trace(request.block_hash.clone(), entry_points_with_params)
            .await
            .into_iter()
            .collect::<Result<Vec<_>, _>>() //TODO: Ideally we would want to return each error separately and not just a single
            // error for the whole batch
            .map_err(|e| RpcError::Unknown(format!("Error while tracing entry points: {e:?}")))?;
        Ok(trace_results)
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
    security(
         ("apiKey" = [])
    ),
)]
#[instrument(skip_all, fields(user_identity, page, page_size, protocol_system))]
pub async fn contract_state<G: Gateway, T: EntryPointTracer>(
    req: HttpRequest,
    body: web::Json<dto::StateRequestBody>,
    handler: web::Data<RpcHandler<G, T>>,
) -> HttpResponse {
    // Note - filtering by protocol system is not supported on this endpoint. This is due to the
    // complexity of paginating this endpoint with the current design.

    let user_identity = req
        .headers()
        .get("user-identity")
        .map(|value| {
            value
                .to_str()
                .unwrap_or("unknown")
                .to_string()
        })
        .unwrap_or_else(|| "unknown".to_string());

    // Tracing and metrics
    tracing::Span::current().record("page", body.pagination.page);
    tracing::Span::current().record("page_size", body.pagination.page_size);
    tracing::Span::current().record("protocol_system", &body.protocol_system);
    tracing::Span::current().record("user_identity", &user_identity);
    counter!("rpc_requests", "endpoint" => "contract_state", "user_identity" => user_identity.clone()).increment(1);

    if body.pagination.page_size > 100 {
        counter!("rpc_requests_failed", "endpoint" => "contract_state", "status" => "400", "user_identity" => user_identity)
            .increment(1);
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
            let status = err.status_code().as_u16().to_string();
            counter!("rpc_requests_failed", "endpoint" => "contract_state", "status" => status, "user_identity" => user_identity)
                .increment(1);
            HttpResponse::from_error(err)
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
    security(
         ("apiKey" = [])
    ),
)]
#[instrument(skip_all, fields(user_identity, page, page_size))]
pub async fn tokens<G: Gateway, T: EntryPointTracer>(
    req: HttpRequest,
    body: web::Json<dto::TokensRequestBody>,
    handler: web::Data<RpcHandler<G, T>>,
) -> HttpResponse {
    let user_identity = req
        .headers()
        .get("user-identity")
        .map(|value| {
            value
                .to_str()
                .unwrap_or("unknown")
                .to_string()
        })
        .unwrap_or_else(|| "unknown".to_string());

    // Tracing and metrics
    tracing::Span::current().record("page", body.pagination.page);
    tracing::Span::current().record("page_size", body.pagination.page_size);
    tracing::Span::current().record("user_identity", &user_identity);
    counter!("rpc_requests", "endpoint" => "tokens", "user_identity" => user_identity.clone())
        .increment(1);

    if body.pagination.page_size > 3000 {
        counter!("rpc_requests_failed", "endpoint" => "tokens", "status" => "400", "user_identity" => user_identity).increment(1);
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
            let status = err.status_code().as_u16().to_string();
            counter!("rpc_requests_failed", "endpoint" => "tokens", "status" => status, "user_identity" => user_identity)
                .increment(1);
            HttpResponse::from_error(err)
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
    security(
         ("apiKey" = [])
    ),
)]
#[instrument(skip_all, fields(user_identity, page, page_size, protocol_system))]
pub async fn protocol_components<G: Gateway, T: EntryPointTracer>(
    req: HttpRequest,
    body: web::Json<dto::ProtocolComponentsRequestBody>,
    handler: web::Data<RpcHandler<G, T>>,
) -> HttpResponse {
    let user_identity = req
        .headers()
        .get("user-identity")
        .map(|value| {
            value
                .to_str()
                .unwrap_or("unknown")
                .to_string()
        })
        .unwrap_or_else(|| "unknown".to_string());

    // Tracing and metrics
    tracing::Span::current().record("page", body.pagination.page);
    tracing::Span::current().record("page_size", body.pagination.page_size);
    tracing::Span::current().record("protocol_system", &body.protocol_system);
    tracing::Span::current().record("user_identity", &user_identity);
    counter!("rpc_requests", "endpoint" => "protocol_components", "user_identity" => user_identity.clone()).increment(1);

    if body.pagination.page_size > 500 {
        counter!("rpc_requests_failed", "endpoint" => "protocol_components", "status" => "400", "user_identity" => user_identity)
            .increment(1);
        return HttpResponse::BadRequest().body("Page size must be less than or equal to 500.");
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
            let status = err.status_code().as_u16().to_string();
            counter!("rpc_requests_failed", "endpoint" => "protocol_components", "status" => status, "user_identity" => user_identity).increment(1);
            HttpResponse::from_error(err)
        }
    }
}

/// Retrieve protocol states
///
/// This endpoint retrieves the state of protocols within a specific execution environment.
#[utoipa::path(
    post,
    path = "/v1/protocol_state",
    responses(
        (status = 200, description = "OK", body = ProtocolStateRequestResponse),
    ),
    request_body = ProtocolStateRequestBody,
    security(
         ("apiKey" = [])
    ),
)]
#[instrument(skip_all, fields(user_identity, page, page_size, protocol_system))]
pub async fn protocol_state<G: Gateway, T: EntryPointTracer>(
    req: HttpRequest,
    body: web::Json<dto::ProtocolStateRequestBody>,
    handler: web::Data<RpcHandler<G, T>>,
) -> HttpResponse {
    let user_identity = req
        .headers()
        .get("user-identity")
        .map(|value| {
            value
                .to_str()
                .unwrap_or("unknown")
                .to_string()
        })
        .unwrap_or_else(|| "unknown".to_string());

    // Tracing and metrics
    tracing::Span::current().record("page", body.pagination.page);
    tracing::Span::current().record("page_size", body.pagination.page_size);
    tracing::Span::current().record("protocol_system", &body.protocol_system);
    tracing::Span::current().record("user_identity", &user_identity);
    counter!("rpc_requests", "endpoint" => "protocol_state", "user_identity" => user_identity.clone()).increment(1);

    if body.pagination.page_size > 100 {
        counter!("rpc_requests_failed", "endpoint" => "protocol_state", "status" => "400", "user_identity" => user_identity)
            .increment(1);
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
            let status = err.status_code().as_u16().to_string();
            counter!("rpc_requests_failed", "endpoint" => "protocol_state", "status" => status, "user_identity" => user_identity)
                .increment(1);
            HttpResponse::from_error(err)
        }
    }
}

/// Retrieve protocol systems
///
/// This endpoint retrieves the protocol systems available in the indexer.
#[utoipa::path(
    post,
    path = "/v1/protocol_systems",
    responses(
        (status = 200, description = "OK", body = ProtocolSystemsRequestResponse),
    ),
    request_body = ProtocolSystemsRequestBody,
    security(
        ("apiKey" = [])
    ),
)]
#[instrument(skip_all, fields(user_identity, page, page_size))]
pub async fn protocol_systems<G: Gateway, T: EntryPointTracer>(
    req: HttpRequest,
    body: web::Json<dto::ProtocolSystemsRequestBody>,
    handler: web::Data<RpcHandler<G, T>>,
) -> HttpResponse {
    let user_identity = req
        .headers()
        .get("user-identity")
        .map(|value| {
            value
                .to_str()
                .unwrap_or("unknown")
                .to_string()
        })
        .unwrap_or_else(|| "unknown".to_string());

    // Tracing and metrics
    tracing::Span::current().record("page", body.pagination.page);
    tracing::Span::current().record("page_size", body.pagination.page_size);
    tracing::Span::current().record("user_identity", &user_identity);
    counter!("rpc_requests", "endpoint" => "protocol_systems", "user_identity" => user_identity.clone()).increment(1);

    if body.pagination.page_size > 100 {
        counter!("rpc_requests_failed", "endpoint" => "protocol_systems", "status" => "400", "user_identity" => user_identity)
            .increment(1);
        return HttpResponse::BadRequest().body("Page size must be less than or equal to 100.");
    }

    // Call the handler to get protocol systems
    let response = handler
        .into_inner()
        .get_protocol_systems(&body)
        .await;

    match response {
        Ok(systems) => HttpResponse::Ok().json(systems),
        Err(err) => {
            error!(error = %err, ?body, "Error while getting protocol systems.");
            let status = err.status_code().as_u16().to_string();
            counter!("rpc_requests_failed", "endpoint" => "protocol_systems", "status" => status, "user_identity" => user_identity)
                .increment(1);
            HttpResponse::from_error(err)
        }
    }
}

/// Retrieve protocol component tvl
///
/// This endpoint retrieves component tvl
#[utoipa::path(
    post,
    path = "/v1/component_tvl",
    responses(
        (status = 200, description = "OK", body = ProtocolComponentTvlRequestResponse),
    ),
    request_body = ProtocolComponentTvlRequestBody,
    security(
         ("apiKey" = [])
    ),
)]
#[instrument(skip_all, fields(user_identity, page, page_size))]
pub async fn component_tvl<G: Gateway, T: EntryPointTracer>(
    req: HttpRequest,
    body: web::Json<dto::ComponentTvlRequestBody>,
    handler: web::Data<RpcHandler<G, T>>,
) -> HttpResponse {
    let user_identity = req
        .headers()
        .get("user-identity")
        .map(|value| {
            value
                .to_str()
                .unwrap_or("unknown")
                .to_string()
        })
        .unwrap_or_else(|| "unknown".to_string());

    // Tracing and metrics
    tracing::Span::current().record("page", body.pagination.page);
    tracing::Span::current().record("page_size", body.pagination.page_size);
    tracing::Span::current().record("user_identity", &user_identity);
    counter!("rpc_requests", "endpoint" => "component_tvl", "user_identity" => user_identity.clone()).increment(1);

    // Call the handler to get component tvl
    let response = handler
        .into_inner()
        .get_component_tvls(&body)
        .await;

    match response {
        Ok(systems) => HttpResponse::Ok().json(systems),
        Err(err) => {
            error!(error = %err, ?body, "Error while getting component tvl.");
            let status = err.status_code().as_u16().to_string();
            counter!("rpc_requests_failed", "endpoint" => "component_tvl", "status" => status, "user_identity" => user_identity)
                .increment(1);
            HttpResponse::from_error(err)
        }
    }
}

/// Retrieve traced entry points
///
/// This endpoint retrieves the traced entry points available in the indexer
#[utoipa::path(
    post,
    path = "/v1/traced_entry_points",
    responses(
    (status = 200, description = "OK", body = TracedEntryPointRequestResponse),
    ),
    request_body = TracedEntryPointRequestBody,
    security(
    ("apiKey" = [])
    ),
)]
#[instrument(skip_all, fields(user_identity, page, page_size))]
pub async fn traced_entry_points<G: Gateway, T: EntryPointTracer>(
    req: HttpRequest,
    body: web::Json<dto::TracedEntryPointRequestBody>,
    handler: web::Data<RpcHandler<G, T>>,
) -> HttpResponse {
    let user_identity = req
        .headers()
        .get("user-identity")
        .map(|value| {
            value
                .to_str()
                .unwrap_or("unknown")
                .to_string()
        })
        .unwrap_or_else(|| "unknown".to_string());

    // Tracing and metrics
    tracing::Span::current().record("page", body.pagination.page);
    tracing::Span::current().record("page_size", body.pagination.page_size);
    tracing::Span::current().record("user_identity", &user_identity);
    counter!("rpc_requests", "endpoint" => "traced_entry_points", "user_identity" => user_identity.clone()).increment(1);

    if body.pagination.page_size > 100 {
        counter!("rpc_requests_failed", "endpoint" => "traced_entry_points", "status" => "400", "user_identity" => user_identity)
            .increment(1);
        return HttpResponse::BadRequest().body("Page size must be less than or equal to 100.");
    }

    // Call the handler to get traced entry points
    let response = handler
        .into_inner()
        .get_traced_entry_points(&body)
        .await;

    match response {
        Ok(entry_points) => HttpResponse::Ok().json(entry_points),
        Err(err) => {
            error!(error = %err, ?body, "Error while getting traced entry points.");
            let status = err.status_code().as_u16().to_string();
            counter!("rpc_requests_failed", "endpoint" => "traced_entry_points", "status" => status, "user_identity" => user_identity)
                .increment(1);
            HttpResponse::from_error(err)
        }
    }
}

/// Add Entry Point
///
/// Trace the given entry points and add the entry point, tracing params and results to DB.
#[utoipa::path(
    post,
    path = "/v1/add_entry_points",
    responses(
    (status = 200, description = "OK", body = AddEntryPointRequestResponse),
    ),
    request_body = AddEntryPointRequestBody,
    security(
    ("apiKey" = [])
    ),
)]
#[instrument(skip_all, fields(user_identity))]
pub async fn add_entry_points<G: Gateway, T: EntryPointTracer>(
    req: HttpRequest,
    body: web::Json<dto::AddEntryPointRequestBody>,
    handler: web::Data<RpcHandler<G, T>>,
) -> HttpResponse {
    let user_identity = req
        .headers()
        .get("user-identity")
        .map(|value| {
            value
                .to_str()
                .unwrap_or("unknown")
                .to_string()
        })
        .unwrap_or_else(|| "unknown".to_string());

    // Tracing and metrics
    tracing::Span::current().record("user_identity", &user_identity);
    counter!("rpc_requests", "endpoint" => "add_entry_points", "user_identity" => user_identity.clone()).increment(1);

    // Call the handler to add entry points
    let response = handler
        .into_inner()
        .add_entry_points(&body)
        .await;

    match response {
        Ok(add_entry_points_result) => HttpResponse::Ok().json(add_entry_points_result),
        Err(err) => {
            error!(error = %err, ?body, "Error while adding entry points.");
            let status = err.status_code().as_u16().to_string();
            counter!("rpc_requests_failed", "endpoint" => "add_entry_points", "status" => status, "user_identity" => user_identity)
                .increment(1);
            HttpResponse::from_error(err)
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
    security(
         ("apiKey" = [])
    )
)]
pub async fn health() -> HttpResponse {
    counter!("rpc_requests", "endpoint" => "health").increment(1);
    HttpResponse::Ok().json(dto::Health::Ready)
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, env, str::FromStr};

    use actix_web::test;
    use chrono::NaiveDateTime;
    use mockall::{mock, predicate::eq};
    use tycho_common::{
        dto, keccak256,
        models::{
            blockchain,
            blockchain::{
                EntryPoint, EntryPointWithTracingParams, RPCTracerParams, TracingParams,
                TracingResult,
            },
            contract::Account,
            protocol::{ProtocolComponent, ProtocolComponentState},
            token::Token,
            ChangeType,
        },
        storage::WithTotal,
        traits::MockEntryPointTracer,
    };
    use tycho_ethereum::entrypoint_tracer::tracer::EVMEntrypointService;

    use super::*;
    use crate::testing::{evm_contract_slots, MockGateway};

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
                protocol_system: &'a str,
            ) -> Result<(), PendingDeltasError>;

            fn update_vm_states<'a>(
                &self,
                addresses: Option<&'a [Bytes]>,
                db_states: &mut Vec<Account>,
                version: Option<BlockNumberOrTimestamp>,
                protocol_system: &'a str,
            ) -> Result<(), PendingDeltasError>;

            fn get_new_components<'a>(
                &self,
                ids: Option<&'a [&'a str]>,
                protocol_system: &'a str,
                min_tvl: Option<f64>,
            ) -> Result<Vec<ProtocolComponent>, PendingDeltasError>;

            fn get_block_finality<'a>(
                &self,
                version: BlockNumberOrTimestamp,
                protocol_system: &'a str,
            ) -> Result<Option<FinalityStatus>, PendingDeltasError>;

            fn search_block<'a>(
                &self,
                f: &dyn Fn(&BlockAggregatedChanges) -> bool,
                protocol_system: &'a str,
            ) -> Result<Option<BlockAggregatedChanges>,PendingDeltasError>;
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
        "protocol_system": "uniswap_v2",
        "contractIds": [
            "0xb4eccE46b8D4e4abFd03C9B806276A6735C9c092"
        ]
    }
    "#;

        let result: dto::StateRequestBody = serde_json::from_str(json_str).unwrap();

        let contract0 = "b4eccE46b8D4e4abFd03C9B806276A6735C9c092".into();

        let expected = dto::StateRequestBody {
            contract_ids: Some(vec![contract0]),
            protocol_system: "uniswap_v2".to_string(),
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
    async fn test_get_contract_state() {
        let expected = Account::new(
            Chain::Ethereum,
            "0x6b175474e89094c44da98b954eedeac495271d0f"
                .parse()
                .unwrap(),
            "account0".to_owned(),
            evm_contract_slots([(6, 30), (5, 25), (1, 3), (2, 1), (0, 2)]),
            Bytes::from(101u8).lpad(32, 0),
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
        let mock_response = Ok(WithTotal { entity: vec![expected.clone()], total: Some(10) });
        gw.expect_get_contracts()
            .return_once(|_, _, _, _, _| Box::pin(async move { mock_response }));

        let mut mock_buffer = MockPendingDeltas::new();
        let buf_expected = Account::new(
            Chain::Ethereum,
            "0x388C818CA8B9251b393131C08a736A67ccB19297"
                .parse()
                .unwrap(),
            "account1".to_owned(),
            evm_contract_slots([(6, 30), (5, 25), (1, 3), (2, 1), (0, 2)]),
            Bytes::from(101u8).lpad(32, 0),
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
        mock_buffer
            .expect_update_vm_states()
            .return_once({
                let buf_expected_clone = buf_expected.clone();
                move |_, db_states: &mut Vec<Account>, _, _| {
                    db_states.push(buf_expected_clone);
                    Ok(())
                }
            });
        mock_buffer
            .expect_get_block_finality()
            .return_once(|_, _| Ok(Some(FinalityStatus::Unfinalized)));

        let req_handler =
            RpcHandler::new(gw, Some(Arc::new(mock_buffer)), MockEntryPointTracer::new());

        let request = dto::StateRequestBody {
            contract_ids: Some(vec![
                Bytes::from_str("6B175474E89094C44Da98b954EedeAC495271d0F").unwrap(),
                Bytes::from_str("388C818CA8B9251b393131C08a736A67ccB19297").unwrap(),
            ]),
            protocol_system: "uniswap_v2".to_string(),
            version: dto::VersionParam { timestamp: Some(Utc::now().naive_utc()), block: None },
            chain: dto::Chain::Ethereum,
            pagination: dto::PaginationParams::default(),
        };
        let state = req_handler
            .get_contract_state_inner(request)
            .await
            .unwrap();

        assert_eq!(state.accounts.len(), 2);
        assert_eq!(state.accounts[0], expected.into());
        assert_eq!(state.accounts[1], buf_expected.into());
        assert_eq!(state.pagination.total, 2);
    }

    /// Helper used to make tracing results comparisons deterministic.
    #[allow(clippy::type_complexity)]
    fn normalize_tracing_result(
        result: &dto::TracingResult,
    ) -> (Vec<(Bytes, dto::AddressStorageLocation)>, Vec<(Bytes, Vec<Bytes>)>) {
        let mut retriggers: Vec<_> = result
            .retriggers
            .iter()
            .cloned()
            .collect();
        retriggers.sort();
        let mut accessed_slots: Vec<_> = result
            .accessed_slots
            .iter()
            .map(|(k, v)| (k.clone(), v.iter().cloned().collect()))
            .collect();
        accessed_slots.sort_by(|(a, _), (b, _)| a.cmp(b));
        (retriggers, accessed_slots)
    }

    fn sort_tracing_results(
        params_to_result: &mut [(dto::EntryPointWithTracingParams, dto::TracingResult)],
    ) {
        params_to_result.sort_by(|(a, _), (b, _)| {
            a.entry_point
                .external_id
                .cmp(&b.entry_point.external_id)
                .then_with(|| match (a.params.clone(), b.params.clone()) {
                    (dto::TracingParams::RPCTracer(a), dto::TracingParams::RPCTracer(b)) => {
                        a.caller.cmp(&b.caller)
                    }
                })
        });
    }

    #[allow(clippy::type_complexity)]
    fn get_add_entry_point_test_data(
        block_hash: Bytes,
        component_id: ComponentId,
        entry_point_ids: &[String],
    ) -> (
        Vec<dto::EntryPointWithTracingParams>,
        Vec<TracedEntryPoint>,
        HashMap<ComponentId, HashSet<EntryPoint>>,
        HashMap<EntryPointId, HashSet<(TracingParams, Option<ComponentId>)>>,
        Vec<(dto::EntryPointWithTracingParams, dto::TracingResult)>,
    ) {
        let entry_points = [
            dto::EntryPoint {
                external_id: entry_point_ids[0].clone(),
                target: Bytes::from_str("0xEdf63cce4bA70cbE74064b7687882E71ebB0e988").unwrap(),
                signature: "getRate()".to_string(),
            },
            dto::EntryPoint {
                external_id: entry_point_ids[1].clone(),
                target: Bytes::from_str("0x8f4E8439b970363648421C692dd897Fb9c0Bd1D9").unwrap(),
                signature: "getRate()".to_string(),
            },
        ];
        let tracing_params = [
            dto::TracingParams::RPCTracer(dto::RPCTracerParams {
                caller: None,
                calldata: Bytes::from(&keccak256("getRate()").to_vec()[0..4]),
                state_overrides: None,
                prune_addresses: None,
            }),
            dto::TracingParams::RPCTracer(dto::RPCTracerParams {
                caller: None,
                calldata: Bytes::from(&keccak256("getRate()").to_vec()[0..4]),
                state_overrides: None,
                prune_addresses: None,
            }),
        ];
        let entry_points_with_tracing_params = vec![
            dto::EntryPointWithTracingParams {
                entry_point: entry_points[0].clone(),
                params: tracing_params[0].clone(),
            },
            dto::EntryPointWithTracingParams {
                entry_point: entry_points[1].clone(),
                params: tracing_params[1].clone(),
            },
        ];
        let tracing_results = vec![
            TracedEntryPoint {
                entry_point_with_params: entry_points_with_tracing_params[0].clone().into(),
                detection_block_hash: block_hash.clone(),
                tracing_result: TracingResult::new(
                    HashSet::from([
                    (
                        Bytes::from_str("0x7bc3485026ac48b6cf9baf0a377477fff5703af8").unwrap(),
                        Bytes::from_str("0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc").unwrap().into(),
                    ),
                    (
                        Bytes::from_str("0x87870bca3f3fd6335c3f4ce8392d69350b4fa4e2").unwrap(),
                        Bytes::from_str("0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc").unwrap().into(),
                    ),
                ]),
                HashMap::from([
                        (Bytes::from_str("0x87870bca3f3fd6335c3f4ce8392d69350b4fa4e2").unwrap(), HashSet::from([
                            Bytes::from_str("0xca6decca4edae0c692b2b0c41376a54b812edb060282d36e07a7060ccb58244d").unwrap(),
                            Bytes::from_str("0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc").unwrap(),
                            Bytes::from_str("0xca6decca4edae0c692b2b0c41376a54b812edb060282d36e07a7060ccb58244f").unwrap(),
                        ])),
                        (Bytes::from_str("0x487c2c53c0866f0a73ae317bd1a28f63adcd9ad1").unwrap(), HashSet::new()),
                        (Bytes::from_str("0x9aeb8aaa1ca38634aa8c0c8933e7fb4d61091327").unwrap(), HashSet::new()),
                        (Bytes::from_str("0xedf63cce4ba70cbe74064b7687882e71ebb0e988").unwrap(), HashSet::new()),
                        (Bytes::from_str("0x7bc3485026ac48b6cf9baf0a377477fff5703af8").unwrap(), HashSet::from([
                            Bytes::from_str("0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc").unwrap(),
                            Bytes::from_str("0x0773e532dfede91f04b12a73d3d2acd361424f41f76b4fb79f090161e36b4e00").unwrap(),
                        ])),
                    ]),
                ),
            },
            TracedEntryPoint {
                entry_point_with_params: entry_points_with_tracing_params[1].clone().into(),
                detection_block_hash: block_hash.clone(),
                tracing_result: TracingResult::new(
                    HashSet::from([
                        (
                        Bytes::from_str("0xd4fa2d31b7968e448877f69a96de69f5de8cd23e").unwrap(),
                        Bytes::from_str("0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc").unwrap().into(),
                    ),
                    (
                        Bytes::from_str("0x87870bca3f3fd6335c3f4ce8392d69350b4fa4e2").unwrap(),
                        Bytes::from_str("0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc").unwrap().into(),
                    ),
                    ]),
                    HashMap::from([
                        (Bytes::from_str("0x87870bca3f3fd6335c3f4ce8392d69350b4fa4e2").unwrap(), HashSet::from([
                            Bytes::from_str("0xed960c71bd5fa1333658850f076b35ec5565086b606556c3dd36a916b43ddf23").unwrap(),
                            Bytes::from_str("0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc").unwrap(),
                            Bytes::from_str("0xed960c71bd5fa1333658850f076b35ec5565086b606556c3dd36a916b43ddf21").unwrap(),
                        ])),
                        (Bytes::from_str("0x487c2c53c0866f0a73ae317bd1a28f63adcd9ad1").unwrap(), HashSet::new()),
                        (Bytes::from_str("0x9aeb8aaa1ca38634aa8c0c8933e7fb4d61091327").unwrap(), HashSet::new()),
                        (Bytes::from_str("0x8f4e8439b970363648421c692dd897fb9c0bd1d9").unwrap(), HashSet::new()),
                        (Bytes::from_str("0xd4fa2d31b7968e448877f69a96de69f5de8cd23e").unwrap(), HashSet::from([
                            Bytes::from_str("0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc").unwrap(),
                            Bytes::from_str("0x0773e532dfede91f04b12a73d3d2acd361424f41f76b4fb79f090161e36b4e00").unwrap(),
                        ])),
                    ]),
                ),
            }];

        let expected_inserted_entry_points: HashMap<ComponentId, HashSet<EntryPoint>> =
            HashMap::from([(
                component_id.clone(),
                HashSet::from([entry_points[0].clone().into(), entry_points[1].clone().into()]),
            )]);

        let expected_inserted_tracing_params: HashMap<
            EntryPointId,
            HashSet<(TracingParams, Option<ComponentId>)>,
        > = HashMap::from([
            (
                entry_point_ids[0].clone(),
                HashSet::from([(tracing_params[0].clone().into(), Some(component_id.clone()))]),
            ),
            (
                entry_point_ids[1].clone(),
                HashSet::from([(tracing_params[1].clone().into(), Some(component_id.clone()))]),
            ),
        ]);

        let mut expected_traces_for_component: Vec<(
            dto::EntryPointWithTracingParams,
            dto::TracingResult,
        )> = tracing_results
            .iter()
            .map(|tep| {
                (
                    tep.entry_point_with_params
                        .clone()
                        .into(),
                    tep.tracing_result.clone().into(),
                )
            })
            .collect();

        sort_tracing_results(&mut expected_traces_for_component);
        (
            entry_points_with_tracing_params,
            tracing_results,
            expected_inserted_entry_points,
            expected_inserted_tracing_params,
            expected_traces_for_component,
        )
    }

    fn mock_gateway_add_entry_points(
        expected_inserted_entry_points: HashMap<ComponentId, HashSet<EntryPoint>>,
        expected_inserted_tracing_params: HashMap<
            EntryPointId,
            HashSet<(TracingParams, Option<ComponentId>)>,
        >,
        expected_upserted_tracing_results: Vec<TracedEntryPoint>,
    ) -> MockGateway {
        let mut gw = MockGateway::new();
        gw.expect_insert_entry_points()
            .return_once(move |inserted_entry_points| {
                assert_eq!(*inserted_entry_points, expected_inserted_entry_points);
                Box::pin(async move { Ok(()) })
            });
        gw.expect_insert_entry_point_tracing_params()
            .return_once(move |inserted_tracing_params| {
                assert_eq!(*inserted_tracing_params, expected_inserted_tracing_params);
                Box::pin(async move { Ok(()) })
            });
        gw.expect_upsert_traced_entry_points()
            .return_once(move |upserted_tracing_results| {
                assert_eq!(upserted_tracing_results, expected_upserted_tracing_results);
                Box::pin(async move { Ok(()) })
            });
        gw
    }

    #[test]
    async fn test_add_entry_points() {
        // Mocks tracer and DB.

        let mut mock_entrypoint_tracer = MockEntryPointTracer::new();

        let block_hash =
            Bytes::from_str("0x354c90a0a98912aff15b044bdff6ce3d4ace63a6fc5ac006ce53c8737d425ab2")
                .unwrap();

        // Balancer v3 stable pool
        let component_id = "0x0000000000000000000000000000000000000001".to_string();

        let entry_point_ids = [
            "0xEdf63cce4bA70cbE74064b7687882E71ebB0e988:getRate()".to_string(),
            "0x8f4E8439b970363648421C692dd897Fb9c0Bd1D9:getRate()".to_string(),
        ];

        let (
            entry_points_with_tracing_params,
            tracing_results,
            expected_inserted_entry_points,
            expected_inserted_tracing_params,
            expected_traces_for_component,
        ) = get_add_entry_point_test_data(
            block_hash.clone(),
            component_id.clone(),
            &entry_point_ids,
        );
        let entry_points_by_component =
            vec![(component_id.clone(), entry_points_with_tracing_params.clone())];

        let req_body = dto::AddEntryPointRequestBody {
            chain: Chain::Ethereum.into(),
            block_hash: block_hash.clone(),
            entry_points_with_tracing_data: entry_points_by_component.clone(),
        };

        let expected_upserted_tracing_results = tracing_results.clone();
        mock_entrypoint_tracer
            .expect_trace()
            .with(
                eq(block_hash.clone()),
                eq(entry_points_with_tracing_params
                    .iter()
                    .cloned()
                    .map(EntryPointWithTracingParams::from)
                    .collect::<Vec<_>>()),
            )
            .return_once(move |_, _| {
                tracing_results
                    .clone()
                    .into_iter()
                    .map(Ok)
                    .collect()
            });

        let gw = mock_gateway_add_entry_points(
            expected_inserted_entry_points,
            expected_inserted_tracing_params,
            expected_upserted_tracing_results,
        );

        let req_handler = RpcHandler::new(gw, None, mock_entrypoint_tracer);
        let response = req_handler
            .add_entry_points(&req_body)
            .await
            .unwrap();

        // Sort to make test deterministic
        let mut traced_entry_points_response = response.traced_entry_points.clone();
        let traced_entry_points_for_component = traced_entry_points_response
            .get_mut(&component_id)
            .unwrap();
        sort_tracing_results(traced_entry_points_for_component);

        for ((actual_entry, actual_result), (expected_entry, expected_result)) in
            traced_entry_points_for_component
                .iter()
                .zip(expected_traces_for_component.iter())
        {
            assert_eq!(actual_entry, expected_entry);
            assert_eq!(
                normalize_tracing_result(actual_result),
                normalize_tracing_result(expected_result)
            );
        }
    }

    #[test]
    #[ignore = "requires a RPC connection"]
    async fn test_add_entry_points_integration() {
        // Tests the RPC integration with the tracer. The DB writing is still mocked, however.
        let url = env::var("RPC_URL").expect("RPC_URL is not set");
        let tracer = EVMEntrypointService::try_from_url(&url).unwrap();

        let block_hash =
            Bytes::from_str("0x354c90a0a98912aff15b044bdff6ce3d4ace63a6fc5ac006ce53c8737d425ab2")
                .unwrap();

        // Balancer v3 stable pool
        let component_id = "0x0000000000000000000000000000000000000001".to_string();

        let entry_point_ids = [
            "0xEdf63cce4bA70cbE74064b7687882E71ebB0e988:getRate()".to_string(),
            "0x8f4E8439b970363648421C692dd897Fb9c0Bd1D9:getRate()".to_string(),
        ];
        let (
            entry_points_with_tracing_params,
            expected_upserted_tracing_results,
            expected_inserted_entry_points,
            expected_inserted_tracing_params,
            expected_traces_for_component,
        ) = get_add_entry_point_test_data(
            block_hash.clone(),
            component_id.clone(),
            &entry_point_ids,
        );
        let entry_points_by_component =
            vec![(component_id.clone(), entry_points_with_tracing_params.clone())];

        let req_body = dto::AddEntryPointRequestBody {
            chain: Chain::Ethereum.into(),
            block_hash: Bytes::from_str(
                "0x354c90a0a98912aff15b044bdff6ce3d4ace63a6fc5ac006ce53c8737d425ab2",
            )
            .unwrap(),
            entry_points_with_tracing_data: entry_points_by_component.clone(),
        };

        let gw = mock_gateway_add_entry_points(
            expected_inserted_entry_points,
            expected_inserted_tracing_params,
            expected_upserted_tracing_results,
        );

        let req_handler = RpcHandler::new(gw, None, tracer);
        let response = req_handler
            .add_entry_points(&req_body)
            .await
            .unwrap();

        // Sort to make test deterministic
        let mut traced_entry_points_response = response.traced_entry_points.clone();
        let traced_entry_points_for_component = traced_entry_points_response
            .get_mut(&component_id)
            .unwrap();
        sort_tracing_results(traced_entry_points_for_component);

        for ((actual_entry, actual_result), (expected_entry, expected_result)) in
            traced_entry_points_for_component
                .iter()
                .zip(expected_traces_for_component.iter())
        {
            assert_eq!(actual_entry, expected_entry);
            assert_eq!(
                normalize_tracing_result(actual_result),
                normalize_tracing_result(expected_result)
            );
        }
    }

    #[test]
    async fn test_get_traced_entry_points() {
        // We attempt to fetch results for two components.
        // Only one component will be returned, due to a pagination size of 1.
        // This component has one entry point and two tracing results.
        // This test ensures that the cache is hit on the second request.

        // Component to be included in the response
        let component_id_a = "component_a".to_string();

        // Component to be excluded due to pagination
        let component_id_c = "component_b".to_string();

        // Entry points to be included in the response
        let entry_point_id_a = "entrypoint_a".to_string();
        let entry_point_a = EntryPoint {
            external_id: entry_point_id_a.clone(),
            target: Bytes::from("0x0000000000000000000000000000000000000001"),
            signature: "sig()".to_string(),
        };
        let tracing_params_a = TracingParams::RPCTracer(RPCTracerParams {
            caller: Some(Bytes::from("0x000000000000000000000000000000000000000a")),
            calldata: Bytes::from("0x000000000000000000000000000000000000000b"),
            state_overrides: None,
            prune_addresses: None,
        });
        let tracing_params_b = TracingParams::RPCTracer(RPCTracerParams {
            caller: Some(Bytes::from("0x000000000000000000000000000000000000000b")),
            calldata: Bytes::from("0x000000000000000000000000000000000000000c"),
            state_overrides: None,
            prune_addresses: None,
        });
        let entry_point_with_params_a = EntryPointWithTracingParams {
            entry_point: entry_point_a.clone(),
            params: tracing_params_a.clone(),
        };
        let entry_point_with_params_b = EntryPointWithTracingParams {
            entry_point: entry_point_a.clone(),
            params: tracing_params_b.clone(),
        };
        let trace_result_a = TracingResult {
            retriggers: HashSet::from([(
                Bytes::from("0x00000000000000000000000000000000000000aa"),
                Bytes::from("0x0000000000000000000000000000000000000aaa").into(),
            )]),
            accessed_slots: HashMap::from([(
                Bytes::from("0x0000000000000000000000000000000000aaaa"),
                HashSet::from([Bytes::from("0x0000000000000000000000000000000000aaaa")]),
            )]),
        };
        let trace_result_b = TracingResult {
            retriggers: HashSet::from([(
                Bytes::from("0x00000000000000000000000000000000000000bb"),
                Bytes::from("0x0000000000000000000000000000000000000bbb").into(),
            )]),
            accessed_slots: HashMap::from([(
                Bytes::from("0x0000000000000000000000000000000000bbbb"),
                HashSet::from([Bytes::from("0x0000000000000000000000000000000000bbbb")]),
            )]),
        };

        // Gateway responses
        // At this point, the component ids have already been paginated, so they are not
        // queried from the gateway unless they are on page 1
        let params_to_trace_result = HashMap::from([
            (tracing_params_a.clone(), trace_result_a.clone()),
            (tracing_params_b.clone(), trace_result_b.clone()),
        ]);
        let expected_entry_points_with_params = HashMap::from([(
            component_id_a.clone(),
            HashSet::from([entry_point_with_params_a.clone(), entry_point_with_params_b.clone()]),
        )]);

        let expected_trace_results =
            HashMap::from([(entry_point_id_a.clone(), params_to_trace_result)]);

        let mut gw = MockGateway::new();

        let mock_get_entry_points_response =
            Ok(WithTotal { entity: expected_entry_points_with_params.clone(), total: Some(2) });
        gw.expect_get_entry_points_tracing_params()
            .return_once(|_, _| Box::pin(async move { mock_get_entry_points_response }));

        let mock_traced_entry_points_response = Ok(expected_trace_results.clone());
        gw.expect_get_traced_entry_points()
            .return_once(|_| Box::pin(async move { mock_traced_entry_points_response }));

        let req_handler = RpcHandler::new(gw, None, MockEntryPointTracer::new());

        // Request for two protocol components
        let request = dto::TracedEntryPointRequestBody {
            chain: dto::Chain::Ethereum,
            protocol_system: "uniswap_v2".to_string(),
            component_ids: Some(vec![component_id_a.clone(), component_id_c.clone()]),
            pagination: dto::PaginationParams { page: 0, page_size: 1 },
        };

        // First request
        let mut traced_entry_points = req_handler
            .get_traced_entry_points(&request)
            .await
            .unwrap();

        let expected_rpc_result = HashMap::from([(
            component_id_a.clone(),
            vec![
                (
                    dto::EntryPointWithTracingParams::from(entry_point_with_params_a.clone()),
                    dto::TracingResult::from(trace_result_a.clone()),
                ),
                (
                    dto::EntryPointWithTracingParams::from(entry_point_with_params_b.clone()),
                    dto::TracingResult::from(trace_result_b.clone()),
                ),
            ],
        )]);

        // One protocol component returned
        assert_eq!(
            traced_entry_points
                .traced_entry_points
                .len(),
            1
        );
        // Sort to make test deterministic
        let traced_entry_points_for_component: &mut Vec<(
            dto::EntryPointWithTracingParams,
            dto::TracingResult,
        )> = traced_entry_points
            .traced_entry_points
            .get_mut(&component_id_a)
            .unwrap();

        traced_entry_points_for_component.sort_by(|(a, _), (b, _)| {
            a.entry_point
                .external_id
                .cmp(&b.entry_point.external_id)
                .then_with(|| match (a.params.clone(), b.params.clone()) {
                    (dto::TracingParams::RPCTracer(a), dto::TracingParams::RPCTracer(b)) => {
                        a.caller.cmp(&b.caller)
                    }
                })
        });

        assert_eq!(
            traced_entry_points_for_component,
            expected_rpc_result
                .get(&component_id_a)
                .unwrap(),
        );
        assert_eq!(traced_entry_points.pagination.total, 2);
        assert_eq!(
            traced_entry_points
                .pagination
                .total_pages(),
            2
        );

        // Second request (should hit cache and not increase gateway access count)
        let mut traced_entry_points_second_request = req_handler
            .get_traced_entry_points(&request)
            .await
            .unwrap();

        // One protocol component returned
        assert_eq!(
            traced_entry_points_second_request
                .traced_entry_points
                .len(),
            1
        );
        // Sort to make test deterministic
        let traced_entry_points_for_component_second_request: &mut Vec<(
            dto::EntryPointWithTracingParams,
            dto::TracingResult,
        )> = traced_entry_points_second_request
            .traced_entry_points
            .get_mut(&component_id_a)
            .unwrap();

        traced_entry_points_for_component_second_request.sort_by(|(a, _), (b, _)| {
            a.entry_point
                .external_id
                .cmp(&b.entry_point.external_id)
                .then_with(|| match (a.params.clone(), b.params.clone()) {
                    (dto::TracingParams::RPCTracer(a), dto::TracingParams::RPCTracer(b)) => {
                        a.caller.cmp(&b.caller)
                    }
                })
        });

        assert_eq!(
            traced_entry_points_for_component_second_request,
            expected_rpc_result
                .get(&component_id_a)
                .unwrap(),
        );
        assert_eq!(
            traced_entry_points_second_request
                .pagination
                .total,
            2
        );
        assert_eq!(
            traced_entry_points_second_request
                .pagination
                .total_pages(),
            2
        );
    }
    #[test]
    async fn test_get_traced_entry_points_missing_result() {
        // We attempt to fetch results for one component, where one tracing params  does not have a
        // matching result. This param should not be included in the final response.

        let component_id_a = "component_a".to_string();

        let entry_point_id_a = "entrypoint_a".to_string();
        let entry_point_a = EntryPoint {
            external_id: entry_point_id_a.clone(),
            target: Bytes::from("0x0000000000000000000000000000000000000001"),
            signature: "sig()".to_string(),
        };
        let tracing_params_a = TracingParams::RPCTracer(RPCTracerParams {
            caller: Some(Bytes::from("0x000000000000000000000000000000000000000a")),
            calldata: Bytes::from("0x000000000000000000000000000000000000000b"),
            state_overrides: None,
            prune_addresses: None,
        });
        let tracing_params_b = TracingParams::RPCTracer(RPCTracerParams {
            caller: Some(Bytes::from("0x000000000000000000000000000000000000000b")),
            calldata: Bytes::from("0x000000000000000000000000000000000000000c"),
            state_overrides: None,
            prune_addresses: None,
        });
        let entry_point_with_params_a = EntryPointWithTracingParams {
            entry_point: entry_point_a.clone(),
            params: tracing_params_a.clone(),
        };
        let entry_point_with_params_b = EntryPointWithTracingParams {
            entry_point: entry_point_a.clone(),
            params: tracing_params_b.clone(),
        };
        let trace_result_a = TracingResult {
            retriggers: HashSet::from([(
                Bytes::from("0x00000000000000000000000000000000000000aa"),
                blockchain::AddressStorageLocation::new(
                    Bytes::from("0x0000000000000000000000000000000000000aaa"),
                    0,
                ),
            )]),
            accessed_slots: HashMap::from([(
                Bytes::from("0x0000000000000000000000000000000000aaaa"),
                HashSet::from([Bytes::from("0x0000000000000000000000000000000000aaaa")]),
            )]),
        };

        // Gateway responses
        // At this point, the component ids have already been paginated, so they are not
        // queried from the gateway unless they are on page 1
        let params_to_trace_result =
            HashMap::from([(tracing_params_a.clone(), trace_result_a.clone())]);
        let expected_entry_points_with_params = HashMap::from([(
            component_id_a.clone(),
            HashSet::from([entry_point_with_params_a.clone(), entry_point_with_params_b.clone()]),
        )]);

        let expected_trace_results =
            HashMap::from([(entry_point_id_a.clone(), params_to_trace_result)]);

        let mut gw = MockGateway::new();

        let mock_get_entry_points_response =
            Ok(WithTotal { entity: expected_entry_points_with_params.clone(), total: Some(2) });
        gw.expect_get_entry_points_tracing_params()
            .return_once(|_, _| Box::pin(async move { mock_get_entry_points_response }));

        let mock_traced_entry_points_response = Ok(expected_trace_results.clone());
        gw.expect_get_traced_entry_points()
            .return_once(|_| Box::pin(async move { mock_traced_entry_points_response }));

        let req_handler = RpcHandler::new(gw, None, MockEntryPointTracer::new());

        let request = dto::TracedEntryPointRequestBody {
            chain: dto::Chain::Ethereum,
            protocol_system: "uniswap_v2".to_string(),
            component_ids: Some(vec![component_id_a.clone()]),
            pagination: dto::PaginationParams { page: 0, page_size: 1 },
        };

        let mut traced_entry_points = req_handler
            .get_traced_entry_points(&request)
            .await
            .unwrap();

        let expected_rpc_result = HashMap::from([(
            component_id_a.clone(),
            vec![(
                dto::EntryPointWithTracingParams::from(entry_point_with_params_a.clone()),
                dto::TracingResult::from(trace_result_a.clone()),
            )],
        )]);

        assert_eq!(
            traced_entry_points
                .traced_entry_points
                .get_mut(&component_id_a)
                .unwrap(),
            expected_rpc_result
                .get(&component_id_a)
                .unwrap(),
        );
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
            protocol_system: "uniswap_v2".to_string(),
            version: dto::VersionParam::default(),
            chain: dto::Chain::Ethereum,
            pagination: dto::PaginationParams::default(),
        };

        // Serialize the request body to JSON
        let json_data = serde_json::to_string(&request_body).expect("Failed to serialize to JSON");

        // Print the curl command
        println!("curl -X POST -H \"Content-Type: application/json\" -d '{json_data}' {endpoint}");
    }

    #[tokio::test]
    async fn test_get_tokens() {
        let expected = vec![
            Token::new(&(USDC.parse().unwrap()), "USDC", 6, 0, &[], Chain::Ethereum, 100),
            Token::new(&(WETH.parse().unwrap()), "WETH", 18, 0, &[], Chain::Ethereum, 100),
        ];
        let mut gw = MockGateway::new();
        let mock_response = Ok(WithTotal { entity: expected.clone(), total: Some(3) });
        // ensure the gateway is only accessed once - the second request should hit cache
        gw.expect_get_tokens()
            .return_once(|_, _, _, _, _| Box::pin(async move { mock_response }));
        let req_handler = RpcHandler::new(gw, None, MockEntryPointTracer::new());

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
        assert_eq!(tokens.pagination.total, 3);
        assert_eq!(tokens.pagination.total_pages(), 2);

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
        let mock_response = Ok(WithTotal { entity: vec![expected.clone()], total: Some(1) });
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
                move |_, db_states: &mut Vec<ProtocolComponentState>, _, _| {
                    db_states.push(buf_expected_clone);
                    Ok(())
                }
            });
        mock_buffer
            .expect_get_block_finality()
            .return_once(|_, _| Ok(Some(FinalityStatus::Unfinalized)));

        let req_handler =
            RpcHandler::new(gw, Some(Arc::new(mock_buffer)), MockEntryPointTracer::new());

        let request = dto::ProtocolStateRequestBody {
            protocol_ids: Some(vec!["state1".to_owned(), "state_buff".to_owned()]),
            protocol_system: "uniswap_v2".to_string(),
            chain: dto::Chain::Ethereum,
            include_balances: true,
            version: dto::VersionParam { timestamp: Some(Utc::now().naive_utc()), block: None },
            pagination: dto::PaginationParams::default(),
        };
        let res = req_handler
            .get_protocol_state_inner(request)
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

        let unsorted_tokens =
            vec![Bytes::from_str("0x01").unwrap(), Bytes::from_str("0x00").unwrap()];

        let expected = ProtocolComponent::new(
            "comp1",
            "ambient",
            "pool",
            Chain::Ethereum,
            vec![Bytes::from_str("0x00").unwrap(), Bytes::from_str("0x01").unwrap()],
            vec![],
            HashMap::new(),
            ChangeType::Creation,
            "0x50449de1973d86f21bfafa7c72011854a7e33a226709dc3e2e4edcca34"
                .parse()
                .unwrap(),
            NaiveDateTime::default(),
        );

        let mut mock_res = expected.clone();
        mock_res
            .tokens
            .clone_from(&unsorted_tokens);
        let mock_response = Ok(WithTotal { entity: vec![mock_res], total: Some(1) });
        gw.expect_get_protocol_components()
            .return_once(|_, _, _, _, _| Box::pin(async move { mock_response }));

        let mut mock_buffer = MockPendingDeltas::new();
        let buf_expected = ProtocolComponent::new(
            "comp_buff",
            "ambient",
            "pool",
            Chain::Ethereum,
            vec![Bytes::from_str("0x00").unwrap(), Bytes::from_str("0x01").unwrap()],
            vec![],
            HashMap::new(),
            ChangeType::Creation,
            "0x50449de1973d86f21bfafa7c72011854a7e33a226709dc3e2e4edcca34"
                .parse()
                .unwrap(),
            NaiveDateTime::default(),
        );

        let mut mock_res = buf_expected.clone();
        mock_res.tokens = unsorted_tokens;
        mock_buffer
            .expect_get_new_components()
            .return_once(move |_, _, _| Ok(vec![mock_res]));

        let req_handler =
            RpcHandler::new(gw, Some(Arc::new(mock_buffer)), MockEntryPointTracer::new());

        let request = dto::ProtocolComponentsRequestBody {
            protocol_system: "ambient".to_string(),
            component_ids: None,
            tvl_gt: None,
            chain: dto::Chain::Ethereum,
            pagination: dto::PaginationParams::new(0, 2),
        };

        let components = req_handler
            .get_protocol_components_inner(request)
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
                        Ok((num, components)) => {
                            Ok(WithTotal { entity: components.clone(), total: Some(*num) })
                        }
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
                move |_, _, _| Ok(vec![buf_expected1_clone.clone(), buf_expected2_clone.clone()])
            });

        let req_handler =
            RpcHandler::new(gw, Some(Arc::new(mock_buffer)), MockEntryPointTracer::new());

        let request = dto::ProtocolComponentsRequestBody {
            protocol_system: "ambient".to_string(),
            component_ids: None,
            tvl_gt: None,
            chain: dto::Chain::Ethereum,
            pagination: dto::PaginationParams::new(0, 2),
        };

        let response1 = req_handler
            .get_protocol_components_inner(request)
            .await
            .unwrap();

        assert_eq!(response1.protocol_components.len(), 2);
        assert_eq!(response1.protocol_components[0], expected.into());
        assert_eq!(response1.protocol_components[1], buf_expected1.into());
        assert_eq!(response1.pagination.total, 3);

        let request = dto::ProtocolComponentsRequestBody {
            protocol_system: "ambient".to_string(),
            component_ids: None,
            tvl_gt: None,
            chain: dto::Chain::Ethereum,
            pagination: dto::PaginationParams::new(1, 2),
        };

        let response2 = req_handler
            .get_protocol_components_inner(request)
            .await
            .unwrap();

        assert_eq!(response2.protocol_components.len(), 1);
        assert_eq!(response2.protocol_components[0], buf_expected2.into());
        assert_eq!(response2.pagination.total, 3);
    }
}
