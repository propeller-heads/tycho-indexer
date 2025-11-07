//! # Tycho RPC Client
//!
//! The objective of this module is to provide swift and simplified access to the Remote Procedure
//! Call (RPC) endpoints of Tycho. These endpoints are chiefly responsible for facilitating data
//! queries, especially querying snapshots of data.
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, SystemTime},
};

use async_trait::async_trait;
use backoff::{exponential::ExponentialBackoffBuilder, ExponentialBackoff};
use futures03::future::try_join_all;
#[cfg(test)]
use mockall::automock;
use reqwest::{header, Client, ClientBuilder, Response, StatusCode, Url};
use serde::Serialize;
use thiserror::Error;
use time::{format_description::well_known::Rfc2822, OffsetDateTime};
use tokio::{
    sync::{RwLock, Semaphore},
    time::sleep,
};
use tracing::{debug, error, instrument, trace, warn};
use tycho_common::{
    dto::{
        BlockParam, Chain, ComponentTvlRequestBody, ComponentTvlRequestResponse,
        EntryPointWithTracingParams, PaginationParams, PaginationResponse, ProtocolComponent,
        ProtocolComponentRequestResponse, ProtocolComponentsRequestBody, ProtocolStateRequestBody,
        ProtocolStateRequestResponse, ProtocolSystemsRequestBody, ProtocolSystemsRequestResponse,
        ResponseToken, StateRequestBody, StateRequestResponse, TokensRequestBody,
        TokensRequestResponse, TracedEntryPointRequestBody, TracedEntryPointRequestResponse,
        TracingResult, VersionParam,
    },
    models::ComponentId,
    Bytes,
};

use crate::{
    feed::synchronizer::{ComponentWithState, Snapshot},
    TYCHO_SERVER_VERSION,
};

/// Request body for fetching a snapshot of protocol states and VM storage.
///
/// This struct helps to coordinate fetching  multiple pieces of related data
/// (protocol states, contract storage, TVL, entry points).
#[derive(Clone, Debug, PartialEq)]
pub struct SnapshotParameters<'a> {
    /// Which chain to fetch snapshots for
    pub chain: Chain,
    /// Protocol system name, required for correct state resolution
    pub protocol_system: &'a str,
    /// Components to fetch protocol states for
    pub components: &'a HashMap<ComponentId, ProtocolComponent>,
    /// Traced entry points data mapped by component id
    pub entrypoints: Option<&'a HashMap<String, Vec<(EntryPointWithTracingParams, TracingResult)>>>,
    /// Contract addresses to fetch VM storage for
    pub contract_ids: &'a [Bytes],
    /// Block number for versioning
    pub block_number: u64,
    /// Whether to include balance information
    pub include_balances: bool,
    /// Whether to fetch TVL data
    pub include_tvl: bool,
}

impl<'a> SnapshotParameters<'a> {
    pub fn new(
        chain: Chain,
        protocol_system: &'a str,
        components: &'a HashMap<ComponentId, ProtocolComponent>,
        contract_ids: &'a [Bytes],
        block_number: u64,
    ) -> Self {
        Self {
            chain,
            protocol_system,
            components,
            entrypoints: None,
            contract_ids,
            block_number,
            include_balances: true,
            include_tvl: true,
        }
    }

    /// Set whether to include balance information (default: true)
    pub fn include_balances(mut self, include_balances: bool) -> Self {
        self.include_balances = include_balances;
        self
    }

    /// Set whether to fetch TVL data (default: true)
    pub fn include_tvl(mut self, include_tvl: bool) -> Self {
        self.include_tvl = include_tvl;
        self
    }

    pub fn entrypoints(
        mut self,
        entrypoints: &'a HashMap<String, Vec<(EntryPointWithTracingParams, TracingResult)>>,
    ) -> Self {
        self.entrypoints = Some(entrypoints);
        self
    }
}

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
    HttpClient(String, #[source] reqwest::Error),

    /// The response from the server could not be parsed correctly.
    #[error("Failed to parse response: {0}")]
    ParseResponse(String),

    /// Other fatal errors.
    #[error("Fatal error: {0}")]
    Fatal(String),

    #[error("Rate limited until {0:?}")]
    RateLimited(Option<SystemTime>),

    #[error("Server unreachable: {0}")]
    ServerUnreachable(String),
}

#[cfg_attr(test, automock)]
#[async_trait]
pub trait RPCClient: Send + Sync {
    /// Retrieves a snapshot of contract state.
    async fn get_contract_state(
        &self,
        request: &StateRequestBody,
    ) -> Result<StateRequestResponse, RPCError>;

    async fn get_contract_state_paginated(
        &self,
        chain: Chain,
        ids: &[Bytes],
        protocol_system: &str,
        version: &VersionParam,
        chunk_size: usize,
        concurrency: usize,
    ) -> Result<StateRequestResponse, RPCError> {
        let semaphore = Arc::new(Semaphore::new(concurrency));

        // Sort the ids to maximize server-side cache hits
        let mut sorted_ids = ids.to_vec();
        sorted_ids.sort();

        let chunked_bodies = sorted_ids
            .chunks(chunk_size)
            .map(|chunk| StateRequestBody {
                contract_ids: Some(chunk.to_vec()),
                protocol_system: protocol_system.to_string(),
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

        // Execute all tasks concurrently with the defined concurrency limit.
        let responses = try_join_all(tasks).await?;

        // Aggregate the responses into a single result.
        let accounts = responses
            .iter()
            .flat_map(|r| r.accounts.clone())
            .collect();
        let total: i64 = responses
            .iter()
            .map(|r| r.pagination.total)
            .sum();

        Ok(StateRequestResponse {
            accounts,
            pagination: PaginationResponse { page: 0, page_size: chunk_size as i64, total },
        })
    }

    async fn get_protocol_components(
        &self,
        request: &ProtocolComponentsRequestBody,
    ) -> Result<ProtocolComponentRequestResponse, RPCError>;

    async fn get_protocol_components_paginated(
        &self,
        request: &ProtocolComponentsRequestBody,
        chunk_size: usize,
        concurrency: usize,
    ) -> Result<ProtocolComponentRequestResponse, RPCError> {
        let semaphore = Arc::new(Semaphore::new(concurrency));

        // If a set of component IDs is specified, the maximum return size is already known,
        // allowing us to pre-compute the number of requests to be made.
        match request.component_ids {
            Some(ref ids) => {
                // We can divide the component_ids into chunks of size chunk_size
                let chunked_bodies = ids
                    .chunks(chunk_size)
                    .enumerate()
                    .map(|(index, _)| ProtocolComponentsRequestBody {
                        protocol_system: request.protocol_system.clone(),
                        component_ids: request.component_ids.clone(),
                        tvl_gt: request.tvl_gt,
                        chain: request.chain,
                        pagination: PaginationParams {
                            page: index as i64,
                            page_size: chunk_size as i64,
                        },
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
                        self.get_protocol_components(body).await
                    });
                }

                try_join_all(tasks)
                    .await
                    .map(|responses| ProtocolComponentRequestResponse {
                        protocol_components: responses
                            .into_iter()
                            .flat_map(|r| r.protocol_components.into_iter())
                            .collect(),
                        pagination: PaginationResponse {
                            page: 0,
                            page_size: chunk_size as i64,
                            total: ids.len() as i64,
                        },
                    })
            }
            _ => {
                // If no component ids are specified, we need to make requests based on the total
                // number of results from the first response.

                let initial_request = ProtocolComponentsRequestBody {
                    protocol_system: request.protocol_system.clone(),
                    component_ids: request.component_ids.clone(),
                    tvl_gt: request.tvl_gt,
                    chain: request.chain,
                    pagination: PaginationParams { page: 0, page_size: chunk_size as i64 },
                };
                let first_response = self
                    .get_protocol_components(&initial_request)
                    .await
                    .map_err(|err| RPCError::Fatal(err.to_string()))?;

                let total_items = first_response.pagination.total;
                let total_pages = (total_items as f64 / chunk_size as f64).ceil() as i64;

                // Initialize the final response accumulator
                let mut accumulated_response = ProtocolComponentRequestResponse {
                    protocol_components: first_response.protocol_components,
                    pagination: PaginationResponse {
                        page: 0,
                        page_size: chunk_size as i64,
                        total: total_items,
                    },
                };

                let mut page = 1;
                while page < total_pages {
                    let requests_in_this_iteration = (total_pages - page).min(concurrency as i64);

                    // Create request bodies for parallel requests, respecting the concurrency limit
                    let chunked_bodies = (0..requests_in_this_iteration)
                        .map(|iter| ProtocolComponentsRequestBody {
                            protocol_system: request.protocol_system.clone(),
                            component_ids: request.component_ids.clone(),
                            tvl_gt: request.tvl_gt,
                            chain: request.chain,
                            pagination: PaginationParams {
                                page: page + iter,
                                page_size: chunk_size as i64,
                            },
                        })
                        .collect::<Vec<_>>();

                    let tasks: Vec<_> = chunked_bodies
                        .iter()
                        .map(|body| {
                            let sem = semaphore.clone();
                            async move {
                                let _permit = sem.acquire().await.map_err(|_| {
                                    RPCError::Fatal("Semaphore dropped".to_string())
                                })?;
                                self.get_protocol_components(body).await
                            }
                        })
                        .collect();

                    let responses = try_join_all(tasks)
                        .await
                        .map(|responses| {
                            let total = responses[0].pagination.total;
                            ProtocolComponentRequestResponse {
                                protocol_components: responses
                                    .into_iter()
                                    .flat_map(|r| r.protocol_components.into_iter())
                                    .collect(),
                                pagination: PaginationResponse {
                                    page,
                                    page_size: chunk_size as i64,
                                    total,
                                },
                            }
                        });

                    // Update the accumulated response or set the initial response
                    match responses {
                        Ok(mut resp) => {
                            accumulated_response
                                .protocol_components
                                .append(&mut resp.protocol_components);
                        }
                        Err(e) => return Err(e),
                    }

                    page += concurrency as i64;
                }
                Ok(accumulated_response)
            }
        }
    }

    async fn get_protocol_states(
        &self,
        request: &ProtocolStateRequestBody,
    ) -> Result<ProtocolStateRequestResponse, RPCError>;

    #[allow(clippy::too_many_arguments)]
    async fn get_protocol_states_paginated<T>(
        &self,
        chain: Chain,
        ids: &[T],
        protocol_system: &str,
        include_balances: bool,
        version: &VersionParam,
        chunk_size: usize,
        concurrency: usize,
    ) -> Result<ProtocolStateRequestResponse, RPCError>
    where
        T: AsRef<str> + Sync + 'static,
    {
        let semaphore = Arc::new(Semaphore::new(concurrency));
        let chunked_bodies = ids
            .chunks(chunk_size)
            .map(|c| ProtocolStateRequestBody {
                protocol_ids: Some(
                    c.iter()
                        .map(|id| id.as_ref().to_string())
                        .collect(),
                ),
                protocol_system: protocol_system.to_string(),
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
            .map(|responses| {
                let states = responses
                    .clone()
                    .into_iter()
                    .flat_map(|r| r.states)
                    .collect();
                let total = responses
                    .iter()
                    .map(|r| r.pagination.total)
                    .sum();
                ProtocolStateRequestResponse {
                    states,
                    pagination: PaginationResponse { page: 0, page_size: chunk_size as i64, total },
                }
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

    async fn get_protocol_systems(
        &self,
        request: &ProtocolSystemsRequestBody,
    ) -> Result<ProtocolSystemsRequestResponse, RPCError>;

    async fn get_component_tvl(
        &self,
        request: &ComponentTvlRequestBody,
    ) -> Result<ComponentTvlRequestResponse, RPCError>;

    async fn get_component_tvl_paginated(
        &self,
        request: &ComponentTvlRequestBody,
        chunk_size: usize,
        concurrency: usize,
    ) -> Result<ComponentTvlRequestResponse, RPCError> {
        let semaphore = Arc::new(Semaphore::new(concurrency));

        match request.component_ids {
            Some(ref ids) => {
                let chunked_requests = ids
                    .chunks(chunk_size)
                    .enumerate()
                    .map(|(index, _)| ComponentTvlRequestBody {
                        chain: request.chain,
                        protocol_system: request.protocol_system.clone(),
                        component_ids: Some(ids.clone()),
                        pagination: PaginationParams {
                            page: index as i64,
                            page_size: chunk_size as i64,
                        },
                    })
                    .collect::<Vec<_>>();

                let tasks: Vec<_> = chunked_requests
                    .into_iter()
                    .map(|req| {
                        let sem = semaphore.clone();
                        async move {
                            let _permit = sem
                                .acquire()
                                .await
                                .map_err(|_| RPCError::Fatal("Semaphore dropped".to_string()))?;
                            self.get_component_tvl(&req).await
                        }
                    })
                    .collect();

                let responses = try_join_all(tasks).await?;

                let mut merged_tvl = HashMap::new();
                for resp in responses {
                    for (key, value) in resp.tvl {
                        *merged_tvl.entry(key).or_insert(0.0) = value;
                    }
                }

                Ok(ComponentTvlRequestResponse {
                    tvl: merged_tvl,
                    pagination: PaginationResponse {
                        page: 0,
                        page_size: chunk_size as i64,
                        total: ids.len() as i64,
                    },
                })
            }
            _ => {
                let first_request = ComponentTvlRequestBody {
                    chain: request.chain,
                    protocol_system: request.protocol_system.clone(),
                    component_ids: request.component_ids.clone(),
                    pagination: PaginationParams { page: 0, page_size: chunk_size as i64 },
                };

                let first_response = self
                    .get_component_tvl(&first_request)
                    .await?;
                let total_items = first_response.pagination.total;
                let total_pages = (total_items as f64 / chunk_size as f64).ceil() as i64;

                let mut merged_tvl = first_response.tvl;

                let mut page = 1;
                while page < total_pages {
                    let requests_in_this_iteration = (total_pages - page).min(concurrency as i64);

                    let chunked_requests: Vec<_> = (0..requests_in_this_iteration)
                        .map(|i| ComponentTvlRequestBody {
                            chain: request.chain,
                            protocol_system: request.protocol_system.clone(),
                            component_ids: request.component_ids.clone(),
                            pagination: PaginationParams {
                                page: page + i,
                                page_size: chunk_size as i64,
                            },
                        })
                        .collect();

                    let tasks: Vec<_> = chunked_requests
                        .into_iter()
                        .map(|req| {
                            let sem = semaphore.clone();
                            async move {
                                let _permit = sem.acquire().await.map_err(|_| {
                                    RPCError::Fatal("Semaphore dropped".to_string())
                                })?;
                                self.get_component_tvl(&req).await
                            }
                        })
                        .collect();

                    let responses = try_join_all(tasks).await?;

                    // merge hashmap
                    for resp in responses {
                        for (key, value) in resp.tvl {
                            *merged_tvl.entry(key).or_insert(0.0) += value;
                        }
                    }

                    page += concurrency as i64;
                }

                Ok(ComponentTvlRequestResponse {
                    tvl: merged_tvl,
                    pagination: PaginationResponse {
                        page: 0,
                        page_size: chunk_size as i64,
                        total: total_items,
                    },
                })
            }
        }
    }

    async fn get_traced_entry_points(
        &self,
        request: &TracedEntryPointRequestBody,
    ) -> Result<TracedEntryPointRequestResponse, RPCError>;

    async fn get_traced_entry_points_paginated(
        &self,
        chain: Chain,
        protocol_system: &str,
        component_ids: &[String],
        chunk_size: usize,
        concurrency: usize,
    ) -> Result<TracedEntryPointRequestResponse, RPCError> {
        let semaphore = Arc::new(Semaphore::new(concurrency));
        let chunked_bodies = component_ids
            .chunks(chunk_size)
            .map(|c| TracedEntryPointRequestBody {
                chain,
                protocol_system: protocol_system.to_string(),
                component_ids: Some(c.to_vec()),
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
                self.get_traced_entry_points(body).await
            });
        }

        try_join_all(tasks)
            .await
            .map(|responses| {
                let traced_entry_points = responses
                    .clone()
                    .into_iter()
                    .flat_map(|r| r.traced_entry_points)
                    .collect();
                let total = responses
                    .iter()
                    .map(|r| r.pagination.total)
                    .sum();
                TracedEntryPointRequestResponse {
                    traced_entry_points,
                    pagination: PaginationResponse { page: 0, page_size: chunk_size as i64, total },
                }
            })
    }

    async fn get_snapshots<'a>(
        &self,
        request: &SnapshotParameters<'a>,
        chunk_size: usize,
        concurrency: usize,
    ) -> Result<Snapshot, RPCError>;
}

/// Configuration options for HttpRPCClient
#[derive(Debug, Clone)]
pub struct HttpRPCClientOptions {
    /// Optional API key for authentication
    pub auth_key: Option<String>,
    /// Enable compression for requests (default: true)
    /// When enabled, adds Accept-Encoding: zstd header
    pub compression: bool,
}

impl Default for HttpRPCClientOptions {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpRPCClientOptions {
    /// Create new options with default values (compression enabled)
    pub fn new() -> Self {
        Self { auth_key: None, compression: true }
    }

    /// Set the authentication key
    pub fn with_auth_key(mut self, auth_key: Option<String>) -> Self {
        self.auth_key = auth_key;
        self
    }

    /// Set whether to enable compression (default: true)
    pub fn with_compression(mut self, compression: bool) -> Self {
        self.compression = compression;
        self
    }
}

#[derive(Debug, Clone)]
pub struct HttpRPCClient {
    http_client: Client,
    url: Url,
    retry_after: Arc<RwLock<Option<SystemTime>>>,
    backoff_policy: ExponentialBackoff,
    server_restart_duration: Duration,
}

impl HttpRPCClient {
    pub fn new(base_uri: &str, options: HttpRPCClientOptions) -> Result<Self, RPCError> {
        let uri = base_uri
            .parse::<Url>()
            .map_err(|e| RPCError::UrlParsing(base_uri.to_string(), e.to_string()))?;

        // Add default headers
        let mut headers = header::HeaderMap::new();
        headers.insert(header::CONTENT_TYPE, header::HeaderValue::from_static("application/json"));
        let user_agent = format!("tycho-client-{version}", version = env!("CARGO_PKG_VERSION"));
        headers.insert(
            header::USER_AGENT,
            header::HeaderValue::from_str(&user_agent)
                .map_err(|e| RPCError::FormatRequest(format!("Invalid user agent format: {e}")))?,
        );

        // Add Accept-Encoding header when compression is enabled
        // Note: reqwest with zstd feature will automatically decompress responses
        if options.compression {
            headers.insert(header::ACCEPT_ENCODING, header::HeaderValue::from_static("zstd"));
        }

        // Add Authorization if one is given
        if let Some(key) = options.auth_key.as_deref() {
            let mut auth_value = header::HeaderValue::from_str(key).map_err(|e| {
                RPCError::FormatRequest(format!("Invalid authorization key format: {e}"))
            })?;
            auth_value.set_sensitive(true);
            headers.insert(header::AUTHORIZATION, auth_value);
        }

        let client = ClientBuilder::new()
            .default_headers(headers)
            .http2_prior_knowledge()
            .build()
            .map_err(|e| RPCError::HttpClient(e.to_string(), e))?;
        Ok(Self {
            http_client: client,
            url: uri,
            retry_after: Arc::new(RwLock::new(None)),
            backoff_policy: ExponentialBackoffBuilder::new()
                .with_initial_interval(Duration::from_millis(250))
                // increase backoff time by 75% each failure
                .with_multiplier(1.75)
                // keep retrying every 30s
                .with_max_interval(Duration::from_secs(30))
                // if all retries take longer than 2m, give up
                .with_max_elapsed_time(Some(Duration::from_secs(125)))
                .build(),
            server_restart_duration: Duration::from_secs(120),
        })
    }

    #[cfg(test)]
    pub fn with_test_backoff_policy(mut self) -> Self {
        // Extremely short intervals for very fast testing
        self.backoff_policy = ExponentialBackoffBuilder::new()
            .with_initial_interval(Duration::from_millis(1))
            .with_multiplier(1.1)
            .with_max_interval(Duration::from_millis(5))
            .with_max_elapsed_time(Some(Duration::from_millis(50)))
            .build();
        self.server_restart_duration = Duration::from_millis(50);
        self
    }

    /// Converts a error response to a Result.
    ///
    /// Raises an error if the response status code id 429, 502, 503 or 504. In the 429
    /// case it will try to look for a retry-after header an parse it accordingly. The
    /// parsed value is then passed as part of the error.
    async fn error_for_response(
        &self,
        response: reqwest::Response,
    ) -> Result<reqwest::Response, RPCError> {
        match response.status() {
            StatusCode::TOO_MANY_REQUESTS => {
                let retry_after_raw = response
                    .headers()
                    .get(reqwest::header::RETRY_AFTER)
                    .and_then(|h| h.to_str().ok())
                    .and_then(parse_retry_value);

                Err(RPCError::RateLimited(retry_after_raw))
            }
            StatusCode::BAD_GATEWAY |
            StatusCode::SERVICE_UNAVAILABLE |
            StatusCode::GATEWAY_TIMEOUT => Err(RPCError::ServerUnreachable(
                response
                    .text()
                    .await
                    .unwrap_or_else(|_| "Server Unreachable".to_string()),
            )),
            _ => Ok(response),
        }
    }

    /// Classifies errors into transient or permanent ones.
    ///
    /// Transient errors are retried with a potential backoff, permanent ones are not.
    /// If the error is RateLimited, this method will set the self.retry_after value so
    /// future requests wait until the rate limit has been reset.
    async fn handle_error_for_backoff(&self, e: RPCError) -> backoff::Error<RPCError> {
        match e {
            RPCError::ServerUnreachable(_) => {
                backoff::Error::retry_after(e, self.server_restart_duration)
            }
            RPCError::RateLimited(Some(until)) => {
                let mut retry_after_guard = self.retry_after.write().await;
                *retry_after_guard = Some(
                    retry_after_guard
                        .unwrap_or(until)
                        .max(until),
                );

                if let Ok(duration) = until.duration_since(SystemTime::now()) {
                    backoff::Error::retry_after(e, duration)
                } else {
                    e.into()
                }
            }
            RPCError::RateLimited(None) => e.into(),
            _ => backoff::Error::permanent(e),
        }
    }

    /// Waits until the current rate limit time has passed.
    ///
    /// Only waits if there is a time and that time is in the future, else return
    /// immediately.
    async fn wait_until_retry_after(&self) {
        if let Some(&until) = self.retry_after.read().await.as_ref() {
            let now = SystemTime::now();
            if until > now {
                if let Ok(duration) = until.duration_since(now) {
                    sleep(duration).await
                }
            }
        }
    }

    /// Makes a post request handling transient failures.
    ///
    /// If a retry-after header is received it will be respected. Else the configured
    /// backoff policy is used to deal with transient network or server errors.
    async fn make_post_request<T: Serialize + ?Sized>(
        &self,
        request: &T,
        uri: &String,
    ) -> Result<Response, RPCError> {
        self.wait_until_retry_after().await;
        let response = backoff::future::retry(self.backoff_policy.clone(), || async {
            let server_response = self
                .http_client
                .post(uri)
                .json(request)
                .send()
                .await
                .map_err(|e| RPCError::HttpClient(e.to_string(), e))?;

            match self
                .error_for_response(server_response)
                .await
            {
                Ok(response) => Ok(response),
                Err(e) => Err(self.handle_error_for_backoff(e).await),
            }
        })
        .await?;
        Ok(response)
    }
}

fn parse_retry_value(val: &str) -> Option<SystemTime> {
    if let Ok(secs) = val.parse::<u64>() {
        return Some(SystemTime::now() + Duration::from_secs(secs));
    }
    if let Ok(date) = OffsetDateTime::parse(val, &Rfc2822) {
        return Some(date.into());
    }
    None
}

#[async_trait]
impl RPCClient for HttpRPCClient {
    #[instrument(skip(self, request))]
    async fn get_contract_state(
        &self,
        request: &StateRequestBody,
    ) -> Result<StateRequestResponse, RPCError> {
        // Check if contract ids are specified
        if request
            .contract_ids
            .as_ref()
            .is_none_or(|ids| ids.is_empty())
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
            .make_post_request(request, &uri)
            .await?;
        trace!(?response, "Received response from Tycho server");

        let body = response
            .text()
            .await
            .map_err(|e| RPCError::ParseResponse(e.to_string()))?;
        if body.is_empty() {
            // Pure native protocols will return empty contract states
            return Ok(StateRequestResponse {
                accounts: vec![],
                pagination: PaginationResponse {
                    page: request.pagination.page,
                    page_size: request.pagination.page,
                    total: 0,
                },
            });
        }

        let accounts = serde_json::from_str::<StateRequestResponse>(&body)
            .map_err(|err| RPCError::ParseResponse(format!("Error: {err}, Body: {body}")))?;
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
            .make_post_request(request, &uri)
            .await?;

        trace!(?response, "Received response from Tycho server");

        let body = response
            .text()
            .await
            .map_err(|e| RPCError::ParseResponse(e.to_string()))?;
        let components = serde_json::from_str::<ProtocolComponentRequestResponse>(&body)
            .map_err(|err| RPCError::ParseResponse(format!("Error: {err}, Body: {body}")))?;
        trace!(?components, "Received protocol_components response from Tycho server");

        Ok(components)
    }

    async fn get_protocol_states(
        &self,
        request: &ProtocolStateRequestBody,
    ) -> Result<ProtocolStateRequestResponse, RPCError> {
        // Check if protocol ids are specified
        if request
            .protocol_ids
            .as_ref()
            .is_none_or(|ids| ids.is_empty())
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
            .make_post_request(request, &uri)
            .await?;
        trace!(?response, "Received response from Tycho server");

        let body = response
            .text()
            .await
            .map_err(|e| RPCError::ParseResponse(e.to_string()))?;

        if body.is_empty() {
            // Pure VM protocols will return empty states
            return Ok(ProtocolStateRequestResponse {
                states: vec![],
                pagination: PaginationResponse {
                    page: request.pagination.page,
                    page_size: request.pagination.page_size,
                    total: 0,
                },
            });
        }

        let states = serde_json::from_str::<ProtocolStateRequestResponse>(&body)
            .map_err(|err| RPCError::ParseResponse(format!("Error: {err}, Body: {body}")))?;
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
            .make_post_request(request, &uri)
            .await?;

        let body = response
            .text()
            .await
            .map_err(|e| RPCError::ParseResponse(e.to_string()))?;
        let tokens = serde_json::from_str::<TokensRequestResponse>(&body)
            .map_err(|err| RPCError::ParseResponse(format!("Error: {err}, Body: {body}")))?;

        Ok(tokens)
    }

    async fn get_protocol_systems(
        &self,
        request: &ProtocolSystemsRequestBody,
    ) -> Result<ProtocolSystemsRequestResponse, RPCError> {
        let uri = format!(
            "{}/{}/protocol_systems",
            self.url
                .to_string()
                .trim_end_matches('/'),
            TYCHO_SERVER_VERSION
        );
        debug!(%uri, "Sending protocol_systems request to Tycho server");
        trace!(?request, "Sending request to Tycho server");
        let response = self
            .make_post_request(request, &uri)
            .await?;
        trace!(?response, "Received response from Tycho server");
        let body = response
            .text()
            .await
            .map_err(|e| RPCError::ParseResponse(e.to_string()))?;
        let protocol_systems = serde_json::from_str::<ProtocolSystemsRequestResponse>(&body)
            .map_err(|err| RPCError::ParseResponse(format!("Error: {err}, Body: {body}")))?;
        trace!(?protocol_systems, "Received protocol_systems response from Tycho server");
        Ok(protocol_systems)
    }

    async fn get_component_tvl(
        &self,
        request: &ComponentTvlRequestBody,
    ) -> Result<ComponentTvlRequestResponse, RPCError> {
        let uri = format!(
            "{}/{}/component_tvl",
            self.url
                .to_string()
                .trim_end_matches('/'),
            TYCHO_SERVER_VERSION
        );
        debug!(%uri, "Sending get_component_tvl request to Tycho server");
        trace!(?request, "Sending request to Tycho server");
        let response = self
            .make_post_request(request, &uri)
            .await?;
        trace!(?response, "Received response from Tycho server");
        let body = response
            .text()
            .await
            .map_err(|e| RPCError::ParseResponse(e.to_string()))?;
        let component_tvl =
            serde_json::from_str::<ComponentTvlRequestResponse>(&body).map_err(|err| {
                error!("Failed to parse component_tvl response: {:?}", &body);
                RPCError::ParseResponse(format!("Error: {err}, Body: {body}"))
            })?;
        trace!(?component_tvl, "Received component_tvl response from Tycho server");
        Ok(component_tvl)
    }

    async fn get_traced_entry_points(
        &self,
        request: &TracedEntryPointRequestBody,
    ) -> Result<TracedEntryPointRequestResponse, RPCError> {
        let uri = format!(
            "{}/{TYCHO_SERVER_VERSION}/traced_entry_points",
            self.url
                .to_string()
                .trim_end_matches('/')
        );
        debug!(%uri, "Sending traced_entry_points request to Tycho server");
        trace!(?request, "Sending request to Tycho server");

        let response = self
            .make_post_request(request, &uri)
            .await?;

        trace!(?response, "Received response from Tycho server");

        let body = response
            .text()
            .await
            .map_err(|e| RPCError::ParseResponse(e.to_string()))?;
        let entrypoints =
            serde_json::from_str::<TracedEntryPointRequestResponse>(&body).map_err(|err| {
                error!("Failed to parse traced_entry_points response: {:?}", &body);
                RPCError::ParseResponse(format!("Error: {err}, Body: {body}"))
            })?;
        trace!(?entrypoints, "Received traced_entry_points response from Tycho server");
        Ok(entrypoints)
    }

    async fn get_snapshots<'a>(
        &self,
        request: &SnapshotParameters<'a>,
        chunk_size: usize,
        concurrency: usize,
    ) -> Result<Snapshot, RPCError> {
        let component_ids: Vec<_> = request
            .components
            .keys()
            .cloned()
            .collect();

        let version = VersionParam::new(
            None,
            Some({
                #[allow(deprecated)]
                BlockParam {
                    hash: None,
                    chain: Some(request.chain),
                    number: Some(request.block_number as i64),
                }
            }),
        );

        let component_tvl = if request.include_tvl && !component_ids.is_empty() {
            let body = ComponentTvlRequestBody::id_filtered(component_ids.clone(), request.chain);
            self.get_component_tvl_paginated(&body, chunk_size, concurrency)
                .await?
                .tvl
        } else {
            HashMap::new()
        };

        let mut protocol_states = if !component_ids.is_empty() {
            self.get_protocol_states_paginated(
                request.chain,
                &component_ids,
                request.protocol_system,
                request.include_balances,
                &version,
                chunk_size,
                concurrency,
            )
            .await?
            .states
            .into_iter()
            .map(|state| (state.component_id.clone(), state))
            .collect()
        } else {
            HashMap::new()
        };

        // Convert to ComponentWithState, which includes entrypoint information.
        let states = request
            .components
            .values()
            .filter_map(|component| {
                if let Some(state) = protocol_states.remove(&component.id) {
                    Some((
                        component.id.clone(),
                        ComponentWithState {
                            state,
                            component: component.clone(),
                            component_tvl: component_tvl
                                .get(&component.id)
                                .cloned(),
                            entrypoints: request
                                .entrypoints
                                .as_ref()
                                .and_then(|map| map.get(&component.id))
                                .cloned()
                                .unwrap_or_default(),
                        },
                    ))
                } else if component_ids.contains(&component.id) {
                    // only emit error event if we requested this component
                    let component_id = &component.id;
                    error!(?component_id, "Missing state for native component!");
                    None
                } else {
                    None
                }
            })
            .collect();

        let vm_storage = if !request.contract_ids.is_empty() {
            let contract_states = self
                .get_contract_state_paginated(
                    request.chain,
                    request.contract_ids,
                    request.protocol_system,
                    &version,
                    chunk_size,
                    concurrency,
                )
                .await?
                .accounts
                .into_iter()
                .map(|acc| (acc.address.clone(), acc))
                .collect::<HashMap<_, _>>();

            trace!(states=?&contract_states, "Retrieved ContractState");

            let contract_address_to_components = request
                .components
                .iter()
                .filter_map(|(id, comp)| {
                    if component_ids.contains(id) {
                        Some(
                            comp.contract_ids
                                .iter()
                                .map(|address| (address.clone(), comp.id.clone())),
                        )
                    } else {
                        None
                    }
                })
                .flatten()
                .fold(HashMap::<Bytes, Vec<String>>::new(), |mut acc, (addr, c_id)| {
                    acc.entry(addr).or_default().push(c_id);
                    acc
                });

            request
                .contract_ids
                .iter()
                .filter_map(|address| {
                    if let Some(state) = contract_states.get(address) {
                        Some((address.clone(), state.clone()))
                    } else if let Some(ids) = contract_address_to_components.get(address) {
                        // only emit error even if we did actually request this address
                        error!(
                            ?address,
                            ?ids,
                            "Component with lacking contract storage encountered!"
                        );
                        None
                    } else {
                        None
                    }
                })
                .collect()
        } else {
            HashMap::new()
        };

        Ok(Snapshot { states, vm_storage })
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{HashMap, HashSet},
        str::FromStr,
    };

    use mockito::Server;
    use rstest::rstest;
    // TODO: remove once deprecated ProtocolId struct is removed
    #[allow(deprecated)]
    use tycho_common::dto::ProtocolId;
    use tycho_common::dto::{AddressStorageLocation, TracingParams};

    use super::*;

    // Dummy implementation of `get_protocol_states_paginated` for backwards compatibility testing
    // purposes
    impl MockRPCClient {
        #[allow(clippy::too_many_arguments)]
        async fn test_get_protocol_states_paginated<T>(
            &self,
            chain: Chain,
            ids: &[T],
            protocol_system: &str,
            include_balances: bool,
            version: &VersionParam,
            chunk_size: usize,
            _concurrency: usize,
        ) -> Vec<ProtocolStateRequestBody>
        where
            T: AsRef<str> + Clone + Send + Sync + 'static,
        {
            ids.chunks(chunk_size)
                .map(|chunk| ProtocolStateRequestBody {
                    protocol_ids: Some(
                        chunk
                            .iter()
                            .map(|id| id.as_ref().to_string())
                            .collect(),
                    ),
                    protocol_system: protocol_system.to_string(),
                    chain,
                    include_balances,
                    version: version.clone(),
                    pagination: PaginationParams { page: 0, page_size: chunk_size as i64 },
                })
                .collect()
        }
    }

    const GET_CONTRACT_STATE_RESP: &str = r#"
        {
            "accounts": [
                {
                    "chain": "ethereum",
                    "address": "0x0000000000000000000000000000000000000000",
                    "title": "",
                    "slots": {},
                    "native_balance": "0x01f4",
                    "token_balances": {},
                    "code": "0x00",
                    "code_hash": "0x5c06b7c5b3d910fd33bc2229846f9ddaf91d584d9b196e16636901ac3a77077e",
                    "balance_modify_tx": "0x0000000000000000000000000000000000000000000000000000000000000000",
                    "code_modify_tx": "0x0000000000000000000000000000000000000000000000000000000000000000",
                    "creation_tx": null
                }
            ],
            "pagination": {
                "page": 0,
                "page_size": 20,
                "total": 10
            }
        }
        "#;

    // TODO: remove once deprecated ProtocolId struct is removed
    #[allow(deprecated)]
    #[rstest]
    #[case::protocol_id_input(vec![
        ProtocolId { id: "id1".to_string(), chain: Chain::Ethereum },
        ProtocolId { id: "id2".to_string(), chain: Chain::Ethereum }
    ])]
    #[case::string_input(vec![
        "id1".to_string(),
        "id2".to_string()
    ])]
    #[tokio::test]
    async fn test_get_protocol_states_paginated_backwards_compatibility<T>(#[case] ids: Vec<T>)
    where
        T: AsRef<str> + Clone + Send + Sync + 'static,
    {
        let mock_client = MockRPCClient::new();

        let request_bodies = mock_client
            .test_get_protocol_states_paginated(
                Chain::Ethereum,
                &ids,
                "test_system",
                true,
                &VersionParam::default(),
                2,
                2,
            )
            .await;

        // Verify that the request bodies have been created correctly
        assert_eq!(request_bodies.len(), 1);
        assert_eq!(
            request_bodies[0]
                .protocol_ids
                .as_ref()
                .unwrap()
                .len(),
            2
        );
    }

    #[tokio::test]
    async fn test_get_contract_state() {
        let mut server = Server::new_async().await;
        let server_resp = GET_CONTRACT_STATE_RESP;
        // test that the response is deserialized correctly
        serde_json::from_str::<StateRequestResponse>(server_resp).expect("deserialize");

        let mocked_server = server
            .mock("POST", "/v1/contract_state")
            .expect(1)
            .with_body(server_resp)
            .create_async()
            .await;

        let client = HttpRPCClient::new(server.url().as_str(), HttpRPCClientOptions::default())
            .expect("create client");

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
                        "attribute_1": "0x00000000000003e8"
                    },
                    "change": "Creation",
                    "creation_tx": "0x0000000000000000000000000000000000000000000000000000000000000000",
                    "created_at": "2022-01-01T00:00:00"
                }
            ],
            "pagination": {
                "page": 0,
                "page_size": 20,
                "total": 10
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

        let client = HttpRPCClient::new(server.url().as_str(), HttpRPCClientOptions::default())
            .expect("create client");

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
            [("attribute_1".to_string(), Bytes::from(1000_u64.to_be_bytes()))]
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
                        "attribute_1": "0x00000000000003e8"
                    },
                    "balances": {
                        "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2": "0x01f4"
                    }
                }
            ],
            "pagination": {
                "page": 0,
                "page_size": 20,
                "total": 10
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
        let client = HttpRPCClient::new(server.url().as_str(), HttpRPCClientOptions::default())
            .expect("create client");

        let response = client
            .get_protocol_states(&Default::default())
            .await
            .expect("get state");
        let states = response.states;

        mocked_server.assert();
        assert_eq!(states.len(), 1);
        assert_eq!(states[0].component_id, "State1");
        let expected_attributes =
            [("attribute_1".to_string(), Bytes::from(1000_u64.to_be_bytes()))]
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
              "page_size": 20,
              "total": 10
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
        let client = HttpRPCClient::new(server.url().as_str(), HttpRPCClientOptions::default())
            .expect("create client");

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
        assert_eq!(response.pagination, PaginationResponse { page: 0, page_size: 20, total: 10 });
    }

    #[tokio::test]
    async fn test_get_protocol_systems() {
        let mut server = Server::new_async().await;
        let server_resp = r#"
        {
            "protocol_systems": [
                "system1",
                "system2"
            ],
            "pagination": {
                "page": 0,
                "page_size": 20,
                "total": 10
            }
        }
        "#;
        // test that the response is deserialized correctly
        serde_json::from_str::<ProtocolSystemsRequestResponse>(server_resp).expect("deserialize");

        let mocked_server = server
            .mock("POST", "/v1/protocol_systems")
            .expect(1)
            .with_body(server_resp)
            .create_async()
            .await;
        let client = HttpRPCClient::new(server.url().as_str(), HttpRPCClientOptions::default())
            .expect("create client");

        let response = client
            .get_protocol_systems(&Default::default())
            .await
            .expect("get protocol systems");
        let protocol_systems = response.protocol_systems;

        mocked_server.assert();
        assert_eq!(protocol_systems, vec!["system1", "system2"]);
    }

    #[tokio::test]
    async fn test_get_component_tvl() {
        let mut server = Server::new_async().await;
        let server_resp = r#"
        {
            "tvl": {
                "component1": 100.0
            },
            "pagination": {
                "page": 0,
                "page_size": 20,
                "total": 10
            }
        }
        "#;
        // test that the response is deserialized correctly
        serde_json::from_str::<ComponentTvlRequestResponse>(server_resp).expect("deserialize");

        let mocked_server = server
            .mock("POST", "/v1/component_tvl")
            .expect(1)
            .with_body(server_resp)
            .create_async()
            .await;
        let client = HttpRPCClient::new(server.url().as_str(), HttpRPCClientOptions::default())
            .expect("create client");

        let response = client
            .get_component_tvl(&Default::default())
            .await
            .expect("get protocol systems");
        let component_tvl = response.tvl;

        mocked_server.assert();
        assert_eq!(component_tvl.get("component1"), Some(&100.0));
    }

    #[tokio::test]
    async fn test_get_traced_entry_points() {
        let mut server = Server::new_async().await;
        let server_resp = r#"
        {
            "traced_entry_points": {
                "component_1": [
                    [
                        {
                            "entry_point": {
                                "external_id": "entrypoint_a",
                                "target": "0x0000000000000000000000000000000000000001",
                                "signature": "sig()"
                            },
                            "params": {
                                "method": "rpctracer",
                                "caller": "0x000000000000000000000000000000000000000a",
                                "calldata": "0x000000000000000000000000000000000000000b"
                            }
                        },
                        {
                            "retriggers": [
                                [
                                    "0x00000000000000000000000000000000000000aa",
                                    {"key": "0x0000000000000000000000000000000000000aaa", "offset": 12}
                                ]
                            ],
                            "accessed_slots": {
                                "0x0000000000000000000000000000000000aaaa": [
                                    "0x0000000000000000000000000000000000aaaa"
                                ]
                            }
                        }
                    ]
                ]
            },
            "pagination": {
                "page": 0,
                "page_size": 20,
                "total": 1
            }
        }
        "#;
        // test that the response is deserialized correctly
        serde_json::from_str::<TracedEntryPointRequestResponse>(server_resp).expect("deserialize");

        let mocked_server = server
            .mock("POST", "/v1/traced_entry_points")
            .expect(1)
            .with_body(server_resp)
            .create_async()
            .await;
        let client = HttpRPCClient::new(server.url().as_str(), HttpRPCClientOptions::default())
            .expect("create client");

        let response = client
            .get_traced_entry_points(&Default::default())
            .await
            .expect("get traced entry points");
        let entrypoints = response.traced_entry_points;

        mocked_server.assert();
        assert_eq!(entrypoints.len(), 1);
        let comp1_entrypoints = entrypoints
            .get("component_1")
            .expect("component_1 entrypoints should exist");
        assert_eq!(comp1_entrypoints.len(), 1);

        let (entrypoint, trace_result) = &comp1_entrypoints[0];
        assert_eq!(entrypoint.entry_point.external_id, "entrypoint_a");
        assert_eq!(
            entrypoint.entry_point.target,
            Bytes::from_str("0x0000000000000000000000000000000000000001").unwrap()
        );
        assert_eq!(entrypoint.entry_point.signature, "sig()");
        let TracingParams::RPCTracer(rpc_params) = &entrypoint.params;
        assert_eq!(
            rpc_params.caller,
            Some(Bytes::from("0x000000000000000000000000000000000000000a"))
        );
        assert_eq!(rpc_params.calldata, Bytes::from("0x000000000000000000000000000000000000000b"));

        assert_eq!(
            trace_result.retriggers,
            HashSet::from([(
                Bytes::from("0x00000000000000000000000000000000000000aa"),
                AddressStorageLocation::new(
                    Bytes::from("0x0000000000000000000000000000000000000aaa"),
                    12
                )
            )])
        );
        assert_eq!(trace_result.accessed_slots.len(), 1);
        assert_eq!(
            trace_result.accessed_slots,
            HashMap::from([(
                Bytes::from("0x0000000000000000000000000000000000aaaa"),
                HashSet::from([Bytes::from("0x0000000000000000000000000000000000aaaa")])
            )])
        );
    }

    #[tokio::test]
    async fn test_parse_retry_value_numeric() {
        let result = parse_retry_value("60");
        assert!(result.is_some());

        let expected_time = SystemTime::now() + Duration::from_secs(60);
        let actual_time = result.unwrap();

        // Allow for small timing differences during test execution
        let diff = if actual_time > expected_time {
            actual_time
                .duration_since(expected_time)
                .unwrap()
        } else {
            expected_time
                .duration_since(actual_time)
                .unwrap()
        };
        assert!(diff < Duration::from_secs(1), "Time difference too large: {:?}", diff);
    }

    #[tokio::test]
    async fn test_parse_retry_value_rfc2822() {
        // Use a fixed future date in RFC2822 format
        let rfc2822_date = "Sat, 01 Jan 2030 12:00:00 +0000";
        let result = parse_retry_value(rfc2822_date);
        assert!(result.is_some());

        let parsed_time = result.unwrap();
        assert!(parsed_time > SystemTime::now());
    }

    #[tokio::test]
    async fn test_parse_retry_value_invalid_formats() {
        // Test various invalid formats
        assert!(parse_retry_value("invalid").is_none());
        assert!(parse_retry_value("").is_none());
        assert!(parse_retry_value("not_a_number").is_none());
        assert!(parse_retry_value("Mon, 32 Jan 2030 25:00:00 +0000").is_none()); // Invalid date
    }

    #[tokio::test]
    async fn test_parse_retry_value_zero_seconds() {
        let result = parse_retry_value("0");
        assert!(result.is_some());

        let expected_time = SystemTime::now();
        let actual_time = result.unwrap();

        // Should be very close to current time
        let diff = if actual_time > expected_time {
            actual_time
                .duration_since(expected_time)
                .unwrap()
        } else {
            expected_time
                .duration_since(actual_time)
                .unwrap()
        };
        assert!(diff < Duration::from_secs(1));
    }

    #[tokio::test]
    async fn test_error_for_response_rate_limited() {
        let mut server = Server::new_async().await;
        let mock = server
            .mock("GET", "/test")
            .with_status(429)
            .with_header("Retry-After", "60")
            .create_async()
            .await;

        let client = reqwest::Client::new();
        let response = client
            .get(format!("{}/test", server.url()))
            .send()
            .await
            .unwrap();

        let http_client =
            HttpRPCClient::new(server.url().as_str(), HttpRPCClientOptions::default())
                .unwrap()
                .with_test_backoff_policy();
        let result = http_client
            .error_for_response(response)
            .await;

        mock.assert();
        assert!(matches!(result, Err(RPCError::RateLimited(_))));
        if let Err(RPCError::RateLimited(retry_after)) = result {
            assert!(retry_after.is_some());
        }
    }

    #[tokio::test]
    async fn test_error_for_response_rate_limited_no_header() {
        let mut server = Server::new_async().await;
        let mock = server
            .mock("GET", "/test")
            .with_status(429)
            .create_async()
            .await;

        let client = reqwest::Client::new();
        let response = client
            .get(format!("{}/test", server.url()))
            .send()
            .await
            .unwrap();

        let http_client =
            HttpRPCClient::new(server.url().as_str(), HttpRPCClientOptions::default())
                .unwrap()
                .with_test_backoff_policy();
        let result = http_client
            .error_for_response(response)
            .await;

        mock.assert();
        assert!(matches!(result, Err(RPCError::RateLimited(None))));
    }

    #[tokio::test]
    async fn test_error_for_response_server_errors() {
        let test_cases =
            vec![(502, "Bad Gateway"), (503, "Service Unavailable"), (504, "Gateway Timeout")];

        for (status_code, expected_body) in test_cases {
            let mut server = Server::new_async().await;
            let mock = server
                .mock("GET", "/test")
                .with_status(status_code)
                .with_body(expected_body)
                .create_async()
                .await;

            let client = reqwest::Client::new();
            let response = client
                .get(format!("{}/test", server.url()))
                .send()
                .await
                .unwrap();

            let http_client =
                HttpRPCClient::new(server.url().as_str(), HttpRPCClientOptions::default())
                    .unwrap()
                    .with_test_backoff_policy();
            let result = http_client
                .error_for_response(response)
                .await;

            mock.assert();
            assert!(matches!(result, Err(RPCError::ServerUnreachable(_))));
            if let Err(RPCError::ServerUnreachable(body)) = result {
                assert_eq!(body, expected_body);
            }
        }
    }

    #[tokio::test]
    async fn test_error_for_response_success() {
        let mut server = Server::new_async().await;
        let mock = server
            .mock("GET", "/test")
            .with_status(200)
            .with_body("success")
            .create_async()
            .await;

        let client = reqwest::Client::new();
        let response = client
            .get(format!("{}/test", server.url()))
            .send()
            .await
            .unwrap();

        let http_client =
            HttpRPCClient::new(server.url().as_str(), HttpRPCClientOptions::default())
                .unwrap()
                .with_test_backoff_policy();
        let result = http_client
            .error_for_response(response)
            .await;

        mock.assert();
        assert!(result.is_ok());

        let response = result.unwrap();
        assert_eq!(response.status(), 200);
    }

    #[tokio::test]
    async fn test_handle_error_for_backoff_server_unreachable() {
        let http_client =
            HttpRPCClient::new("http://localhost:8080", HttpRPCClientOptions::default())
                .unwrap()
                .with_test_backoff_policy();
        let error = RPCError::ServerUnreachable("Service down".to_string());

        let backoff_error = http_client
            .handle_error_for_backoff(error)
            .await;

        match backoff_error {
            backoff::Error::Transient { err: RPCError::ServerUnreachable(msg), retry_after } => {
                assert_eq!(msg, "Service down");
                assert_eq!(retry_after, Some(Duration::from_millis(50))); // Fast test duration
            }
            _ => panic!("Expected transient error for ServerUnreachable"),
        }
    }

    #[tokio::test]
    async fn test_handle_error_for_backoff_rate_limited_with_retry_after() {
        let http_client =
            HttpRPCClient::new("http://localhost:8080", HttpRPCClientOptions::default())
                .unwrap()
                .with_test_backoff_policy();
        let future_time = SystemTime::now() + Duration::from_secs(30);
        let error = RPCError::RateLimited(Some(future_time));

        let backoff_error = http_client
            .handle_error_for_backoff(error)
            .await;

        match backoff_error {
            backoff::Error::Transient { err: RPCError::RateLimited(retry_after), .. } => {
                assert_eq!(retry_after, Some(future_time));
            }
            _ => panic!("Expected transient error for RateLimited"),
        }

        // Verify that retry_after was stored in the client state
        let stored_retry_after = http_client.retry_after.read().await;
        assert_eq!(*stored_retry_after, Some(future_time));
    }

    #[tokio::test]
    async fn test_handle_error_for_backoff_rate_limited_no_retry_after() {
        let http_client =
            HttpRPCClient::new("http://localhost:8080", HttpRPCClientOptions::default())
                .unwrap()
                .with_test_backoff_policy();
        let error = RPCError::RateLimited(None);

        let backoff_error = http_client
            .handle_error_for_backoff(error)
            .await;

        match backoff_error {
            backoff::Error::Transient { err: RPCError::RateLimited(None), .. } => {
                // This is expected - no retry-after still allows retries with default policy
            }
            _ => panic!("Expected transient error for RateLimited without retry-after"),
        }
    }

    #[tokio::test]
    async fn test_handle_error_for_backoff_other_errors() {
        let http_client =
            HttpRPCClient::new("http://localhost:8080", HttpRPCClientOptions::default())
                .unwrap()
                .with_test_backoff_policy();
        let error = RPCError::ParseResponse("Invalid JSON".to_string());

        let backoff_error = http_client
            .handle_error_for_backoff(error)
            .await;

        match backoff_error {
            backoff::Error::Permanent(RPCError::ParseResponse(msg)) => {
                assert_eq!(msg, "Invalid JSON");
            }
            _ => panic!("Expected permanent error for ParseResponse"),
        }
    }

    #[tokio::test]
    async fn test_wait_until_retry_after_no_retry_time() {
        let http_client =
            HttpRPCClient::new("http://localhost:8080", HttpRPCClientOptions::default())
                .unwrap()
                .with_test_backoff_policy();

        let start = std::time::Instant::now();
        http_client
            .wait_until_retry_after()
            .await;
        let elapsed = start.elapsed();

        // Should return immediately if no retry time is set
        assert!(elapsed < Duration::from_millis(100));
    }

    #[tokio::test]
    async fn test_wait_until_retry_after_past_time() {
        let http_client =
            HttpRPCClient::new("http://localhost:8080", HttpRPCClientOptions::default())
                .unwrap()
                .with_test_backoff_policy();

        // Set a retry time in the past
        let past_time = SystemTime::now() - Duration::from_secs(10);
        *http_client.retry_after.write().await = Some(past_time);

        let start = std::time::Instant::now();
        http_client
            .wait_until_retry_after()
            .await;
        let elapsed = start.elapsed();

        // Should return immediately if retry time is in the past
        assert!(elapsed < Duration::from_millis(100));
    }

    #[tokio::test]
    async fn test_wait_until_retry_after_future_time() {
        let http_client =
            HttpRPCClient::new("http://localhost:8080", HttpRPCClientOptions::default())
                .unwrap()
                .with_test_backoff_policy();

        // Set a retry time 100ms in the future
        let future_time = SystemTime::now() + Duration::from_millis(100);
        *http_client.retry_after.write().await = Some(future_time);

        let start = std::time::Instant::now();
        http_client
            .wait_until_retry_after()
            .await;
        let elapsed = start.elapsed();

        // Should wait approximately the specified duration
        assert!(elapsed >= Duration::from_millis(80)); // Allow some tolerance
        assert!(elapsed <= Duration::from_millis(200)); // Upper bound for test stability
    }

    #[tokio::test]
    async fn test_make_post_request_success() {
        let mut server = Server::new_async().await;
        let server_resp = r#"{"success": true}"#;

        let mock = server
            .mock("POST", "/test")
            .with_status(200)
            .with_body(server_resp)
            .create_async()
            .await;

        let http_client =
            HttpRPCClient::new(server.url().as_str(), HttpRPCClientOptions::default())
                .unwrap()
                .with_test_backoff_policy();
        let request_body = serde_json::json!({"test": "data"});
        let uri = format!("{}/test", server.url());

        let result = http_client
            .make_post_request(&request_body, &uri)
            .await;

        mock.assert();
        assert!(result.is_ok());

        let response = result.unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(response.text().await.unwrap(), server_resp);
    }

    #[tokio::test]
    async fn test_make_post_request_retry_on_server_error() {
        let mut server = Server::new_async().await;
        // First request fails with 503, second succeeds
        let error_mock = server
            .mock("POST", "/test")
            .with_status(503)
            .with_body("Service Unavailable")
            .expect(1)
            .create_async()
            .await;

        let success_mock = server
            .mock("POST", "/test")
            .with_status(200)
            .with_body(r#"{"success": true}"#)
            .expect(1)
            .create_async()
            .await;

        let http_client =
            HttpRPCClient::new(server.url().as_str(), HttpRPCClientOptions::default())
                .unwrap()
                .with_test_backoff_policy();
        let request_body = serde_json::json!({"test": "data"});
        let uri = format!("{}/test", server.url());

        let result = http_client
            .make_post_request(&request_body, &uri)
            .await;

        error_mock.assert();
        success_mock.assert();
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_make_post_request_respect_retry_after_header() {
        let mut server = Server::new_async().await;

        // First request returns 429 with retry-after, second succeeds
        let rate_limit_mock = server
            .mock("POST", "/test")
            .with_status(429)
            .with_header("Retry-After", "1") // 1 second
            .expect(1)
            .create_async()
            .await;

        let success_mock = server
            .mock("POST", "/test")
            .with_status(200)
            .with_body(r#"{"success": true}"#)
            .expect(1)
            .create_async()
            .await;

        let http_client =
            HttpRPCClient::new(server.url().as_str(), HttpRPCClientOptions::default())
                .unwrap()
                .with_test_backoff_policy();
        let request_body = serde_json::json!({"test": "data"});
        let uri = format!("{}/test", server.url());

        let start = std::time::Instant::now();
        let result = http_client
            .make_post_request(&request_body, &uri)
            .await;
        let elapsed = start.elapsed();

        rate_limit_mock.assert();
        success_mock.assert();
        assert!(result.is_ok());

        // Should have waited at least 1 second due to retry-after header
        assert!(elapsed >= Duration::from_millis(900)); // Allow some tolerance
        assert!(elapsed <= Duration::from_millis(2000)); // Upper bound for test stability
    }

    #[tokio::test]
    async fn test_make_post_request_permanent_error() {
        let mut server = Server::new_async().await;

        let mock = server
            .mock("POST", "/test")
            .with_status(400) // Bad Request - should not be retried
            .with_body("Bad Request")
            .expect(1)
            .create_async()
            .await;

        let http_client =
            HttpRPCClient::new(server.url().as_str(), HttpRPCClientOptions::default())
                .unwrap()
                .with_test_backoff_policy();
        let request_body = serde_json::json!({"test": "data"});
        let uri = format!("{}/test", server.url());

        let result = http_client
            .make_post_request(&request_body, &uri)
            .await;

        mock.assert();
        assert!(result.is_ok()); // 400 doesn't trigger retry logic, just returns the response

        let response = result.unwrap();
        assert_eq!(response.status(), 400);
    }

    #[tokio::test]
    async fn test_concurrent_requests_with_different_retry_after() {
        let mut server = Server::new_async().await;

        // First request gets rate limited with 1 second retry-after
        let rate_limit_mock_1 = server
            .mock("POST", "/test1")
            .with_status(429)
            .with_header("Retry-After", "1")
            .expect(1)
            .create_async()
            .await;

        // Second request gets rate limited with 2 second retry-after
        let rate_limit_mock_2 = server
            .mock("POST", "/test2")
            .with_status(429)
            .with_header("Retry-After", "2")
            .expect(1)
            .create_async()
            .await;

        // Success mocks for retries
        let success_mock_1 = server
            .mock("POST", "/test1")
            .with_status(200)
            .with_body(r#"{"result": "success1"}"#)
            .expect(1)
            .create_async()
            .await;

        let success_mock_2 = server
            .mock("POST", "/test2")
            .with_status(200)
            .with_body(r#"{"result": "success2"}"#)
            .expect(1)
            .create_async()
            .await;

        let http_client =
            HttpRPCClient::new(server.url().as_str(), HttpRPCClientOptions::default())
                .unwrap()
                .with_test_backoff_policy();
        let request_body = serde_json::json!({"test": "data"});

        let uri1 = format!("{}/test1", server.url());
        let uri2 = format!("{}/test2", server.url());

        // Start both requests concurrently
        let start = std::time::Instant::now();
        let (result1, result2) = tokio::join!(
            http_client.make_post_request(&request_body, &uri1),
            http_client.make_post_request(&request_body, &uri2)
        );
        let elapsed = start.elapsed();

        rate_limit_mock_1.assert();
        rate_limit_mock_2.assert();
        success_mock_1.assert();
        success_mock_2.assert();

        assert!(result1.is_ok());
        assert!(result2.is_ok());

        // Both requests should succeed, but the second should take longer due to the 2s retry-after
        // The total time should be at least 2 seconds since the shared retry_after state
        // gets updated by both requests
        assert!(elapsed >= Duration::from_millis(1800)); // Allow some tolerance
        assert!(elapsed <= Duration::from_millis(3000)); // Upper bound

        // Check the final retry_after state - should be the latest (higher) value
        let final_retry_after = http_client.retry_after.read().await;
        assert!(final_retry_after.is_some());

        // The retry_after should be set to the latest (higher) value from the two requests
        if let Some(retry_time) = *final_retry_after {
            // The retry_after time might be in the past now since we waited,
            // but it should be reasonable (not too far in past/future)
            let now = SystemTime::now();
            let diff = if retry_time > now {
                retry_time.duration_since(now).unwrap()
            } else {
                now.duration_since(retry_time).unwrap()
            };

            // Should be within a reasonable range (the 2s retry-after plus some buffer)
            assert!(diff <= Duration::from_secs(3), "Retry time difference too large: {:?}", diff);
        }
    }

    #[tokio::test]
    async fn test_get_snapshots() {
        let mut server = Server::new_async().await;

        // Mock protocol states response
        let protocol_states_resp = r#"
        {
            "states": [
                {
                    "component_id": "component1",
                    "attributes": {
                        "attribute_1": "0x00000000000003e8"
                    },
                    "balances": {
                        "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2": "0x01f4"
                    }
                }
            ],
            "pagination": {
                "page": 0,
                "page_size": 100,
                "total": 1
            }
        }
        "#;

        // Mock contract state response
        let contract_state_resp = r#"
        {
            "accounts": [
                {
                    "chain": "ethereum",
                    "address": "0x1111111111111111111111111111111111111111",
                    "title": "",
                    "slots": {},
                    "native_balance": "0x01f4",
                    "token_balances": {},
                    "code": "0x00",
                    "code_hash": "0x5c06b7c5b3d910fd33bc2229846f9ddaf91d584d9b196e16636901ac3a77077e",
                    "balance_modify_tx": "0x0000000000000000000000000000000000000000000000000000000000000000",
                    "code_modify_tx": "0x0000000000000000000000000000000000000000000000000000000000000000",
                    "creation_tx": null
                }
            ],
            "pagination": {
                "page": 0,
                "page_size": 100,
                "total": 1
            }
        }
        "#;

        // Mock component TVL response
        let tvl_resp = r#"
        {
            "tvl": {
                "component1": 1000000.0
            },
            "pagination": {
                "page": 0,
                "page_size": 100,
                "total": 1
            }
        }
        "#;

        let protocol_states_mock = server
            .mock("POST", "/v1/protocol_state")
            .expect(1)
            .with_body(protocol_states_resp)
            .create_async()
            .await;

        let contract_state_mock = server
            .mock("POST", "/v1/contract_state")
            .expect(1)
            .with_body(contract_state_resp)
            .create_async()
            .await;

        let tvl_mock = server
            .mock("POST", "/v1/component_tvl")
            .expect(1)
            .with_body(tvl_resp)
            .create_async()
            .await;

        let client = HttpRPCClient::new(server.url().as_str(), HttpRPCClientOptions::default())
            .expect("create client");

        #[allow(deprecated)]
        let component = tycho_common::dto::ProtocolComponent {
            id: "component1".to_string(),
            protocol_system: "test_protocol".to_string(),
            protocol_type_name: "test_type".to_string(),
            chain: Chain::Ethereum,
            tokens: vec![],
            contract_ids: vec![
                Bytes::from_str("0x1111111111111111111111111111111111111111").unwrap()
            ],
            static_attributes: HashMap::new(),
            change: tycho_common::dto::ChangeType::Creation,
            creation_tx: Bytes::from_str(
                "0x0000000000000000000000000000000000000000000000000000000000000000",
            )
            .unwrap(),
            created_at: chrono::Utc::now().naive_utc(),
        };

        let mut components = HashMap::new();
        components.insert("component1".to_string(), component);

        let contract_ids =
            vec![Bytes::from_str("0x1111111111111111111111111111111111111111").unwrap()];

        let request = SnapshotParameters::new(
            Chain::Ethereum,
            "test_protocol",
            &components,
            &contract_ids,
            12345,
        );

        let response = client
            .get_snapshots(&request, 100, 4)
            .await
            .expect("get snapshots");

        // Verify all mocks were called
        protocol_states_mock.assert();
        contract_state_mock.assert();
        tvl_mock.assert();

        // Assert states
        assert_eq!(response.states.len(), 1);
        assert!(response
            .states
            .contains_key("component1"));

        // Check that the state has the expected TVL
        let component_state = response
            .states
            .get("component1")
            .unwrap();
        assert_eq!(component_state.component_tvl, Some(1000000.0));

        // Assert VM storage
        assert_eq!(response.vm_storage.len(), 1);
        let contract_addr = Bytes::from_str("0x1111111111111111111111111111111111111111").unwrap();
        assert!(response
            .vm_storage
            .contains_key(&contract_addr));
    }

    #[tokio::test]
    async fn test_get_snapshots_empty_components() {
        let server = Server::new_async().await;
        let client = HttpRPCClient::new(server.url().as_str(), HttpRPCClientOptions::default())
            .expect("create client");

        let components = HashMap::new();
        let contract_ids = vec![];

        let request = SnapshotParameters::new(
            Chain::Ethereum,
            "test_protocol",
            &components,
            &contract_ids,
            12345,
        );

        let response = client
            .get_snapshots(&request, 100, 4)
            .await
            .expect("get snapshots");

        // Should return empty response without making any requests
        assert!(response.states.is_empty());
        assert!(response.vm_storage.is_empty());
    }

    #[tokio::test]
    async fn test_get_snapshots_without_tvl() {
        let mut server = Server::new_async().await;

        let protocol_states_resp = r#"
        {
            "states": [
                {
                    "component_id": "component1",
                    "attributes": {},
                    "balances": {}
                }
            ],
            "pagination": {
                "page": 0,
                "page_size": 100,
                "total": 1
            }
        }
        "#;

        let protocol_states_mock = server
            .mock("POST", "/v1/protocol_state")
            .expect(1)
            .with_body(protocol_states_resp)
            .create_async()
            .await;

        let client = HttpRPCClient::new(server.url().as_str(), HttpRPCClientOptions::default())
            .expect("create client");

        // Create test component
        #[allow(deprecated)]
        let component = tycho_common::dto::ProtocolComponent {
            id: "component1".to_string(),
            protocol_system: "test_protocol".to_string(),
            protocol_type_name: "test_type".to_string(),
            chain: Chain::Ethereum,
            tokens: vec![],
            contract_ids: vec![],
            static_attributes: HashMap::new(),
            change: tycho_common::dto::ChangeType::Creation,
            creation_tx: Bytes::from_str(
                "0x0000000000000000000000000000000000000000000000000000000000000000",
            )
            .unwrap(),
            created_at: chrono::Utc::now().naive_utc(),
        };

        let mut components = HashMap::new();
        components.insert("component1".to_string(), component);
        let contract_ids = vec![];

        let request = SnapshotParameters::new(
            Chain::Ethereum,
            "test_protocol",
            &components,
            &contract_ids,
            12345,
        )
        .include_balances(false)
        .include_tvl(false);

        let response = client
            .get_snapshots(&request, 100, 4)
            .await
            .expect("get snapshots");

        // Verify only necessary mocks were called
        protocol_states_mock.assert();
        // No contract_state_mock.assert() since contract_ids is empty
        // No tvl_mock.assert() since include_tvl is false

        assert_eq!(response.states.len(), 1);
        // Check that TVL is None since we didn't request it
        let component_state = response
            .states
            .get("component1")
            .unwrap();
        assert_eq!(component_state.component_tvl, None);
    }

    #[tokio::test]
    async fn test_compression_enabled() {
        let mut server = Server::new_async().await;
        let server_resp = GET_CONTRACT_STATE_RESP;

        // Compress the response using zstd
        let compressed_body =
            zstd::encode_all(server_resp.as_bytes(), 0).expect("compression failed");

        let mocked_server = server
            .mock("POST", "/v1/contract_state")
            .expect(1)
            .with_header("Content-Encoding", "zstd")
            .with_body(compressed_body)
            .create_async()
            .await;

        // Create client with compression enabled
        let client = HttpRPCClient::new(
            server.url().as_str(),
            HttpRPCClientOptions::new().with_compression(true),
        )
        .expect("create client");

        let response = client
            .get_contract_state(&Default::default())
            .await
            .expect("get state");
        let accounts = response.accounts;

        mocked_server.assert();
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].native_balance, Bytes::from(500u16.to_be_bytes()));
    }

    #[tokio::test]
    async fn test_compression_disabled() {
        let mut server = Server::new_async().await;
        let server_resp = GET_CONTRACT_STATE_RESP;

        // Server sends plain text response
        let mocked_server = server
            .mock("POST", "/v1/contract_state")
            .expect(1)
            .with_body(server_resp)
            .create_async()
            .await;

        // Create client with compression disabled
        let client = HttpRPCClient::new(
            server.url().as_str(),
            HttpRPCClientOptions::new().with_compression(false),
        )
        .expect("create client");

        let response = client
            .get_contract_state(&Default::default())
            .await
            .expect("get state");
        let accounts = response.accounts;

        mocked_server.assert();
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].native_balance, Bytes::from(500u16.to_be_bytes()));
    }
}
