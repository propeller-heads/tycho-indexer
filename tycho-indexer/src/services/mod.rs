//! This module contains Tycho web services implementation
// TODO: remove once deprecated ProtocolId struct is removed
#![allow(deprecated)]
use std::{
    collections::HashMap,
    sync::{mpsc, Arc},
};

use actix_cors::Cors;
use actix_web::{dev::ServerHandle, http, web, App, HttpServer};
use actix_web_opentelemetry::RequestTracing;
use deltas_buffer::PendingDeltasBuffer;
use futures03::future::try_join_all;
use tokio::task::JoinHandle;
use tracing::info;
use tycho_common::{
    dto::{
        AccountUpdate, BlockParam, Chain, ChangeType, ComponentTvlRequestBody,
        ComponentTvlRequestResponse, ContractId, Health, PaginationParams, PaginationResponse,
        ProtocolComponent, ProtocolComponentRequestResponse, ProtocolComponentsRequestBody,
        ProtocolId, ProtocolStateDelta, ProtocolStateRequestBody, ProtocolStateRequestResponse,
        ProtocolSystemsRequestBody, ProtocolSystemsRequestResponse, ResponseAccount,
        ResponseProtocolState, ResponseToken, StateRequestBody, StateRequestResponse,
        TokensRequestBody, TokensRequestResponse, TracedEntryPointRequestBody,
        TracedEntryPointRequestResponse, VersionParam,
    },
    storage::Gateway,
};
use tycho_ethereum::entrypoint_tracer::tracer::EVMEntrypointService;
use utoipa::{
    openapi::security::{ApiKey, ApiKeyValue, SecurityScheme},
    Modify, OpenApi,
};
use utoipa_swagger_ui::SwaggerUi;

use crate::{
    extractor::{runner::ExtractorHandle, ExtractionError},
    services::deltas_buffer::PendingDeltas,
};

mod access_control;
mod cache;
mod deltas_buffer;
mod rpc;
mod ws;

/// Helper struct to build Tycho services such as HTTP and WS server.
pub struct ServicesBuilder<G> {
    prefix: String,
    port: u16,
    bind: String,
    rpc_url: String,
    api_key: String,
    extractor_handles: ws::MessageSenderMap,
    db_gateway: G,
}

impl<G> ServicesBuilder<G>
where
    G: Gateway + Send + Sync + 'static,
{
    pub fn new(db_gateway: G, rpc_url: String, api_key: String) -> Self {
        Self {
            prefix: "v1".to_owned(),
            port: 4242,
            bind: "0.0.0.0".to_owned(),
            rpc_url,
            api_key,
            extractor_handles: HashMap::new(),
            db_gateway,
        }
    }

    /// Registers extractors for the services
    pub fn register_extractors(mut self, handles: Vec<ExtractorHandle>) -> Self {
        for e in handles {
            let id = e.get_id();
            self.extractor_handles
                .insert(id, Arc::new(e));
        }
        self
    }

    /// Sets the URL prefix for the endpoints
    pub fn prefix(mut self, v: &str) -> Self {
        v.clone_into(&mut self.prefix);
        self
    }

    /// Sets the IP address for the server
    pub fn bind(mut self, v: &str) -> Self {
        v.clone_into(&mut self.bind);
        self
    }

    /// Sets the port for the server
    pub fn port(mut self, v: u16) -> Self {
        self.port = v;
        self
    }

    /// Starts the Tycho server. Returns a tuple containing a handle for the server and a Tokio
    /// handle for the tasks. If no extractor tasks are registered, it starts the server without
    /// running the delta tasks.
    pub fn run(
        self,
    ) -> Result<(ServerHandle, JoinHandle<Result<(), ExtractionError>>), ExtractionError> {
        #[derive(OpenApi)]
        #[openapi(
            info(title = "Tycho-Indexer RPC",),
            paths(
                rpc::health,
                rpc::protocol_systems,
                rpc::tokens,
                rpc::protocol_components,
                rpc::traced_entry_points,
                rpc::protocol_state,
                rpc::contract_state,
                rpc::component_tvl,
            ),
            components(
                schemas(VersionParam),
                schemas(BlockParam),
                schemas(ContractId),
                schemas(StateRequestResponse),
                schemas(StateRequestBody),
                schemas(Chain),
                schemas(ResponseAccount),
                schemas(TokensRequestBody),
                schemas(TokensRequestResponse),
                schemas(PaginationParams),
                schemas(PaginationResponse),
                schemas(ResponseToken),
                schemas(ProtocolComponentsRequestBody),
                schemas(ProtocolComponentRequestResponse),
                schemas(ProtocolComponent),
                schemas(ProtocolStateRequestBody),
                schemas(TracedEntryPointRequestBody),
                schemas(TracedEntryPointRequestResponse),
                schemas(ProtocolStateRequestResponse),
                schemas(AccountUpdate),
                schemas(ProtocolId),
                schemas(ResponseProtocolState),
                schemas(ChangeType),
                schemas(ProtocolStateDelta),
                schemas(Health),
                schemas(ProtocolSystemsRequestBody),
                schemas(ProtocolSystemsRequestResponse),
                schemas(ComponentTvlRequestBody),
                schemas(ComponentTvlRequestResponse),
            ),
            modifiers(&SecurityAddon),
        )]
        struct ApiDoc;

        struct SecurityAddon;

        impl Modify for SecurityAddon {
            fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
                let components = openapi.components.as_mut().unwrap();
                components.add_security_scheme(
                    "apiKey",
                    SecurityScheme::ApiKey(ApiKey::Header(ApiKeyValue::with_description(
                        "authorization",
                        "Use 'sampletoken' as value for testing",
                    ))),
                );
            }
        }

        let open_api = ApiDoc::openapi();

        // If no extractors are registered, run the server without spawning extractor-related tasks.
        if self.extractor_handles.is_empty() {
            info!("Starting standalone rpc server");
            self.start_server(None, open_api, None)
        } else {
            info!("Starting full server");
            self.start_server_with_deltas(open_api)
        }
    }

    /// Runs the server with both RPC and WebSocket services, and spawns tasks for handling
    /// pending delta processing.
    fn start_server_with_deltas(
        self,
        openapi: utoipa::openapi::OpenApi,
    ) -> Result<(ServerHandle, JoinHandle<Result<(), ExtractionError>>), ExtractionError> {
        let pending_deltas = PendingDeltas::new(
            self.extractor_handles
                .keys()
                .map(|e_id| e_id.name.as_str()),
        );
        let extractor_handles_clone = self
            .extractor_handles
            .clone()
            .into_values();
        let pending_deltas_clone = pending_deltas.clone();
        let (start_tx, start_rx) = mpsc::sync_channel::<()>(1);
        let deltas_task = tokio::spawn(async move {
            pending_deltas_clone
                .run(extractor_handles_clone, start_tx)
                .await
                .map_err(|err| ExtractionError::Unknown(err.to_string()))
        });

        // Wait for the pending deltas task to start
        start_rx.recv().map_err(|err| {
            ExtractionError::ServiceError(format!(
                "Failed to receive PendingDeltas start signal: {err}"
            ))
        })?;
        let ws_data = web::Data::new(ws::WsData::new(self.extractor_handles.clone()));
        let (server_handle, server_task) =
            self.start_server(Some(ws_data), openapi, Some(Arc::new(pending_deltas)))?;

        let task = tokio::spawn(async move {
            try_join_all(vec![deltas_task, server_task])
                .await
                .map_err(|err| ExtractionError::Unknown(err.to_string()))?;
            Ok(())
        });

        Ok((server_handle, task))
    }

    /// Helper to spawn the main server task, optionally enabling WebSocket services.
    fn start_server(
        self,
        ws_data: Option<web::Data<ws::WsData>>,
        openapi: utoipa::openapi::OpenApi,
        pending_deltas: Option<Arc<dyn PendingDeltasBuffer + Send + Sync>>,
    ) -> Result<(ServerHandle, JoinHandle<Result<(), ExtractionError>>), ExtractionError> {
        let tracer = EVMEntrypointService::try_from_url(&self.rpc_url)
            .map_err(|err| ExtractionError::Setup(format!("Failed to create tracer: {err}")))?;

        let rpc_data =
            web::Data::new(rpc::RpcHandler::new(self.db_gateway, pending_deltas, tracer));

        let server = HttpServer::new(move || {
            let cors = Cors::default()
                .allowed_origin("https://open.gitbook.com")
                .allowed_origin_fn(|origin, _req_head| {
                    // Allow all propellerheads.xyz subdomains
                    origin
                        .as_bytes()
                        .ends_with(b".propellerheads.xyz")
                })
                .allow_any_method()
                .allowed_headers(vec![
                    http::header::AUTHORIZATION,
                    http::header::ACCEPT,
                    http::header::CONTENT_TYPE,
                ])
                .max_age(3600); // Cache preflight requests for 1 hour

            let mut app = App::new()
                .wrap(cors)
                .app_data(rpc_data.clone())
                .service(
                    web::resource(format!("/{}/contract_state", self.prefix))
                        .route(web::post().to(rpc::contract_state::<G, EVMEntrypointService>)),
                )
                .service(
                    web::resource(format!("/{}/protocol_state", self.prefix))
                        .route(web::post().to(rpc::protocol_state::<G, EVMEntrypointService>)),
                )
                .service(
                    web::resource(format!("/{}/tokens", self.prefix))
                        .route(web::post().to(rpc::tokens::<G, EVMEntrypointService>)),
                )
                .service(
                    web::resource(format!("/{}/protocol_components", self.prefix))
                        .route(web::post().to(rpc::protocol_components::<G, EVMEntrypointService>)),
                )
                .service(
                    web::resource(format!("/{}/traced_entry_points", self.prefix))
                        .route(web::post().to(rpc::traced_entry_points::<G, EVMEntrypointService>)),
                )
                .service(
                    web::resource(format!("/{}/add_entry_points", self.prefix))
                        // TODO: add swagger service for internal endpoints
                        .wrap(access_control::AccessControl::new(&self.api_key))
                        .route(web::post().to(rpc::add_entry_points::<G, EVMEntrypointService>)),
                )
                .service(
                    web::resource(format!("/{}/health", self.prefix))
                        .route(web::get().to(rpc::health)),
                )
                .service(
                    web::resource(format!("/{}/protocol_systems", self.prefix))
                        .route(web::post().to(rpc::protocol_systems::<G, EVMEntrypointService>)),
                )
                .service(
                    web::resource(format!("/{}/component_tvl", self.prefix))
                        .route(web::post().to(rpc::component_tvl::<G, EVMEntrypointService>)),
                )
                .wrap(RequestTracing::new())
                .service(
                    SwaggerUi::new("/docs/{_:.*}").url("/api-docs/openapi.json", openapi.clone()),
                );

            if let Some(ws_data) = ws_data.clone() {
                app = app.app_data(ws_data).service(
                    web::resource(format!("/{}/ws", self.prefix))
                        .route(web::get().to(ws::WsActor::ws_index)),
                );
            }

            app
        })
        .keep_alive(std::time::Duration::from_secs(60)) // prevents early connection closures
        // Allows clients up to 30 seconds to reconnect before forcefully closing the connection.
        // This prevents us from closing a connection the client is expecting to be able to reuse.
        .client_disconnect_timeout(std::time::Duration::from_secs(30))
        .bind_auto_h2c((self.bind, self.port)) // allow HTTP2 requests over http connections
        .map_err(|err| ExtractionError::ServiceError(err.to_string()))?
        .run();
        let handle = server.handle();
        let task = tokio::spawn(async move {
            server
                .await
                .map_err(|err| ExtractionError::Unknown(err.to_string()))
        });
        Ok((handle, task))
    }
}
