//! This module contains Tycho web services implementation
// TODO: remove once deprecated ProtocolId struct is removed
#![allow(deprecated)]
use actix_web::{dev::ServerHandle, web, App, HttpServer};
use actix_web_opentelemetry::RequestTracing;
use deltas_buffer::PendingDeltasBuffer;
use futures03::future::try_join_all;
use std::{collections::HashMap, sync::Arc};
use tokio::task::JoinHandle;
use tracing::info;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use tycho_core::{
    dto::{
        AccountUpdate, BlockParam, Chain, ChangeType, ContractId, Health, PaginationParams,
        PaginationResponse, ProtocolComponent, ProtocolComponentRequestResponse,
        ProtocolComponentsRequestBody, ProtocolId, ProtocolStateDelta, ProtocolStateRequestBody,
        ProtocolStateRequestResponse, ResponseAccount, ResponseProtocolState, ResponseToken,
        StateRequestBody, StateRequestResponse, TokensRequestBody, TokensRequestResponse,
        VersionParam,
    },
    storage::Gateway,
};

use crate::{
    extractor::{runner::ExtractorHandle, ExtractionError},
    services::deltas_buffer::PendingDeltas,
};

mod cache;
mod deltas_buffer;
mod rpc;
mod ws;

/// Helper struct to build Tycho services such as HTTP and WS server.
pub struct ServicesBuilder<G> {
    prefix: String,
    port: u16,
    bind: String,
    extractor_handles: ws::MessageSenderMap,
    db_gateway: G,
}

impl<G> ServicesBuilder<G>
where
    G: Gateway + Send + Sync + 'static,
{
    pub fn new(db_gateway: G) -> Self {
        Self {
            prefix: "v1".to_owned(),
            port: 4242,
            bind: "0.0.0.0".to_owned(),
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
            paths(
                rpc::contract_state,
                rpc::tokens,
                rpc::protocol_components,
                rpc::protocol_state,
                rpc::health,
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
                schemas(ProtocolStateRequestResponse),
                schemas(AccountUpdate),
                schemas(ProtocolId),
                schemas(ResponseProtocolState),
                schemas(ChangeType),
                schemas(ProtocolStateDelta),
                schemas(Health),
            )
        )]
        struct ApiDoc;

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
        let deltas_task = tokio::spawn(async move {
            pending_deltas_clone
                .run(extractor_handles_clone)
                .await
                .map_err(|err| ExtractionError::Unknown(err.to_string()))
        });
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
        let rpc_data = web::Data::new(rpc::RpcHandler::new(self.db_gateway, pending_deltas));

        let server = HttpServer::new(move || {
            let mut app = App::new()
                .app_data(rpc_data.clone())
                .service(
                    web::resource(format!("/{}/contract_state", self.prefix))
                        .route(web::post().to(rpc::contract_state::<G>)),
                )
                .service(
                    web::resource(format!("/{}/protocol_state", self.prefix))
                        .route(web::post().to(rpc::protocol_state::<G>)),
                )
                .service(
                    web::resource(format!("/{}/tokens", self.prefix))
                        .route(web::post().to(rpc::tokens::<G>)),
                )
                .service(
                    web::resource(format!("/{}/protocol_components", self.prefix))
                        .route(web::post().to(rpc::protocol_components::<G>)),
                )
                .service(
                    web::resource(format!("/{}/health", self.prefix))
                        .route(web::get().to(rpc::health)),
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
        .bind((self.bind, self.port))
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
