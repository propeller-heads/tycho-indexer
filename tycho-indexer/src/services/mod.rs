//! This module contains Tycho web services implementation

use std::{collections::HashMap, sync::Arc};

use crate::extractor::{runner::ExtractorHandle, ExtractionError};
use actix_web::{dev::ServerHandle, web, App, HttpServer};
use actix_web_opentelemetry::RequestTracing;
use tokio::task::JoinHandle;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use tycho_core::{
    dto::{
        AccountUpdate, BlockParam, ChangeType, ContractDeltaRequestBody,
        ContractDeltaRequestResponse, PaginationParams, ProtocolComponent,
        ProtocolComponentRequestResponse, ProtocolComponentsRequestBody, ProtocolDeltaRequestBody,
        ProtocolDeltaRequestResponse, ProtocolId, ProtocolStateDelta, ProtocolStateRequestBody,
        ProtocolStateRequestResponse, ResponseAccount, ResponseProtocolState, ResponseToken,
        StateRequestBody, StateRequestResponse, TokensRequestBody, TokensRequestResponse,
        VersionParam,
    },
    models::{Chain, ContractId},
    storage::Gateway,
};

mod rpc;
mod ws;
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

    pub fn register_extractors(mut self, handle: Vec<ExtractorHandle>) -> Self {
        for e in handle {
            let id = e.get_id();
            self.extractor_handles
                .insert(id, Arc::new(e));
        }
        self
    }

    pub fn prefix(mut self, v: &str) -> Self {
        v.clone_into(&mut self.prefix);
        self
    }

    pub fn bind(mut self, v: &str) -> Self {
        v.clone_into(&mut self.bind);
        self
    }

    pub fn port(mut self, v: u16) -> Self {
        self.port = v;
        self
    }

    pub fn run(
        self,
    ) -> Result<(ServerHandle, JoinHandle<Result<(), ExtractionError>>), ExtractionError> {
        #[derive(OpenApi)]
        #[openapi(
            paths(
                rpc::contract_state,
                rpc::tokens,
                rpc::protocol_components,
                rpc::contract_delta,
                rpc::protocol_state,
                rpc::protocol_delta
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
                schemas(ResponseToken),
                schemas(ProtocolComponentsRequestBody),
                schemas(ProtocolComponentRequestResponse),
                schemas(ProtocolComponent),
                schemas(ContractDeltaRequestBody),
                schemas(ContractDeltaRequestResponse),
                schemas(ProtocolStateRequestBody),
                schemas(ProtocolStateRequestResponse),
                schemas(AccountUpdate),
                schemas(ProtocolId),
                schemas(ResponseProtocolState),
                schemas(ChangeType),
                schemas(ProtocolDeltaRequestBody),
                schemas(ProtocolDeltaRequestResponse),
                schemas(ProtocolStateDelta),
            )
        )]
        struct ApiDoc;

        let openapi = ApiDoc::openapi();
        let ws_data = web::Data::new(ws::WsData::new(self.extractor_handles));
        let rpc_data = web::Data::new(rpc::RpcHandler::new(self.db_gateway));
        let server = HttpServer::new(move || {
            App::new()
                .app_data(rpc_data.clone())
                .service(
                    web::resource(format!("/{}/{{execution_env}}/contract_state", self.prefix))
                        .route(web::post().to(rpc::contract_state::<G>)),
                )
                .service(
                    web::resource(format!("/{}/{{execution_env}}/contract_delta", self.prefix))
                        .route(web::post().to(rpc::contract_delta::<G>)),
                )
                .service(
                    web::resource(format!("/{}/{{execution_env}}/protocol_state", self.prefix))
                        .route(web::post().to(rpc::protocol_state::<G>)),
                )
                .service(
                    web::resource(format!("/{}/{{execution_env}}/protocol_delta", self.prefix))
                        .route(web::post().to(rpc::protocol_delta::<G>)),
                )
                .service(
                    web::resource(format!("/{}/{{execution_env}}/tokens", self.prefix))
                        .route(web::post().to(rpc::tokens::<G>)),
                )
                .service(
                    web::resource(format!(
                        "/{}/{{execution_env}}/protocol_components",
                        self.prefix
                    ))
                    .route(web::post().to(rpc::protocol_components::<G>)),
                )
                .app_data(ws_data.clone())
                .service(
                    web::resource(format!("/{}/ws", self.prefix))
                        .route(web::get().to(ws::WsActor::ws_index)),
                )
                .wrap(RequestTracing::new())
                // Create a swagger-ui endpoint to http://0.0.0.0:4242/docs/
                .service(
                    SwaggerUi::new("/docs/{_:.*}").url("/api-docs/openapi.json", openapi.clone()),
                )
        })
        .bind((self.bind, self.port))
        .map_err(|err| ExtractionError::ServiceError(err.to_string()))?
        .run();
        let handle = server.handle();
        let server = async move {
            let res = server.await;
            res.map_err(|err| ExtractionError::Unknown(err.to_string()))
        };
        let task = tokio::spawn(server);
        Ok((handle, task))
    }
}
