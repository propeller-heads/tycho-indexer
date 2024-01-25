//! This module contains Tycho web services implementation

use std::{collections::HashMap, sync::Arc};

use crate::{
    extractor::{evm, runner::ExtractorHandle, ExtractionError},
    models::Chain,
    services::rpc::{
        Block, ContractDeltaRequestBody, ContractDeltaRequestResponse, ContractStateRequestBody,
        ContractStateRequestResponse, EVMAccount, EVMAccountUpdate, Version,
    },
    storage::{postgres::PostgresGateway, ChangeType, ContractId},
};
use actix_web::{dev::ServerHandle, web, App, HttpServer};
use actix_web_opentelemetry::RequestTracing;
use diesel_async::{pooled_connection::deadpool::Pool, AsyncPgConnection};
use tokio::task::JoinHandle;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

mod rpc;
mod ws;

pub type EvmPostgresGateway = PostgresGateway<
    evm::Block,         //B
    evm::Transaction,   //TX
    evm::Account,       //A
    evm::AccountUpdate, //D
    evm::ERC20Token,    //T
>;

pub struct ServicesBuilder {
    prefix: String,
    port: u16,
    bind: String,
    extractor_handles: ws::MessageSenderMap,
    db_gateway: Arc<EvmPostgresGateway>,
    db_connection_pool: Pool<AsyncPgConnection>,
}

impl ServicesBuilder {
    pub fn new(
        db_gateway: Arc<EvmPostgresGateway>,
        db_connection_pool: Pool<AsyncPgConnection>,
    ) -> Self {
        Self {
            prefix: "v1".to_owned(),
            port: 4242,
            bind: "0.0.0.0".to_owned(),
            extractor_handles: HashMap::new(),
            db_gateway,
            db_connection_pool,
        }
    }

    pub fn register_extractor(mut self, handle: ExtractorHandle) -> Self {
        let id = handle.get_id();
        self.extractor_handles
            .insert(id, Arc::new(handle));
        self
    }

    pub fn prefix(mut self, v: &str) -> Self {
        self.prefix = v.to_owned();
        self
    }

    pub fn bind(mut self, v: &str) -> Self {
        self.bind = v.to_owned();
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
            paths(rpc::contract_state, rpc::contract_delta),
            components(
                schemas(Version),
                schemas(Block),
                schemas(ContractId),
                schemas(ContractStateRequestResponse),
                schemas(ContractStateRequestBody),
                schemas(ContractDeltaRequestResponse),
                schemas(ContractDeltaRequestBody),
                schemas(Chain),
                schemas(EVMAccount),
                schemas(EVMAccountUpdate),
                schemas(ChangeType),
            )
        )]
        struct ApiDoc;

        let openapi = ApiDoc::openapi();
        let ws_data = web::Data::new(ws::WsData::new(self.extractor_handles));
        let rpc_data =
            web::Data::new(rpc::RpcHandler::new(self.db_gateway, self.db_connection_pool));
        let server = HttpServer::new(move || {
            App::new()
                .app_data(rpc_data.clone())
                .service(
                    web::resource(format!("/{}/contract_state", self.prefix))
                        .route(web::post().to(rpc::contract_state)),
                )
                .service(
                    web::resource(format!("/{}/contract_delta", self.prefix))
                        .route(web::post().to(rpc::contract_delta)),
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
