use futures::StreamExt;
use hyper::{client::HttpConnector, Body, Client, Request, Uri};
use std::{collections::HashMap, string::ToString};
use thiserror::Error;
use tracing::{debug, error, info, instrument, trace, warn};
use uuid::Uuid;

use super::tycho_models::{
    BlockAccountChanges, Chain, Command, ExtractorIdentity, Response, WebSocketMessage,
};
use crate::evm_simulation::tycho_models::{
    StateRequestBody, StateRequestParameters, StateRequestResponse,
};
use async_trait::async_trait;
use futures::SinkExt;
use tokio::sync::mpsc::{self, Receiver};
use tokio_tungstenite::{connect_async, tungstenite::protocol::Message};

/// TODO read consts from config
pub const TYCHO_SERVER_VERSION: &str = "v1";
pub const AMBIENT_EXTRACTOR_HANDLE: &str = "vm:ambient";
pub const AMBIENT_ACCOUNT_ADDRESS: &str = "0xaaaaaaaaa24eeeb8d57d431224f73832bc34f688";

#[derive(Error, Debug)]
pub enum TychoClientError {
    #[error("Failed to parse URI: {0}. Error: {1}")]
    UriParsing(String, String),
    #[error("Failed to format request: {0}")]
    FormatRequest(String),
    #[error("Unexpected HTTP client error: {0}")]
    HttpClient(String),
    #[error("Failed to parse response: {0}")]
    ParseResponse(String),
}

#[derive(Debug, Clone)]
pub struct TychoHttpClientImpl {
    http_client: Client<HttpConnector>,
    uri: Uri,
}

impl TychoHttpClientImpl {
    pub fn new(base_uri: &str) -> Result<Self, TychoClientError> {
        let uri = base_uri
            .parse::<Uri>()
            .map_err(|e| TychoClientError::UriParsing(base_uri.to_string(), e.to_string()))?;

        Ok(Self { http_client: Client::new(), uri })
    }
}

#[async_trait]
pub trait TychoHttpClient {
    async fn get_state(
        &self,
        filters: &StateRequestParameters,
        request: &StateRequestBody,
    ) -> Result<StateRequestResponse, TychoClientError>;
}

#[async_trait]
impl TychoHttpClient for TychoHttpClientImpl {
    #[instrument(skip(self, filters, request))]
    async fn get_state(
        &self,
        filters: &StateRequestParameters,
        request: &StateRequestBody,
    ) -> Result<StateRequestResponse, TychoClientError> {
        // Check if contract ids are specified
        if request.contract_ids.is_none() ||
            request
                .contract_ids
                .as_ref()
                .unwrap()
                .is_empty()
        {
            warn!("No contract ids specified in request.");
        }

        let uri = format!(
            "{}/{}/contract_state?{}",
            self.uri
                .to_string()
                .trim_end_matches('/'),
            TYCHO_SERVER_VERSION,
            filters.to_query_string()
        );

        debug!(%uri, "Sending contract_state request to Tycho server");
        let body = serde_json::to_string(&request)
            .map_err(|e| TychoClientError::FormatRequest(e.to_string()))?;

        let header = hyper::header::HeaderValue::from_str("application/json")
            .map_err(|e| TychoClientError::FormatRequest(e.to_string()))?;

        let req = Request::post(uri)
            .header(hyper::header::CONTENT_TYPE, header)
            .body(Body::from(body))
            .map_err(|e| TychoClientError::FormatRequest(e.to_string()))?;
        debug!(?req, "Sending request to Tycho server");

        let response = self
            .http_client
            .request(req)
            .await
            .map_err(|e| TychoClientError::HttpClient(e.to_string()))?;
        debug!(?response, "Received response from Tycho server");

        let body = hyper::body::to_bytes(response.into_body())
            .await
            .map_err(|e| TychoClientError::ParseResponse(e.to_string()))?;
        let accounts: StateRequestResponse = serde_json::from_slice(&body)
            .map_err(|e| TychoClientError::ParseResponse(e.to_string()))?;
        info!(?accounts, "Received contract_state response from Tycho server");

        Ok(accounts)
    }
}

pub struct TychoWsClientImpl {
    uri: Uri,
}

impl TychoWsClientImpl {
    pub fn new(ws_uri: &str) -> Result<Self, TychoClientError> {
        let uri = ws_uri
            .parse::<Uri>()
            .map_err(|e| TychoClientError::UriParsing(ws_uri.to_string(), e.to_string()))?;

        Ok(Self { uri })
    }
}

#[async_trait]
pub trait TychoWsClient {
    /// Subscribe to an extractor and receive realtime messages
    fn subscribe(&self, extractor_id: ExtractorIdentity) -> Result<(), TychoClientError>;

    /// Unsubscribe from an extractor
    fn unsubscribe(&self, subscription_id: Uuid) -> Result<(), TychoClientError>;

    /// Consumes realtime messages from the WebSocket server
    async fn realtime_messages(&self) -> Receiver<BlockAccountChanges>;
}

#[async_trait]
impl TychoWsClient for TychoWsClientImpl {
    #[allow(unused_variables)]
    fn subscribe(&self, extractor_id: ExtractorIdentity) -> Result<(), TychoClientError> {
        panic!("Not implemented");
    }

    #[allow(unused_variables)]
    fn unsubscribe(&self, subscription_id: Uuid) -> Result<(), TychoClientError> {
        panic!("Not implemented");
    }

    async fn realtime_messages(&self) -> Receiver<BlockAccountChanges> {
        // Create a channel to send and receive messages.
        let (tx, rx) = mpsc::channel(30); //TODO: Set this properly.

        // Spawn a task to connect to the WebSocket server and listen for realtime messages.
        let ws_uri = format!("{}{}/ws", self.uri, TYCHO_SERVER_VERSION); // TODO: Set path properly
        info!(?ws_uri, "Spawning task to connect to WebSocket server");
        tokio::spawn(async move {
            let mut active_extractors: HashMap<Uuid, ExtractorIdentity> = HashMap::new();

            // Connect to Tycho server
            info!(?ws_uri, "Connecting to WebSocket server");
            let (ws, _) = connect_async(&ws_uri)
                .await
                .map_err(|e| error!(error = %e, "Failed to connect to WebSocket server"))
                .expect("connect to websocket");
            // Split the WebSocket into a sender and receive of messages.
            let (mut ws_sink, ws_stream) = ws.split();

            // Send a subscribe request to ambient extractor
            // TODO: Read from config
            let command = Command::Subscribe {
                extractor_id: ExtractorIdentity::new(Chain::Ethereum, AMBIENT_EXTRACTOR_HANDLE),
            };
            let _ = ws_sink
                .send(Message::Text(serde_json::to_string(&command).unwrap()))
                .await
                .map_err(|e| error!(error = %e, "Failed to send subscribe request"));

            // Use the stream directly to listen for messages.
            let mut incoming_messages = ws_stream.boxed();
            while let Some(msg) = incoming_messages.next().await {
                match msg {
                    Ok(Message::Text(text)) => {
                        match serde_json::from_str::<WebSocketMessage>(&text) {
                            Ok(WebSocketMessage::BlockAccountChanges(block_state_changes)) => {
                                info!(
                                    ?block_state_changes,
                                    "Received a block state change, sending to channel"
                                );
                                tx.send(block_state_changes)
                                    .await
                                    .map_err(|e| error!(error = %e, "Failed to send message"))
                                    .expect("send message");
                            }
                            Ok(WebSocketMessage::Response(Response::NewSubscription {
                                extractor_id,
                                subscription_id,
                            })) => {
                                info!(
                                    ?extractor_id,
                                    ?subscription_id,
                                    "Received a new subscription"
                                );
                                active_extractors.insert(subscription_id, extractor_id);
                                trace!(?active_extractors, "Active extractors");
                            }
                            Ok(WebSocketMessage::Response(Response::SubscriptionEnded {
                                subscription_id,
                            })) => {
                                info!(?subscription_id, "Received a subscription ended");
                                active_extractors
                                    .remove(&subscription_id)
                                    .expect("subscription id in active extractors");
                            }
                            Err(e) => {
                                error!(error = %e, "Failed to deserialize message");
                            }
                        }
                    }
                    Ok(Message::Ping(_)) => {
                        // Respond to pings with pongs.
                        ws_sink
                            .send(Message::Pong(Vec::new()))
                            .await
                            .unwrap();
                    }
                    Ok(Message::Pong(_)) => {
                        // Do nothing.
                    }
                    Ok(Message::Close(_)) => {
                        // Close the connection.
                        drop(tx);
                        return
                    }
                    Ok(unknown_msg) => {
                        info!("Received an unknown message type: {:?}", unknown_msg);
                    }
                    Err(e) => {
                        error!("Failed to get a websocket message: {}", e);
                    }
                }
            }
        });

        info!("Returning receiver");
        rx
    }
}

#[cfg(test)]
mod tests {
    use crate::evm_simulation::tycho_models::{AccountUpdate, Block, ChangeType};
    use chrono::NaiveDateTime;
    use std::str::FromStr;

    use super::*;

    use mockito::Server;

    use futures::SinkExt;
    use revm::primitives::{B160, B256, U256 as rU256};
    use warp::{ws::WebSocket, Filter};

    #[tokio::test]
    async fn test_realtime_messages() {
        // Mock WebSocket server using warp
        async fn handle_connection(ws: WebSocket) {
            let (mut tx, _) = ws.split();
            let test_msg_content = r#"
            {
                "extractor": "vm:ambient",
                "chain": "ethereum",
                "block": {
                    "number": 123,
                    "hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
                    "parent_hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
                    "chain": "ethereum",
                    "ts": "2023-09-14T00:00:00"
                },
                "account_updates": {
                    "0x7a250d5630b4cf539739df2c5dacb4c659f2488d": {
                        "address": "0x7a250d5630b4cf539739df2c5dacb4c659f2488d",
                        "chain": "ethereum",
                        "slots": {},
                        "balance": "0x00000000000000000000000000000000000000000000000000000000000001f4",
                        "code": "",
                        "change": "Update"
                    }
                },
                "new_pools": {}
            }
            "#;
            // test that the response is deserialized correctly
            serde_json::from_str::<BlockAccountChanges>(test_msg_content).expect("deserialize");
            let test_msg = warp::ws::Message::text(test_msg_content);
            let _ = tx.send(test_msg).await;
        }

        // let ws_route = warp::ws().map(|ws: warp::ws::Ws| ws.on_upgrade(handle_connection));
        let ws_route = warp::path!("v1" / "ws")
            .and(warp::ws())
            .map(|ws: warp::ws::Ws| ws.on_upgrade(handle_connection));
        let (addr, server) = warp::serve(ws_route).bind_ephemeral(([127, 0, 0, 1], 0));
        tokio::task::spawn(server);

        // Now, you can create a client and connect to the mocked WebSocket server
        let client = TychoWsClientImpl::new(&format!("{}", addr)).unwrap();

        // You can listen to the realtime_messages and expect the messages that you send from
        // handle_connection
        let mut rx = client.realtime_messages().await;
        let received_msg = rx
            .recv()
            .await
            .expect("receive message");

        let expected_blk = Block {
            number: 123,
            hash: B256::from_str(
                "0x0000000000000000000000000000000000000000000000000000000000000000",
            )
            .unwrap(),
            parent_hash: B256::from_str(
                "0x0000000000000000000000000000000000000000000000000000000000000000",
            )
            .unwrap(),
            chain: Chain::Ethereum,
            ts: NaiveDateTime::from_str("2023-09-14T00:00:00").unwrap(),
        };
        let account_update = AccountUpdate::new(
            B160::from_str("0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D").unwrap(),
            Chain::Ethereum,
            HashMap::new(),
            Some(rU256::from(500)),
            Some(Vec::<u8>::new()),
            ChangeType::Update,
        );
        let account_updates: HashMap<B160, AccountUpdate> = vec![(
            B160::from_str("0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D").unwrap(),
            account_update,
        )]
        .into_iter()
        .collect();
        let expected = BlockAccountChanges::new(
            "vm:ambient".to_string(),
            Chain::Ethereum,
            expected_blk,
            account_updates,
            HashMap::new(),
        );

        assert_eq!(received_msg, expected);
    }

    #[tokio::test]
    async fn test_simple_route_mock_async() {
        let mut server = Server::new_async().await;
        let server_resp = r#"
        {
            "accounts": [
                {
                    "chain": "ethereum",
                    "address": "0x0000000000000000000000000000000000000000",
                    "title": "",
                    "slots": {},
                    "balance": "0x1f4",
                    "code": "",
                    "code_hash": "0x5c06b7c5b3d910fd33bc2229846f9ddaf91d584d9b196e16636901ac3a77077e",
                    "balance_modify_tx": "0x0000000000000000000000000000000000000000000000000000000000000000",
                    "code_modify_tx": "0x0000000000000000000000000000000000000000000000000000000000000000",
                    "creation_tx": null
                }
            ]
        }
        "#;
        // test that the response is deserialized correctly
        serde_json::from_str::<StateRequestResponse>(server_resp).expect("deserialize");

        let mocked_server = server
            .mock("POST", "/v1/contract_state?chain=ethereum")
            .expect(1)
            .with_body(server_resp)
            .create_async()
            .await;

        let client = TychoHttpClientImpl::new(
            server
                .uri()
                .replace("http://", "")
                .as_str(),
        )
        .expect("create client");

        let response = client
            .get_state(&Default::default(), &Default::default())
            .await
            .expect("get state");
        let accounts = response.accounts;

        mocked_server.assert();
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].slots, HashMap::new());
        assert_eq!(accounts[0].balance, rU256::from(500));
        assert_eq!(accounts[0].code, Vec::<u8>::new());
        assert_eq!(
            accounts[0].code_hash,
            B256::from_str("0x5c06b7c5b3d910fd33bc2229846f9ddaf91d584d9b196e16636901ac3a77077e")
                .unwrap()
        );
    }
}
