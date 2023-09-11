//! This module contains Tycho Websocket implementation

use crate::{
    extractor::runner::ExtractorHandle,
    models::{ExtractorIdentity, NormalisedMessage},
};
use actix::{Actor, ActorContext, StreamHandler};
use actix_web::{web, Error, HttpRequest, HttpResponse};
use actix_web_actors::ws;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use thiserror::Error;
use tokio::sync::mpsc::Receiver;
use tracing::{error, info};
use uuid::Uuid;

#[derive(Error, Debug)]
pub enum WebsocketError {
    #[error("Extractor not found: {0}")]
    ExtractorNotFound(ExtractorIdentity),

    #[error("Subscription not found: {0}")]
    SubscriptionNotFound(Uuid),

    #[error("Failed to parse JSON: {0}")]
    ParseError(serde_json::Error),
}

impl From<serde_json::Error> for WebsocketError {
    fn from(e: serde_json::Error) -> Self {
        WebsocketError::ParseError(e)
    }
}

impl Serialize for WebsocketError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            WebsocketError::ExtractorNotFound(extractor_id) => {
                serializer.serialize_str(&format!("Extractor not found: {:?}", extractor_id))
            }
            WebsocketError::SubscriptionNotFound(subscription_id) => {
                serializer.serialize_str(&format!("Subscription not found: {:?}", subscription_id))
            }
            WebsocketError::ParseError(e) => {
                serializer.serialize_str(&format!("Parse error: {:?}", e))
            }
        }
    }
}

/// Shared application data between all connections
/// Parameters are hidden behind a Mutex to allow for sharing between threads
pub struct AppState<M> {
    /// There is one extractor handle per extractor
    pub extractors: Arc<Mutex<HashMap<ExtractorIdentity, ExtractorHandle<M>>>>,
}

impl<M> AppState<M> {
    pub fn new() -> Self {
        Self { extractors: Arc::new(Mutex::new(HashMap::new())) }
    }
}

/// Actor handling a single WS connection
struct WsActor<M> {
    _id: Uuid,
    app_state: web::Data<AppState<M>>,
    subscriptions: HashMap<Uuid, Receiver<Arc<M>>>,
}

impl<M> WsActor<M>
where
    M: NormalisedMessage + Sync + Send + 'static,
{
    fn new(app_state: web::Data<AppState<M>>) -> Self {
        Self { _id: Uuid::new_v4(), app_state, subscriptions: HashMap::new() }
    }

    pub async fn ws_index(
        req: HttpRequest,
        stream: web::Payload,
        data: web::Data<AppState<M>>,
    ) -> Result<HttpResponse, Error> {
        ws::start(WsActor::new(data), &req, stream)
    }

    fn subscribe(
        &mut self,
        ctx: &mut ws::WebsocketContext<Self>,
        extractor_id: &ExtractorIdentity,
    ) {
        info!("Subscribing to extractor: {:?}", extractor_id);

        let extractors_guard = self
            .app_state
            .extractors
            .lock()
            .unwrap();

        if let Some(extractor_handle) = extractors_guard.get(extractor_id) {
            // Generate a unique ID for this subscription
            let _subscription_id = Uuid::new_v4();

            // FIXME: Subscribe to the events and spawn an Actor forwarding the messages to the
            // client
            let _receiver = extractor_handle.subscribe();
        } else {
            error!("Extractor not found: {:?}", extractor_id);

            let error = WebsocketError::ExtractorNotFound(extractor_id.clone());
            ctx.text(serde_json::to_string(&error).unwrap());
        }
    }

    fn unsubscribe(&mut self, ctx: &mut ws::WebsocketContext<Self>, subscription_id: Uuid) {
        info!("Unsubscribing from subscription: {:?}", subscription_id);

        if let Some(mut receiver) = self
            .subscriptions
            .remove(&subscription_id)
        {
            // FIXME: Should I also call extractor_handle.stop()?

            // Call the close method on the receiver to close the channel
            receiver.close();

            ctx.text(format!("Unsubscribed from {}", subscription_id));
        } else {
            error!("Subscription ID not found: {}", subscription_id);

            let error = WebsocketError::SubscriptionNotFound(subscription_id);
            ctx.text(serde_json::to_string(&error).unwrap());
        }
    }
}

impl<M> Actor for WsActor<M>
where
    M: NormalisedMessage + Sync + Send + 'static,
{
    type Context = ws::WebsocketContext<Self>;

    fn started(&mut self, _ctx: &mut Self::Context) {
        info!("Websocket connection established");
    }

    fn stopped(&mut self, _ctx: &mut Self::Context) {
        info!("Websocket connection closed");
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "method", rename_all = "lowercase")]
pub enum Message {
    #[serde(rename = "subscribe")]
    Subscribe { extractor: ExtractorIdentity },

    #[serde(rename = "unsubscribe")]
    Unsubscribe { subscription_id: Uuid },
}

/// Handle incoming messages from the WS connection
impl<M> StreamHandler<Result<ws::Message, ws::ProtocolError>> for WsActor<M>
where
    M: NormalisedMessage + Sync + Send + 'static,
{
    fn handle(&mut self, msg: Result<ws::Message, ws::ProtocolError>, ctx: &mut Self::Context) {
        info!("Websocket message received: {:?}", msg);
        match msg {
            Ok(ws::Message::Ping(msg)) => ctx.pong(&msg),
            Ok(ws::Message::Pong(_)) => (),
            Ok(ws::Message::Text(text)) => {
                info!("Websocket text message received: {:?}", text);

                // Try to deserialize the message to a Message enum
                match serde_json::from_str::<Message>(&text) {
                    Ok(message) => {
                        // Handle the message based on its variant
                        match message {
                            Message::Subscribe { extractor } => {
                                self.subscribe(ctx, &extractor);
                            }
                            Message::Unsubscribe { subscription_id } => {
                                self.unsubscribe(ctx, subscription_id);
                            }
                        }
                    }
                    Err(e) => {
                        error!("Failed to parse message: {:?}", e);

                        let error = WebsocketError::ParseError(e);
                        ctx.text(serde_json::to_string(&error).unwrap());
                    }
                }
            }
            Ok(ws::Message::Binary(bin)) => {
                info!("Websocket binary message received: {:?}", bin);
                ctx.binary(bin)
            }
            Ok(ws::Message::Close(reason)) => {
                info!("Websocket close message received: {:?}", reason);
                ctx.close(reason);
                ctx.stop()
            }
            _ => ctx.stop(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use actix_rt::time::timeout;
    use actix_test::start;
    use actix_web::App;
    use futures03::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::{
        protocol::{frame::coding::CloseCode, CloseFrame},
        Message,
    };

    struct DummyMessage {
        extractor_id: ExtractorIdentity,
    }

    impl DummyMessage {
        pub fn new(extractor_id: ExtractorIdentity) -> Self {
            Self { extractor_id }
        }
    }

    impl NormalisedMessage for DummyMessage {
        fn source(&self) -> ExtractorIdentity {
            self.extractor_id.clone()
        }
    }

    #[actix_rt::test]
    async fn test_websocket_ping_pong() {
        let state = web::Data::new(AppState::<DummyMessage>::new());
        let srv = start(move || {
            App::new()
                .app_data(state.clone())
                .service(
                    web::resource("/ws/").route(web::get().to(WsActor::<DummyMessage>::ws_index)),
                )
        });

        let url = srv
            .url("/ws/")
            .to_string()
            .replacen("http://", "ws://", 1);
        println!("Connecting to test server at {}", url);

        // Connect to the server
        let (mut connection, _response) = tokio_tungstenite::connect_async(url)
            .await
            .expect("Failed to connect");

        println!("Connected to test server");

        // Test sending ping message and receiving pong message
        connection
            .send(Message::Ping(vec![]))
            .await
            .expect("Failed to send ping message");

        println!("Sent ping message");

        let msg = timeout(Duration::from_secs(1), connection.next())
            .await
            .expect("Failed to receive message")
            .unwrap()
            .unwrap();

        if let Message::Pong(_) = msg {
            // Pong received as expected
            info!("Received pong message");
        } else {
            panic!("Unexpected message {:?}", msg);
        }

        // Close the connection
        connection
            .send(Message::Close(Some(CloseFrame { code: CloseCode::Normal, reason: "".into() })))
            .await
            .expect("Failed to send close message");
        println!("Closed connection");
    }
}
