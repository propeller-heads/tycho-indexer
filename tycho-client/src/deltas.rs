//! # Deltas Client
//!
//! This module focuses on implementing the Real-Time Deltas client for the Tycho Indexer service.
//! Utilizing this client facilitates efficient, instant communication with the indexing service,
//! promoting seamless data synchronization.
//!
//! ## Websocket Implementation
//!
//! The present WebSocket implementation is clonable, which enables it to be shared
//! across multiple asynchronous tasks without creating separate instances for each task. This
//! unique feature boosts efficiency as it:
//!
//! - **Reduces Server Load:** By maintaining a single universal client, the load on the server is
//!   significantly reduced. This is because fewer connections are made to the server, preventing it
//!   from getting overwhelmed by numerous simultaneous requests.
//! - **Conserves Resource Usage:** A single shared client requires fewer system resources than if
//!   multiple clients were instantiated and used separately as there is some overhead for websocket
//!   handshakes and message.
//!
//! Therefore, sharing one client among multiple tasks ensures optimal performance, reduces resource
//! consumption, and enhances overall software scalability.
use async_trait::async_trait;
use futures03::{stream::SplitSink, SinkExt, StreamExt};
use hyper::{
    header::{
        AUTHORIZATION, CONNECTION, HOST, SEC_WEBSOCKET_KEY, SEC_WEBSOCKET_VERSION, UPGRADE,
        USER_AGENT,
    },
    Uri,
};
#[cfg(test)]
use mockall::automock;
use std::{
    collections::{hash_map::Entry, HashMap},
    sync::Arc,
    time::Duration,
};
use thiserror::Error;
use tokio::{
    net::TcpStream,
    sync::{
        mpsc::{self, error::TrySendError, Receiver, Sender},
        oneshot, Mutex, Notify,
    },
    task::JoinHandle,
    time::sleep,
};
use tokio_tungstenite::{
    connect_async,
    tungstenite::{
        self,
        handshake::client::{generate_key, Request},
    },
    MaybeTlsStream, WebSocketStream,
};
use tracing::{debug, error, info, instrument, trace, warn};
use uuid::Uuid;

use tycho_core::dto::{BlockChanges, Command, ExtractorIdentity, Response, WebSocketMessage};

use crate::TYCHO_SERVER_VERSION;

#[derive(Error, Debug)]
pub enum DeltasError {
    /// The passed tycho url failed to parse.
    #[error("Failed to parse URI: {0}. Error: {1}")]
    UriParsing(String, String),
    /// Informs you about a subscription being already pending and is awaiting conformation from
    /// the server.
    #[error("The requested subscription is already pending")]
    SubscriptionAlreadyPending,
    /// Informs that an message failed to send via an internal channel or throuh the websocket
    /// channel. This is most likely fatal and might mean that the implementation is buggy under
    /// certain conditions.
    #[error("{0}")]
    TransportError(String),
    /// An internal buffer is full. This likely means that messages are not being consumed fast
    /// enough. If the incoming load emits messages in bursts, consider increasing the buffer size.
    #[error("The buffer is full!")]
    BufferFull,
    /// The client has currently no active connection but it was accessed e.g. by calling
    /// subscribe.
    #[error("The client is not connected!")]
    NotConnected,
    /// The connect method was called while the client already had an active connection.
    #[error("The client is already connected!")]
    AlreadyConnected,
    /// The connection was closed orderly by the server, e.g. because it restarted.
    #[error("The server closed the connection!")]
    ConnectionClosed,
    /// The connection was closed unexpectedly by the server.
    #[error("ConnectionError {source}")]
    ConnectionError {
        #[from]
        source: tungstenite::Error,
    },
    /// Other fatal errors: e.g. if the underlying websockets buffer is full.
    #[error("Tycho FatalError: {0}")]
    Fatal(String),
}

#[derive(Clone, Debug)]
pub struct SubscriptionOptions {
    include_state: bool,
}

impl Default for SubscriptionOptions {
    fn default() -> Self {
        Self { include_state: true }
    }
}

impl SubscriptionOptions {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn with_state(mut self, val: bool) -> Self {
        self.include_state = val;
        self
    }
}

#[cfg_attr(test, automock)]
#[async_trait]
pub trait DeltasClient {
    /// Subscribe to an extractor and receive realtime messages
    ///
    /// Will request a subscription from tycho and wait for confirmation of it. If the caller
    /// cancels while waiting for confirmation the subscription may still be registered. If the
    /// receiver was deallocated though, the first message from the subscription will remove it
    /// again - since there is no one to inform about these messages.
    async fn subscribe(
        &self,
        extractor_id: ExtractorIdentity,
        options: SubscriptionOptions,
    ) -> Result<(Uuid, Receiver<BlockChanges>), DeltasError>;

    /// Unsubscribe from an subscription
    async fn unsubscribe(&self, subscription_id: Uuid) -> Result<(), DeltasError>;

    /// Start the clients message handling loop.
    async fn connect(&self) -> Result<JoinHandle<Result<(), DeltasError>>, DeltasError>;

    /// Close the clients message handling loop.
    async fn close(&self) -> Result<(), DeltasError>;
}

#[derive(Clone)]
pub struct WsDeltasClient {
    /// The tycho indexer websocket uri.
    uri: Uri,
    /// Authorization key for the websocket connection.
    auth_key: Option<String>,
    /// Maximum amount of reconnects to try before giving up.
    max_reconnects: u32,
    /// The client will buffer this many messages incoming from the websocket
    /// before starting to drop them.
    ws_buffer_size: usize,
    /// The client will buffer that many messages for each subscription before it starts droppping
    /// them.
    subscription_buffer_size: usize,
    /// Notify tasks waiting for a connection to be established.
    conn_notify: Arc<Notify>,
    /// Shared client instance state.
    inner: Arc<Mutex<Option<Inner>>>,
}

type WebSocketSink =
    SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, tungstenite::protocol::Message>;

/// Subscription State
///
/// Subscription go through a lifecycle:
///
/// ```text
/// O ---> requested subscribe ----> active ----> requested unsub ---> ended
/// ```
///
/// We use oneshot channels to inform the client struct about when these transition happened. E.g.
/// because for `subscribe`` to finish, we want the state to have transition to `active` and similar
/// for `unsubscribe`.
#[derive(Debug)]
enum SubscriptionInfo {
    /// Subscription was requested we wait for server confirmation and uuid assignment.
    RequestedSubscription(oneshot::Sender<(Uuid, Receiver<BlockChanges>)>),
    /// Subscription is active.
    Active,
    /// Unsubscription was requested, we wait for server confirmation.
    RequestedUnsubscription(oneshot::Sender<()>),
}

/// Internal struct containing shared state between of WsDeltaClient instances.
struct Inner {
    /// Websocket sender handle.
    sink: WebSocketSink,
    /// Command channel sender handle.
    cmd_tx: Sender<()>,
    /// Currently pending subscriptions.
    pending: HashMap<ExtractorIdentity, SubscriptionInfo>,
    /// Active subscriptions.
    subscriptions: HashMap<Uuid, SubscriptionInfo>,
    /// For eachs subscription we keep a sender handle, the receiver is returned to the caller of
    /// subscribe.
    sender: HashMap<Uuid, Sender<BlockChanges>>,
    /// How many messages to buffer per subscription before starting to drop new messages.
    buffer_size: usize,
}

/// Shared state betweeen all client instances.
///
/// This state is behind a mutex and requires synchronisation to be read of modified.
impl Inner {
    fn new(cmd_tx: Sender<()>, sink: WebSocketSink, buffer_size: usize) -> Self {
        Self {
            sink,
            cmd_tx,
            pending: HashMap::new(),
            subscriptions: HashMap::new(),
            sender: HashMap::new(),
            buffer_size,
        }
    }

    /// Registers a new pending subscription.
    fn new_subscription(
        &mut self,
        id: &ExtractorIdentity,
        ready_tx: oneshot::Sender<(Uuid, Receiver<BlockChanges>)>,
    ) -> Result<(), DeltasError> {
        if self.pending.contains_key(id) {
            return Err(DeltasError::SubscriptionAlreadyPending);
        }
        self.pending
            .insert(id.clone(), SubscriptionInfo::RequestedSubscription(ready_tx));
        Ok(())
    }

    /// Transitions a pending subscription to active.
    ///
    /// Will ignore any request to do so for subscriptions that are not pending.
    fn mark_active(&mut self, extractor_id: &ExtractorIdentity, subscription_id: Uuid) {
        if let Some(info) = self.pending.remove(extractor_id) {
            if let SubscriptionInfo::RequestedSubscription(ready_tx) = info {
                let (tx, rx) = mpsc::channel(self.buffer_size);
                self.sender.insert(subscription_id, tx);
                self.subscriptions
                    .insert(subscription_id, SubscriptionInfo::Active);
                let _ = ready_tx
                    .send((subscription_id, rx))
                    .map_err(|_| {
                        warn!(
                            ?extractor_id,
                            ?subscription_id,
                            "Subscriber for has gone away. Ignoring."
                        )
                    });
            } else {
                error!(
                    ?extractor_id,
                    ?subscription_id,
                    "Pending subscription was not in the correct state to 
                    transition to active. Ignoring!"
                )
            }
        } else {
            error!(
                ?extractor_id,
                ?subscription_id,
                "Tried to mark an unkown subscription as active. Ignoring!"
            );
        }
    }

    /// Sends a message to a subscription's receiver.
    fn send(&mut self, id: &Uuid, msg: BlockChanges) -> Result<(), DeltasError> {
        if let Some(sender) = self.sender.get_mut(id) {
            sender
                .try_send(msg)
                .map_err(|e| match e {
                    TrySendError::Full(_) => DeltasError::BufferFull,
                    TrySendError::Closed(_) => {
                        DeltasError::TransportError("The subscriber has gone away".to_string())
                    }
                })?;
        }
        Ok(())
    }

    /// Requests a subscription to end.
    ///
    /// The subscription needs to exist and be active for this to have any effect. Wll use
    /// `ready_tx` to notify the receiver once the transition to ended completed.
    fn end_subscription(&mut self, subscription_id: &Uuid, ready_tx: oneshot::Sender<()>) {
        if let Some(info) = self
            .subscriptions
            .get_mut(subscription_id)
        {
            if let SubscriptionInfo::Active = info {
                *info = SubscriptionInfo::RequestedUnsubscription(ready_tx);
            }
        } else {
            // no big deal imo so only debug lvl..
            debug!(?subscription_id, "Tried unsubscribing from a non existent subscription");
        }
    }

    /// Removes and fully ends a subscription
    ///
    /// Any calls for non-existing subscriptions will be simply ignored. May panic on internal state
    /// inconsistencies: e.g. if the subscription exists but there is no sender for it.
    /// Will remove a subscription even it was in active or pending state before, this is to support
    /// any server side failure of the subscription.
    fn remove_subscription(&mut self, subscription_id: Uuid) {
        if let Entry::Occupied(e) = self
            .subscriptions
            .entry(subscription_id)
        {
            let info = e.remove();
            if let SubscriptionInfo::RequestedUnsubscription(tx) = info {
                let _ = tx.send(()).map_err(|_| {
                    warn!(?subscription_id, "failed to notify about removed subscription")
                });
                self.sender
                    .remove(&subscription_id)
                    .expect(
                        "Inconsistent internal client state: `sender` state 
                        drifted from `info` while removing a subscription.",
                    );
            } else {
                warn!(?subscription_id, "Subscription ended unexpectedly!");
                self.sender
                    .remove(&subscription_id)
                    .expect("sender channel missing");
            }
        } else {
            error!(
                ?subscription_id,
                "Received `SubscriptionEnded`, but was never subscribed 
                to it. This is likely a bug!"
            );
        }
    }

    /// Sends a message through the websocket.
    async fn ws_send(&mut self, msg: tungstenite::protocol::Message) -> Result<(), DeltasError> {
        self.sink.send(msg).await.map_err(|e| {
            DeltasError::TransportError(format!("Failed to send message to websocket: {e}"))
        })
    }
}

/// Tycho client websocket implementation.
impl WsDeltasClient {
    // Construct a new client with 5 reconnection attempts.
    pub fn new(ws_uri: &str, auth_key: Option<&str>) -> Result<Self, DeltasError> {
        let uri = ws_uri
            .parse::<Uri>()
            .map_err(|e| DeltasError::UriParsing(ws_uri.to_string(), e.to_string()))?;
        Ok(Self {
            uri,
            auth_key: auth_key.map(|s| s.to_string()),
            inner: Arc::new(Mutex::new(None)),
            ws_buffer_size: 128,
            subscription_buffer_size: 128,
            conn_notify: Arc::new(Notify::new()),
            max_reconnects: 5,
        })
    }

    // Construct a new client with a custom number of reconnection attempts.
    pub fn new_with_reconnects(
        ws_uri: &str,
        max_reconnects: u32,
        auth_key: Option<&str>,
    ) -> Result<Self, DeltasError> {
        let uri = ws_uri
            .parse::<Uri>()
            .map_err(|e| DeltasError::UriParsing(ws_uri.to_string(), e.to_string()))?;

        Ok(Self {
            uri,
            auth_key: auth_key.map(|s| s.to_string()),
            inner: Arc::new(Mutex::new(None)),
            ws_buffer_size: 128,
            subscription_buffer_size: 128,
            conn_notify: Arc::new(Notify::new()),
            max_reconnects,
        })
    }

    /// Ensures that the client is connected.
    ///
    /// This method will acquire the lock for inner.
    async fn is_connected(&self) -> bool {
        let guard = self.inner.as_ref().lock().await;
        guard.is_some()
    }

    /// Waits for the client to be connected
    ///
    /// This method acquires the lock for inner for a short period, then waits until the  
    /// connection is established if not already connected.
    async fn ensure_connection(&self) {
        if !self.is_connected().await {
            self.conn_notify.notified().await;
        }
    }

    /// Main message handling logic
    ///
    /// If the message returns an error, a reconnect attempt may be considered depending on the
    /// error type.
    #[instrument(skip(self, msg))]
    async fn handle_msg(
        &self,
        msg: Result<tungstenite::protocol::Message, tokio_tungstenite::tungstenite::error::Error>,
    ) -> Result<(), DeltasError> {
        let mut guard = self.inner.lock().await;

        match msg {
            // We do not deserialize the message directly into a WebSocketMessage. This is because
            // the serde arbitrary_precision feature (often included in many
            // dependencies we use) breaks some untagged enum deserializations. Instead,
            // we deserialize the message into a serde_json::Value and convert that into a WebSocketMessage. For more info on this issue, see: https://github.com/serde-rs/json/issues/740
            Ok(tungstenite::protocol::Message::Text(text)) => match serde_json::from_str::<
                serde_json::Value,
            >(&text)
            {
                Ok(value) => match serde_json::from_value::<WebSocketMessage>(value) {
                    Ok(ws_message) => match ws_message {
                        WebSocketMessage::BlockChanges { subscription_id, deltas } => {
                            trace!(?deltas, "Received a block state change, sending to channel");
                            let inner = guard
                                .as_mut()
                                .ok_or_else(|| DeltasError::NotConnected)?;
                            match inner.send(&subscription_id, deltas) {
                                Err(DeltasError::BufferFull) => {
                                    error!(?subscription_id, "Buffer full, message dropped!");
                                }
                                Err(_) => {
                                    warn!(
                                        ?subscription_id,
                                        "Receiver for has gone away, unsubscribing!"
                                    );
                                    let (tx, _) = oneshot::channel();
                                    let _ = WsDeltasClient::unsubscribe_inner(
                                        inner,
                                        subscription_id,
                                        tx,
                                    )
                                    .await;
                                }
                                _ => { /* Do nothing */ }
                            }
                        }
                        WebSocketMessage::Response(Response::NewSubscription {
                            extractor_id,
                            subscription_id,
                        }) => {
                            info!(?extractor_id, ?subscription_id, "Received a new subscription");
                            let inner = guard
                                .as_mut()
                                .ok_or_else(|| DeltasError::NotConnected)?;
                            inner.mark_active(&extractor_id, subscription_id);
                        }
                        WebSocketMessage::Response(Response::SubscriptionEnded {
                            subscription_id,
                        }) => {
                            info!(?subscription_id, "Received a subscription ended");
                            let inner = guard
                                .as_mut()
                                .ok_or_else(|| DeltasError::NotConnected)?;
                            inner.remove_subscription(subscription_id);
                        }
                    },
                    Err(e) => {
                        error!(error = %e, message=text, "Failed to deserialize WebSocketMessage: message does not match expected structs");
                    }
                },
                Err(e) => {
                    error!(error = %e, message=text, "Failed to deserialize message: invalid json");
                }
            },
            Ok(tungstenite::protocol::Message::Ping(_)) => {
                // Respond to pings with pongs.
                let inner = guard
                    .as_mut()
                    .ok_or_else(|| DeltasError::NotConnected)?;
                if let Err(error) = inner
                    .ws_send(tungstenite::protocol::Message::Pong(Vec::new()))
                    .await
                {
                    debug!(?error, "Failed to send pong!");
                }
            }
            Ok(tungstenite::protocol::Message::Pong(_)) => {
                // Do nothing.
            }
            Ok(tungstenite::protocol::Message::Close(_)) => {
                return Err(DeltasError::ConnectionClosed);
            }
            Ok(unknown_msg) => {
                info!("Received an unknown message type: {:?}", unknown_msg);
            }
            Err(error) => {
                error!(?error, "Websocket error");
                return Err(match &error {
                    tungstenite::Error::ConnectionClosed => DeltasError::from(error),
                    tungstenite::Error::AlreadyClosed => {
                        warn!("Received AlreadyClosed error which is indicative of a bug!");
                        DeltasError::from(error)
                    }
                    tungstenite::Error::Io(_) => DeltasError::from(error),
                    tungstenite::Error::Protocol(_) => DeltasError::from(error),
                    _ => DeltasError::Fatal(error.to_string()),
                });
            }
        };
        Ok(())
    }

    /// Helper method to force request a unsubscribe of a subscription
    ///
    /// This method expects to receive a mutable reference to `Inner` so it does not acquire a
    /// lock. Used for normal unsubscribes as well to remove any subscriptions with deallocated
    /// receivers.
    async fn unsubscribe_inner(
        inner: &mut Inner,
        subscription_id: Uuid,
        ready_tx: oneshot::Sender<()>,
    ) -> Result<(), DeltasError> {
        inner.end_subscription(&subscription_id, ready_tx);
        let cmd = Command::Unsubscribe { subscription_id };
        inner
            .ws_send(tungstenite::protocol::Message::Text(
                serde_json::to_string(&cmd).expect("serialize cmd encode error"),
            ))
            .await?;
        Ok(())
    }
}

#[async_trait]
impl DeltasClient for WsDeltasClient {
    #[instrument(skip(self))]
    async fn subscribe(
        &self,
        extractor_id: ExtractorIdentity,
        options: SubscriptionOptions,
    ) -> Result<(Uuid, Receiver<BlockChanges>), DeltasError> {
        trace!("Starting subscribe");
        self.ensure_connection().await;
        let (ready_tx, ready_rx) = oneshot::channel();
        {
            let mut guard = self.inner.lock().await;
            let inner = guard
                .as_mut()
                .expect("ws not connected");
            trace!("Sending subscribe command");
            inner.new_subscription(&extractor_id, ready_tx)?;
            let cmd = Command::Subscribe { extractor_id, include_state: options.include_state };
            inner
                .ws_send(tungstenite::protocol::Message::Text(
                    serde_json::to_string(&cmd).expect("serialize cmd encode error"),
                ))
                .await?;
        }
        trace!("Waiting for subscription response");
        let rx = ready_rx
            .await
            .expect("ready channel closed");
        trace!("Subscription successfull");
        Ok(rx)
    }

    #[instrument(skip(self))]
    async fn unsubscribe(&self, subscription_id: Uuid) -> Result<(), DeltasError> {
        self.ensure_connection().await;
        let (ready_tx, ready_rx) = oneshot::channel();
        {
            let mut guard = self.inner.lock().await;
            let inner = guard
                .as_mut()
                .expect("ws not connected");

            WsDeltasClient::unsubscribe_inner(inner, subscription_id, ready_tx).await?;
        }
        ready_rx
            .await
            .expect("ready channel closed");

        Ok(())
    }

    #[instrument(skip(self))]
    async fn connect(&self) -> Result<JoinHandle<Result<(), DeltasError>>, DeltasError> {
        if self.is_connected().await {
            return Err(DeltasError::AlreadyConnected);
        }
        let ws_uri = format!("{}{}/ws", self.uri, TYCHO_SERVER_VERSION);
        info!(?ws_uri, "Starting TychoWebsocketClient");

        let (cmd_tx, mut cmd_rx) = mpsc::channel(self.ws_buffer_size);
        {
            let mut guard = self.inner.as_ref().lock().await;
            *guard = None;
        }
        let this = self.clone();
        let jh = tokio::spawn(async move {
            let mut retry_count = 0;
            let mut result = Err(DeltasError::NotConnected);

            'retry: while retry_count < this.max_reconnects {
                info!(?ws_uri, "Connecting to WebSocket server");

                // Create a WebSocket request
                let mut request_builder = Request::builder()
                    .uri(&ws_uri)
                    .header(SEC_WEBSOCKET_KEY, generate_key())
                    .header(SEC_WEBSOCKET_VERSION, 13)
                    .header(CONNECTION, "Upgrade")
                    .header(UPGRADE, "websocket")
                    .header(
                        HOST,
                        this.uri
                            .host()
                            .expect("no host found in tycho url"),
                    )
                    .header(USER_AGENT, format!("tycho-client-{}", env!("CARGO_PKG_VERSION")));

                // Add Authorization if one is given
                if let Some(ref key) = this.auth_key {
                    request_builder = request_builder.header(AUTHORIZATION, key);
                }

                let request = request_builder.body(()).unwrap();
                let (conn, _) = match connect_async(request).await {
                    Ok(conn) => conn,
                    Err(e) => {
                        // Prepare for reconnection
                        retry_count += 1;
                        let mut guard = this.inner.as_ref().lock().await;
                        *guard = None;

                        warn!(
                            e = e.to_string(),
                            "Failed to connect to WebSocket server; Reconnecting"
                        );
                        sleep(Duration::from_millis(500)).await;

                        continue 'retry;
                    }
                };

                let (ws_tx_new, ws_rx_new) = conn.split();
                {
                    let mut guard = this.inner.as_ref().lock().await;
                    *guard =
                        Some(Inner::new(cmd_tx.clone(), ws_tx_new, this.subscription_buffer_size));
                }
                let mut msg_rx = ws_rx_new.boxed();

                info!("Connection Successful: TychoWebsocketClient started");
                this.conn_notify.notify_waiters();
                result = Ok(());

                loop {
                    let res = tokio::select! {
                        msg = msg_rx.next() => match msg {
                            Some(msg) => this.handle_msg(msg).await,
                            None => { break 'retry } // ws connection silently closed
                        },
                        _ = cmd_rx.recv() => {break 'retry},
                    };
                    if let Err(error) = res {
                        if matches!(
                            error,
                            DeltasError::ConnectionClosed | DeltasError::ConnectionError { .. }
                        ) {
                            // Prepare for reconnection
                            retry_count += 1;
                            let mut guard = this.inner.as_ref().lock().await;
                            *guard = None;

                            warn!(
                                ?error,
                                ?retry_count,
                                "Connection dropped unexpectedly; Reconnecting"
                            );
                            break;
                        } else {
                            // Other errors are considered fatal
                            error!(?error, "Fatal error; Exiting");
                            result = Err(error);
                            break 'retry;
                        }
                    }
                }
            }

            // Clean up before exiting
            let mut guard = this.inner.as_ref().lock().await;
            *guard = None;

            // Check if max retries has been reached.
            if retry_count >= this.max_reconnects {
                error!("Max reconnection attempts reached; Exiting");
                this.conn_notify.notify_waiters(); // Notify that the task is done
                result = Err(DeltasError::ConnectionClosed);
            }

            result
        });

        self.conn_notify.notified().await;

        if self.is_connected().await {
            Ok(jh)
        } else {
            Err(DeltasError::NotConnected)
        }
    }

    #[instrument(skip(self))]
    async fn close(&self) -> Result<(), DeltasError> {
        info!("Closing TychoWebsocketClient");
        let mut guard = self.inner.lock().await;
        let inner = guard
            .as_mut()
            .ok_or_else(|| DeltasError::NotConnected)?;
        inner
            .cmd_tx
            .send(())
            .await
            .map_err(|e| DeltasError::TransportError(e.to_string()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use tycho_core::dto::Chain;

    use super::*;

    use std::net::SocketAddr;
    use tokio::{net::TcpListener, time::timeout};

    #[derive(Clone)]
    enum ExpectedComm {
        Receive(u64, tungstenite::protocol::Message),
        Send(tungstenite::protocol::Message),
    }

    async fn mock_tycho_ws(
        messages: &[ExpectedComm],
        reconnects: usize,
    ) -> (SocketAddr, JoinHandle<()>) {
        info!("Starting mock webserver");
        // zero port here means the OS chooses an open port
        let server = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("localhost bind failed");
        let addr = server.local_addr().unwrap();
        let messages = messages.to_vec();

        let jh = tokio::spawn(async move {
            info!("mock webserver started");
            for _ in 0..(reconnects + 1) {
                if let Ok((stream, _)) = server.accept().await {
                    let mut websocket = tokio_tungstenite::accept_async(stream)
                        .await
                        .unwrap();

                    info!("Handling messages..");
                    for c in messages.iter().cloned() {
                        match c {
                            ExpectedComm::Receive(t, exp) => {
                                info!("Awaiting message...");
                                let msg = timeout(Duration::from_millis(t), websocket.next())
                                    .await
                                    .expect("Receive timeout")
                                    .expect("Stream exhausted")
                                    .expect("Failed to receive message.");
                                info!("Message received");
                                assert_eq!(msg, exp)
                            }
                            ExpectedComm::Send(data) => {
                                info!("Sending message");
                                websocket
                                    .send(data)
                                    .await
                                    .expect("Failed to send message");
                                info!("Message sent");
                            }
                        };
                    }
                    sleep(Duration::from_millis(100)).await;
                    // Close the WebSocket connection
                    let _ = websocket.close(None).await;
                }
            }
        });
        (addr, jh)
    }

    #[tokio::test]
    async fn test_subscribe_receive() {
        let exp_comm = [
            ExpectedComm::Receive(100, tungstenite::protocol::Message::Text(r#"
                {
                    "method":"subscribe",
                    "extractor_id":{
                        "chain":"ethereum",
                        "name":"vm:ambient"
                    },
                    "include_state": true
                }"#.to_owned().replace(|c: char| c.is_whitespace(), "")
            )),
            ExpectedComm::Send(tungstenite::protocol::Message::Text(r#"
                {
                    "method":"newsubscription",
                    "extractor_id":{
                    "chain":"ethereum",
                    "name":"vm:ambient"
                    },
                    "subscription_id":"30b740d1-cf09-4e0e-8cfe-b1434d447ece"
                }"#.to_owned().replace(|c: char| c.is_whitespace(), "")
            )),
            ExpectedComm::Send(tungstenite::protocol::Message::Text(r#"
                {
                    "subscription_id": "30b740d1-cf09-4e0e-8cfe-b1434d447ece",
                    "deltas": {
                        "extractor": "vm:ambient",
                        "chain": "ethereum",
                        "block": {
                            "number": 123,
                            "hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
                            "parent_hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
                            "chain": "ethereum",             
                            "ts": "2023-09-14T00:00:00"
                        },
                        "finalized_block_height": 0,
                        "revert": false,
                        "new_tokens": {},
                        "account_updates": {
                            "0x7a250d5630b4cf539739df2c5dacb4c659f2488d": {
                                "address": "0x7a250d5630b4cf539739df2c5dacb4c659f2488d",
                                "chain": "ethereum",
                                "slots": {},
                                "balance": "0x01f4",
                                "code": "",
                                "change": "Update"
                            }
                        },
                        "state_updates": {
                            "component_1": {
                                "component_id": "component_1",
                                "updated_attributes": {"attr1": "0x01"},
                                "deleted_attributes": ["attr2"]
                            }
                        },
                        "new_protocol_components": 
                            { "protocol_1": {
                                    "id": "protocol_1",
                                    "protocol_system": "system_1",
                                    "protocol_type_name": "type_1",
                                    "chain": "ethereum",
                                    "tokens": ["0x01", "0x02"],
                                    "contract_ids": ["0x01", "0x02"],
                                    "static_attributes": {"attr1": "0x01f4"},
                                    "change": "Update",
                                    "creation_tx": "0x01",
                                    "created_at": "2023-09-14T00:00:00"
                                }
                            },
                        "deleted_protocol_components": {},
                        "component_balances": {
                            "protocol_1":
                                {
                                    "0x01": {
                                        "token": "0x01",
                                        "balance": "0x01f4",
                                        "balance_float": 0.0,
                                        "modify_tx": "0x01",
                                        "component_id": "protocol_1"
                                    }
                                }
                        },
                        "account_balances": {
                            "0x7a250d5630b4cf539739df2c5dacb4c659f2488d": {
                                "0x7a250d5630b4cf539739df2c5dacb4c659f2488d": {
                                    "account": "0x7a250d5630b4cf539739df2c5dacb4c659f2488d",
                                    "token": "0x7a250d5630b4cf539739df2c5dacb4c659f2488d",
                                    "balance": "0x01f4",
                                    "modify_tx": "0x01"
                                }
                            }
                        },
                        "component_tvl": {
                            "protocol_1": 1000.0
                        }
                    }
                }
                "#.to_owned()
            ))
        ];
        let (addr, server_thread) = mock_tycho_ws(&exp_comm, 0).await;

        let client = WsDeltasClient::new(&format!("ws://{}", addr), None).unwrap();
        let jh = client
            .connect()
            .await
            .expect("connect failed");
        let (_, mut rx) = timeout(
            Duration::from_millis(100),
            client.subscribe(
                ExtractorIdentity::new(Chain::Ethereum, "vm:ambient"),
                SubscriptionOptions::new(),
            ),
        )
        .await
        .expect("subscription timed out")
        .expect("subscription failed");
        let _ = timeout(Duration::from_millis(100), rx.recv())
            .await
            .expect("awaiting message timeout out")
            .expect("receiving message failed");
        timeout(Duration::from_millis(100), client.close())
            .await
            .expect("close timed out")
            .expect("close failed");
        jh.await
            .expect("ws loop errored")
            .unwrap();
        server_thread.await.unwrap();
    }

    #[tokio::test]
    async fn test_unsubscribe() {
        let exp_comm = [
            ExpectedComm::Receive(
                100,
                tungstenite::protocol::Message::Text(
                    r#"
                {
                    "method": "subscribe",
                    "extractor_id":{
                        "chain": "ethereum",
                        "name": "vm:ambient"
                    },
                    "include_state": true
                }"#
                    .to_owned()
                    .replace(|c: char| c.is_whitespace(), ""),
                ),
            ),
            ExpectedComm::Send(tungstenite::protocol::Message::Text(
                r#"
                {
                    "method": "newsubscription",
                    "extractor_id":{
                        "chain": "ethereum",
                        "name": "vm:ambient"
                    },
                    "subscription_id": "30b740d1-cf09-4e0e-8cfe-b1434d447ece"
                }"#
                .to_owned()
                .replace(|c: char| c.is_whitespace(), ""),
            )),
            ExpectedComm::Receive(
                100,
                tungstenite::protocol::Message::Text(
                    r#"
                {
                    "method": "unsubscribe",
                    "subscription_id": "30b740d1-cf09-4e0e-8cfe-b1434d447ece"
                }
                "#
                    .to_owned()
                    .replace(|c: char| c.is_whitespace(), ""),
                ),
            ),
            ExpectedComm::Send(tungstenite::protocol::Message::Text(
                r#"
                {
                    "method": "subscriptionended",
                    "subscription_id": "30b740d1-cf09-4e0e-8cfe-b1434d447ece"
                }
                "#
                .to_owned()
                .replace(|c: char| c.is_whitespace(), ""),
            )),
        ];
        let (addr, server_thread) = mock_tycho_ws(&exp_comm, 0).await;

        let client = WsDeltasClient::new(&format!("ws://{}", addr), None).unwrap();
        let jh = client
            .connect()
            .await
            .expect("connect failed");
        let (sub_id, mut rx) = timeout(
            Duration::from_millis(100),
            client.subscribe(
                ExtractorIdentity::new(Chain::Ethereum, "vm:ambient"),
                SubscriptionOptions::new(),
            ),
        )
        .await
        .expect("subscription timed out")
        .expect("subscription failed");

        timeout(Duration::from_millis(100), client.unsubscribe(sub_id))
            .await
            .expect("unsubscribe timed out")
            .expect("unsubscribe failed");
        let res = timeout(Duration::from_millis(100), rx.recv())
            .await
            .expect("awaiting message timeout out");

        // If the subscription ended, the channel should have been closed.
        assert!(res.is_none());

        timeout(Duration::from_millis(100), client.close())
            .await
            .expect("close timed out")
            .expect("close failed");
        jh.await
            .expect("ws loop errored")
            .unwrap();
        server_thread.await.unwrap();
    }

    #[tokio::test]
    async fn test_subscription_unexpected_end() {
        let exp_comm = [
            ExpectedComm::Receive(
                100,
                tungstenite::protocol::Message::Text(
                    r#"
                {
                    "method":"subscribe",
                    "extractor_id":{
                        "chain":"ethereum",
                        "name":"vm:ambient"
                    },
                    "include_state": true
                }"#
                    .to_owned()
                    .replace(|c: char| c.is_whitespace(), ""),
                ),
            ),
            ExpectedComm::Send(tungstenite::protocol::Message::Text(
                r#"
                {
                    "method":"newsubscription",
                    "extractor_id":{
                        "chain":"ethereum",
                        "name":"vm:ambient"
                    },
                    "subscription_id":"30b740d1-cf09-4e0e-8cfe-b1434d447ece"
                }"#
                .to_owned()
                .replace(|c: char| c.is_whitespace(), ""),
            )),
            ExpectedComm::Send(tungstenite::protocol::Message::Text(
                r#"
                {
                    "method": "subscriptionended",
                    "subscription_id": "30b740d1-cf09-4e0e-8cfe-b1434d447ece"
                }"#
                .to_owned()
                .replace(|c: char| c.is_whitespace(), ""),
            )),
        ];
        let (addr, server_thread) = mock_tycho_ws(&exp_comm, 0).await;

        let client = WsDeltasClient::new(&format!("ws://{}", addr), None).unwrap();
        let jh = client
            .connect()
            .await
            .expect("connect failed");
        let (_, mut rx) = timeout(
            Duration::from_millis(100),
            client.subscribe(
                ExtractorIdentity::new(Chain::Ethereum, "vm:ambient"),
                SubscriptionOptions::new(),
            ),
        )
        .await
        .expect("subscription timed out")
        .expect("subscription failed");
        let res = timeout(Duration::from_millis(100), rx.recv())
            .await
            .expect("awaiting message timeout out");

        // If the subscription ended, the channel should have been closed.
        assert!(res.is_none());

        timeout(Duration::from_millis(100), client.close())
            .await
            .expect("close timed out")
            .expect("close failed");
        jh.await
            .expect("ws loop errored")
            .unwrap();
        server_thread.await.unwrap();
    }

    #[test_log::test(tokio::test)]
    async fn test_reconnect() {
        let exp_comm = [
            ExpectedComm::Receive(100, tungstenite::protocol::Message::Text(r#"
                {
                    "method":"subscribe",
                    "extractor_id":{
                        "chain":"ethereum",
                        "name":"vm:ambient"
                    },
                    "include_state": true
                }"#.to_owned().replace(|c: char| c.is_whitespace(), "")
            )),
            ExpectedComm::Send(tungstenite::protocol::Message::Text(r#"
                {
                    "method":"newsubscription",
                    "extractor_id":{
                    "chain":"ethereum",
                    "name":"vm:ambient"
                    },
                    "subscription_id":"30b740d1-cf09-4e0e-8cfe-b1434d447ece"
                }"#.to_owned().replace(|c: char| c.is_whitespace(), "")
            )),
            ExpectedComm::Send(tungstenite::protocol::Message::Text(r#"
                {
                    "subscription_id": "30b740d1-cf09-4e0e-8cfe-b1434d447ece",
                    "deltas": {
                        "extractor": "vm:ambient",
                        "chain": "ethereum",
                        "block": {
                            "number": 123,
                            "hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
                            "parent_hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
                            "chain": "ethereum",             
                            "ts": "2023-09-14T00:00:00"
                        },
                        "finalized_block_height": 0,
                        "revert": false,
                        "new_tokens": {},
                        "account_updates": {
                            "0x7a250d5630b4cf539739df2c5dacb4c659f2488d": {
                                "address": "0x7a250d5630b4cf539739df2c5dacb4c659f2488d",
                                "chain": "ethereum",
                                "slots": {},
                                "balance": "0x01f4",
                                "code": "",
                                "change": "Update"
                            }
                        },
                        "state_updates": {
                            "component_1": {
                                "component_id": "component_1",
                                "updated_attributes": {"attr1": "0x01"},
                                "deleted_attributes": ["attr2"]
                            }
                        },
                        "new_protocol_components": {
                            "protocol_1":
                                {
                                    "id": "protocol_1",
                                    "protocol_system": "system_1",
                                    "protocol_type_name": "type_1",
                                    "chain": "ethereum",
                                    "tokens": ["0x01", "0x02"],
                                    "contract_ids": ["0x01", "0x02"],
                                    "static_attributes": {"attr1": "0x01f4"},
                                    "change": "Update",
                                    "creation_tx": "0x01",
                                    "created_at": "2023-09-14T00:00:00"
                                }
                            },
                        "deleted_protocol_components": {},
                        "component_balances": {
                            "protocol_1": {
                                "0x01": {
                                    "token": "0x01",
                                    "balance": "0x01f4",
                                    "balance_float": 1000.0,
                                    "modify_tx": "0x01",
                                    "component_id": "protocol_1"
                                }
                            }
                        },
                        "account_balances": {
                            "0x7a250d5630b4cf539739df2c5dacb4c659f2488d": {
                                "0x7a250d5630b4cf539739df2c5dacb4c659f2488d": {
                                    "account": "0x7a250d5630b4cf539739df2c5dacb4c659f2488d",
                                    "token": "0x7a250d5630b4cf539739df2c5dacb4c659f2488d",
                                    "balance": "0x01f4",
                                    "modify_tx": "0x01"
                                }
                            }
                        },
                        "component_tvl": {
                            "protocol_1": 1000.0
                        }
                    }
                }
                "#.to_owned()
            ))
        ];
        let (addr, server_thread) = mock_tycho_ws(&exp_comm, 1).await;
        let client = WsDeltasClient::new(&format!("ws://{}", addr), None).unwrap();
        let jh: JoinHandle<Result<(), DeltasError>> = client
            .connect()
            .await
            .expect("connect failed");

        for _ in 0..2 {
            let (_, mut rx) = timeout(
                Duration::from_millis(100),
                client.subscribe(
                    ExtractorIdentity::new(Chain::Ethereum, "vm:ambient"),
                    SubscriptionOptions::new(),
                ),
            )
            .await
            .expect("subscription timed out")
            .expect("subscription failed");

            let _ = timeout(Duration::from_millis(100), rx.recv())
                .await
                .expect("awaiting message timeout out")
                .expect("receiving message failed");

            // wait for the connection to drop
            let res = timeout(Duration::from_millis(200), rx.recv())
                .await
                .expect("awaiting closed connection timeout out");
            assert!(res.is_none());
        }
        let res = jh.await.expect("ws client join failed");
        // 5th client reconnect attempt should fail
        assert!(res.is_err());
        server_thread
            .await
            .expect("ws server loop errored");
    }

    async fn mock_bad_connection_tycho_ws() -> (SocketAddr, JoinHandle<()>) {
        let server = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("localhost bind failed");
        let addr = server.local_addr().unwrap();
        let jh = tokio::spawn(async move {
            while let Ok((stream, _)) = server.accept().await {
                // Immediately close the connection to simulate a failure
                drop(stream);
            }
        });
        (addr, jh)
    }

    #[tokio::test]
    async fn test_connect_max_attempts() {
        let (addr, _) = mock_bad_connection_tycho_ws().await;
        let client =
            WsDeltasClient::new_with_reconnects(&format!("ws://{}", addr), 3, None).unwrap();

        let join_handle = client.connect().await;

        assert!(join_handle.is_err());
        assert_eq!(join_handle.unwrap_err().to_string(), DeltasError::NotConnected.to_string());
    }
}
