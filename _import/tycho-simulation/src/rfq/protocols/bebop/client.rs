#![allow(dead_code)] // TODO remove this
use std::{
    collections::{HashMap, HashSet},
    time::SystemTime,
};

use async_trait::async_trait;
use futures::{stream::BoxStream, StreamExt};
use tokio_tungstenite::{connect_async_with_config, tungstenite::Message};
use tracing;

use crate::{
    rfq::{
        client::RFQClient,
        errors::RFQError,
        indicatively_priced::SignedQuote,
        models::{GetAmountOutParams, TimestampHeader},
        protocols::bebop::models::BebopPriceData,
    },
    tycho_client::feed::synchronizer::{ComponentWithState, Snapshot, StateSyncMessage},
    tycho_common::dto::{ProtocolComponent, ResponseProtocolState},
    tycho_core::dto::Chain,
};

type BebopPriceMessage = HashMap<String, BebopPriceData>;

fn pair_to_bebop_format(pair: &(String, String)) -> String {
    format!("{}/{}", pair.0, pair.1)
}

#[derive(Clone)]
pub struct BebopClient {
    chain: Chain,
    url: String,
    // Pairs that we want prices for
    pairs: HashSet<String>,
    // Min tvl value.
    tvl: f64,
    // name header for authentication
    ws_user: String,
    // key header for authentication
    ws_key: String,
    // quote tokens to normalize to for TVL purposes
    quote_tokens: HashSet<String>,
}

impl BebopClient {
    pub fn new(
        chain: Chain,
        pairs: Vec<(String, String)>,
        tvl: f64,
        ws_user: String,
        ws_key: String,
    ) -> Self {
        let url = "wss://api.bebop.xyz/pmm/ethereum/v3/pricing".to_string();

        let mut pair_names: HashSet<String> = HashSet::new();
        for pair in pairs {
            pair_names.insert(pair_to_bebop_format(&pair));
        }
        let quote_tokens = HashSet::from([
            String::from("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"), // USDC
            String::from("0xdAC17F958D2ee523a2206206994597C13D831ec7"), // USDT
        ]);
        Self { url, pairs: pair_names, chain, tvl, ws_user, ws_key, quote_tokens }
    }

    fn create_component_with_state(
        &self,
        component_id: String,
        tokens: Vec<tycho_common::Bytes>,
        price_data: &BebopPriceData,
        tvl: f64,
    ) -> ComponentWithState {
        let protocol_component = ProtocolComponent {
            id: component_id.clone(),
            protocol_system: "rfq:bebop".to_string(),
            protocol_type_name: "bebop_pool".to_string(),
            chain: self.chain,
            tokens,
            contract_ids: vec![], // empty for RFQ
            static_attributes: Default::default(),
            change: Default::default(),
            creation_tx: Default::default(),
            created_at: Default::default(),
        };

        let mut attributes = HashMap::new();

        // Store all bids and asks as JSON strings, since we cannot store arrays
        if !price_data.bids.is_empty() {
            let bids_json = serde_json::to_string(&price_data.bids).unwrap_or_default();
            attributes.insert("bids".to_string(), bids_json.as_bytes().to_vec().into());
        }
        if !price_data.asks.is_empty() {
            let asks_json = serde_json::to_string(&price_data.asks).unwrap_or_default();
            attributes.insert("asks".to_string(), asks_json.as_bytes().to_vec().into());
        }

        ComponentWithState {
            state: ResponseProtocolState {
                component_id: component_id.clone(),
                attributes,
                balances: HashMap::new(),
            },
            component: protocol_component,
            component_tvl: Some(tvl),
            entrypoints: vec![],
        }
    }
}

#[async_trait]
impl RFQClient for BebopClient {
    fn stream(
        &self,
    ) -> BoxStream<'static, Result<(String, StateSyncMessage<TimestampHeader>), RFQError>> {
        let pairs = self.pairs.clone();
        let url = self.url.clone();
        let tvl_threshold = self.tvl;
        let name = self.ws_user.clone();
        let authorization = self.ws_key.clone();
        let client = self.clone();

        Box::pin(async_stream::stream! {
            use http::Request;
            use tokio_tungstenite::tungstenite::handshake::client::generate_key;
            use tokio::time::{sleep, Duration};

            let mut current_components: HashMap<String, ComponentWithState> = HashMap::new();
            let mut reconnect_attempts = 0;
            const MAX_RECONNECT_ATTEMPTS: u32 = 10;

            loop {
                let request = Request::builder()
                    .method("GET")
                    .uri(&url)
                    .header("Host", "api.bebop.xyz")
                    .header("Upgrade", "websocket")
                    .header("Connection", "Upgrade")
                    .header("Sec-WebSocket-Key", generate_key())
                    .header("Sec-WebSocket-Version", "13")
                    .header("name", &name)
                    .header("Authorization", &authorization)
                    .body(())
                    .map_err(|_| RFQError::ConnectionError("Failed to build request".into()))?;

                // Connect to Bebop WebSocket with custom headers
                let (ws_stream, _) = match connect_async_with_config(request, None, false).await {
                    Ok(connection) => {
                        tracing::info!("Successfully connected to Bebop WebSocket");
                        reconnect_attempts = 0; // Reset counter on successful connection
                        connection
                    },
                    Err(e) => {
                        reconnect_attempts += 1;
                        tracing::error!("Failed to connect to Bebop WebSocket (attempt {}): {}", reconnect_attempts, e);

                        if reconnect_attempts >= MAX_RECONNECT_ATTEMPTS {
                            yield Err(RFQError::ConnectionError(format!("Failed to connect after {MAX_RECONNECT_ATTEMPTS} attempts: {e}")));
                            return;
                        }

                        let backoff_duration = Duration::from_secs(2_u64.pow(reconnect_attempts.min(5)));
                        tracing::info!("Retrying connection in {} seconds...", backoff_duration.as_secs());
                        sleep(backoff_duration).await;
                        continue;
                    }
                };

                let (_, mut ws_receiver) = ws_stream.split();

                // Message processing loop
                while let Some(msg) = ws_receiver.next().await {
                    match msg {
                        Ok(Message::Text(text)) => {
                            match serde_json::from_str::<BebopPriceMessage>(&text) {
                                Ok(price_data_map) => {
                                    let mut new_components = HashMap::new();

                                    // Process all pairs from this WebSocket message
                                    for (pair, price_data) in price_data_map.iter() {
                                        if pairs.contains(pair) {
                                            let component_id = format!("bebop_{}", pair.replace("/", "_"));

                                            let (token0, token1);
                                            if let Some((t0, t1)) = pair.split_once('/') {
                                                token0 = t0;
                                                token1 = t1;
                                            } else {
                                                // Tokens improperly formatted. Skip.
                                                tracing::warn!("Tokens improperly formatted. Skipping.");
                                                continue;
                                            };

                                            let tokens = vec![
                                                tycho_common::Bytes::from(token0.as_bytes().to_vec()),
                                                tycho_common::Bytes::from(token1.as_bytes().to_vec())
                                            ];

                                            let mut quote_price_data: Option<BebopPriceData> = None;
                                            // The quote token is not one of the approved quote tokens
                                            // Get the price, so we can normalize our TVL calculation
                                            if !client.quote_tokens.contains(token1) {
                                                for quote_token in &client.quote_tokens {
                                                    let quote_pair_name = pair_to_bebop_format(&(token1.into(), quote_token.into()));
                                                    if let Some(data) = price_data_map.get(&quote_pair_name) {
                                                        quote_price_data = Some(data.clone());
                                                        break;
                                                    };
                                                }

                                                // Quote token doesn't have price levels in approved quote tokens.
                                                // Skip.
                                                if quote_price_data.is_none() {
                                                    tracing::warn!("Quote token does not have price levels in approved quote token. Skipping.");
                                                    continue;
                                                }
                                            }

                                            let tvl = price_data.calculate_tvl(quote_price_data.clone());
                                            if tvl < tvl_threshold {
                                                continue;
                                            }

                                            let component_with_state = client.create_component_with_state(
                                                component_id.clone(),
                                                tokens,
                                                price_data,
                                                tvl
                                            );
                                            new_components.insert(component_id, component_with_state);
                                        }
                                    }

                                    // Find components that were removed (existed before but not in this update)
                                    // This includes components with no bids or asks, since they are filtered
                                    // out by the tvl threshold.
                                    let removed_components: Vec<String> = current_components.keys()
                                        .filter(|id| !new_components.contains_key(*id))
                                        .cloned()
                                        .collect();

                                    // Update our current state
                                    current_components = new_components.clone();

                                    let snapshot = Snapshot {
                                        states: new_components,
                                        vm_storage: HashMap::new(),
                                    };
                                    let timestamp = SystemTime::now().duration_since(
                                        SystemTime::UNIX_EPOCH
                                    ).map_err(
                                        |_| RFQError::ParsingError("SystemTime before UNIX EPOCH!".into())
                                    )?.as_secs();

                                    let msg = StateSyncMessage::<TimestampHeader> {
                                        header: TimestampHeader { timestamp },
                                        snapshots: snapshot,
                                        deltas: None, // Deltas are always None - all the changes are absolute
                                        removed_components: removed_components.into_iter().map(|id| (id, Default::default())).collect(),
                                    };

                                    // Yield one message containing all updated pairs
                                    yield Ok(("bebop".to_string(), msg));
                                },
                                Err(e) => {
                                    tracing::error!("Failed to parse websocket message: {}", e);
                                    yield Err(RFQError::ParsingError(format!("Failed to parse message: {e}")));
                                    break;
                                }
                            }
                        }
                        Ok(Message::Close(_)) => {
                            tracing::info!("WebSocket connection closed by server");
                            break;
                        }
                        Err(e) => {
                            tracing::error!("WebSocket error: {}", e);
                            break;
                        }
                        _ => {} // Ignore other message types
                    }
                }

                // If we're here, the message loop exited - always attempt to reconnect
                reconnect_attempts += 1;
                if reconnect_attempts >= MAX_RECONNECT_ATTEMPTS {
                    yield Err(RFQError::ConnectionError(format!("Connection failed after {MAX_RECONNECT_ATTEMPTS} attempts")));
                    return;
                }

                let backoff_duration = Duration::from_secs(2_u64.pow(reconnect_attempts.min(5)));
                tracing::info!("Reconnecting in {} seconds (attempt {})...", backoff_duration.as_secs(), reconnect_attempts);
                sleep(backoff_duration).await;
                // Continue to the next iteration of the main loop
            }
        })
    }

    async fn request_binding_quote(
        &self,
        _params: &GetAmountOutParams,
    ) -> Result<SignedQuote, RFQError> {
        todo!()
    }

    fn clone_box(&self) -> Box<dyn RFQClient> {
        Box::new(self.clone())
    }
}

#[cfg(test)]
mod tests {
    use std::{env, time::Duration};

    use futures::StreamExt;
    use tokio::time::timeout;

    use super::*;

    #[tokio::test]
    #[ignore] // Requires network access and setting proper env vars
    async fn test_bebop_websocket_connection() {
        tracing_subscriber::fmt::init();

        // We test with quote tokens that are not USDC in order to ensure our normalization works
        // fine
        let wbtc = "0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599".to_string();
        let weth = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2".to_string();

        let ws_user = String::from("tycho");
        let ws_key = env::var("BEBOP_KEY").expect("BEBOP_KEY environment variable is required");

        let client = BebopClient::new(
            Chain::Ethereum,
            vec![(weth.to_string(), wbtc.to_string())],
            10.0, // $10 minimum TVL
            ws_user,
            ws_key,
        );

        let mut stream = client.stream();

        // Test connection and message reception with timeout
        let result = timeout(Duration::from_secs(30), async {
            let mut message_count = 0;
            let max_messages = 5;

            while let Some(result) = stream.next().await {
                match result {
                    Ok((component_id, msg)) => {
                        println!("Received message with ID: {component_id}");

                        assert!(!component_id.is_empty());
                        assert_eq!(component_id, "bebop");
                        assert!(msg.header.timestamp > 0);
                        assert!(!msg.snapshots.states.is_empty());

                        let snapshot = &msg.snapshots;

                        // We got at least one component
                        assert!(!snapshot.states.is_empty());

                        println!("Received {} components in this message", snapshot.states.len());
                        for (id, component_with_state) in &snapshot.states {
                            // Expect component ID to be in format "bebop_{pair}"
                            assert!(id.starts_with("bebop_"));
                            assert_eq!(
                                component_with_state
                                    .component
                                    .protocol_system,
                                "rfq:bebop"
                            );
                            assert_eq!(
                                component_with_state
                                    .component
                                    .protocol_type_name,
                                "bebop_pool"
                            );
                            assert_eq!(component_with_state.component.chain, Chain::Ethereum);

                            let attributes = &component_with_state.state.attributes;

                            // Check that bids and asks exist and have non-empty byte strings
                            assert!(attributes.contains_key("bids"));
                            assert!(attributes.contains_key("asks"));
                            assert!(!attributes["bids"].is_empty());
                            assert!(!attributes["asks"].is_empty());

                            if let Some(tvl) = component_with_state.component_tvl {
                                assert!(tvl >= 0.0);
                                println!("Component {id} TVL: ${tvl:.2}");
                            }
                        }

                        message_count += 1;
                        if message_count >= max_messages {
                            break;
                        }
                    }
                    Err(e) => {
                        panic!("Stream error: {e}");
                    }
                }
            }

            assert!(message_count > 0, "Should have received at least one message");
            println!("Successfully received {message_count} messages");
        })
        .await;

        match result {
            Ok(_) => println!("Test completed successfully"),
            Err(_) => panic!("Test timed out - no messages received within 10 seconds"),
        }
    }
}
