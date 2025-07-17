use std::collections::{HashMap, HashSet};

use async_trait::async_trait;
use futures::{stream::BoxStream, StreamExt};
use serde::{Deserialize, Serialize};
use tokio_tungstenite::{connect_async_with_config, tungstenite::Message};
use tracing;

use crate::{
    rfq::{
        client::RFQClient,
        errors::RFQError,
        indicatively_priced::SignedQuote,
        models::{GetAmountOutParams, TimestampHeader},
    },
    tycho_client::feed::synchronizer::{ComponentWithState, Snapshot, StateSyncMessage},
    tycho_common::dto::{ProtocolComponent, ResponseProtocolState},
    tycho_core::dto::Chain,
};

type BebopPriceMessage = HashMap<String, BebopPriceData>;

#[derive(Debug, Serialize, Deserialize)]
struct BebopPriceData {
    last_update_ts: f64,
    /// Vec where each tuple is (price, size)
    bids: Vec<(f64, f64)>,
    /// Vec where each tuple is (price, size)
    asks: Vec<(f64, f64)>,
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
}

fn pair_to_bebop_format(pair: &(String, String)) -> String {
    format!("{}/{}", pair.0, pair.1)
}

/// Gets the mid price of the given token with USDC as the quote token
///
/// # Parameters
/// - `token_amount`: The amount of tokens to price
/// - `price_data`: The price data containing bids and asks
///
/// # Returns
/// The USDC amount at mid price, or None if insufficient liquidity on either side
fn get_mid_usdc_price(token_amount: f64, price_data: &BebopPriceData) -> Option<f64> {
    let sell_usdc = calculate_usdc_amount(token_amount, price_data, true)?;
    let buy_usdc = calculate_usdc_amount(token_amount, price_data, false)?;

    // Return average (mid price)
    Some((sell_usdc + buy_usdc) / 2.0)
}

/// Calculate USDC amount for trading tokens through price levels
///
/// # Parameters
/// - `token_amount`: The amount of tokens to trade
/// - `price_data`: The price data containing bids and asks
/// - `is_selling`: True for selling tokens (use bids), false for buying tokens (use asks)
///
/// # Returns
/// Total USDC amount, or None if insufficient liquidity
fn calculate_usdc_amount(
    token_amount: f64,
    price_data: &BebopPriceData,
    sell: bool,
) -> Option<f64> {
    // Price levels are already sorted: https://docs.bebop.xyz/bebop/bebop-api-pmm-rfq/rfq-api-endpoints/pricing#interpreting-price-levels
    let price_levels = if sell { price_data.bids.clone() } else { price_data.asks.clone() };

    let mut remaining_tokens = token_amount;
    let mut total_usdc = 0.0;

    for (price, usdc_size) in price_levels.iter() {
        if remaining_tokens <= 0.0 {
            break;
        }

        // Convert USDC size to token quantity available at this level
        let tokens_available = usdc_size / price;
        let tokens_to_trade = remaining_tokens.min(tokens_available);

        total_usdc += tokens_to_trade * price;
        remaining_tokens -= tokens_to_trade;
    }

    // Return None if we couldn't fill the entire order
    if remaining_tokens > 0.0 {
        None
    } else {
        Some(total_usdc)
    }
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
        Self { url, pairs: pair_names, chain, tvl, ws_user, ws_key }
    }

    /// Calculates Total Value Locked (TVL) based on bid/ask levels.
    ///
    /// TVL is calculated using the formula from Bebop's documentation:
    /// https://docs.bebop.xyz/bebop/bebop-api-pmm-rfq/rfq-api-endpoints/pricing#interpreting-price-levels
    ///
    /// Returns the average of bid and ask TVLs across all price levels.
    ///
    /// Note: This calculation assumes all pairs use the same quote token.
    /// For cross-pair comparisons, token prices should be normalized to a common denomination.
    fn calculate_tvl(&self, price_data: &BebopPriceData) -> f64 {
        let bid_tvl: f64 = price_data
            .bids
            .iter()
            .map(|(price, size)| price * size)
            .sum();

        let ask_tvl: f64 = price_data
            .asks
            .iter()
            .map(|(price, size)| price * size)
            .sum();

        (bid_tvl + ask_tvl) / 2.0
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
                    .expect("Failed to build request");

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
                                    let mut latest_timestamp = 0u64;

                                    // Process all pairs from this WebSocket message
                                    for (pair, price_data) in price_data_map {
                                        if pairs.contains(&pair) {
                                            let tvl = client.calculate_tvl(&price_data);
                                            if tvl < tvl_threshold {
                                                continue;
                                            }

                                            let component_id = format!("bebop_{}", pair.replace("/", "_"));

                                            let tokens;
                                            if let Some((token0, token1)) = pair.split_once('/') {
                                                tokens = vec![token0.as_bytes().to_vec().into(), token1.as_bytes().to_vec().into()]
                                            } else {
                                                continue;
                                            };

                                            let component_with_state = client.create_component_with_state(component_id.clone(), tokens, &price_data, tvl);
                                            new_components.insert(component_id, component_with_state);

                                            // Track the latest timestamp across all pairs
                                            let timestamp = price_data.last_update_ts as u64;
                                            if timestamp > latest_timestamp {
                                                latest_timestamp = timestamp;
                                            }
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

                                    let msg = StateSyncMessage::<TimestampHeader> {
                                        header: TimestampHeader { timestamp: latest_timestamp },
                                        snapshots: snapshot,
                                        deltas: None, // Deltas are always None - all the changes are absolute
                                        removed_components: removed_components.into_iter().map(|id| (id, Default::default())).collect(),
                                    };

                                    // Yield one message containing all updated pairs
                                    yield Ok(("bebop_all_pairs".to_string(), msg));
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

        let usdc = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48".to_string();
        let weth = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2".to_string();

        let ws_user = String::from("tycho");
        let ws_key = env::var("BEBOP_KEY").expect("BEBOP_KEY environment variable is required");

        let client = BebopClient::new(
            Chain::Ethereum,
            vec![(weth.to_string(), usdc.to_string())],
            1000.0, // $1000 minimum TVL
            ws_user,
            ws_key,
        );

        let mut stream = client.stream();

        // Test connection and message reception with timeout
        let result = timeout(Duration::from_secs(10), async {
            let mut message_count = 0;
            let max_messages = 5;

            while let Some(result) = stream.next().await {
                match result {
                    Ok((component_id, msg)) => {
                        println!("Received message with ID: {component_id}");

                        assert!(!component_id.is_empty());
                        assert_eq!(component_id, "bebop_all_pairs");
                        assert!(msg.header.timestamp > 0);
                        assert!(!msg.snapshots.states.is_empty());

                        let snapshot = &msg.snapshots;

                        // We got at least one component
                        assert!(!snapshot.states.is_empty());
                        println!("Received {} components in this message", snapshot.states.len());

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

    #[test]
    fn test_calculate_tvl() {
        let ws_user = String::from("tycho");
        let ws_key = String::from("mock-key");
        let client = BebopClient::new(Chain::Ethereum, vec![], 0.0, ws_user, ws_key);

        let price_data = BebopPriceData {
            last_update_ts: 1234567890.0,
            bids: vec![(2000.0, 1.0), (1999.0, 2.0)],
            asks: vec![(2001.0, 1.5), (2002.0, 1.0)],
        };

        let tvl = client.calculate_tvl(&price_data);

        // Expected calculation:
        // Bid TVL: (2000.0 * 1.0) + (1999.0 * 2.0) = 2000.0 + 3998.0 = 5998.0
        // Ask TVL: (2001.0 * 1.5) + (2002.0 * 1.0) = 3001.5 + 2002.0 = 5003.5
        // Total TVL: (5998.0 + 5003.5) / 2 = 5500.75
        assert!((tvl - 5500.75).abs() < 0.01);
    }

    #[test]
    fn test_get_mid_usdc_price() {
        let price_data = BebopPriceData {
            last_update_ts: 1234567890.0,
            // You can buy 2000 USDC for 1 of token X, up to 4000 USDC worth
            // and then 1999 USDC for 1 of token X after that, up to an additional 3998 USDC worth
            bids: vec![(2000.0, 4000.0), (1999.0, 3998.0)],
            asks: vec![(2001.0, 6003.0), (2002.0, 2002.0)],
        };

        // Test mid price for larger amount spanning multiple levels
        let mid_price_large = get_mid_usdc_price(3.0, &price_data);
        // Sell 3.0 tokens: 2.0 at 2000.0 + 1.0 at 1999.0 = 4000.0 + 1999.0 = 5999.0
        // Buy 3.0 tokens: 3.0 at 2001.0 = 6003.0
        // Mid = (5999.0 + 6003.0) / 2 = 6001.0
        assert_eq!(mid_price_large, Some(6001.0));

        // Test insufficient liquidity
        let insufficient_mid = get_mid_usdc_price(10.0, &price_data);
        assert_eq!(insufficient_mid, None); // Not enough liquidity for 10 tokens
    }
}
