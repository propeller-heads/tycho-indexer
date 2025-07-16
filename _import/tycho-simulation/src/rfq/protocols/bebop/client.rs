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

impl BebopClient {
    pub fn new(
        chain: Chain,
        pairs: Vec<(String, String)>,
        tvl: f64,
        ws_user: String,
        ws_key: String,
    ) -> Self {
        // TODO should I specify protobuf serialization here? Is that even possible?
        // https://docs.bebop.xyz/bebop/bebop-api-pmm-rfq/rfq-api-endpoints/pricing#interpreting-price-levels

        let url = "wss://api.bebop.xyz/pmm/ethereum/v3/pricing".to_string();

        let mut pair_names: HashSet<String> = HashSet::new();
        for pair in pairs {
            pair_names.insert(pair_to_bebop_format(&pair));
        }
        Self { url, pairs: pair_names, chain, tvl, ws_user, ws_key }
    }

    // TVL is calculated using https://docs.bebop.xyz/bebop/bebop-api-pmm-rfq/rfq-api-endpoints/pricing#interpreting-price-levels
    // TODO make a proper docstring here
    fn calculate_tvl(&self, price_data: &BebopPriceData) -> f64 {
        // TODO this only works if the quote token is the same for each token pair - which I think
        //  is not the case. Should we get token prices at this point to translate everything to
        //  ETH or USD?

        let bid_tvl: f64 = price_data
            .bids
            .iter()
            .take(5) // Consider top 5 levels
            .map(|(price, size)| price * size)
            .sum();

        let ask_tvl: f64 = price_data
            .asks
            .iter()
            .take(5) // Consider top 5 levels
            .map(|(price, size)| price * size)
            .sum();

        (bid_tvl + ask_tvl) / 2.0
    }

    fn create_component_with_state(
        &self,
        pair: &str,
        price_data: &BebopPriceData,
    ) -> ComponentWithState {
        let id = format!("bebop_{}", pair.replace("/", "_"));

        let protocol_component = ProtocolComponent {
            id: id.clone(),
            protocol_system: "rfq:bebop".to_string(),
            protocol_type_name: "bebop_pool".to_string(),
            chain: self.chain,
            tokens: vec![],       // TODO: Extract from pair
            contract_ids: vec![], // empty for RFQ
            static_attributes: Default::default(),
            change: Default::default(),
            creation_tx: Default::default(),
            created_at: Default::default(),
        };

        let mut attributes = HashMap::new();

        // TODO should we put all of the bids and asks here - not just the best price?
        if let Some(&(price, size)) = price_data.bids.first() {
            attributes.insert(
                "best_bid_price".to_string(),
                price
                    .to_string()
                    .as_bytes()
                    .to_vec()
                    .into(),
            );
            attributes.insert(
                "best_bid_size".to_string(),
                size.to_string()
                    .as_bytes()
                    .to_vec()
                    .into(),
            );
        }
        // TODO what if no bids or asks? Error?

        if let Some(&(price, size)) = price_data.asks.first() {
            attributes.insert(
                "best_ask_price".to_string(),
                price
                    .to_string()
                    .as_bytes()
                    .to_vec()
                    .into(),
            );
            attributes.insert(
                "best_ask_size".to_string(),
                size.to_string()
                    .as_bytes()
                    .to_vec()
                    .into(),
            );
        }

        ComponentWithState {
            state: ResponseProtocolState {
                component_id: id.clone(),
                attributes,
                balances: HashMap::new(),
            },
            component: protocol_component,
            // TODO pass tvl instead of calculating it twice
            component_tvl: Some(self.calculate_tvl(price_data)),
            entrypoints: vec![],
        }
    }
}

#[async_trait]
impl RFQClient for BebopClient {
    fn stream(&self) -> BoxStream<'static, (String, StateSyncMessage<TimestampHeader>)> {
        let pairs = self.pairs.clone();
        let url = self.url.clone();
        let tvl_threshold = self.tvl;
        let name = self.ws_user.clone();
        let authorization = self.ws_key.clone();
        let client = self.clone();

        Box::pin(async_stream::stream! {
            // Create WebSocket request with custom headers
            use http::Request;
            use tokio_tungstenite::tungstenite::handshake::client::generate_key;

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
                Ok(connection) => connection,
                Err(e) => {
                    tracing::error!("Failed to connect to Bebop WebSocket: {}", e);
                    return;
                }
            };

            let (_, mut ws_receiver) = ws_stream.split();

            // TODO: What to do if the program crashes and restarts? Should we be retrieving these components
            // from the database?
            let mut current_components: HashMap<String, ComponentWithState> = HashMap::new();

            while let Some(msg) = ws_receiver.next().await {
                match msg {
                    Ok(Message::Text(text)) => {
                        if let Ok(price_data_map) = serde_json::from_str::<BebopPriceMessage>(&text) {
                            for (pair, price_data) in price_data_map {
                                if pairs.contains(&pair) {

                                    let tvl = client.calculate_tvl(&price_data);
                                    if tvl < tvl_threshold {
                                        continue;
                                    }

                                    let component_id = format!("bebop_{}", pair.replace("/", "_"));
                                    let component_with_state = client.create_component_with_state(&pair, &price_data);

                                    let new_components = HashMap::from([(component_id.clone(), component_with_state)]);

                                    let removed_components: Vec<String> = current_components.keys()
                                        .filter(|id| !new_components.contains_key(*id))
                                        .cloned()
                                        .collect();

                                    current_components = new_components.clone();

                                    let snapshot = Snapshot {
                                        states: new_components,
                                        vm_storage: HashMap::new(),
                                    };

                                    let timestamp = price_data.last_update_ts as u64;
                                    let msg = StateSyncMessage::<TimestampHeader> {
                                        header: TimestampHeader { timestamp },
                                        snapshots: snapshot,
                                        deltas: None,
                                        removed_components: removed_components.into_iter().map(|id| (id, Default::default())).collect(),
                                    };

                                    yield (component_id, msg);
                                }
                            }
                        } else {
                            // TODO use proper error handling instead of tracing
                            tracing::error!("Failed to parse websocket message.");
                            break;
                        }
                    }
                    Ok(Message::Close(_)) => {
                        tracing::info!("WebSocket connection closed");
                        break;
                    }
                    Err(e) => {
                        tracing::error!("WebSocket error: {}", e);
                        break;
                    }
                    _ => {} // Ignore other message types
                }
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

        let ws_user = String::from("propellerheads");
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

            while let Some((component_id, msg)) = stream.next().await {
                println!("Received message for component: {}", component_id);
                println!("Timestamp: {}", msg.header.timestamp);
                println!("Snapshots states count: {}", msg.snapshots.states.len());

                assert!(!component_id.is_empty());
                assert_eq!(component_id, "bebop_0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2_0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48");
                assert!(msg.header.timestamp > 0);
                assert!(!msg.snapshots.states.is_empty());

                let snapshot = &msg.snapshots;
                assert!(!snapshot.states.is_empty());

                for (id, component_with_state) in &snapshot.states {
                    assert_eq!(id, &component_id);
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
                    if attributes.contains_key("best_bid_price") {
                        assert!(attributes.contains_key("best_bid_size"));
                    }
                    if attributes.contains_key("best_ask_price") {
                        assert!(attributes.contains_key("best_ask_size"));
                    }

                    if let Some(tvl) = component_with_state.component_tvl {
                        assert!(tvl >= 0.0);
                        println!("Component TVL: ${:.2}", tvl);
                    }
                }

                message_count += 1;
                if message_count >= max_messages {
                    break;
                }
            }

            assert!(message_count > 0, "Should have received at least one message");
            println!("Successfully received {} messages", message_count);
        })
        .await;

        match result {
            Ok(_) => println!("Test completed successfully"),
            Err(_) => panic!("Test timed out - no messages received within 30 seconds"),
        }
    }

    #[test]
    fn test_calculate_tvl() {
        let ws_user = String::from("propellerheads");
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
}
