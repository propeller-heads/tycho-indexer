#![allow(dead_code)] // TODO remove this
use std::{
    collections::{HashMap, HashSet},
    time::SystemTime,
};

use alloy::primitives::utils::keccak256;
use async_trait::async_trait;
use futures::stream::BoxStream;
use reqwest::Client;
use tokio::time::{interval, Duration};
use tracing::{error, info};
use tycho_common::{
    models::{protocol::GetAmountOutParams, Chain},
    simulation::indicatively_priced::SignedQuote,
    Bytes,
};

use crate::{
    rfq::{
        client::RFQClient,
        errors::RFQError,
        models::TimestampHeader,
        protocols::hashflow::models::{
            HashflowMarketMakerLevels, HashflowMarketMakersResponse, HashflowPriceLevelsResponse,
        },
    },
    tycho_client::feed::synchronizer::{ComponentWithState, Snapshot, StateSyncMessage},
    tycho_common::dto::{ProtocolComponent, ResponseProtocolState},
};

#[derive(Clone)]
pub struct HashflowClient {
    chain: Chain,
    price_levels_endpoint: String,
    market_makers_endpoint: String,
    quote_endpoint: String,
    // Tokens that we want prices for
    tokens: HashSet<Bytes>,
    // Min tvl value in the quote token.
    tvl: f64,
    http_client: Client,
    auth_key: String,
    source: String,
    // Quote tokens to normalize to for TVL purposes. Should have the same prices.
    quote_tokens: HashSet<Bytes>,
    market_makers: Vec<String>,
    poll_time: u64,
}

impl HashflowClient {
    pub fn new(
        chain: Chain,
        tokens: HashSet<Bytes>,
        tvl: f64,
        quote_tokens: HashSet<Bytes>,
        auth_user: String,
        auth_key: String,
        poll_time: u64,
    ) -> Result<Self, RFQError> {
        Ok(Self {
            chain,
            price_levels_endpoint: "https://api.hashflow.com/taker/v3/price-levels".to_string(),
            market_makers_endpoint: "https://api.hashflow.com/taker/v3/market-makers".to_string(),
            quote_endpoint: "https://api.hashflow.com/taker/v3/rfq".to_string(),
            tokens,
            tvl,
            http_client: Client::new(),
            auth_key,
            source: auth_user,
            quote_tokens,
            market_makers: Vec::new(), // Will be populated during first fetch
            poll_time,
        })
    }

    /// Normalize TVL to a common quote token for comparison
    /// Returns the normalized TVL value, or 0.0 if normalization fails due to no liquidity
    fn normalize_tvl(
        &self,
        raw_tvl: f64,
        quote_token: Bytes,
        levels_by_mm: &HashMap<String, Vec<HashflowMarketMakerLevels>>,
    ) -> Result<f64, RFQError> {
        // If the quote token is already in our approved quote token set, no conversion needed
        if self.quote_tokens.contains(&quote_token) {
            return Ok(raw_tvl);
        }

        // Try to find the price of the quote token in one of the approved quote tokens
        // for normalization.
        for approved_quote_token in &self.quote_tokens {
            for (_mm, mm_levels_inner) in levels_by_mm.iter() {
                for quote_mm_level in mm_levels_inner {
                    // Check for direct pair: quote_token/approved_quote_token
                    if quote_mm_level.pair.base_token == quote_token &&
                        quote_mm_level.pair.quote_token == *approved_quote_token
                    {
                        if let Some(price) = quote_mm_level.get_price(1.0) {
                            return Ok(raw_tvl * price);
                        }
                    }
                }
            }
        }

        // If we can't normalize, return TVL 0 (pool will be filtered out)
        Ok(0.0)
    }

    fn create_component_with_state(
        &self,
        component_id: String,
        tokens: Vec<Bytes>,
        mm_name: &str,
        mm_level: &HashflowMarketMakerLevels,
        tvl: f64,
    ) -> ComponentWithState {
        let protocol_component = ProtocolComponent {
            id: component_id.clone(),
            protocol_system: "rfq:hashflow".to_string(),
            protocol_type_name: "hashflow_pool".to_string(),
            chain: self.chain.into(),
            tokens,
            contract_ids: vec![], // empty for RFQ
            ..Default::default()
        };

        let mut attributes = HashMap::new();

        // Store price levels as JSON string
        if !mm_level.levels.is_empty() {
            let levels_json = serde_json::to_string(&mm_level.levels).unwrap_or_default();
            attributes.insert("levels".to_string(), levels_json.as_bytes().to_vec().into());
        }
        attributes.insert("mm".to_string(), mm_name.as_bytes().to_vec().into());

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

    async fn fetch_market_makers(&mut self) -> Result<(), RFQError> {
        let query_params = vec![
            ("source", self.source.clone()),
            ("baseChainType", "evm".to_string()),
            ("baseChainId", self.chain.id().to_string()),
        ];

        let request = self
            .http_client
            .get(&self.market_makers_endpoint)
            .query(&query_params)
            .header("accept", "application/json")
            .header("Authorization", &self.auth_key);

        let response = request.send().await.map_err(|e| {
            RFQError::ConnectionError(format!("Failed to fetch market makers: {e}"))
        })?;

        if !response.status().is_success() {
            return Err(RFQError::ConnectionError(format!(
                "HTTP error {}: {}",
                response.status(),
                response
                    .text()
                    .await
                    .unwrap_or_default()
            )));
        }

        let mm_response: HashflowMarketMakersResponse = response.json().await.map_err(|e| {
            RFQError::ParsingError(format!("Failed to parse market makers response: {e}"))
        })?;

        self.market_makers = mm_response.market_makers;

        info!("Fetched {} market makers: {:?}", self.market_makers.len(), self.market_makers);

        Ok(())
    }

    async fn fetch_price_levels(
        &self,
    ) -> Result<HashMap<String, Vec<HashflowMarketMakerLevels>>, RFQError> {
        let mut query_params = vec![
            ("source", self.source.clone()),
            ("baseChainType", "evm".to_string()),
            ("baseChainId", self.chain.id().to_string()),
        ];

        // Add market makers as array parameters
        for mm in &self.market_makers {
            query_params.push(("marketMakers[]", mm.clone()));
        }

        let request = self
            .http_client
            .get(&self.price_levels_endpoint)
            .query(&query_params)
            .header("accept", "application/json")
            .header("Authorization", &self.auth_key);

        let response = request
            .send()
            .await
            .map_err(|e| RFQError::ConnectionError(format!("Failed to fetch price levels: {e}")))?;

        if !response.status().is_success() {
            return Err(RFQError::ConnectionError(format!(
                "HTTP error {}: {}",
                response.status(),
                response
                    .text()
                    .await
                    .unwrap_or_default()
            )));
        }

        let price_response: HashflowPriceLevelsResponse = response.json().await.map_err(|e| {
            RFQError::ParsingError(format!("Failed to parse price levels response: {e}"))
        })?;

        if price_response.status != "success" {
            return Err(RFQError::InvalidInput(format!(
                "API returned error status: {}",
                price_response.error.unwrap_or_default()
            )));
        }

        price_response
            .levels
            .ok_or_else(|| RFQError::ParsingError("API response missing levels".to_string()))
    }
}

#[async_trait]
impl RFQClient for HashflowClient {
    fn stream(
        &self,
    ) -> BoxStream<'static, Result<(String, StateSyncMessage<TimestampHeader>), RFQError>> {
        let mut client = self.clone();

        Box::pin(async_stream::stream! {
            let mut current_components: HashMap<String, ComponentWithState> = HashMap::new();
            let mut ticker = interval(Duration::from_secs(client.poll_time));

            info!("Starting Hashflow price levels polling every {} seconds", client.poll_time);
            info!("TVL threshold: {:.2}", client.tvl);

            loop {
                ticker.tick().await;
                match client.fetch_market_makers().await {
                    Ok(()) => {
                        info!("Successfully fetched market makers");
                    }
                    Err(e) => {
                        info!("Failed to fetch market makers: {}", e);
                        continue;
                    }
                }

                match client.fetch_price_levels().await {
                    Ok(levels_by_mm) => {
                        let mut new_components = HashMap::new();

                        info!("Fetched price levels from {} market makers", levels_by_mm.len());
                        // Process all market maker levels
                        for (mm_name, mm_levels) in levels_by_mm.iter() {
                            for mm_level in mm_levels {
                                let base_token = &mm_level.pair.base_token;
                                let quote_token = &mm_level.pair.quote_token;

                                // Check if both tokens are in our tokens set
                                if client.tokens.contains(base_token) && client.tokens.contains(quote_token) {
                                    let tokens = vec![base_token.clone(), quote_token.clone()];
                                    let tvl = mm_level.calculate_tvl();

                                    // Apply TVL normalization if needed
                                    let normalized_tvl = client.normalize_tvl(
                                        tvl,
                                        mm_level.pair.quote_token.clone(),
                                        &levels_by_mm,
                                    )?;

                                    // Hash the pair for component id
                                    let pair_str = format!("{}/{}", hex::encode(base_token), hex::encode(quote_token));
                                    let component_id = format!("{}", keccak256(pair_str.as_bytes()));

                                    if normalized_tvl < client.tvl {
                                        info!("Filtering out component {} due to low TVL: {:.2} < {:.2}",
                                              component_id, normalized_tvl, client.tvl);
                                        continue;
                                    }

                                    let component_with_state = client.create_component_with_state(
                                        component_id.clone(),
                                        tokens,
                                        mm_name,
                                        mm_level,
                                        normalized_tvl
                                    );
                                    new_components.insert(component_id, component_with_state);
                                }
                            }
                        }

                        // Find components that were removed
                        let removed_components: HashMap<String, ProtocolComponent> = current_components
                            .iter()
                            .filter(|&(id, _)| !new_components.contains_key(id))
                            .map(|(k, v)| (k.clone(), v.component.clone()))
                            .collect();

                        // Update current state
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
                            deltas: None,
                            removed_components,
                        };

                        yield Ok(("hashflow".to_string(), msg));
                    },
                    Err(e) => {
                        error!("Failed to fetch price levels from Hashflow API: {}", e);
                        continue;
                    }
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
}

#[cfg(test)]
mod tests {
    use std::{str::FromStr, time::Duration};

    use futures::StreamExt;
    use tokio::time::timeout;

    use super::*;
    use crate::rfq::protocols::hashflow::models::{HashflowPair, HashflowPriceLevel};

    #[test]
    fn test_normalize_tvl_same_quote_token() {
        let client = create_test_client();
        let levels = HashMap::new();

        // USDC is in our quote tokens, so no normalization should happen
        let result = client.normalize_tvl(
            1000.0,
            Bytes::from_str("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48").unwrap(),
            &levels,
        );
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 1000.0);
    }

    #[test]
    fn test_normalize_tvl_different_quote_token() {
        let client = create_test_client();
        let mut levels = HashMap::new();
        let weth = Bytes::from_str("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2").unwrap();
        let usdc = Bytes::from_str("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48").unwrap();

        // Create mock levels for ETH/USDC pair for normalization
        let eth_usdc_level = HashflowMarketMakerLevels {
            pair: HashflowPair { base_token: weth.clone(), quote_token: usdc },
            levels: vec![
                HashflowPriceLevel { quantity: 1.0, price: 3000.0 }, /* 1 ETH = 3000 USDC */
            ],
        };

        levels.insert("test_mm".to_string(), vec![eth_usdc_level]);

        // Test normalizing ETH TVL to USDC
        let result = client.normalize_tvl(2.0, weth, &levels);
        assert!(result.is_ok());
        // 2 ETH * 3000 USDC/ETH = 6000 USDC
        assert_eq!(result.unwrap(), 6000.0);
    }

    #[test]
    fn test_normalize_tvl_no_conversion_available() {
        let client = create_test_client();
        let levels = HashMap::new();
        let result = client.normalize_tvl(
            1000.0,
            Bytes::from_str("0x1234567890123456789012345678901234567890").unwrap(),
            &levels,
        );
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0.0);
    }

    fn create_test_client() -> HashflowClient {
        let quote_tokens = HashSet::from([
            Bytes::from_str("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48").unwrap(), // USDC
            Bytes::from_str("0xdAC17F958D2ee523a2206206994597C13D831ec7").unwrap(), // USDT
        ]);

        HashflowClient::new(
            Chain::Ethereum,
            HashSet::new(),
            1.0,
            quote_tokens,
            "test_user".to_string(),
            "test_key".to_string(),
            5,
        )
        .unwrap()
    }

    #[tokio::test]
    #[ignore] // Requires network access and HASHFLOW_KEY environment variable
    async fn test_hashflow_api_polling() {
        use std::env;
        let hashflow_key = env::var("HASHFLOW_KEY").unwrap();

        let lpt = Bytes::from_str("0x58b6a8a3302369daec383334672404ee733ab239").unwrap();
        let usdc = Bytes::from_str("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48").unwrap();

        let tokens = HashSet::from([lpt, usdc.clone()]);

        let quote_tokens = HashSet::from([
            Bytes::from_str("0xa0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48").unwrap(), // USDC
            Bytes::from_str("0xdac17f958d2ee523a2206206994597c13d831ec7").unwrap(), // USDT
        ]);

        let client = HashflowClient::new(
            Chain::Ethereum,
            tokens,
            1.0, // $1 minimum TVL - very low to capture most pairs
            quote_tokens,
            "propellerheads".to_string(),
            hashflow_key,
            1,
        )
        .unwrap();

        let mut stream = client.stream();

        let result = timeout(Duration::from_secs(5), async {
            let mut message_count = 0;
            let max_messages = 3;
            let mut total_components_received = 0;

            while let Some(result) = stream.next().await {
                match result {
                    Ok((component_id, msg)) => {
                        println!("Received message with ID: {component_id}");

                        assert!(!component_id.is_empty());
                        assert_eq!(component_id, "hashflow");
                        assert!(msg.header.timestamp > 0);

                        let snapshot = &msg.snapshots;
                        total_components_received += snapshot.states.len();

                        println!("Received {} components in this message (Total so far: {})", 
                                snapshot.states.len(), total_components_received);

                        for (id, component_with_state) in &snapshot.states {
                            let attributes = &component_with_state.state.attributes;

                            // Check that levels exist
                            if attributes.contains_key("levels") {
                                assert!(!attributes["levels"].is_empty());
                            }
                            // Check that mm name exist
                            if attributes.contains_key("mm") {
                                assert!(!attributes["mm"].is_empty());
                            }

                            if let Some(tvl) = component_with_state.component_tvl {
                                assert!(tvl >= 1.0);
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
            assert!(total_components_received >= 1, "Should have received at least 1 component with $1 TVL threshold");
            println!("Successfully received {message_count} messages with {total_components_received} total components");
        })
        .await;

        match result {
            Ok(_) => println!("Test completed successfully"),
            Err(_) => panic!("Test timed out - no messages received within 5 seconds"),
        }
    }
}
