use std::{collections::HashMap, time::Duration};

use alloy::{
    json_abi::{Event, Function},
    primitives::{Selector, B256},
};
use reqwest::Client;
use serde::Deserialize;
use tokio::time::sleep;

/// Response from 4byte.directory API for function signatures
#[derive(Debug, Deserialize)]
struct FourByteResponse {
    results: Vec<FunctionSignature>,
}

#[derive(Debug, Deserialize)]
struct FunctionSignature {
    text_signature: String,
}

/// Response from 4byte.directory API for event signatures  
#[derive(Debug, Deserialize)]
struct EventSignatureResponse {
    results: Vec<EventSignature>,
}

#[derive(Debug, Deserialize)]
struct EventSignature {
    text_signature: String,
}

/// Signature identifier that uses 4byte.directory
pub struct SignaturesIdentifier {
    client: Client,
    /// Cache for function signatures
    function_cache: HashMap<Selector, Function>,
    /// Cache for event signatures
    event_cache: HashMap<B256, Event>,
    /// Whether to work in offline mode
    offline: bool,
}

impl SignaturesIdentifier {
    /// Create a new signature identifier
    pub fn new(offline: bool) -> Result<Self, Box<dyn std::error::Error>> {
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .build()?;

        Ok(Self { client, function_cache: HashMap::new(), event_cache: HashMap::new(), offline })
    }

    /// Identify a function by its selector
    pub async fn identify_function(&mut self, selector: Selector) -> Option<Function> {
        // Check cache first
        if let Some(func) = self.function_cache.get(&selector) {
            return Some(func.clone());
        }

        // Don't make network calls if offline
        if self.offline {
            return None;
        }

        // Query 4byte.directory
        let hex_selector = format!("0x{}", hex::encode(selector.as_slice()));
        let url = format!(
            "https://www.4byte.directory/api/v1/signatures/?hex_signature={}",
            hex_selector
        );

        match self.fetch_with_retry(&url).await {
            Ok(response) => {
                if let Ok(data) = response
                    .json::<FourByteResponse>()
                    .await
                {
                    if let Some(sig) = data.results.first() {
                        if let Ok(function) = Function::parse(&sig.text_signature) {
                            self.function_cache
                                .insert(selector, function.clone());
                            return Some(function);
                        }
                    }
                }
            }
            Err(e) => {
                tracing::warn!(target: "traces::signatures", "failed to fetch function signature: {}", e);
            }
        }

        None
    }

    /// Identify an event by its topic hash
    pub async fn identify_event(&mut self, topic: B256) -> Option<Event> {
        // Check cache first
        if let Some(event) = self.event_cache.get(&topic) {
            return Some(event.clone());
        }

        // Don't make network calls if offline
        if self.offline {
            return None;
        }

        // Query 4byte.directory for event signatures
        let hex_topic = format!("0x{}", hex::encode(topic.as_slice()));
        let url = format!(
            "https://www.4byte.directory/api/v1/event-signatures/?hex_signature={}",
            hex_topic
        );

        match self.fetch_with_retry(&url).await {
            Ok(response) => {
                if let Ok(data) = response
                    .json::<EventSignatureResponse>()
                    .await
                {
                    if let Some(sig) = data.results.first() {
                        if let Ok(event) = Event::parse(&sig.text_signature) {
                            self.event_cache
                                .insert(topic, event.clone());
                            return Some(event);
                        }
                    }
                }
            }
            Err(e) => {
                tracing::warn!(target: "traces::signatures", "failed to fetch event signature: {}", e);
            }
        }

        None
    }

    /// Identify multiple signatures at once
    pub async fn identify_batch(
        &mut self,
        selectors: &[SelectorKind],
    ) -> Result<(), Box<dyn std::error::Error>> {
        if self.offline {
            return Ok(());
        }

        // Split into functions and events
        let functions: Vec<_> = selectors
            .iter()
            .filter_map(|s| match s {
                SelectorKind::Function(sel) => Some(*sel),
                _ => None,
            })
            .collect();

        let events: Vec<_> = selectors
            .iter()
            .filter_map(|s| match s {
                SelectorKind::Event(topic) => Some(*topic),
                _ => None,
            })
            .collect();

        // Fetch functions
        for selector in functions {
            if !self
                .function_cache
                .contains_key(&selector)
            {
                if let Some(func) = self.identify_function(selector).await {
                    self.function_cache
                        .insert(selector, func);
                }
                // Rate limiting - don't overwhelm 4byte.directory
                sleep(Duration::from_millis(100)).await;
            }
        }

        // Fetch events
        for topic in events {
            if !self.event_cache.contains_key(&topic) {
                if let Some(event) = self.identify_event(topic).await {
                    self.event_cache.insert(topic, event);
                }
                // Rate limiting
                sleep(Duration::from_millis(100)).await;
            }
        }

        Ok(())
    }

    /// Fetch with basic retry logic
    async fn fetch_with_retry(&self, url: &str) -> Result<reqwest::Response, reqwest::Error> {
        let mut retries = 3;
        loop {
            match self.client.get(url).send().await {
                Ok(response) => {
                    if response.status().is_success() {
                        return Ok(response);
                    } else if response.status().as_u16() == 429 && retries > 0 {
                        // Rate limited, wait and retry
                        sleep(Duration::from_secs(1)).await;
                        retries -= 1;
                        continue;
                    } else {
                        return Ok(response);
                    }
                }
                Err(_e) if retries > 0 => {
                    sleep(Duration::from_millis(500)).await;
                    retries -= 1;
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
    }
}

/// Selector kind for batch identification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SelectorKind {
    /// Function selector (4 bytes)
    Function(Selector),
    /// Event topic hash (32 bytes)
    Event(B256),
}
