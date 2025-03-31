//! WASM entry point for Tycho client
#![cfg(target_arch = "wasm32")]

use js_sys::{self, Function, JSON};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{collections::HashSet, str::FromStr};
use tycho_common::dto::{Chain, PaginationParams, ProtocolSystemsRequestBody};
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::{future_to_promise, spawn_local, JsFuture};
use web_sys::{self, console, Event, MessageEvent};

// Define our configuration structure
#[derive(Serialize, Deserialize, Clone)]
pub struct TychoClientConfig {
    /// Tycho server URL, without protocol. Example: localhost:4242
    pub tycho_url: String,

    /// Tycho gateway API key
    pub auth_key: Option<String>,

    /// If set, use unsecured transports: http and ws instead of https and wss.
    pub no_tls: bool,

    /// The blockchain to index on
    pub chain: String,

    /// Exchanges with optional pool addresses in format [["uniswap_v2", "0x1234..."], ["uniswap_v3", null]]
    pub exchanges: Vec<(String, Option<String>)>,

    /// Minimum TVL for filtering components
    pub min_tvl: u32,

    /// Lower bound TVL threshold
    pub remove_tvl_threshold: Option<u32>,

    /// Upper bound TVL threshold
    pub add_tvl_threshold: Option<u32>,

    /// Expected block time in seconds
    pub block_time: u64,

    /// Maximum wait time in seconds beyond the block time
    pub timeout: u64,

    /// Stream only components and tokens, omit state updates
    pub no_state: bool,

    /// Maximum messages to process before exiting
    pub max_messages: Option<usize>,

    /// Maximum blocks an exchange can be absent before marked stale
    pub max_missed_blocks: u64,
}

#[wasm_bindgen]
pub struct TychoClient {
    config: TychoClientConfig,
    callback: Option<js_sys::Function>,
}

#[wasm_bindgen]
impl TychoClient {
    /// Create a new TychoClient instance with the given configuration
    #[wasm_bindgen(constructor)]
    pub fn new(config_js: JsValue) -> Result<TychoClient, JsValue> {
        // Set console error panic hook for better error messages
        console_error_panic_hook::set_once();

        let config: TychoClientConfig = serde_wasm_bindgen::from_value(config_js)?;

        // Validate config
        if config.remove_tvl_threshold.is_some() && config.add_tvl_threshold.is_none() {
            return Err(JsValue::from_str(
                "Both remove_tvl_threshold and add_tvl_threshold must be set",
            ));
        }
        if config.remove_tvl_threshold.is_none() && config.add_tvl_threshold.is_some() {
            return Err(JsValue::from_str(
                "Both remove_tvl_threshold and add_tvl_threshold must be set",
            ));
        }

        Ok(TychoClient { config, callback: None })
    }

    /// Set a callback function that will be called with each message
    #[wasm_bindgen]
    pub fn set_message_callback(&mut self, callback: js_sys::Function) {
        self.callback = Some(callback);
    }

    /// Start the client and begin receiving data
    #[wasm_bindgen]
    pub fn start(&self) -> Result<(), JsValue> {
        let config = self.config.clone();
        let callback = match &self.callback {
            Some(cb) => cb.clone(),
            None => {
                return Err(JsValue::from_str(
                    "No message callback set. Call set_message_callback() before starting.",
                ))
            }
        };

        spawn_local(async move {
            let result = run_wasm(config, callback).await;
            if let Err(err) = result {
                console::error_1(&JsValue::from_str(&format!("Error: {:?}", err)));
            }
        });

        Ok(())
    }

    /// Get available protocols for the configured chain
    #[wasm_bindgen]
    pub fn get_available_protocols(&self) -> js_sys::Promise {
        let config = self.config.clone();

        future_to_promise(async move {
            let chain = Chain::from_str(&config.chain).map_err(|e| {
                JsValue::from_str(&format!("Unknown chain {}: {:?}", &config.chain, e))
            })?;

            let (_, tycho_rpc_url) = get_endpoints(&config.tycho_url, config.no_tls);

            let protocols =
                fetch_protocols(&tycho_rpc_url, config.auth_key.as_deref(), chain).await?;

            Ok(serde_wasm_bindgen::to_value(&protocols)?)
        })
    }
}

// Helper function to get WebSocket and HTTP endpoints
fn get_endpoints(tycho_url: &str, no_tls: bool) -> (String, String) {
    if no_tls {
        let tycho_ws_url = format!("ws://{}", tycho_url);
        let tycho_rpc_url = format!("http://{}", tycho_url);
        (tycho_ws_url, tycho_rpc_url)
    } else {
        let tycho_ws_url = format!("wss://{}", tycho_url);
        let tycho_rpc_url = format!("https://{}", tycho_url);
        (tycho_ws_url, tycho_rpc_url)
    }
}

async fn fetch_protocols(
    tycho_rpc_url: &str,
    auth_key: Option<&str>,
    chain: Chain,
) -> Result<Vec<String>, JsValue> {
    let mut headers = web_sys::Headers::new()?;
    headers.append("Content-Type", "application/json")?;

    if let Some(key) = auth_key {
        headers.append("Authorization", &format!("Bearer {}", key))?;
    }

    let body = ProtocolSystemsRequestBody {
        chain,
        pagination: PaginationParams { page: 0, page_size: 100 },
    };

    let body_js = serde_wasm_bindgen::to_value(&body)?;
    let body_str = JSON::stringify(&body_js)?;

    let mut init = web_sys::RequestInit::new();
    init.method("POST");
    init.headers(&headers);
    init.body(Some(&body_str.into()));

    let endpoint = format!("{}/protocol-systems", tycho_rpc_url);
    let request = web_sys::Request::new_with_str_and_init(&endpoint, &init)?;

    let window = web_sys::window().ok_or(JsValue::from_str("No window found"))?;
    let response_value = JsFuture::from(window.fetch_with_request(&request)).await?;
    let response: web_sys::Response = response_value.dyn_into()?;

    if !response.ok() {
        return Err(JsValue::from_str(&format!("HTTP error: {}", response.status())));
    }

    let json_value = JsFuture::from(response.json()?).await?;
    let protocols_response: ProtocolSystemsResponse = serde_wasm_bindgen::from_value(json_value)?;

    Ok(protocols_response.protocol_systems)
}

async fn run_wasm(config: TychoClientConfig, callback: js_sys::Function) -> Result<(), JsValue> {
    console::log_1(&JsValue::from_str("Starting Tycho Client in WASM mode"));

    // Get WebSocket and HTTP endpoints
    let (tycho_ws_url, tycho_rpc_url) = get_endpoints(&config.tycho_url, config.no_tls);

    // Connect to WebSocket
    let ws = web_sys::WebSocket::new(&tycho_ws_url)?;

    // Add auth header if available (this would need to be handled differently for WebSockets)
    if let Some(auth_key) = &config.auth_key {
        // For WebSockets, auth typically needs to be in query params or custom protocol
        console::log_1(&JsValue::from_str(&format!(
            "Auth key present: {}",
            auth_key
                .chars()
                .take(5)
                .collect::<String>()
        )));
    }

    // Fetch available protocols for information
    let chain = Chain::from_str(&config.chain)
        .map_err(|e| JsValue::from_str(&format!("Unknown chain {}: {:?}", &config.chain, e)))?;

    let available_protocols =
        fetch_protocols(&tycho_rpc_url, config.auth_key.as_deref(), chain).await?;

    let requested_protocol_set: HashSet<String> = config
        .exchanges
        .iter()
        .map(|(name, _)| name.clone())
        .collect();

    let available_protocols_set: HashSet<String> = available_protocols
        .into_iter()
        .collect();

    let not_requested_protocols: Vec<String> = available_protocols_set
        .difference(&requested_protocol_set)
        .cloned()
        .collect();

    if !not_requested_protocols.is_empty() {
        console::log_1(&JsValue::from_str(&format!(
            "Other available protocols: {}",
            not_requested_protocols.join(", ")
        )));
    }

    // Set up message handling for WebSocket
    let onmessage_callback = Closure::wrap(Box::new(move |event: MessageEvent| {
        if let Some(txt) = event.data().as_string() {
            let _ = callback.call1(&JsValue::NULL, &JsValue::from_str(&txt));
        }
    }) as Box<dyn FnMut(MessageEvent)>);

    ws.set_onmessage(Some(
        onmessage_callback
            .as_ref()
            .unchecked_ref(),
    ));
    onmessage_callback.forget(); // Prevent closure from being dropped

    // Set up message handling for WebSocket errors
    let onerror_callback = Closure::wrap(Box::new(move |event: Event| {
        console::error_1(&JsValue::from_str(&format!("WebSocket error: {:?}", event.type_())));
    }) as Box<dyn FnMut(Event)>);

    ws.set_onerror(Some(
        onerror_callback
            .as_ref()
            .unchecked_ref(),
    ));
    onerror_callback.forget(); // Prevent closure from being dropped

    // Set up WebSocket open handler
    let ws_clone = ws.clone();
    let config_clone = config.clone();
    let onopen_callback = Closure::wrap(Box::new(move |_event: Event| {
        console::log_1(&JsValue::from_str("WebSocket connection established"));

        // Send subscription messages for each exchange
        for (name, address) in &config_clone.exchanges {
            let subscription = create_subscription_message(
                chain,
                name,
                address.as_deref(),
                config_clone.min_tvl,
                config_clone.remove_tvl_threshold,
                config_clone.add_tvl_threshold,
                !config_clone.no_state,
            );

            match subscription {
                Ok(msg) => {
                    console::log_1(&JsValue::from_str(&format!("Sending subscription: {}", msg)));
                    if let Err(e) = ws_clone.send_with_str(&msg) {
                        console::error_1(&JsValue::from_str(&format!(
                            "Error sending subscription: {:?}",
                            e
                        )));
                    }
                }
                Err(e) => {
                    console::error_1(&JsValue::from_str(&format!(
                        "Error creating subscription: {:?}",
                        e
                    )));
                }
            }
        }
    }) as Box<dyn FnMut(Event)>);

    ws.set_onopen(Some(onopen_callback.as_ref().unchecked_ref()));
    onopen_callback.forget();

    Ok(())
}

fn create_subscription_message(
    chain: Chain,
    name: &str,
    address: Option<&str>,
    min_tvl: u32,
    remove_tvl_threshold: Option<u32>,
    add_tvl_threshold: Option<u32>,
    include_state: bool,
) -> Result<String, JsValue> {
    // Create filter based on params
    let filter = if let Some(addr) = address {
        json!({
            "type": "ids",
            "ids": [addr]
        })
    } else if let (Some(remove_tvl), Some(add_tvl)) = (remove_tvl_threshold, add_tvl_threshold) {
        json!({
            "type": "tvl_range",
            "min": remove_tvl as f64,
            "max": add_tvl as f64
        })
    } else {
        json!({
            "type": "tvl_range",
            "min": min_tvl as f64,
            "max": min_tvl as f64
        })
    };

    // Create subscription message
    let msg = json!({
        "action": "subscribe",
        "protocol": {
            "chain": chain.to_string(),
            "name": name,
        },
        "filter": filter,
        "include_state": include_state
    });

    Ok(msg.to_string())
}

// Add necessary structs
#[derive(Serialize, Deserialize)]
struct ProtocolSystemsResponse {
    protocol_systems: Vec<String>,
}
