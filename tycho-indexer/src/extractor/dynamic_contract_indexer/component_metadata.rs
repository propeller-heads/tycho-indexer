#![allow(unused_variables)] // TODO: Remove this
#![allow(dead_code)] // TODO: Remove this

use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tycho_common::{
    models::{
        blockchain::{Block, EntryPointWithTracingParams},
        protocol::ProtocolComponent,
        Address, ComponentId, TxHash,
    },
    Bytes,
};

// Core Types

// Core Metadata structure. Each Component that has a hook is expected to have Some (or None in case
// of error) of those fields by the end of the extraction process.

type Balances = HashMap<Address, Bytes>;
// Here we link the limits to the entrypoint that triggered the limit fetching. This is necessary
// so that Tycho Simulation can use this information to calculate the limits for the component on
// every block.
type Limits = Vec<((Address, Address), (Bytes, Bytes, Option<EntryPointWithTracingParams>))>;
type Tvl = f64;

pub struct ComponentTracingMetadata {
    // Here we need to link the each metadata field with the transaction hash that triggered the
    // fetching so we can modify the Block data with the new balances - and link the generated
    // Entrypoints to the correct transaction hash.
    pub balances: Option<Result<(TxHash, Balances), MetadataError>>,
    pub limits: Option<Result<(TxHash, Limits), MetadataError>>,
    pub tvl: Option<Result<(TxHash, Tvl), MetadataError>>,
}

// Request Generation Types

type RequestId = String;
// Represents a request to a provider.
pub struct MetadataRequest {
    pub request_id: RequestId,
    pub component_id: ComponentId,
    pub request_type: MetadataRequestType,
    pub transport: Box<dyn RequestTransport>,
    // tx_hash: Transaction hash that triggered this metadata request
    // Used to map balance/limit changes back to specific on-chain events
    pub tx_hash: TxHash,
}

impl Clone for MetadataRequest {
    fn clone(&self) -> Self {
        Self {
            request_id: self.request_id.clone(),
            component_id: self.component_id.clone(),
            request_type: self.request_type.clone(),
            transport: self.transport.clone_box(),
            tx_hash: self.tx_hash.clone(),
        }
    }
}

#[derive(Clone)]
pub enum MetadataRequestType {
    ComponentBalance { token_addresses: Vec<Address> },
    Tvl,
    // Every request should cover only one token pair - but we should leave the interface
    // open to allow for future extensions or requests that cover multiple token pairs.
    Limits { token_pair: Vec<(Address, Address)> },
}

// Specifies a transport type that can be used to send requests. It's essential for differentiating
// requests and the trait should provide flexibility to support different chains.
// A transport on EVM context can be RPC Provider or API Provider.
pub trait RequestTransport: Send + Sync {
    // Routing key is used to group requests by provider.
    fn routing_key(&self) -> String;

    // Allow setting custom routing keys.
    fn set_routing_key(&mut self, key: String);

    // Deduplication ID is used to deduplicate requests by provider.
    fn deduplication_id(&self) -> String;

    // Clone method for boxed trait objects
    fn clone_box(&self) -> Box<dyn RequestTransport>;

    // Get the raw request data for execution.
    fn as_any(&self) -> &dyn std::any::Any;
}

// Focused metadata generation trait - purely for request generation
pub trait MetadataRequestGenerator: Send + Sync {
    /// Generate all metadata requests for a component
    /// Returns boxed requests that can contain different transport types
    fn generate_requests(
        &self,
        component: &ProtocolComponent,
        block: &Block,
    ) -> Result<Vec<MetadataRequest>, MetadataError>;

    fn generate_balance_only_requests(
        &self,
        component: &ProtocolComponent,
        block: &Block,
    ) -> Result<Vec<MetadataRequest>, MetadataError>;

    /// Return which metadata types this generator supports  
    fn supported_metadata_types(&self) -> Vec<MetadataRequestType>;
}

// Registry maps components to generators (not providers)
pub struct MetadataGeneratorRegistry {
    // Maps hook address to generator instance
    hook_generators: HashMap<Address, Box<dyn MetadataRequestGenerator>>,
    // Fallback for hooks without specific hook mapping
    default_generator: Option<Box<dyn MetadataRequestGenerator>>,
}

impl MetadataGeneratorRegistry {
    // Component-to-generator mapping logic
    pub fn get_generator_for_component(
        &self,
        component: &ProtocolComponent,
    ) -> Option<&dyn MetadataRequestGenerator> {
        // Extract hook address from component
        let hook_address = component
            .static_attributes
            .get("hook")?;
        // Map hook to generator
        self.hook_generators
            .get(hook_address)
            .map(|boxed_generator| boxed_generator.as_ref())
            .or(self
                .default_generator
                .as_ref()
                .map(|boxed_generator| boxed_generator.as_ref()))
    }
}

// Request Execution Types

// Provider handles batching, deduplication and intelligent grouping, whenever possible.
// It's also responsible for interacting with the provider (sending requests and receiving
// responses).
#[async_trait]
pub trait RequestProvider: Send + Sync {
    // Here, each provider implementation should be able to handle only one Type of
    // RequestTransport. So there's a 1-1 relationship between RequestProvider and
    // RequestTransport. This is important for the orchestrator to be able to group requests by
    // provider. Also, for both RPC and HTTP requests, pay attention to the optimization
    // opportunities, like deduplication, connection pooling, etc. They should be specified on
    // the plan.
    async fn execute_batch(&self, requests: &[Box<dyn RequestTransport>]) -> Vec<MetadataResult>;

    // For RPC providers: group compatible requests into batched calls.
    // For API providers: Currently, not batching will be done, but in the
    // future we might add the ability to group compatible requests into single calls
    // (e.g., multiple TVL requests -> single Defillama call). This means that there could be more
    // than one HTTP request transport type and, consequently, more than one RequestProvider that
    // handles HTTP requests.
    fn can_group_requests(
        &self,
        requests: &[Box<dyn RequestTransport>],
    ) -> Vec<Vec<Box<dyn RequestTransport>>> {
        // Default: no grouping, one request per call
        requests
            .iter()
            .map(|r| vec![r.clone_box()])
            .collect()
    }
}

pub struct MetadataResult {
    pub request_id: RequestId,
    pub component_id: ComponentId,
    pub request_type: MetadataRequestType,
    pub result: Result<MetadataValue, MetadataError>,
}

// Simple enum for actual metadata values
#[derive(Debug, Clone)]
pub enum MetadataValue {
    Balances(HashMap<Address, Bytes>),
    Limits(Vec<((Address, Address), (Bytes, Bytes))>),
    Tvl(f64),
}

// Provider registry with configurable routing keys
pub struct ProviderRegistry {
    providers: HashMap<String, Arc<dyn RequestProvider>>, // routing_key -> provider
}

impl ProviderRegistry {
    pub fn register_provider(&mut self, routing_key: String, provider: Arc<dyn RequestProvider>) {
        self.providers
            .insert(routing_key, provider);
    }

    pub fn get_provider(
        &self,
        transport: &dyn RequestTransport,
    ) -> Option<Arc<dyn RequestProvider>> {
        self.providers
            .get(&transport.routing_key())
            .cloned()
    }
}

pub struct BlockMetadataOrchestrator {
    generator_registry: MetadataGeneratorRegistry,
    provider_registry: ProviderRegistry,
}

impl BlockMetadataOrchestrator {
    pub async fn collect_metadata_for_block(
        &self,
        balance_only_components: &[ProtocolComponent],
        full_processing_components: &[ProtocolComponent],
        block: &Block,
    ) -> Result<HashMap<ProtocolComponent, ComponentTracingMetadata>, MetadataError> {
        // 1. Generate all requests using component-to-generator mapping
        let mut all_requests =
            self.generate_requests_for_components(full_processing_components, block)?;

        let balance_only_requests =
            self.generate_balance_only_requests(balance_only_components, block)?;
        all_requests.extend(balance_only_requests);

        // 2. Group requests by provider routing key
        let requests_by_provider = self.group_requests_by_routing_key(&all_requests);

        // 3. Execute all provider batches in parallel
        // Each provider handles its own deduplication and request grouping
        let all_results = self
            .execute_provider_batches(requests_by_provider)
            .await;

        // 4. Assemble ComponentTracingMetadata. Request deduplication is done here - also linking
        //    back
        // Balance requests to the transaction hash that triggered the balance fetching.
        self.assemble_component_metadata(&all_requests, all_results)
    }

    fn generate_requests_for_components(
        &self,
        components: &[ProtocolComponent],
        block: &Block,
    ) -> Result<Vec<MetadataRequest>, MetadataError> {
        let mut all_requests = Vec::new();

        for component in components {
            if let Some(generator) = self
                .generator_registry
                .get_generator_for_component(component)
            {
                let requests = generator.generate_requests(component, block)?;
                all_requests.extend(requests);
            }
        }

        Ok(all_requests)
    }

    fn generate_balance_only_requests(
        &self,
        components: &[ProtocolComponent],
        block: &Block,
    ) -> Result<Vec<MetadataRequest>, MetadataError> {
        let mut all_requests = Vec::new();

        for component in components {
            if let Some(generator) = self
                .generator_registry
                .get_generator_for_component(component)
            {
                let requests = generator.generate_balance_only_requests(component, block)?;
                all_requests.extend(requests);
            }
        }

        Ok(all_requests)
    }

    fn group_requests_by_routing_key(
        &self,
        requests: &[MetadataRequest],
    ) -> HashMap<String, Vec<MetadataRequest>> {
        let mut grouped = HashMap::new();

        for request in requests {
            let routing_key = request.transport.routing_key();
            grouped
                .entry(routing_key)
                .or_insert_with(Vec::new)
                .push(request.clone());
        }

        grouped
    }

    async fn execute_provider_batches(
        &self,
        _requests_by_provider: HashMap<String, Vec<MetadataRequest>>,
    ) -> Vec<MetadataResult> {
        todo!()
    }

    fn assemble_component_metadata(
        &self,
        _all_requests: &[MetadataRequest],
        _results: Vec<MetadataResult>,
    ) -> Result<HashMap<ProtocolComponent, ComponentTracingMetadata>, MetadataError> {
        todo!()
    }
}

// Error types
#[derive(Error, Debug)]
pub enum MetadataError {
    #[error("Metadata generation failed: {0}")]
    GenerationFailed(String),
    #[error("Provider failed: {0}")]
    ProviderFailed(String),
    #[error("Request failed: {0}")]
    RequestFailed(String),
    #[error("Unknown error: {0}")]
    UnknownError(String),
}

// Example Implementations

// HTTP Transport Example Implementation
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HttpTransport {
    pub url: String,
    pub method: HttpMethod,
    pub headers: HashMap<String, String>,
    pub body: Option<serde_json::Value>,
    routing_key: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum HttpMethod {
    Get,
    Post,
}

impl HttpTransport {
    pub fn new(url: String, method: HttpMethod) -> Self {
        let routing_key = format!(
            "http_{}",
            url.split('/')
                .nth(2)
                .unwrap_or("default")
        );
        Self { url, method, headers: HashMap::new(), body: None, routing_key }
    }

    pub fn with_header(mut self, key: String, value: String) -> Self {
        self.headers.insert(key, value);
        self
    }

    pub fn with_body(mut self, body: serde_json::Value) -> Self {
        self.body = Some(body);
        self
    }
}

impl RequestTransport for HttpTransport {
    fn routing_key(&self) -> String {
        self.routing_key.clone()
    }

    fn set_routing_key(&mut self, key: String) {
        self.routing_key = key;
    }

    fn deduplication_id(&self) -> String {
        // Create unique ID based on URL and body. Please use a hash function.
        let body_str = self
            .body
            .as_ref()
            .map(|b| b.to_string())
            .unwrap_or_default();
        format!("{}_{}_{}", self.method.as_str(), self.url, body_str)
    }

    fn clone_box(&self) -> Box<dyn RequestTransport> {
        Box::new(self.clone())
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

impl HttpMethod {
    fn as_str(&self) -> &str {
        match self {
            HttpMethod::Get => "GET",
            HttpMethod::Post => "POST",
        }
    }
}

// RPC Transport Implementation
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RpcTransport {
    pub endpoint: String,
    pub method: String,
    pub params: Vec<serde_json::Value>,
    pub id: u64,
    routing_key: String,
}

impl RpcTransport {
    pub fn new(endpoint: String, method: String, params: Vec<serde_json::Value>) -> Self {
        // Extract chain identifier from endpoint for routing. Since there is no expectation of
        // separation between RPC requests and providers, we will use a default routing key.
        let routing_key = "rpc_default".to_string();

        Self { endpoint, method, params, id: rand::random::<u64>() % 10000, routing_key }
    }

    pub fn eth_call(
        endpoint: String,
        contract: Address,
        data: Bytes,
        block: Option<String>,
    ) -> Self {
        let call_object = serde_json::json!({
            "to": format!("0x{}", hex::encode(contract.as_ref())),
            "data": format!("0x{}", hex::encode(data.as_ref()))
        });

        let params = if let Some(block_tag) = block {
            vec![call_object, serde_json::Value::String(block_tag)]
        } else {
            vec![call_object, serde_json::Value::String("latest".to_string())]
        };

        Self::new(endpoint, "eth_call".to_string(), params)
    }

    pub fn multicall(
        endpoint: String,
        calls: Vec<(Address, Bytes)>,
        block: Option<String>,
    ) -> Self {
        // Create multicall3 aggregate call data
        // Function selector for aggregate3((address,bool,bytes)[])
        let selector = hex::decode("82ad56cb").unwrap();
        let call_data = selector;

        // Encode array of calls
        // This is simplified - in production you'd use proper ABI encoding
        let encoded_calls = calls
            .iter()
            .map(|(target, data)| {
                serde_json::json!({
                    "target": format!("0x{}", hex::encode(target.as_ref())),
                    "allowFailure": true,
                    "callData": format!("0x{}", hex::encode(data.as_ref()))
                })
            })
            .collect::<Vec<_>>();

        // Multicall3 contract address (same on most chains)
        let multicall_address =
            Address::from(hex::decode("cA11bde05977b3631167028862bE2a173976CA11").unwrap());

        Self::eth_call(endpoint, multicall_address, Bytes::from(call_data), block)
    }
}

impl RequestTransport for RpcTransport {
    fn routing_key(&self) -> String {
        self.routing_key.clone()
    }

    fn set_routing_key(&mut self, key: String) {
        self.routing_key = key;
    }

    fn deduplication_id(&self) -> String {
        // Create unique ID based on method and params
        let params_str = serde_json::to_string(&self.params).unwrap_or_default();
        format!("{}_{}", self.method, params_str)
    }

    fn clone_box(&self) -> Box<dyn RequestTransport> {
        Box::new(self.clone())
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
