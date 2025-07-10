#![allow(dead_code)] // TODO: Remove when implementation is complete

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

/// Specifies a transport mechanism for sending metadata requests to external data providers.
///
/// This trait abstracts the transport layer, allowing different implementations for various
/// protocols (HTTP, RPC, WebSocket, GraphQL etc.) and chains. Implementations handle the low-level
/// details of how requests are formatted and transmitted.
///
/// # Examples
///
/// Common implementations include:
/// - `DefiLLamaHttpTransport`: For REST API calls to Defillama API (e.g., DeFiLlama TVL data)
/// - `RpcTransport`: For JSON-RPC calls to blockchain nodes
pub trait RequestTransport: Send + Sync {
    /// Returns a routing key that identifies which provider should handle this request.
    ///
    /// The routing key groups requests by their destination provider, enabling efficient
    /// batching and connection pooling. For example, all RPC requests might share a routing key
    /// like "rpc_mainnet". All API requests to the same provider, like Defillama should share
    /// a routing key like defillama_api_v1
    ///
    /// # Returns
    ///
    /// A string identifier for routing requests to the appropriate provider.
    fn routing_key(&self) -> String;

    /// Sets a custom routing key for this transport.
    ///
    /// # Arguments
    ///
    /// * `key` - The new routing key to use for this transport
    fn set_routing_key(&mut self, key: String);

    /// Returns a unique identifier for request deduplication.
    ///
    /// This ID helps prevent duplicate requests within a batch. Transports should generate
    /// IDs based on the request content, so identical requests produce the same ID.
    ///
    /// # Returns
    ///
    /// A string that uniquely identifies this request's content for deduplication purposes.
    ///
    /// # Implementation Notes
    ///
    /// - Should be deterministic: same request parameters always produce the same ID
    /// - Should include all relevant request data (method, parameters, etc.)
    /// - Consider using a hash function for complex request data
    fn deduplication_id(&self) -> String;

    /// Creates a boxed clone of this transport.
    ///
    /// Required for cloning trait objects, as Rust's standard `Clone` trait cannot be
    /// object-safe. This enables storing and passing transports as trait objects.
    ///
    /// # Returns
    ///
    /// A new boxed instance with the same state as this transport.
    /// TODO: Might not be removed if not necessary on the final implementations
    fn clone_box(&self) -> Box<dyn RequestTransport>;

    /// Returns a reference to the concrete type as `Any`.
    ///
    /// This enables downcasting to the specific transport implementation when needed,
    /// allowing providers to access transport-specific data and methods.
    ///
    /// # Returns
    ///
    /// A reference to this transport as a trait object that can be downcast.
    fn as_any(&self) -> &dyn std::any::Any;
}

/// Generates metadata requests for protocol components.
///
/// This trait is responsible for analyzing a protocol component and determining what metadata
/// needs to be fetched. It creates the appropriate requests but does not execute them.
/// Different implementations can specialize in different types of protocols or metadata.
///
/// # Design Philosophy
///
/// Generators are protocol-aware but transport-agnostic. They understand what data is needed
/// based on the component type and current blockchain state, but delegate the actual fetching
/// to providers through transport objects.
///
/// # Implementation Guidelines
///
/// - Generators should be stateless when possible
/// - Each generator typically specializes in one protocol or hook type
/// - Generators can create requests with different transport types as needed. Example: using RPC
/// transport for Balances and API calls for TVL
pub trait MetadataRequestGenerator: Send + Sync {
    /// Generates all metadata requests needed for a component.
    ///
    /// Analyzes the component's state and the current block to determine what metadata
    /// should be fetched. This includes balances, limits, TVL, and any other relevant data.
    ///
    /// # Arguments
    ///
    /// * `component` - The protocol component to generate requests for
    /// * `block` - The current block context, used to determine state changes
    ///
    /// # Returns
    ///
    /// A vector of metadata requests with appropriate transport configurations, or an error
    /// if request generation fails.
    ///
    /// # Example Requests Generated
    ///
    /// - Token balance from onchain calls via RPC
    /// - TVL data from external APIs
    /// - Trading limits from onchain calls via RPC
    fn generate_requests(
        &self,
        component: &ProtocolComponent,
        block: &Block,
    ) -> Result<Vec<MetadataRequest>, MetadataError>;

    /// Generates only balance-related metadata requests for a component.
    ///
    /// This is a specialized method for components that only need balance updates,
    /// providing an optimized path for lightweight metadata collection.
    ///
    /// # Arguments
    ///
    /// * `component` - The protocol component to generate balance requests for
    /// * `block` - The current block context
    ///
    /// # Returns
    ///
    /// A vector of balance-specific metadata requests, or an error if generation fails.
    ///
    /// # Use Cases
    ///
    /// - Components marked for balance-only updates
    /// - Periodic balance reconciliation
    /// - Lightweight monitoring scenarios
    fn generate_balance_only_requests(
        &self,
        component: &ProtocolComponent,
        block: &Block,
    ) -> Result<Vec<MetadataRequest>, MetadataError>;

    /// Returns the types of metadata this generator can produce.
    ///
    /// Used by the orchestrator to understand generator capabilities and ensure
    /// all required metadata types are covered by available generators.
    ///
    /// # Returns
    ///
    /// A vector of metadata request types this generator supports.
    ///
    /// # Example
    ///
    /// A DEX generator might return:
    /// ```ignore
    /// vec![
    ///     MetadataRequestType::ComponentBalance { token_addresses: vec![] },
    ///     MetadataRequestType::Limits { token_pair: vec![] },
    ///     MetadataRequestType::Tvl,
    /// ]
    /// ```
    fn supported_metadata_types(&self) -> Vec<MetadataRequestType>;
}

/// Registry that manages the mapping between protocol components and their metadata generators.
///
/// This registry is the central configuration point for determining which generator should
/// handle metadata requests for a given component. It supports both specific hook-based
/// mappings and a default fallback generator.
///
/// # Architecture
///
/// The registry uses a two-tier lookup system:
/// 1. **Hook-specific generators**: Mapped by the hook address from the component's static
///    attributes
/// 2. **Default generator**: Fallback for components without specific mappings
///
/// # Usage
///
/// The registry is typically configured during application initialization with generators
/// for each supported protocol or hook type. During runtime, the orchestrator queries
/// this registry to find the appropriate generator for each component.
///
/// # Example Configuration
///
/// ```ignore
/// let mut registry = MetadataGeneratorRegistry::new();
///
/// // Register specific generators for known hooks
/// registry.register_hook_generator(bunni_hook, BunniGenerator::new());
/// registry.register_hook_generator(euler_hook, EulerGenerator::new());
///
/// // Set a default generator for unknown hooks
/// registry.set_default_generator(GenericDexGenerator::new());
/// ```
pub struct MetadataGeneratorRegistry {
    /// Maps hook addresses to their specific generator instances.
    ///
    /// Each hook address corresponds to a protocol-specific generator that understands
    /// how to create metadata requests for components using that hook.
    hook_generators: HashMap<Address, Box<dyn MetadataRequestGenerator>>,

    /// Fallback generator for components without specific hook mappings.
    ///
    /// This ensures that all components can have metadata generated, even if they
    /// use an unknown or new hook type. The default generator should implement
    /// conservative, generic metadata collection strategies.
    default_generator: Option<Box<dyn MetadataRequestGenerator>>,
}

impl MetadataGeneratorRegistry {
    /// Retrieves the appropriate metadata generator for a given component.
    ///
    /// This method implements the lookup logic, first checking for a hook-specific
    /// generator, then falling back to the default generator if available.
    ///
    /// # Arguments
    ///
    /// * `component` - The protocol component to find a generator for
    ///
    /// # Returns
    ///
    /// - `Some(&dyn MetadataRequestGenerator)` if a suitable generator is found
    /// - `None` if no generator is registered for the component's hook and no default is set
    ///
    /// # Lookup Process
    ///
    /// 1. Extract the hook address from the component's static attributes
    /// 2. Look for a hook-specific generator in the registry
    /// 3. If not found, use the default generator if configured
    /// 4. Return None if no suitable generator exists
    ///
    /// # Example
    ///
    /// ```ignore
    /// if let Some(generator) = registry.get_generator_for_component(&component) {
    ///     let requests = generator.generate_requests(&component, &block)?;
    ///     // Process requests...
    /// }
    /// ```
    pub fn get_generator_for_component(
        &self,
        component: &ProtocolComponent,
    ) -> Option<&dyn MetadataRequestGenerator> {
        // Extract hook address from component's static attributes
        // The hook address is the key identifier for protocol-specific behavior
        let hook_address = component
            .static_attributes
            .get("hook")?;

        // First try to find a hook-specific generator
        self.hook_generators
            .get(hook_address)
            .map(|boxed_generator| boxed_generator.as_ref())
            // Fall back to default generator if no specific mapping exists
            .or(self
                .default_generator
                .as_ref()
                .map(|boxed_generator| boxed_generator.as_ref()))
    }
}

// Request Execution Types

/// Executes metadata requests by interacting with external data sources.
///
/// Providers handle the actual communication with external systems (RPC nodes, APIs, etc.)
/// and implement optimizations like batching, deduplication, and connection pooling.
/// Each provider typically specializes in one transport type and protocol.
///
/// # Architecture
///
/// The provider layer sits between the high-level request generation and the low-level
/// transport execution. It adds intelligence for:
///
/// - Request batching (e.g., multicall for RPC)
/// - Deduplication of identical requests
/// - Connection management and pooling
/// - Error handling and retries
/// - Response parsing and normalization
///
/// # Implementation Requirements
///
/// - Each provider handles one specific `RequestTransport` type
/// - Providers must be thread-safe for concurrent execution
/// - Batch operations should be atomic when possible
#[async_trait]
pub trait RequestProvider: Send + Sync {
    /// Executes a batch of requests and returns their results.
    ///
    /// This is the main entry point for request execution. Providers should implement
    /// optimizations like deduplication and batching internally. Results are returned
    /// in the same order as requests, with errors for failed requests.
    ///
    /// # Arguments
    ///
    /// * `requests` - Slice of boxed transport objects to execute
    ///
    /// # Returns
    ///
    /// A vector of results corresponding to each request. Failed requests return
    /// `MetadataError` in their result field.
    ///
    /// # Implementation Notes
    ///
    /// - Providers should downcast transports to their expected type
    /// - Batch size limits should be respected (e.g., RPC batch limits)
    /// - Connection pooling should be used for network efficiency
    /// - Duplicate requests within the batch should be deduplicated
    ///
    /// # Example
    ///
    /// An RPC provider might:
    /// 1. Group requests by endpoint
    /// 2. Deduplicate identical calls
    /// 3. Batch into multicall or JSON-RPC batch requests
    /// 4. Execute with connection pooling
    /// 5. Map results back to original requests
    async fn execute_batch(&self, requests: &[Box<dyn RequestTransport>]) -> Vec<MetadataResult>;

    /// Groups requests into optimal batches for execution.
    ///
    /// Providers can override this to implement smart batching strategies.
    /// The default implementation treats each request independently.
    ///
    /// # Arguments
    ///
    /// * `requests` - Slice of requests to potentially group
    ///
    /// # Returns
    ///
    /// A vector of request groups, where each group can be executed together.
    ///
    /// # Batching Strategies
    ///
    /// - **RPC Providers**: Always group eth_calls for multicall
    /// - **API Providers**: Group by API endpoint and rate limits
    /// - **Default**: Each request in its own group (no batching)
    /// ```
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
        let _encoded_calls = calls
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
