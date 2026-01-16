# Hook Integration Guide

### Integration Guide <a href="#integration-guide" id="integration-guide"></a>

This page provides step-by-step instructions for integrating any Uniswap V4 hook with the Hooks DCI.

#### Determine Your Requirements <a href="#id-51-determine-your-requirements" id="id-51-determine-your-requirements"></a>

Before implementing anything, determine what (if anything) you need to customize:

**Decision Tree**

```
START: I want to index my Uniswap V4 hook

Q1: Is my hook composable (works with empty hookData)?
    ├─ NO  → ⚠️ STOP: Non-composable hooks not yet supported
    │         Wait for future release with hookData source support
    └─ YES → Continue to Q2

Q2: Where does my hook store liquidity?
    ├─ In PoolManager (ERC6909 claims)
    │   └─→ INTERNAL LIQUIDITY
    │       ✓ No custom code needed - your hook will be automatically indexed
    │       
    │
    └─ In external contracts (vaults, protocols, etc.)
        └─→ EXTERNAL LIQUIDITY
            ⚙️ Requires metadata generator + parser
            → Continue to the next step 

Q3: (External liquidity only) Does my hook need custom entrypoint encoding?
    ├─ NO  → Implement Generator + Parser only
    │         Skip custom orchestrator (use default)
    │
    └─ YES → Implement Generator + Parser + Custom Orchestrator

```

**Quick Reference Table**

| Hook Type                         | What to Implement                 |
| --------------------------------- | --------------------------------- |
| **Internal Liquidity**            | Nothing (auto-handled)            |
| **External Liquidity (Standard)** | Generator + Parser                |
| **External Liquidity (Custom)**   | Generator + Parser + Orchestrator |
| **Non-Composable**                | Not supported yet                 |

#### Prerequisites <a href="#id-52-prerequisites" id="id-52-prerequisites"></a>

**Understand the Hook's Architecture**:

* Where tokens are stored (which external contracts?)
* How balances are queried (what functions?)
* How limits are determined (withdrawal limits, caps, etc.)
* What state needs to be simulated

#### 1. Minimal Setup (Internal Liquidity Hooks) <a href="#id-53-minimal-setup-internal-liquidity-hooks" id="id-53-minimal-setup-internal-liquidity-hooks"></a>

If your hook stores all liquidity in the PoolManager and is Composable, your hook should be auto-indexed by Tycho.

**If you have external liquidity**, continue to the next Section&#x20;

#### 2. Custom Setup (External Liquidity Hooks) <a href="#id-54-prerequisites-external-liquidity-hooks" id="id-54-prerequisites-external-liquidity-hooks"></a>

#### 2.1 Implementation Steps <a href="#id-52-implementation-steps" id="id-52-implementation-steps"></a>

**Step 1: Implement Metadata Request Generator**

The generator creates requests to fetch external data for your hook.

**Trait to Implement**:

```rust
pub trait MetadataRequestGenerator: Send + Sync {
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

    fn supported_metadata_types(&self) -> Vec<MetadataRequestType>;
}
```

**Template**:

```rust
use tycho_common::models::{Block, Address};
use crate::extractor::dynamic_contract_indexer::component_metadata::{
    MetadataRequestGenerator, MetadataRequest, MetadataRequestType, MetadataError,
};

pub struct MyHookGenerator {
    rpc_url: String,
}

impl MyHookGenerator {
    pub fn new(rpc_url: String) -> Self {
        Self { rpc_url }
    }

    // Helper to extract hook address from component
    fn get_hook_address(
        &self,
        component: &ProtocolComponent,
    ) -> Result<Address, MetadataError> {
        component
            .static_attributes
            .get("hooks")
            .and_then(|v| v.as_address())
            .ok_or_else(|| MetadataError::InvalidComponent(
                "Missing 'hooks' attribute".to_string()
            ))
    }
}

impl MetadataRequestGenerator for MyHookGenerator {
    fn generate_requests(
        &self,
        component: &ProtocolComponent,
        block: &Block,
    ) -> Result<Vec<MetadataRequest>, MetadataError> {
        let hook_address = self.get_hook_address(component)?;
        let mut requests = Vec::new();

        // 1. Generate balance request
        requests.push(self.create_balance_request(component, block, &hook_address)?);

        // 2. Generate limits requests (if applicable)
        requests.extend(self.create_limits_requests(component, block, &hook_address)?);

        // 3. Generate TVL request (if applicable)
        // requests.push(self.create_tvl_request(component, block, &hook_address)?);

        Ok(requests)
    }

    fn generate_balance_only_requests(
        &self,
        component: &ProtocolComponent,
        block: &Block,
    ) -> Result<Vec<MetadataRequest>, MetadataError> {
        let hook_address = self.get_hook_address(component)?;

        // Only generate balance request for balance-only updates
        Ok(vec![self.create_balance_request(component, block, &hook_address)?])
    }

    fn supported_metadata_types(&self) -> Vec<MetadataRequestType> {
        vec![
            MetadataRequestType::ComponentBalance {
                token_addresses: vec![],
            },
            MetadataRequestType::Limits {
                token_pair: vec![],
            },
        ]
    }
}

impl MyHookGenerator {
    fn create_balance_request(
        &self,
        component: &ProtocolComponent,
        block: &Block,
        hook_address: &Address,
    ) -> Result<MetadataRequest, MetadataError> {
        // TODO: Implement your balance request logic
        // Example: Call a function like getBalances() or getReserves()

        let calldata = format!(
            "0x{}", // Function selector + encoded parameters
            "YOUR_FUNCTION_SELECTOR_HERE"
        );

        Ok(MetadataRequest {
            request_type: MetadataRequestType::ComponentBalance {
                token_addresses: component.tokens.clone(),
            },
            routing_key: "rpc_default".to_string(),
            generator_name: "my_hook".to_string(), // Must match parser registration
            transport: RpcTransport::new(
                self.rpc_url.clone(),
                "eth_call".to_string(),
                vec![
                    json!({
                        "to": hook_address,
                        "data": calldata,
                    }),
                    json!(format!("0x{:x}", block.number)),
                ],
            ),
        })
    }

    fn create_limits_requests(
        &self,
        component: &ProtocolComponent,
        block: &Block,
        hook_address: &Address,
    ) -> Result<Vec<MetadataRequest>, MetadataError> {
        let mut requests = Vec::new();
        let tokens = &component.tokens;

        // Generate limits request for each token pair
        for i in 0..tokens.len() {
            for j in (i + 1)..tokens.len() {
                let token_pair = vec![tokens[i].clone(), tokens[j].clone()];

                // TODO: Implement your limits request logic
                // This might involve:
                // - Calling a function on the hook
                // - Using a lens contract pattern (like Euler)
                // - Querying external protocol limits

                requests.push(MetadataRequest {
                    request_type: MetadataRequestType::Limits {
                        token_pair: token_pair.clone(),
                    },
                    routing_key: "rpc_default".to_string(),
                    generator_name: "my_hook".to_string(),
                    transport: RpcTransport::new(
                        self.rpc_url.clone(),
                        "eth_call".to_string(),
                        vec![
                            json!({
                                "to": "YOUR_CONTRACT_ADDRESS",
                                "data": "YOUR_CALLDATA",
                            }),
                            json!(format!("0x{:x}", block.number)),
                            // Optional: state overrides
                            // json!({ "address": { "code": "0x...", "state": {...} } }),
                        ],
                    ),
                });
            }
        }

        Ok(requests)
    }
}
```

**Euler Reference Implementation**:

```rust
// From: tycho-indexer/src/extractor/dynamic_contract_indexer/hooks/integrations/euler/metadata_generator.rs

impl MetadataRequestGenerator for EulerMetadataGenerator {
    fn generate_requests(
        &self,
        component: &ProtocolComponent,
        block: &Block,
    ) -> Result<Vec<MetadataRequest>, MetadataError> {
        let hook_address = self.get_hook_address(component)?;
        let mut requests = Vec::new();

        // 1. Balance request: Call getReserves() on hook
        requests.push(MetadataRequest {
            request_type: MetadataRequestType::ComponentBalance {
                token_addresses: component.tokens.clone(),
            },
            routing_key: "rpc_default".to_string(),
            generator_name: "euler".to_string(),
            transport: RpcTransport::new(
                self.rpc_url.clone(),
                "eth_call".to_string(),
                vec![
                    json!({
                        "to": hook_address,
                        "data": "0x0902f1ac" // getReserves() selector
                    }),
                    json!(format!("0x{:x}", block.number)),
                ],
            ),
        });

        // 2. Limits requests: Use lens contract with state overrides
        let lens_address = "0x0000000000000000000000000000000000001337";
        let lens_bytecode_hex = hex::encode(EULER_LENS_BYTECODE_BYTES);

        for token_pair in get_token_pairs(&component.tokens) {
            requests.push(MetadataRequest {
                request_type: MetadataRequestType::Limits {
                    token_pair: token_pair.clone(),
                },
                routing_key: "rpc_default".to_string(),
                generator_name: "euler".to_string(),
                transport: RpcTransport::new(
                    self.rpc_url.clone(),
                    "eth_call".to_string(),
                    vec![
                        json!({
                            "to": lens_address,
                            "data": format!(
                                "0xaaed87a3{}{}",  // getLimits(address,address)
                                &token_pair[0].to_string()[2..],
                                &token_pair[1].to_string()[2..]
                            )
                        }),
                        json!(format!("0x{:x}", block.number)),
                        json!({  // Deploy lens contract at deterministic address
                            lens_address: {
                                "code": format!("0x{}", lens_bytecode_hex),
                                "state": {
                                    // Store hook address in slot 0
                                    "0x0000000000000000000000000000000000000000000000000000000000000000":
                                        format!("0x{:0>64}", &hook_address.to_string()[2..])
                                }
                            }
                        }),
                    ],
                ),
            });
        }

        Ok(requests)
    }

    fn generate_balance_only_requests(
        &self,
        component: &ProtocolComponent,
        block: &Block,
    ) -> Result<Vec<MetadataRequest>, MetadataError> {
        // Only balance request needed for balance-only updates
        let hook_address = self.get_hook_address(component)?;

        Ok(vec![MetadataRequest {
            request_type: MetadataRequestType::ComponentBalance {
                token_addresses: component.tokens.clone(),
            },
            routing_key: "rpc_default".to_string(),
            generator_name: "euler".to_string(),
            transport: RpcTransport::new(
                self.rpc_url.clone(),
                "eth_call".to_string(),
                vec![
                    json!({"to": hook_address, "data": "0x0902f1ac"}),
                    json!(format!("0x{:x}", block.number)),
                ],
            ),
        }])
    }
}
```

**Key Decisions**:

1. **Balance Request**: How do you query balances? Direct call, lens contract, or multiple calls?
2. **Limits Request**: Do you have withdrawal limits, liquidity caps, or other constraints?
3. **State Overrides**: Do you need to deploy helper contracts or modify state for queries?
4. **Token Pairs**: Do limits apply per token or per token pair?

**Step 2: Implement Response Parser**

The parser converts raw RPC responses into structured metadata.

**Trait to Implement**:

```rust
pub trait MetadataResponseParser: Send + Sync {
    fn parse_response(
        &self,
        component: &ProtocolComponent,
        request: &MetadataRequest,
        response: &Value,
    ) -> Result<MetadataValue, MetadataError>;
}
```

**Template**:

```rust
use serde_json::Value;
use tycho_common::models::{ProtocolComponent, Address};
use crate::extractor::dynamic_contract_indexer::component_metadata::{
    MetadataResponseParser, MetadataRequest, MetadataRequestType,
    MetadataValue, MetadataError,
};

pub struct MyHookParser;

impl MetadataResponseParser for MyHookParser {
    fn parse_response(
        &self,
        component: &ProtocolComponent,
        request: &MetadataRequest,
        response: &Value,
    ) -> Result<MetadataValue, MetadataError> {
        // Extract hex string from response
        let hex_str = response
            .as_str()
            .ok_or_else(|| MetadataError::InvalidResponse(
                "Response is not a string".to_string()
            ))?
            .trim_start_matches("0x");

        match &request.request_type {
            MetadataRequestType::ComponentBalance { token_addresses } => {
                self.parse_balances(component, hex_str, token_addresses)
            }
            MetadataRequestType::Limits { token_pair } => {
                self.parse_limits(component, request, hex_str, token_pair)
            }
            MetadataRequestType::Tvl => {
                self.parse_tvl(component, hex_str)
            }
            _ => Err(MetadataError::UnsupportedRequestType),
        }
    }
}

impl MyHookParser {
    fn parse_balances(
        &self,
        component: &ProtocolComponent,
        hex_str: &str,
        token_addresses: &[Address],
    ) -> Result<MetadataValue, MetadataError> {
        // TODO: Parse your balance response format
        // Example: Two 32-byte values (64 hex chars each)

        if hex_str.len() < 128 {
            return Err(MetadataError::InvalidResponse(
                format!("Balance response too short: {} chars", hex_str.len())
            ));
        }

        // Ensure tokens are sorted (for consistent mapping)
        let mut tokens = component.tokens.clone();
        tokens.sort();

        // Extract balances
        let balance_0 = Bytes::from(&hex_str[0..64]);
        let balance_1 = Bytes::from(&hex_str[64..128]);

        let mut balances = HashMap::new();
        balances.insert(tokens[0].clone(), balance_0);
        balances.insert(tokens[1].clone(), balance_1);

        Ok(MetadataValue::Balances(balances))
    }

    fn parse_limits(
        &self,
        component: &ProtocolComponent,
        request: &MetadataRequest,
        hex_str: &str,
        token_pair: &[Address],
    ) -> Result<MetadataValue, MetadataError> {
        // TODO: Parse your limits response format

        if hex_str.len() < 128 {
            return Err(MetadataError::InvalidResponse(
                format!("Limits response too short: {} chars", hex_str.len())
            ));
        }

        // Extract limits
        let limit_0 = Bytes::from(&hex_str[0..64]);
        let limit_1 = Bytes::from(&hex_str[64..128]);

        // Optional: Create entrypoint for the limits call itself
        // This can be used for tracing/reference
        let limits_entrypoint = self.create_limits_entrypoint(
            component,
            token_pair,
            request,
        ).ok(); // Make optional

        Ok(MetadataValue::Limits(vec![
            (token_pair[0].clone(), (limit_0, limit_1, limits_entrypoint))
        ]))
    }

    fn parse_tvl(
        &self,
        component: &ProtocolComponent,
        hex_str: &str,
    ) -> Result<MetadataValue, MetadataError> {
        // TODO: Parse TVL if applicable
        // This might involve converting token amounts to USD values

        Err(MetadataError::UnsupportedRequestType)
    }

    fn create_limits_entrypoint(
        &self,
        component: &ProtocolComponent,
        token_pair: &[Address],
        request: &MetadataRequest,
    ) -> Result<EntryPointWithTracingParams, MetadataError> {
        // TODO: Create entrypoint for limits call
        // This is optional but useful for tracing

        Ok(EntryPointWithTracingParams {
            entry_point: EntryPoint {
                external_id: format!(
                    "limits_{}_{}_{}",
                    component.id,
                    token_pair[0],
                    token_pair[1]
                ),
                target: /* your target address */,
                signature: "getLimits(address,address)".to_string(),
            },
            params: TracingParams::RPCTracer(RPCTracerParams {
                caller: None,
                calldata: /* your calldata */,
                state_overrides: /* your overrides */,
                prune_addresses: None,
            }),
        })
    }
}
```

**Euler Reference Implementation**:

```rust
// From: tycho-indexer/src/extractor/dynamic_contract_indexer/hooks/integrations/euler/metadata_generator.rs

impl MetadataResponseParser for EulerMetadataResponseParser {
    fn parse_response(
        &self,
        component: &ProtocolComponent,
        request: &MetadataRequest,
        response: &Value,
    ) -> Result<MetadataValue, MetadataError> {
        let res_str = response
            .as_str()
            .ok_or_else(|| MetadataError::InvalidResponse(
                "Expected string response".to_string()
            ))?
            .trim_start_matches("0x");

        match &request.request_type {
            MetadataRequestType::ComponentBalance { .. } => {
                // Parse getReserves() response: two uint112 values
                if res_str.len() < 128 {
                    return Err(MetadataError::InvalidResponse(
                        format!("Balance response too short: {}", res_str.len())
                    ));
                }

                let balance_0 = Bytes::from(&res_str[0..64]);
                let balance_1 = Bytes::from(&res_str[64..128]);

                let mut tokens = component.tokens.clone();
                tokens.sort();

                let mut balances = HashMap::new();
                balances.insert(tokens[0].clone(), balance_0);
                balances.insert(tokens[1].clone(), balance_1);

                Ok(MetadataValue::Balances(balances))
            }

            MetadataRequestType::Limits { token_pair } => {
                // Parse getLimits() response from lens contract
                if res_str.len() < 128 {
                    return Err(MetadataError::InvalidResponse(
                        format!("Limits response too short: {}", res_str.len())
                    ));
                }

                let limit_0 = Bytes::from(&res_str[0..64]);
                let limit_1 = Bytes::from(&res_str[64..128]);

                // Create entrypoint for limits call
                let hook_address = component
                    .static_attributes
                    .get("hooks")
                    .and_then(|v| v.as_address())
                    .ok_or_else(|| MetadataError::InvalidComponent(
                        "Missing hooks attribute".to_string()
                    ))?;

                let limits_entrypoint = create_euler_limits_entrypoint(
                    component,
                    &hook_address,
                    token_pair,
                )?;

                Ok(MetadataValue::Limits(vec![
                    (token_pair[0].clone(), (limit_0, limit_1, Some(limits_entrypoint)))
                ]))
            }

            _ => Err(MetadataError::UnsupportedRequestType),
        }
    }
}
```

**Key Considerations**:

1. **Response Format**: Understand the ABI encoding of your response
2. **Error Handling**: Handle malformed responses gracefully
3. **Token Ordering**: Ensure consistent token ordering between request and response
4. **Entrypoint Creation**: Optional but useful for tracing the limits call itself

**Step 3: (Optional) Implement Custom Hook Orchestrator**

Most hooks can use the default orchestrator. Implement a custom one only if you need:

* Special entrypoint encoding logic
* Custom balance/limit transformations
* Hook-specific state updates
* Non-standard token accounting

**When Default is Sufficient**:

* Balances come directly from metadata
* Limits are straightforward max amounts
* Standard Uniswap V4 swap encoding works
* No special state transformations needed

**Euler Example**: Uses the default orchestrator because it meets all standard requirements.

**Custom Orchestrator Template** (if needed):

```rust
use async_trait::async_trait;
use crate::extractor::{
    dynamic_contract_indexer::{
        hook_orchestrator::{HookOrchestrator, HookOrchestratorError},
        component_metadata::ComponentTracingMetadata,
    },
    models::BlockChanges,
};

pub struct MyHookOrchestrator {
    entrypoint_generator: Box<dyn HookEntrypointGenerator>,
}

#[async_trait]
impl HookOrchestrator for MyHookOrchestrator {
    async fn update_components(
        &self,
        block_changes: &mut BlockChanges,
        components: &[ProtocolComponent],
        metadata: &HashMap<String, ComponentTracingMetadata>,
        generate_entrypoints: bool,
    ) -> Result<(), HookOrchestratorError> {
        // TODO: Implement custom orchestration logic

        // 1. Extract metadata for components
        // 2. Generate entrypoints (if generate_entrypoints == true)
        // 3. Inject balances into components
        // 4. Inject limits for RPC optimization
        // 5. Update block_changes with new data

        Ok(())
    }
}
```

For most use cases, **proceed with the default orchestrator** and skip this step.

**Step 4: Register Components**

Set up all registries to wire your implementation into the Hooks DCI.

**Registration Code**:

In your integration folder add a register function with your protocol specifics

```rust
pub(super) fn register_my_hook_integrations(
    generator_registry: &mut MetadataGeneratorRegistry,
    parser_registry: &mut MetadataResponseParserRegistry,
    _provider_registry: &mut ProviderRegistry,
    rpc_url: String,
) {
    generator_registry.register_hook_identifier(
        "my_hook".to_string(),
        Box::new(MyHookMetadataGenerator::new(rpc_url)),
    );
    parser_registry.register_parser("my_hook".to_string(), Box::new(MyHookMetadataResponseParser));
}
```

Then add it in the global registration function with other hooks

<pre class="language-rust"><code class="lang-rust">// From: tycho-indexer/src/extractor/dynamic_contract_indexer/hooks/integrations/mod.rs
<strong>
</strong><strong>pub(super) fn register_integrations(
</strong>    generator_registry: &#x26;mut MetadataGeneratorRegistry,
    parser_registry: &#x26;mut MetadataResponseParserRegistry,
    provider_registry: &#x26;mut ProviderRegistry,
    rpc_url: String,
) {
    euler::register_euler_integrations(
        generator_registry,
        parser_registry,
        provider_registry,
        rpc_url,
    );
    
    // Add your hook registration here
}
</code></pre>

**Key Configuration Points**:

1. **Generator Registration**: Use `register_hook_identifier()` if your components have a "hook\_identifier" static attribute, or `register_hook_generator()` for specific addresses
2. **Parser Name**: Must match the `generator_name` in your MetadataRequests
3. **Routing Key**: Must match the `routing_key` in your MetadataRequests
4. **Estimation Method**: Choose `with_limits()` if you provide limits, `with_balances()` otherwise
5. **Sample Size**: Number of entrypoints to generate per token pair (typically 4)

**Step 5: Initialize Hooks DCI**

Create and initialize the UniswapV4HookDCI instance.

**Initialization Code**:

```rust
use tycho_common::models::{Chain, Address};
use crate::extractor::dynamic_contract_indexer::{
    dci::DynamicContractIndexer,
    hook_dci::UniswapV4HookDCI,
};

pub async fn create_hooks_dci_indexer(
    chain: Chain,
    extractor_name: String,
    rpc_url: String,
    router_address: Address,
    pool_manager: Address,
    db_gateway: impl EntryPointGateway + ProtocolGateway + Send + Sync + 'static,
    account_extractor: impl AccountExtractor + Send + Sync + 'static,
    entrypoint_tracer: impl EntryPointTracer + Send + Sync + 'static,
) -> Result<UniswapV4HookDCI<...>, ExtractionError> {
    // 1. Create inner DCI (standard indexer)
    let inner_dci = DynamicContractIndexer::new(
        chain.clone(),
        extractor_name.clone(),
        db_gateway.clone(),
        account_extractor,
        entrypoint_tracer,
    );

    // 2. Setup metadata and hook orchestrators (from Step 4)
    let (metadata_orchestrator, hook_orchestrator_registry) =
        setup_my_hook_indexing(rpc_url, router_address, pool_manager, chain.clone());

    // 3. Create Hooks DCI
    let mut hook_dci = UniswapV4HookDCI::new(
        inner_dci,
        metadata_orchestrator,
        hook_orchestrator_registry,
        db_gateway,
        chain,
        max_retries: 3,        // Retry up to 3 times before giving up
        pause_after_retries: 2 // Pause after 2 retries (before hitting max)
    );

    // 4. Initialize (loads existing components from database)
    hook_dci.initialize().await?;

    Ok(hook_dci)
}
```

**Configuration Parameters**:

* `max_retries`: Maximum total retry attempts before permanently failing a component
* `pause_after_retries`: Number of retries before pausing (setting "paused" attribute)

**Typical Values**:

* `max_retries: 5`, `pause_after_retries: 3`

**Step 6: Testing Your Integration**

Test your implementation at multiple levels.

**Unit Tests**:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generator_creates_balance_request() {
        let generator = MyHookGenerator::new("http://localhost:8545".to_string());
        let component = create_test_component();
        let block = create_test_block();

        let requests = generator.generate_balance_only_requests(&component, &block)
            .expect("Should generate requests");

        assert_eq!(requests.len(), 1);
        assert!(matches!(
            requests[0].request_type,
            MetadataRequestType::ComponentBalance { .. }
        ));
    }

    #[test]
    fn test_parser_handles_balance_response() {
        let parser = MyHookParser;
        let component = create_test_component();
        let request = create_test_balance_request();
        let response = json!("0x000000000000000000000000000000000000000000000000000000000000271000000000000000000000000000000000000000000000000000000000000027100");

        let result = parser.parse_response(&component, &request, &response)
            .expect("Should parse response");

        match result {
            MetadataValue::Balances(balances) => {
                assert_eq!(balances.len(), 2);
            }
            _ => panic!("Expected Balances variant"),
        }
    }
}
```

**Integration Tests with Real RPC**:

```rust
#[tokio::test]
#[ignore] // Requires RPC access
async fn test_metadata_collection_integration() {
    let rpc_url = std::env::var("RPC_URL")
        .expect("RPC_URL environment variable must be set");

    // Setup registries
    let (metadata_orchestrator, _) = setup_my_hook_indexing(
        rpc_url,
        router_address,
        pool_manager,
        Chain::Ethereum,
    );

    // Create test component
    let component = create_real_hook_component();
    let block = Block::new(/* real block data */);

    // Collect metadata
    let metadata = metadata_orchestrator
        .collect_metadata_for_block(
            &[],  // No balance-only components
            &[(TxHash::default(), component.clone())],  // Full processing
            &block,
        )
        .await
        .expect("Should collect metadata");

    // Verify metadata
    assert_eq!(metadata.len(), 1);
    let (comp, meta) = &metadata[0];
    assert!(meta.balances.is_some());
    assert!(meta.limits.is_some());
}
```

### Final Step: Submitting a PR

After your integration is tested, please submit a PR on Github so we can add it to our codebase and start indexing the hook on our hosted service.
