#![allow(dead_code)] // TODO: Remove this once the setup is fully implemented

use std::{collections::HashMap, sync::Arc};

use serde::Deserialize;
use tracing::info;
use tycho_common::{
    models::{Address, Chain},
    storage::{EntryPointGateway, ProtocolGateway},
    traits::{AccountExtractor, EntryPointTracer},
};

use crate::extractor::dynamic_contract_indexer::{
    component_metadata::{
        MetadataGeneratorRegistry, MetadataResponseParserRegistry, ProviderRegistry,
    },
    dci::DynamicContractIndexer,
    entrypoint_generator::{
        DefaultSwapAmountEstimator, HookEntrypointConfig, HookEntrypointGenerator,
        UniswapV4DefaultHookEntrypointGenerator,
    },
    euler::metadata_generator::{EulerMetadataGenerator, EulerMetadataResponseParser},
    hook_dci::UniswapV4HookDCI,
    hook_orchestrator::{DefaultUniswapV4HookOrchestrator, HookOrchestratorRegistry},
    metadata_orchestrator::BlockMetadataOrchestrator,
    rpc_metadata_provider::RPCMetadataProvider,
};

#[derive(Deserialize)]
struct EulerHooks {
    pool_addresses: Vec<String>,
}

fn load_euler_hooks() -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let json_content = include_str!("assets/euler_hooks.json");
    let euler_hooks: EulerHooks = serde_json::from_str(json_content)?;
    Ok(euler_hooks.pool_addresses)
}

/// Sets up all necessary registries for Hooks DCI testing with Euler support
pub fn setup_metadata_registries(
    rpc_url: String,
) -> (MetadataGeneratorRegistry, MetadataResponseParserRegistry, ProviderRegistry) {
    let mut generator_registry = MetadataGeneratorRegistry::new();
    let mut parser_registry = MetadataResponseParserRegistry::new();
    let mut provider_registry = ProviderRegistry::new();

    // Load Euler hook addresses from JSON file
    let hook_addresses = load_euler_hooks().expect("Failed to load Euler hooks from JSON");
    info!("Loaded {} hooks from JSON", hook_addresses.len());

    // Register Euler metadata generator for all hook addresses
    for hook_address_str in hook_addresses {
        let hook_address = Address::from(hook_address_str.as_str());
        generator_registry.register_hook_generator(
            hook_address,
            Box::new(EulerMetadataGenerator::new(rpc_url.clone())),
        );
    }

    // Register Euler response parser
    parser_registry.register_parser("euler".to_string(), Box::new(EulerMetadataResponseParser));

    // Register RPC provider with default routing key
    provider_registry.register_provider(
        "rpc_default".to_string(),
        Arc::new(RPCMetadataProvider::new(50)), // batch size limit
    );

    (generator_registry, parser_registry, provider_registry)
}

/// Sets up hook orchestrator registry with Euler hooks configured
pub fn setup_hook_orchestrator_registry(
    router_address: Address,
    pool_manager: Address,
) -> HookOrchestratorRegistry {
    let mut hook_registry = HookOrchestratorRegistry { hooks: HashMap::new() };

    // Load Euler hook addresses from JSON file
    let hook_addresses = load_euler_hooks().expect("Failed to load Euler hooks from JSON");

    // Register separate orchestrator instances for each Euler hook address
    for hook_address_str in hook_addresses {
        let hook_address = Address::from(hook_address_str.as_str());

        // Create hook entrypoint configuration for this hook
        let config = HookEntrypointConfig {
            max_sample_size: Some(10), // Reasonable default for testing
            min_samples: 1,
            router_address: Some(router_address.clone()),
            sender: Some(router_address.clone()), // Use router as sender for testing
            router_code: None,                    // Use default V4MiniRouter bytecode
            pool_manager: pool_manager.clone(),
        };

        // Create entrypoint generator with default swap amount estimator (preferring balances)
        let mut entrypoint_generator = UniswapV4DefaultHookEntrypointGenerator::new(
            DefaultSwapAmountEstimator::with_balances(),
            pool_manager.clone(),
        );
        entrypoint_generator.set_config(config);

        let orchestrator = DefaultUniswapV4HookOrchestrator::new(entrypoint_generator);

        hook_registry
            .hooks
            .insert(hook_address, Box::new(orchestrator));
    }

    hook_registry
}

/// Creates a fully configured UniswapV4HookDCI for testing with Euler support
#[allow(clippy::too_many_arguments)]
pub fn create_testing_hooks_dci<AE, T, G>(
    inner_dci: DynamicContractIndexer<AE, T, G>,
    rpc_url: String,
    router_address: Address,
    pool_manager: Address,
    db_gateway: G,
    chain: Chain,
    pause_after_retries: u32,
    max_retries: u32,
) -> UniswapV4HookDCI<AE, T, G>
where
    AE: AccountExtractor + Send + Sync,
    T: EntryPointTracer + Send + Sync,
    G: EntryPointGateway + ProtocolGateway + Send + Sync,
{
    // Setup metadata registries
    let (generator_registry, parser_registry, provider_registry) =
        setup_metadata_registries(rpc_url);

    // Setup hook orchestrator registry
    let hook_orchestrator_registry = setup_hook_orchestrator_registry(router_address, pool_manager);

    // Create metadata orchestrator
    let metadata_orchestrator =
        BlockMetadataOrchestrator::new(generator_registry, parser_registry, provider_registry);

    // Create and return configured Hook DCI
    UniswapV4HookDCI::new(
        inner_dci,
        metadata_orchestrator,
        hook_orchestrator_registry,
        db_gateway,
        chain,
        pause_after_retries,
        max_retries,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_euler_hook_addresses_parsing() {
        // Test that all addresses from JSON can be parsed
        let hook_addresses = load_euler_hooks().expect("Failed to load Euler hooks from JSON");
        for hook_address_str in hook_addresses {
            let address = Address::from(hook_address_str.as_str());
            assert!(!address.is_zero(), "Hook address should not be zero: {hook_address_str}");
        }
    }

    #[test]
    fn test_setup_metadata_registries() {
        let rpc_url = "https://eth-mainnet.alchemyapi.io/v2/test".to_string();
        let (_generator_registry, parser_registry, provider_registry) =
            setup_metadata_registries(rpc_url);

        // Verify parser registry has Euler parser
        assert!(parser_registry
            .get_parser("euler")
            .is_some());

        // Verify provider registry has RPC provider
        assert!(provider_registry
            .get_provider_by_routing_key("rpc_default")
            .is_some());
    }
}
