#![allow(dead_code)] // TODO: Remove this once the setup is fully implemented

use std::{collections::HashMap, sync::Arc};

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

// Hardcoded Euler hook addresses for testing
const EULER_HOOK_ADDRESSES: &[&str] = &[
    "0x55dcf9455EEe8Fd3f5EEd17606291272cDe428a8",
    "0x2D24b7be7942c25Ea7dd0092235dA7E618dFe8A8",
    "0x5D04285cfD1cF5f6991FB7965D7A44cD236A28A8",
    "0xa4e744240a15AF0AFBef2618D9A0eDAA228428A8",
    "0xA40E0f3243b33a297650c4120277B7c4037528a8",
    "0xC88b618C2c670c2e2a42e06B466B6F0e82A6E8A8",
];

/// Sets up all necessary registries for Hooks DCI testing with Euler support
pub fn setup_metadata_registries(
    rpc_url: String,
) -> (MetadataGeneratorRegistry, MetadataResponseParserRegistry, ProviderRegistry) {
    let mut generator_registry = MetadataGeneratorRegistry::new();
    let mut parser_registry = MetadataResponseParserRegistry::new();
    let mut provider_registry = ProviderRegistry::new();

    // Register Euler metadata generator for all hook addresses
    for hook_address_str in EULER_HOOK_ADDRESSES {
        let hook_address = Address::from(*hook_address_str);
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

    // Register separate orchestrator instances for each Euler hook address
    for hook_address_str in EULER_HOOK_ADDRESSES {
        let hook_address = Address::from(*hook_address_str);

        // Create hook entrypoint configuration for this hook
        let config = HookEntrypointConfig {
            max_sample_size: Some(10), // Reasonable default for testing
            min_samples: 1,
            router_address: Some(router_address.clone()),
            sender: Some(router_address.clone()), // Use router as sender for testing
            router_code: None,                    // Use default V4MiniRouter bytecode
            pool_manager: pool_manager.clone(),
        };

        // Create entrypoint generator with default swap amount estimator
        let mut entrypoint_generator = UniswapV4DefaultHookEntrypointGenerator::new(
            DefaultSwapAmountEstimator,
            pool_manager.clone(),
        );
        entrypoint_generator.set_config(config);

        // Create orchestrator for this hook
        let orchestrator_config = HookEntrypointConfig {
            max_sample_size: Some(10),
            min_samples: 1,
            router_address: Some(router_address.clone()),
            sender: Some(router_address.clone()),
            router_code: None,
            pool_manager: pool_manager.clone(),
        };
        let orchestrator = DefaultUniswapV4HookOrchestrator::new(
            router_address.clone(),
            orchestrator_config,
            entrypoint_generator,
        );

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
        // Test that all hardcoded addresses can be parsed
        for hook_address_str in EULER_HOOK_ADDRESSES {
            let address = Address::from(*hook_address_str);
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
