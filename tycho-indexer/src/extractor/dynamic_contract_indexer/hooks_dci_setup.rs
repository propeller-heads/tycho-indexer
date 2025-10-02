#![allow(dead_code)] // TODO: Remove this once the setup is fully implemented

use std::sync::Arc;

use serde::Deserialize;
use tycho_common::{
    models::{Address, Chain},
    storage::{EntryPointGateway, ProtocolGateway},
    traits::{AccountExtractor, EntryPointTracer},
};
use tycho_ethereum::entrypoint_tracer::balance_slot_detector::{
    BalanceSlotDetectorConfig, EVMBalanceSlotDetector,
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
    rpc_metadata_provider::{RPCMetadataProvider, RPCRetryConfig},
};

#[derive(Deserialize)]
struct EulerHooks {
    pool_addresses: Vec<String>,
}

/// Sets up all necessary registries for Hooks DCI testing with Euler support
pub fn setup_metadata_registries(
    rpc_url: String,
) -> (MetadataGeneratorRegistry, MetadataResponseParserRegistry, ProviderRegistry) {
    let mut generator_registry = MetadataGeneratorRegistry::new();
    let mut parser_registry = MetadataResponseParserRegistry::new();
    let mut provider_registry = ProviderRegistry::new();

    // Register Euler metadata generator for all hook addresses
    generator_registry.register_hook_identifier(
        "euler_v1".to_string(),
        Box::new(EulerMetadataGenerator::new(rpc_url.clone())),
    );

    // Register Euler response parser
    parser_registry.register_parser("euler".to_string(), Box::new(EulerMetadataResponseParser));

    // Register RPC provider with default routing key and retry configuration
    let retry_config =
        RPCRetryConfig { max_retries: 5, initial_backoff_ms: 150, max_backoff_ms: 5000 };
    provider_registry.register_provider(
        "rpc_default".to_string(),
        Arc::new(RPCMetadataProvider::new_with_retry_config(50, retry_config)), // batch size limit with retry config
    );

    (generator_registry, parser_registry, provider_registry)
}

/// Sets up hook orchestrator registry with Euler hooks configured
pub fn setup_hook_orchestrator_registry(
    router_address: Address,
    pool_manager: Address,
    rpc_url: String,
) -> HookOrchestratorRegistry {
    let mut hook_registry = HookOrchestratorRegistry::new();

    // Create EVM balance slot detector
    let balance_slot_detector = {
        let config = BalanceSlotDetectorConfig {
            rpc_url: rpc_url.clone(),
            max_batch_size: 5,
            max_retries: 3,
            initial_backoff_ms: 100,
            max_backoff_ms: 5000,
        };

        EVMBalanceSlotDetector::new(config).expect("Failed to create EVMBalanceSlotDetector")
    };

    // Create hook entrypoint configuration for Euler V1
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
        DefaultSwapAmountEstimator::with_limits(),
        pool_manager.clone(),
        balance_slot_detector,
    );
    entrypoint_generator.set_config(config);

    let orchestrator = DefaultUniswapV4HookOrchestrator::new(entrypoint_generator);

    hook_registry.register_hook_identifier("euler_v1".to_string(), Box::new(orchestrator));

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
        setup_metadata_registries(rpc_url.clone());

    // Setup hook orchestrator registry
    let hook_orchestrator_registry =
        setup_hook_orchestrator_registry(router_address, pool_manager, rpc_url);

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
