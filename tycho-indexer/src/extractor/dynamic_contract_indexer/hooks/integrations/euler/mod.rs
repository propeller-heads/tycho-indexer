use crate::extractor::dynamic_contract_indexer::{
    component_metadata::{
        MetadataGeneratorRegistry, MetadataResponseParserRegistry, ProviderRegistry,
    },
    hooks::integrations::euler::metadata_generator::{
        EulerMetadataGenerator, EulerMetadataResponseParser,
    },
};

pub(crate) mod metadata_generator;

pub(super) fn register_euler_integrations(
    generator_registry: &mut MetadataGeneratorRegistry,
    parser_registry: &mut MetadataResponseParserRegistry,
    _provider_registry: &mut ProviderRegistry,
    rpc_url: String,
) {
    generator_registry.register_hook_identifier(
        "euler_v1".to_string(),
        Box::new(EulerMetadataGenerator::new(rpc_url)),
    );
    parser_registry.register_parser("euler".to_string(), Box::new(EulerMetadataResponseParser));
}
