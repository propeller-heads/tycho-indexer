use crate::extractor::dynamic_contract_indexer::hooks::{
    component_metadata::{
        MetadataGeneratorRegistry, MetadataResponseParserRegistry, ProviderRegistry,
    },
    integrations::universal::metadata_generator::{
        UniversalMetadataGenerator, UniversalMetadataResponseParser,
    },
};

pub(super) mod metadata_generator;

pub(super) fn register_universal_integrations(
    generator_registry: &mut MetadataGeneratorRegistry,
    parser_registry: &mut MetadataResponseParserRegistry,
    _provider_registry: &mut ProviderRegistry,
    rpc_url: String,
) {
    generator_registry.register_hook_identifier(
        "universal_v1".to_string(),
        Box::new(UniversalMetadataGenerator::new(rpc_url)),
    );
    parser_registry
        .register_parser("universal".to_string(), Box::new(UniversalMetadataResponseParser));
}
