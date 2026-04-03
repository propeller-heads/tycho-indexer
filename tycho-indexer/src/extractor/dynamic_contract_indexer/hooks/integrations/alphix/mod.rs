use crate::extractor::dynamic_contract_indexer::hooks::{
    component_metadata::{
        MetadataGeneratorRegistry, MetadataResponseParserRegistry, ProviderRegistry,
    },
    integrations::alphix::metadata_generator::{
        AlphixMetadataGenerator, AlphixMetadataResponseParser,
    },
};

pub(super) mod metadata_generator;

pub(super) fn register_alphix_integrations(
    generator_registry: &mut MetadataGeneratorRegistry,
    parser_registry: &mut MetadataResponseParserRegistry,
    _provider_registry: &mut ProviderRegistry,
    rpc_url: String,
) {
    generator_registry.register_hook_identifier(
        "alphix_v1".to_string(),
        Box::new(AlphixMetadataGenerator::new(rpc_url)),
    );
    parser_registry.register_parser("alphix".to_string(), Box::new(AlphixMetadataResponseParser));
}
