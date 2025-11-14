use crate::extractor::dynamic_contract_indexer::hooks::component_metadata::{
    MetadataGeneratorRegistry, MetadataResponseParserRegistry, ProviderRegistry,
};

pub(super) mod euler;

pub(crate) fn register_integrations(
    generator_registry: &mut MetadataGeneratorRegistry,
    parser_registry: &mut MetadataResponseParserRegistry,
    provider_registry: &mut ProviderRegistry,
    rpc_url: String,
) {
    euler::register_euler_integrations(
        generator_registry,
        parser_registry,
        provider_registry,
        rpc_url,
    );
}
