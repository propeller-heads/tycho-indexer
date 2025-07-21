use std::collections::{HashMap, HashSet};

use tycho_common::models::{blockchain::Block, protocol::ProtocolComponent, TxHash};

use crate::extractor::dynamic_contract_indexer::component_metadata::{
    ComponentTracingMetadata, MetadataError, MetadataGeneratorRegistry, MetadataRequest,
    MetadataResponseParserRegistry, MetadataResult, ProviderRegistry,
};

pub struct BlockMetadataOrchestrator {
    generator_registry: MetadataGeneratorRegistry,
    response_parser_registry: MetadataResponseParserRegistry,
    provider_registry: ProviderRegistry,
}

impl BlockMetadataOrchestrator {
    #[allow(dead_code)] // TODO: Remove this once it's used
    pub fn new(
        generator_registry: MetadataGeneratorRegistry,
        response_parser_registry: MetadataResponseParserRegistry,
        provider_registry: ProviderRegistry,
    ) -> Self {
        Self { generator_registry, response_parser_registry, provider_registry }
    }

    pub async fn collect_metadata_for_block(
        &self,
        balance_only: &[(TxHash, ProtocolComponent)],
        full_processing: &[(TxHash, ProtocolComponent)],
        block: &Block,
    ) -> Result<Vec<(ProtocolComponent, ComponentTracingMetadata)>, MetadataError> {
        let all_components: HashMap<_, _> = balance_only
            .iter()
            .chain(full_processing.iter())
            .map(|(tx_hash, comp)| (comp.id.clone(), (tx_hash.clone(), comp.clone())))
            .collect();

        let full_components: Vec<_> = full_processing
            .iter()
            .map(|(_, c)| c)
            .collect();
        let balance_components: Vec<_> = balance_only
            .iter()
            .map(|(_, c)| c)
            .collect();

        let mut all_requests =
            self.generate_requests(&full_components, block, RequestMode::Full)?;
        all_requests.extend(self.generate_requests(
            &balance_components,
            block,
            RequestMode::BalanceOnly,
        )?);

        let requests_by_provider = self.group_requests_by_routing_key(&all_requests);
        let all_results = self
            .execute_provider_batches(&all_components, requests_by_provider)
            .await?;

        self.assemble_component_metadata(&all_components, all_results)
    }

    fn generate_requests(
        &self,
        components: &[&ProtocolComponent],
        block: &Block,
        mode: RequestMode,
    ) -> Result<Vec<MetadataRequest>, MetadataError> {
        let mut all_requests = Vec::new();

        for component in components {
            if let Some(generator) = self
                .generator_registry
                .get_generator_for_component(component)?
            {
                let mut requests = match mode {
                    RequestMode::Full => generator.generate_requests(component, block)?,
                    RequestMode::BalanceOnly => {
                        generator.generate_balance_only_requests(component, block)?
                    }
                };
                all_requests.append(&mut requests);
            }
        }

        Ok(all_requests)
    }

    fn group_requests_by_routing_key(
        &self,
        requests: &[MetadataRequest],
    ) -> HashMap<String, Vec<MetadataRequest>> {
        let mut grouped: HashMap<String, Vec<MetadataRequest>> = HashMap::new();

        for req in requests {
            grouped
                .entry(req.transport.routing_key())
                .or_default()
                .push(req.clone());
        }

        grouped
    }

    async fn execute_provider_batches(
        &self,
        all_components: &HashMap<String, (TxHash, ProtocolComponent)>,
        requests_by_provider: HashMap<String, Vec<MetadataRequest>>,
    ) -> Result<Vec<MetadataResult>, MetadataError> {
        let mut all_results = Vec::new();

        for (routing_key, requests) in requests_by_provider {
            let Some(provider) = self
                .provider_registry
                .get_provider_by_routing_key(&routing_key)
            else {
                continue;
            };

            let ids_to_requests: HashMap<_, _> = requests
                .iter()
                .map(|r| (r.transport.deduplication_id(), r))
                .collect();

            let component_ids_by_dedup_id: HashMap<String, HashSet<String>> =
                requests
                    .iter()
                    .fold(HashMap::new(), |mut acc, req| {
                        acc.entry(req.transport.deduplication_id())
                            .or_default()
                            .insert(req.component_id.clone());
                        acc
                    });

            let transports: Vec<_> = requests
                .iter()
                .map(|r| r.transport.clone_box())
                .collect();

            let results = provider
                .execute_batch(&transports)
                .await;

            for (dedup_id, result) in results {
                let request = ids_to_requests
                    .get(&dedup_id)
                    .ok_or(MetadataError::UnknownError(format!(
                        "Received result for unknown deduplication id: {dedup_id}"
                    )))?;

                let parser = self
                    .response_parser_registry
                    .get_parser(request.get_generator_name())
                    .ok_or(MetadataError::UnknownError(format!(
                        "No parser found for {}",
                        request.get_generator_name()
                    )))?;

                let component_ids = component_ids_by_dedup_id
                    .get(&dedup_id)
                    .ok_or(MetadataError::UnknownError(format!(
                        "Received result for unknown deduplication id: {dedup_id}"
                    )))?;

                for comp_id in component_ids {
                    let component = all_components
                        .get(comp_id)
                        .expect("All components should contain every relevant component");

                    let metadata_value = match &result {
                        Ok(success) => {
                            parser.parse_response(&component.1, &request.request_type, success)
                        }
                        Err(e) => Err(e.clone()),
                    };

                    all_results.push(MetadataResult {
                        request_id: request.request_id.clone(),
                        component_id: component.1.id.clone(),
                        request_type: request.request_type.clone(),
                        result: metadata_value,
                    });
                }
            }
        }

        Ok(all_results)
    }

    fn assemble_component_metadata(
        &self,
        all_components: &HashMap<String, (TxHash, ProtocolComponent)>,
        results: Vec<MetadataResult>,
    ) -> Result<Vec<(ProtocolComponent, ComponentTracingMetadata)>, MetadataError> {
        let tx_hash_by_component: HashMap<_, _> = all_components
            .iter()
            .map(|(_, (tx_hash, comp))| (comp.id.clone(), tx_hash.clone()))
            .collect();

        let mut metadata_map: HashMap<String, ComponentTracingMetadata> = HashMap::new();

        for result in results {
            let tx_hash = tx_hash_by_component
                .get(&result.component_id)
                .expect("Tx hash must exist");

            metadata_map
                .entry(result.component_id.clone())
                .or_insert_with(ComponentTracingMetadata::new)
                .add_result(tx_hash.clone(), result);
        }

        Ok(metadata_map
            .into_iter()
            .map(|(comp_id, metadata)| {
                let component = &all_components
                    .get(&comp_id)
                    .expect("Component must be present")
                    .1;
                (component.clone(), metadata)
            })
            .collect())
    }
}

enum RequestMode {
    Full,
    BalanceOnly,
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use chrono::NaiveDateTime;
    use mockall::predicate::*;
    use serde_json::json;
    use tycho_common::{
        models::{
            blockchain::Block, protocol::ProtocolComponent, Address, Chain, ChangeType, TxHash,
        },
        Bytes,
    };

    use super::*;
    use crate::extractor::dynamic_contract_indexer::component_metadata::{
        MetadataRequestType, MetadataValue, MockMetadataRequestGenerator,
        MockMetadataResponseParser, MockRequestProvider, RequestTransport, RpcTransport,
    };

    fn create_test_block() -> Block {
        Block {
            number: 12345,
            chain: Chain::Ethereum,
            hash: Bytes::from(vec![1, 2, 3, 4]),
            parent_hash: Bytes::from(vec![0, 0, 0, 0]),
            ts: NaiveDateTime::from_timestamp_opt(1234567890, 0).unwrap(),
        }
    }

    fn create_test_component(id: &str) -> ProtocolComponent {
        let mut static_attributes = HashMap::new();
        static_attributes.insert("hook".to_string(), Address::from([1u8; 20]));
        ProtocolComponent {
            id: id.to_string(),
            protocol_system: "test_protocol".to_string(),
            protocol_type_name: "test_type".to_string(),
            chain: Chain::Ethereum,
            tokens: vec![Address::from([2u8; 20]), Address::from([3u8; 20])],
            contract_addresses: vec![Address::from([1u8; 20])],
            static_attributes,
            change: ChangeType::Creation,
            creation_tx: TxHash::from([0u8; 32]),
            created_at: NaiveDateTime::from_timestamp_opt(1234567890, 0).unwrap(),
        }
    }

    fn create_test_metadata_request(
        component_id: &str,
        request_type: MetadataRequestType,
        routing_key: &str,
    ) -> MetadataRequest {
        let mut transport = RpcTransport::new(
            "http://test.com".to_string(),
            "eth_call".to_string(),
            vec![json!("test")],
        );
        transport.set_routing_key(routing_key.to_string());
        MetadataRequest::new(
            "test_protocol".to_string(),
            "test_request".to_string(),
            component_id.to_string(),
            request_type,
            Box::new(transport),
        )
    }

    #[tokio::test]
    async fn test_collect_metadata_for_block_success() {
        // Setup
        let block = create_test_block();
        let component1 = create_test_component("component1");
        let component2 = create_test_component("component2");
        let tx_hash1 = TxHash::from([1u8; 32]);
        let tx_hash2 = TxHash::from([2u8; 32]);

        let full_components = vec![(tx_hash1.clone(), component1.clone())];
        let balance_components = vec![(tx_hash2.clone(), component2.clone())];

        // Mock generator
        let mut mock_generator = MockMetadataRequestGenerator::new();
        mock_generator
            .expect_generate_requests()
            .with(always(), always())
            .times(1)
            .returning(|_, _| {
                let request = create_test_metadata_request(
                    "component1",
                    MetadataRequestType::ComponentBalance {
                        token_addresses: vec![Address::from([2u8; 20])],
                    },
                    "rpc_mainnet",
                );
                Ok(vec![request])
            });

        mock_generator
            .expect_generate_balance_only_requests()
            .with(always(), always())
            .times(1)
            .returning(|_, _| {
                let request = create_test_metadata_request(
                    "component2",
                    MetadataRequestType::ComponentBalance {
                        token_addresses: vec![Address::from([3u8; 20])],
                    },
                    "rpc_mainnet",
                );
                Ok(vec![request])
            });

        mock_generator
            .expect_supported_metadata_types()
            .returning(|| vec![MetadataRequestType::ComponentBalance { token_addresses: vec![] }]);

        // Mock parser
        let mut mock_parser = MockMetadataResponseParser::new();
        mock_parser
            .expect_parse_response()
            .with(always(), always(), always())
            .returning(|_, _, _| {
                let mut balances = HashMap::new();
                balances.insert(Address::from([2u8; 20]), Bytes::from(vec![100u8]));
                Ok(MetadataValue::Balances(balances))
            });

        // Mock provider
        let mut mock_provider = MockRequestProvider::new();
        mock_provider
            .expect_execute_batch()
            .with(always())
            .times(1)
            .returning(|reqs| {
                // Return one result for each request with the correct deduplication ID
                reqs.iter()
                    .map(|req| {
                        let dedup_id = req.deduplication_id();
                        (dedup_id, Ok(json!("0x1234567890abcdef")))
                    })
                    .collect()
            });

        // Setup registries
        let mut generator_registry = MetadataGeneratorRegistry::new();
        generator_registry.set_default_generator(Some(Box::new(mock_generator)));

        let mut parser_registry = MetadataResponseParserRegistry::new();
        parser_registry.register_parser("test".to_string(), Box::new(mock_parser));

        let mut provider_registry = ProviderRegistry::new();
        provider_registry.register_provider("rpc_mainnet".to_string(), Arc::new(mock_provider));

        // Create orchestrator
        let orchestrator =
            BlockMetadataOrchestrator::new(generator_registry, parser_registry, provider_registry);

        // Execute
        let result = orchestrator
            .collect_metadata_for_block(&balance_components, &full_components, &block)
            .await;

        // Assert
        let metadata_results = result.unwrap();
        assert_eq!(metadata_results.len(), 2);

        // Check that both components have metadata
        let component_ids: Vec<_> = metadata_results
            .iter()
            .map(|(component, _)| component.id.clone())
            .collect();
        assert!(component_ids.contains(&"component1".to_string()));
        assert!(component_ids.contains(&"component2".to_string()));
    }

    #[tokio::test]
    async fn test_collect_metadata_for_block_generator_error() {
        // Setup
        let block = create_test_block();
        let component = create_test_component("component1");
        let tx_hash = TxHash::from([1u8; 32]);
        let full_components = vec![(tx_hash, component)];

        // Mock generator that returns error
        let mut mock_generator = MockMetadataRequestGenerator::new();
        mock_generator
            .expect_generate_requests()
            .returning(|_, _| Err(MetadataError::GenerationFailed("Generator failed".to_string())));

        mock_generator
            .expect_supported_metadata_types()
            .returning(|| vec![MetadataRequestType::ComponentBalance { token_addresses: vec![] }]);

        // Setup registries
        let mut generator_registry = MetadataGeneratorRegistry::new();
        generator_registry.set_default_generator(Some(Box::new(mock_generator)));

        let parser_registry = MetadataResponseParserRegistry::new();
        let provider_registry = ProviderRegistry::new();

        // Create orchestrator
        let orchestrator =
            BlockMetadataOrchestrator::new(generator_registry, parser_registry, provider_registry);

        // Execute
        let result = orchestrator
            .collect_metadata_for_block(&[], &full_components, &block)
            .await;

        // Assert
        assert!(result.is_err());
        match result.unwrap_err() {
            MetadataError::GenerationFailed(msg) => {
                assert_eq!(msg, "Generator failed");
            }
            _ => panic!("Expected GenerationFailed error"),
        }
    }

    #[tokio::test]
    async fn test_collect_metadata_for_block_provider_error() {
        // Setup
        let block = create_test_block();
        let component = create_test_component("component1");
        let tx_hash = TxHash::from([1u8; 32]);
        let full_components = vec![(tx_hash, component)];

        // Mock generator
        let mut mock_generator = MockMetadataRequestGenerator::new();
        mock_generator
            .expect_generate_requests()
            .returning(|_, _| {
                let request = create_test_metadata_request(
                    "component1",
                    MetadataRequestType::ComponentBalance {
                        token_addresses: vec![Address::from([2u8; 20])],
                    },
                    "rpc_mainnet",
                );
                Ok(vec![request])
            });

        mock_generator
            .expect_supported_metadata_types()
            .returning(|| vec![MetadataRequestType::ComponentBalance { token_addresses: vec![] }]);

        // Mock provider that returns error
        let mut mock_provider = MockRequestProvider::new();
        mock_provider
            .expect_execute_batch()
            .returning(|reqs| {
                // Return one error result for each request with the correct deduplication ID
                reqs.iter()
                    .map(|req| {
                        let dedup_id = req.deduplication_id();
                        (
                            dedup_id,
                            Err(MetadataError::ProviderFailed("Provider failed".to_string())),
                        )
                    })
                    .collect()
            });

        // Setup registries
        let mut generator_registry = MetadataGeneratorRegistry::new();
        generator_registry.set_default_generator(Some(Box::new(mock_generator)));

        let mut parser_registry = MetadataResponseParserRegistry::new();
        parser_registry
            .register_parser("test".to_string(), Box::new(MockMetadataResponseParser::new()));

        let mut provider_registry = ProviderRegistry::new();
        provider_registry.register_provider("rpc_mainnet".to_string(), Arc::new(mock_provider));

        // Create orchestrator
        let orchestrator =
            BlockMetadataOrchestrator::new(generator_registry, parser_registry, provider_registry);

        // Execute
        let result = orchestrator
            .collect_metadata_for_block(&[], &full_components, &block)
            .await;

        // Assert - should still succeed but with error in metadata
        assert!(result.is_ok());
        let metadata_results = result.unwrap();
        assert_eq!(metadata_results.len(), 1);

        let (_, metadata) = &metadata_results[0];
        assert!(metadata.balances.is_some());
        assert!(metadata
            .balances
            .as_ref()
            .unwrap()
            .is_err());
    }

    #[test]
    fn test_group_requests_by_routing_key() {
        // Setup
        let generator_registry = MetadataGeneratorRegistry::new();
        let parser_registry = MetadataResponseParserRegistry::new();
        let provider_registry = ProviderRegistry::new();

        let orchestrator =
            BlockMetadataOrchestrator::new(generator_registry, parser_registry, provider_registry);

        // Create test requests with different routing keys
        let request1 = create_test_metadata_request(
            "component1",
            MetadataRequestType::ComponentBalance {
                token_addresses: vec![Address::from([2u8; 20])],
            },
            "rpc_mainnet",
        );

        let request2 = create_test_metadata_request(
            "component2",
            MetadataRequestType::ComponentBalance {
                token_addresses: vec![Address::from([3u8; 20])],
            },
            "rpc_mainnet",
        );

        let request3 =
            create_test_metadata_request("component3", MetadataRequestType::Tvl, "api_defillama");

        let requests = vec![request1, request2, request3];

        // Execute
        let grouped = orchestrator.group_requests_by_routing_key(&requests);

        // Assert
        assert_eq!(grouped.len(), 2);
        assert!(grouped.contains_key("rpc_mainnet"));
        assert!(grouped.contains_key("api_defillama"));
        assert_eq!(grouped["rpc_mainnet"].len(), 2);
        assert_eq!(grouped["api_defillama"].len(), 1);
    }

    #[test]
    fn test_generate_requests_for_components() {
        // Setup
        let block = create_test_block();
        let component = create_test_component("component1");

        let mut mock_generator = MockMetadataRequestGenerator::new();
        mock_generator
            .expect_generate_requests()
            .with(always(), always())
            .times(1)
            .returning(|_, _| {
                let request = create_test_metadata_request(
                    "component1",
                    MetadataRequestType::ComponentBalance {
                        token_addresses: vec![Address::from([2u8; 20])],
                    },
                    "rpc_mainnet",
                );
                Ok(vec![request])
            });

        let mut generator_registry = MetadataGeneratorRegistry::new();
        generator_registry.set_default_generator(Some(Box::new(mock_generator)));

        let parser_registry = MetadataResponseParserRegistry::new();
        let provider_registry = ProviderRegistry::new();

        let orchestrator =
            BlockMetadataOrchestrator::new(generator_registry, parser_registry, provider_registry);

        // Execute
        let result = orchestrator.generate_requests(&[&component], &block, RequestMode::Full);

        // Assert
        assert!(result.is_ok());
        let requests = result.unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].component_id, "component1");
    }

    #[test]
    fn test_generate_balance_only_requests() {
        // Setup
        let block = create_test_block();
        let component = create_test_component("component1");

        let mut mock_generator = MockMetadataRequestGenerator::new();
        mock_generator
            .expect_generate_balance_only_requests()
            .with(always(), always())
            .times(1)
            .returning(|_, _| {
                let request = create_test_metadata_request(
                    "component1",
                    MetadataRequestType::ComponentBalance {
                        token_addresses: vec![Address::from([2u8; 20])],
                    },
                    "rpc_mainnet",
                );
                Ok(vec![request])
            });

        let mut generator_registry = MetadataGeneratorRegistry::new();
        generator_registry.set_default_generator(Some(Box::new(mock_generator)));

        let parser_registry = MetadataResponseParserRegistry::new();
        let provider_registry = ProviderRegistry::new();

        let orchestrator =
            BlockMetadataOrchestrator::new(generator_registry, parser_registry, provider_registry);

        // Execute
        let result =
            orchestrator.generate_requests(&[&component], &block, RequestMode::BalanceOnly);

        // Assert
        assert!(result.is_ok());
        let requests = result.unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].component_id, "component1");
    }

    #[test]
    fn test_assemble_component_metadata() {
        // Setup
        let component1 = create_test_component("component1");
        let component2 = create_test_component("component2");
        let tx_hash1 = TxHash::from([1u8; 32]);
        let tx_hash2 = TxHash::from([2u8; 32]);

        let mut all_components = HashMap::new();
        all_components.insert(component1.id.clone(), (tx_hash1.clone(), component1.clone()));
        all_components.insert(component2.id.clone(), (tx_hash2.clone(), component2.clone()));

        let results = vec![
            MetadataResult {
                request_id: "test_request_1".to_string(),
                component_id: "component1".to_string(),
                request_type: MetadataRequestType::ComponentBalance {
                    token_addresses: vec![Address::from([2u8; 20])],
                },
                result: {
                    let mut balances = HashMap::new();
                    balances.insert(Address::from([2u8; 20]), Bytes::from(vec![100u8]));
                    Ok(MetadataValue::Balances(balances))
                },
            },
            MetadataResult {
                request_id: "test_request_2".to_string(),
                component_id: "component2".to_string(),
                request_type: MetadataRequestType::Tvl,
                result: Ok(MetadataValue::Tvl(1000.0)),
            },
        ];

        let generator_registry = MetadataGeneratorRegistry::new();
        let parser_registry = MetadataResponseParserRegistry::new();
        let provider_registry = ProviderRegistry::new();

        let orchestrator =
            BlockMetadataOrchestrator::new(generator_registry, parser_registry, provider_registry);

        // Execute
        let result = orchestrator.assemble_component_metadata(&all_components, results);

        // Assert
        assert!(result.is_ok());
        let metadata_results = result.unwrap();
        assert_eq!(metadata_results.len(), 2);

        // Check component1 has balance metadata
        let component1_metadata = metadata_results
            .iter()
            .find(|(component, _)| component.id == "component1")
            .unwrap();
        assert!(component1_metadata.1.balances.is_some());
        assert!(component1_metadata
            .1
            .balances
            .as_ref()
            .unwrap()
            .is_ok());

        // Check component2 has TVL metadata
        let component2_metadata = metadata_results
            .iter()
            .find(|(component, _)| component.id == "component2")
            .unwrap();
        assert!(component2_metadata.1.tvl.is_some());
        assert!(component2_metadata
            .1
            .tvl
            .as_ref()
            .unwrap()
            .is_ok());
    }

    #[test]
    /// Test that the orchestrator properly handles errors in results.
    fn test_assemble_component_metadata_with_errors() {
        // Setup
        let component = create_test_component("component1");
        let tx_hash = TxHash::from([1u8; 32]);

        let mut all_components = HashMap::new();
        all_components.insert(component.id.clone(), (tx_hash.clone(), component.clone()));

        let results = vec![MetadataResult {
            request_id: "test_request_1".to_string(),
            component_id: "component1".to_string(),
            request_type: MetadataRequestType::ComponentBalance {
                token_addresses: vec![Address::from([2u8; 20])],
            },
            result: Err(MetadataError::GenerationFailed("Test error".to_string())),
        }];

        let generator_registry = MetadataGeneratorRegistry::new();
        let parser_registry = MetadataResponseParserRegistry::new();
        let provider_registry = ProviderRegistry::new();

        let orchestrator =
            BlockMetadataOrchestrator::new(generator_registry, parser_registry, provider_registry);

        // Execute
        let result = orchestrator.assemble_component_metadata(&all_components, results);

        // Assert
        assert!(result.is_ok());
        let metadata_results = result.unwrap();
        assert_eq!(metadata_results.len(), 1);

        let (_, metadata) = &metadata_results[0];
        assert!(metadata.balances.is_some());
        assert!(metadata
            .balances
            .as_ref()
            .unwrap()
            .is_err());
    }
}
