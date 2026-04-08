use std::collections::HashMap;

use serde_json::json;
use tycho_common::{
    models::{
        blockchain::Block,
        protocol::ProtocolComponent,
    },
    Bytes,
};

use crate::extractor::dynamic_contract_indexer::hooks::component_metadata::{
    MetadataError, MetadataRequest, MetadataRequestGenerator, MetadataRequestType,
    MetadataResponseParser, MetadataValue, RpcTransport,
};

pub(super) struct AlphixMetadataGenerator {
    rpc_url: String,
}

impl AlphixMetadataGenerator {
    pub(super) fn new(rpc_url: String) -> Self {
        Self { rpc_url }
    }
}

impl MetadataRequestGenerator for AlphixMetadataGenerator {
    fn generate_requests(
        &self,
        component: &ProtocolComponent,
        block: &Block,
    ) -> Result<Vec<MetadataRequest>, MetadataError> {
        // For Alphix, balances ARE the full metadata — there are no separate limits
        // because limits are determined by the JIT liquidity available in the yield sources.
        self.generate_balance_only_requests(component, block)
    }

    fn generate_balance_only_requests(
        &self,
        component: &ProtocolComponent,
        block: &Block,
    ) -> Result<Vec<MetadataRequest>, MetadataError> {
        let target = component
            .static_attributes
            .get("hooks")
            .ok_or_else(|| {
                MetadataError::MissingData("hooks".to_string(), component.id.clone())
            })?;

        // getAmountInYieldSource(false) → amount0 in yield source
        // Selector: 0x47afb3a5
        let amount0_transport = RpcTransport::new(
            self.rpc_url.clone(),
            "eth_call".to_string(),
            vec![
                json!({
                    "data": "0x47afb3a50000000000000000000000000000000000000000000000000000000000000000",
                    "to": target
                }),
                json!(format!("0x{:x}", block.number)),
            ],
        );

        // getAmountInYieldSource(true) → amount1 in yield source
        // Selector: 0x47afb3a5
        let amount1_transport = RpcTransport::new(
            self.rpc_url.clone(),
            "eth_call".to_string(),
            vec![
                json!({
                    "data": "0x47afb3a50000000000000000000000000000000000000000000000000000000000000001",
                    "to": target
                }),
                json!(format!("0x{:x}", block.number)),
            ],
        );

        let mut sorted_tokens = component.tokens.clone();
        sorted_tokens.sort_unstable();

        Ok(vec![
            MetadataRequest::new(
                "alphix".to_string(),
                format!("alphix_balance0_{target}"),
                component.id.clone(),
                MetadataRequestType::ComponentBalance {
                    token_addresses: vec![sorted_tokens[0].clone()],
                },
                Box::new(amount0_transport),
            ),
            MetadataRequest::new(
                "alphix".to_string(),
                format!("alphix_balance1_{target}"),
                component.id.clone(),
                MetadataRequestType::ComponentBalance {
                    token_addresses: vec![sorted_tokens[1].clone()],
                },
                Box::new(amount1_transport),
            ),
        ])
    }

    fn supported_metadata_types(&self) -> Vec<MetadataRequestType> {
        vec![MetadataRequestType::ComponentBalance { token_addresses: vec![] }]
    }
}

pub(super) struct AlphixMetadataResponseParser;

impl MetadataResponseParser for AlphixMetadataResponseParser {
    fn parse_response(
        &self,
        _component: &ProtocolComponent,
        request: &MetadataRequest,
        response: &serde_json::Value,
    ) -> Result<MetadataValue, MetadataError> {
        match request.request_type() {
            MetadataRequestType::ComponentBalance { token_addresses } => {
                if token_addresses.is_empty() {
                    return Err(MetadataError::MissingData(
                        "token_addresses".to_string(),
                        request.component_id().clone(),
                    ));
                }

                let res_string = serde_json::from_value::<String>(response.clone()).map_err(
                    |e| {
                        MetadataError::GenerationFailed(format!(
                            "Failed to parse response as string: {e}"
                        ))
                    },
                )?;
                let res_str = res_string.strip_prefix("0x").unwrap_or(&res_string);

                // getAmountInYieldSource returns a single uint256 (64 hex chars)
                if res_str.len() < 64 {
                    return Err(MetadataError::GenerationFailed(format!(
                        "Balance response too short: expected at least 64 characters, got {}",
                        res_str.len()
                    )));
                }

                let balance = Bytes::from(&res_str[0..64]);
                let mut balances = HashMap::new();
                balances.insert(token_addresses[0].clone(), balance);

                Ok(MetadataValue::Balances(balances))
            }
            _ => Err(MetadataError::GenerationFailed(
                "Unsupported request type for Alphix".to_string(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use chrono::NaiveDateTime;
    use mockito::Server;
    use serde_json::json;
    use tycho_common::{
        models::{Chain, ChangeType},
        Bytes,
    };

    use super::*;
    use crate::extractor::dynamic_contract_indexer::hooks::{
        component_metadata::{RequestProvider, RequestTransport},
        rpc_metadata_provider::RPCMetadataProvider,
    };

    fn create_test_component() -> ProtocolComponent {
        let mut static_attributes = HashMap::new();
        static_attributes.insert(
            "hooks".to_string(),
            Bytes::from("0x831CfDf7c0E194f5369f204b3DD2481B843d60c0"),
        );

        ProtocolComponent {
            id: "0x831CfDf7c0E194f5369f204b3DD2481B843d60c0".to_string(),
            tokens: vec![
                Bytes::from("0x4200000000000000000000000000000000000006"), // WETH (Base)
                Bytes::from("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"), // USDC (Base)
            ],
            static_attributes,
            ..Default::default()
        }
    }

    fn create_test_block() -> Block {
        Block::new(
            25400000,
            Chain::Base,
            Bytes::from(
                "0x1234567890123456789012345678901234567890123456789012345678901234",
            ),
            Bytes::from(
                "0x1234567890123456789012345678901234567890123456789012345678901233",
            ),
            NaiveDateTime::parse_from_str("2025-03-01T00:00:00", "%Y-%m-%dT%H:%M:%S").unwrap(),
        )
    }

    #[test]
    fn test_generate_requests() {
        let generator =
            AlphixMetadataGenerator::new("https://base-rpc.example.com".to_string());
        let component = create_test_component();
        let block = create_test_block();

        let requests = generator.generate_requests(&component, &block).unwrap();

        // Should generate 2 requests: one per token (amount0 and amount1 in yield source)
        assert_eq!(requests.len(), 2);

        // Both should be balance requests
        assert!(matches!(
            requests[0].request_type(),
            MetadataRequestType::ComponentBalance { .. }
        ));
        assert!(matches!(
            requests[1].request_type(),
            MetadataRequestType::ComponentBalance { .. }
        ));

        assert!(requests[0]
            .request_id()
            .starts_with("alphix_balance0_"));
        assert!(requests[1]
            .request_id()
            .starts_with("alphix_balance1_"));
    }

    #[test]
    fn test_supported_metadata_types() {
        let generator =
            AlphixMetadataGenerator::new("https://base-rpc.example.com".to_string());
        let supported_types = generator.supported_metadata_types();

        assert_eq!(supported_types.len(), 1);
        assert!(matches!(
            supported_types[0],
            MetadataRequestType::ComponentBalance { .. }
        ));
    }

    #[test]
    fn test_parse_balance_response() {
        let parser = AlphixMetadataResponseParser;
        let component = create_test_component();

        let mut sorted_tokens = component.tokens.clone();
        sorted_tokens.sort_unstable();

        let request = MetadataRequest::new(
            "alphix".to_string(),
            "alphix_balance0_test".to_string(),
            component.id.clone(),
            MetadataRequestType::ComponentBalance {
                token_addresses: vec![sorted_tokens[0].clone()],
            },
            Box::new(RpcTransport::new(
                "http://test".to_string(),
                "eth_call".to_string(),
                vec![],
            )),
        );

        // Simulated response: uint256 = 1000000 (0xF4240)
        let response = serde_json::Value::String(
            "0x00000000000000000000000000000000000000000000000000000000000f4240".to_string(),
        );

        let result = parser
            .parse_response(&component, &request, &response)
            .unwrap();

        if let MetadataValue::Balances(balances) = result {
            assert_eq!(balances.len(), 1);
            assert!(balances.contains_key(&sorted_tokens[0]));
        } else {
            panic!("Expected MetadataValue::Balances");
        }
    }

    #[test]
    fn test_parse_balance_response_too_short() {
        let parser = AlphixMetadataResponseParser;
        let component = create_test_component();

        let mut sorted_tokens = component.tokens.clone();
        sorted_tokens.sort_unstable();

        let request = MetadataRequest::new(
            "alphix".to_string(),
            "alphix_balance0_test".to_string(),
            component.id.clone(),
            MetadataRequestType::ComponentBalance {
                token_addresses: vec![sorted_tokens[0].clone()],
            },
            Box::new(RpcTransport::new(
                "http://test".to_string(),
                "eth_call".to_string(),
                vec![],
            )),
        );

        let response = serde_json::Value::String("0x0f4240".to_string());

        let result = parser.parse_response(&component, &request, &response);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_alphix_metadata_roundtrip_mock() {
        let mut server = Server::new_async().await;
        let endpoint = server.url();

        let generator = AlphixMetadataGenerator::new(endpoint);
        let rpc_provider = RPCMetadataProvider::new(10);
        let parser = AlphixMetadataResponseParser;

        // Base ETH/USDC Alphix pool (all addresses are public on-chain data)
        let component = ProtocolComponent {
            id: "0x831cfdf7c0e194f5369f204b3dd2481b843d60c0".to_string(),
            protocol_system: "uniswap_v4".to_string(),
            protocol_type_name: "swap".to_string(),
            chain: Chain::Base,
            tokens: vec![
                Bytes::from("0x4200000000000000000000000000000000000006"), // WETH
                Bytes::from("0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"), // USDC
            ],
            contract_addresses: vec![],
            static_attributes: HashMap::from([(
                "hooks".to_string(),
                Bytes::from("0x831cfdf7c0e194f5369f204b3dd2481b843d60c0"),
            )]),
            change: ChangeType::Creation,
            creation_tx: Bytes::from(
                "0x0000000000000000000000000000000000000000000000000000000000000000",
            ),
            created_at: NaiveDateTime::parse_from_str("2025-03-01T00:00:00", "%Y-%m-%dT%H:%M:%S")
                .unwrap(),
        };
        let block = Block {
            number: 25400000,
            chain: Chain::Base,
            hash: Bytes::from(
                "0x0000000000000000000000000000000000000000000000000000000000000000",
            ),
            parent_hash: Bytes::from(
                "0x0000000000000000000000000000000000000000000000000000000000000000",
            ),
            ts: NaiveDateTime::parse_from_str("2025-03-01T00:00:00", "%Y-%m-%dT%H:%M:%S").unwrap(),
        };

        let requests = generator.generate_requests(&component, &block).unwrap();
        assert_eq!(requests.len(), 2);

        // Build mock JSON-RPC responses for each request
        let mut mock_responses = vec![];
        for request in &requests {
            let transport = request
                .transport()
                .as_any()
                .downcast_ref::<RpcTransport>()
                .unwrap();
            let id = transport.id();

            // Mock balance: ~8 ETH for token0, ~17200 USDC for token1
            let result_hex = if request.request_id().contains("balance0") {
                // getAmountInYieldSource(false) → 8e18 = 0x6F05B59D3B20000
                "0x0000000000000000000000000000000000000000000000006f05b59d3b200000"
            } else {
                // getAmountInYieldSource(true) → 17200e6 = 0x106B7F7800
                "0x00000000000000000000000000000000000000000000000000000106b7f78000"
            };

            mock_responses.push(json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": result_hex
            }));
        }

        let mock = server
            .mock("POST", "/")
            .with_body(serde_json::to_string(&mock_responses).unwrap())
            .expect(1)
            .create_async()
            .await;

        let id_to_request = requests
            .iter()
            .map(|request| (request.transport().deduplication_id(), request.clone()))
            .collect::<HashMap<String, MetadataRequest>>();

        let rpc_requests: Vec<Box<dyn RequestTransport>> = requests
            .iter()
            .map(|request| request.transport().clone_box())
            .collect();

        let results = rpc_provider.execute_batch(&rpc_requests).await;

        mock.assert();

        let mut parsed_results = vec![];
        for (request_id, result) in results {
            let request = id_to_request
                .get(&request_id)
                .expect("Request ID should be present in the request map");

            let parsed_result = parser
                .parse_response(
                    &component,
                    request,
                    &result.expect("Request should be successful"),
                )
                .unwrap();

            parsed_results.push(parsed_result);
        }

        assert_eq!(parsed_results.len(), 2);

        // Verify all results are balances
        for result in &parsed_results {
            assert!(
                matches!(result, MetadataValue::Balances(_)),
                "Expected MetadataValue::Balances, got: {:?}",
                result
            );
        }
    }

    #[tokio::test]
    #[ignore = "This test requires a real RPC connection"]
    async fn test_alphix_metadata_live_rpc() {
        let rpc_url = std::env::var("RPC_URL").expect("RPC_URL must be set (Base RPC endpoint)");
        let generator = AlphixMetadataGenerator::new(rpc_url);
        let rpc_provider = RPCMetadataProvider::new(10);
        let parser = AlphixMetadataResponseParser;

        // Arbitrum USDC/USDT Alphix pool (public on-chain addresses)
        let component = ProtocolComponent {
            id: "0x5e645c3d580976ca9e3fe77525d954e73a0ce0c0".to_string(),
            protocol_system: "uniswap_v4".to_string(),
            protocol_type_name: "swap".to_string(),
            chain: Chain::Arbitrum,
            tokens: vec![
                Bytes::from("0xaf88d065e77c8cc2239327c5edb3a432268e5831"), // USDC (Arb)
                Bytes::from("0xfd086bc7cd5c481dcc9c85ebe478a1c0b69fcbb9"), // USDT (Arb)
            ],
            contract_addresses: vec![],
            static_attributes: HashMap::from([(
                "hooks".to_string(),
                Bytes::from("0x5e645c3d580976ca9e3fe77525d954e73a0ce0c0"),
            )]),
            change: ChangeType::Creation,
            creation_tx: Bytes::from(
                "0x0000000000000000000000000000000000000000000000000000000000000000",
            ),
            created_at: NaiveDateTime::parse_from_str("2025-03-01T00:00:00", "%Y-%m-%dT%H:%M:%S")
                .unwrap(),
        };
        let block = Block {
            number: 428900000,
            chain: Chain::Arbitrum,
            hash: Bytes::from(
                "0x0000000000000000000000000000000000000000000000000000000000000000",
            ),
            parent_hash: Bytes::from(
                "0x0000000000000000000000000000000000000000000000000000000000000000",
            ),
            ts: NaiveDateTime::parse_from_str("2025-03-01T00:00:00", "%Y-%m-%dT%H:%M:%S").unwrap(),
        };

        let requests = generator.generate_requests(&component, &block).unwrap();
        assert_eq!(requests.len(), 2);

        let id_to_request = requests
            .iter()
            .map(|request| (request.transport().deduplication_id(), request.clone()))
            .collect::<HashMap<String, MetadataRequest>>();

        let rpc_requests: Vec<Box<dyn RequestTransport>> = requests
            .iter()
            .map(|request| request.transport().clone_box())
            .collect();

        let results = rpc_provider.execute_batch(&rpc_requests).await;
        assert_eq!(results.len(), 2);

        for (request_id, result) in results {
            let request = id_to_request
                .get(&request_id)
                .expect("Request ID should be present");

            let parsed = parser
                .parse_response(
                    &component,
                    request,
                    &result.expect("RPC call should succeed"),
                )
                .expect("Response should parse successfully");

            if let MetadataValue::Balances(balances) = parsed {
                assert_eq!(balances.len(), 1, "Each response should have one token balance");
                // Verify the balance is non-zero (pools have >30k USD in rehypo)
                for balance_bytes in balances.values() {
                    let balance_hex = balance_bytes.to_string();
                    let is_zero = balance_hex
                        .trim_start_matches("0x")
                        .chars()
                        .all(|c| c == '0');
                    assert!(!is_zero, "Balance should be non-zero for active pool");
                }
            } else {
                panic!("Expected MetadataValue::Balances");
            }
        }
    }
}
