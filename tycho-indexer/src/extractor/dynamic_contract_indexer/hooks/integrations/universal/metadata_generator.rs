use std::collections::HashMap;

use serde_json::{json, Value};
use tracing::warn;
use tycho_common::{
    models::{
        blockchain::{
            Block, EntryPoint, EntryPointWithTracingParams, RPCTracerParams, TracingParams,
        },
        protocol::ProtocolComponent,
    },
    Bytes,
};

use crate::extractor::dynamic_contract_indexer::hooks::component_metadata::{
    MetadataError, MetadataRequest, MetadataRequestGenerator, MetadataRequestType,
    MetadataResponseParser, MetadataValue, RpcTransport,
};

pub(super) struct UniversalMetadataGenerator {
    rpc_url: String,
}

impl UniversalMetadataGenerator {
    pub(super) fn new(rpc_url: String) -> Self {
        Self { rpc_url }
    }
}

const UNIVERSAL_LENS_BYTECODE_BYTES: &[u8] =
    include_bytes!("./assets/UniversalJITLens.evm.runtime");

// Function selectors:
// getLiquidityForPool(address,address) = 0xcf9ded83
// getLimitsForPool(address,address) = 0x23548892
const GET_LIQUIDITY_SELECTOR: &str = "cf9ded83";
const GET_LIMITS_SELECTOR: &str = "23548892";

impl MetadataRequestGenerator for UniversalMetadataGenerator {
    fn generate_requests(
        &self,
        component: &ProtocolComponent,
        block: &Block,
    ) -> Result<Vec<MetadataRequest>, MetadataError> {
        let mut requests = vec![];

        let balance_request = self
            .generate_balance_only_requests(component, block)?
            .into_iter()
            .next()
            .expect("Balance request should be generated");

        requests.push(balance_request);

        let mut sorted_tokens = component.tokens.clone();
        sorted_tokens.sort_unstable();

        let token_0 = sorted_tokens[0].clone();
        let token_1 = sorted_tokens[1].clone();

        let token_0_str = token_0.to_string().split_off(2);
        let token_1_str = token_1.to_string().split_off(2);

        // Get hook address from component attributes
        let target = component
            .static_attributes
            .get("hooks")
            .expect("Hooks attribute not found");

        // Use a deterministic lens contract address for state override
        let lens_address = "0x0000000000000000000000000000000000001337";
        let target_str = target.to_string().split_off(2);

        // Load the lens contract bytecode and convert to hex
        let lens_bytecode_hex = hex::encode(UNIVERSAL_LENS_BYTECODE_BYTES);

        // Limits request: token_0 -> token_1
        let limits_transport_0to1 = RpcTransport::new(
            self.rpc_url.clone(),
            "eth_call".to_string(),
            vec![
                json!({
                    "data": format!("0x{}000000000000000000000000{}000000000000000000000000{}", GET_LIMITS_SELECTOR, token_0_str, token_1_str),
                    "to": lens_address
                }),
                json!(format!("0x{:x}", block.number)),
                json!({
                    lens_address: {
                        "code": format!("0x{}", lens_bytecode_hex),
                        "state": {
                            // Slot 0: HOOK address
                            "0x0000000000000000000000000000000000000000000000000000000000000000": format!("0x000000000000000000000000{}", target_str)
                        }
                    }
                }),
            ],
        );
        requests.push(MetadataRequest::new(
            "universal".to_string(),
            format!("universal_limits_{target}_{token_0}_to_{token_1}"),
            component.id.clone(),
            MetadataRequestType::Limits { token_pair: vec![(token_0.clone(), token_1.clone())] },
            Box::new(limits_transport_0to1),
        ));

        // Limits request: token_1 -> token_0
        let limits_transport_1to0 = RpcTransport::new(
            self.rpc_url.clone(),
            "eth_call".to_string(),
            vec![
                json!({
                    "data": format!("0x{}000000000000000000000000{}000000000000000000000000{}", GET_LIMITS_SELECTOR, token_1_str, token_0_str),
                    "to": lens_address
                }),
                json!(format!("0x{:x}", block.number)),
                json!({
                    lens_address: {
                        "code": format!("0x{}", lens_bytecode_hex),
                        "state": {
                            "0x0000000000000000000000000000000000000000000000000000000000000000": format!("0x000000000000000000000000{}", target_str)
                        }
                    }
                }),
            ],
        );
        requests.push(MetadataRequest::new(
            "universal".to_string(),
            format!("universal_limits_{target}_{token_1}_to_{token_0}"),
            component.id.clone(),
            MetadataRequestType::Limits { token_pair: vec![(token_1, token_0)] },
            Box::new(limits_transport_1to0),
        ));

        Ok(requests)
    }

    fn generate_balance_only_requests(
        &self,
        component: &ProtocolComponent,
        block: &Block,
    ) -> Result<Vec<MetadataRequest>, MetadataError> {
        let mut requests = vec![];

        let mut sorted_tokens = component.tokens.clone();
        sorted_tokens.sort_unstable();

        let token_0 = sorted_tokens[0].clone();
        let token_1 = sorted_tokens[1].clone();

        let token_0_str = token_0.to_string().split_off(2);
        let token_1_str = token_1.to_string().split_off(2);

        // Get hook address from component attributes
        let target = component
            .static_attributes
            .get("hooks")
            .expect("Hooks attribute not found");

        let lens_address = "0x0000000000000000000000000000000000001337";
        let target_str = target.to_string().split_off(2);

        let lens_bytecode_hex = hex::encode(UNIVERSAL_LENS_BYTECODE_BYTES);

        // Balance request using getLiquidityForPool
        let balance_transport = RpcTransport::new(
            self.rpc_url.clone(),
            "eth_call".to_string(),
            vec![
                json!({
                    "data": format!("0x{}000000000000000000000000{}000000000000000000000000{}", GET_LIQUIDITY_SELECTOR, token_0_str, token_1_str),
                    "to": lens_address
                }),
                json!(format!("0x{:x}", block.number)),
                json!({
                    lens_address: {
                        "code": format!("0x{}", lens_bytecode_hex),
                        "state": {
                            "0x0000000000000000000000000000000000000000000000000000000000000000": format!("0x000000000000000000000000{}", target_str)
                        }
                    }
                }),
            ],
        );
        requests.push(MetadataRequest::new(
            "universal".to_string(),
            format!("universal_balance_{target}"),
            component.id.clone(),
            MetadataRequestType::ComponentBalance { token_addresses: component.tokens.clone() },
            Box::new(balance_transport),
        ));

        Ok(requests)
    }

    fn supported_metadata_types(&self) -> Vec<MetadataRequestType> {
        vec![
            MetadataRequestType::ComponentBalance { token_addresses: vec![] },
            MetadataRequestType::Limits { token_pair: vec![] },
        ]
    }
}

pub(super) struct UniversalMetadataResponseParser;

impl MetadataResponseParser for UniversalMetadataResponseParser {
    fn parse_response(
        &self,
        component: &ProtocolComponent,
        request: &MetadataRequest,
        response: &Value,
    ) -> Result<MetadataValue, MetadataError> {
        match &request.request_type() {
            MetadataRequestType::ComponentBalance { .. } => {
                if component.tokens.len() < 2 {
                    return Err(MetadataError::MissingData(
                        "component must have at least 2 tokens".to_string(),
                        component.id.clone(),
                    ));
                }

                let mut sorted_tokens = component.tokens.clone();
                sorted_tokens.sort_unstable();
                let token_0 = &sorted_tokens[0];
                let token_1 = &sorted_tokens[1];

                let res_string = serde_json::from_value::<String>(response.clone()).unwrap();
                let res_str = res_string.strip_prefix("0x").unwrap_or(&res_string);

                // Check if response has enough data (2 uint256 values = 128 hex chars)
                if res_str.len() < 128 {
                    return Err(MetadataError::GenerationFailed(format!(
                        "Balance response too short: expected at least 128 characters, got {}",
                        res_str.len()
                    )));
                }

                // getLiquidityForPool returns (zeroForOneLiquidity, oneForZeroLiquidity)
                // zeroForOneLiquidity = liquidity available when swapping token0 -> token1
                // oneForZeroLiquidity = liquidity available when swapping token1 -> token0
                let balance_0 = Bytes::from(&res_str[0..64]);
                let balance_1 = Bytes::from(&res_str[64..128]);

                let mut balances = HashMap::new();
                balances.insert(token_0.clone(), balance_0);
                balances.insert(token_1.clone(), balance_1);

                Ok(MetadataValue::Balances(balances))
            }
            MetadataRequestType::Tvl => Err(MetadataError::GenerationFailed(
                "Tvl is not supported for Universal".to_string(),
            )),
            MetadataRequestType::Limits { token_pair } => {
                let res_string = serde_json::from_value::<String>(response.clone()).unwrap();
                let res_str = res_string.strip_prefix("0x").unwrap_or(&res_string);

                let entrypoint = (|| {
                    let request = request
                        .transport()
                        .as_any()
                        .downcast_ref::<RpcTransport>()
                        .ok_or(MetadataError::UnknownError("Not RpcTransport".to_string()))?;

                    let params = &request.params()[0];

                    let target = component
                        .static_attributes
                        .get("hooks")
                        .expect("Hooks attribute not found");

                    let calldata = params["data"]
                        .as_str()
                        .ok_or(MetadataError::UnknownError("calldata not found".to_string()))?;

                    Ok(EntryPointWithTracingParams {
                        entry_point: EntryPoint {
                            external_id: format!("{target}:getLimitsForPool(address,address)"),
                            target: target.clone(),
                            signature: "getLimitsForPool(address,address)".into(),
                        },
                        params: TracingParams::RPCTracer(RPCTracerParams {
                            calldata: Bytes::from(calldata),
                            caller: None,
                            state_overrides: None,
                            prune_addresses: None,
                        }),
                    })
                })()
                .map_err(|e: MetadataError| {
                    warn!("Entrypoint error for {}: {}", component.id, e);
                    e
                })
                .ok();

                // Check if response has enough data
                if res_str.len() < 128 {
                    return Err(MetadataError::GenerationFailed(format!(
                        "Limits response too short: expected at least 128 characters, got {}",
                        res_str.len()
                    )));
                }

                // getLimitsForPool returns (token0Limit, token1Limit)
                let limit_0 = Bytes::from(&res_str[0..64]);
                let limit_1 = Bytes::from(&res_str[64..128]);

                Ok(MetadataValue::Limits(vec![(
                    token_pair[0].clone(),
                    (limit_0, limit_1, entrypoint),
                )]))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use chrono::NaiveDateTime;
    use mockito::Server;
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
        static_attributes
            .insert("hooks".to_string(), Bytes::from("0x000000000000000000000000000000000000beef"));

        ProtocolComponent {
            id: "0x000000000000000000000000000000000000beef".to_string(),
            tokens: vec![
                Bytes::from("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"), // USDC
                Bytes::from("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"), // WETH
            ],
            static_attributes,
            ..Default::default()
        }
    }

    fn create_test_block() -> Block {
        Block::new(
            12345,
            Chain::Unichain,
            Bytes::from("0x1234567890123456789012345678901234567890123456789012345678901234"),
            Bytes::from("0x1234567890123456789012345678901234567890123456789012345678901233"),
            NaiveDateTime::parse_from_str("2023-01-01T00:00:00", "%Y-%m-%dT%H:%M:%S").unwrap(),
        )
    }

    #[test]
    fn test_generate_requests() {
        let generator =
            UniversalMetadataGenerator::new("https://eth-mainnet.alchemyapi.io/v2/test".to_string());
        let component = create_test_component();
        let block = create_test_block();

        let requests = generator.generate_requests(&component, &block).unwrap();

        assert_eq!(requests.len(), 3);

        // Balance request
        assert_eq!(requests[0].component_id(), &component.id);
        assert_eq!(
            requests[0].request_type(),
            &MetadataRequestType::ComponentBalance { token_addresses: component.tokens.clone() }
        );
        assert_eq!(
            requests[0].request_id(),
            "universal_balance_0x000000000000000000000000000000000000beef"
        );
        assert_eq!(requests[0].transport().routing_key(), "rpc_default".to_string());

        // Limits request 0 to 1
        assert_eq!(requests[1].component_id(), &component.id);
        assert!(matches!(requests[1].request_type(), MetadataRequestType::Limits { .. }));

        // Limits request 1 to 0
        assert_eq!(requests[2].component_id(), &component.id);
        assert!(matches!(requests[2].request_type(), MetadataRequestType::Limits { .. }));

        // Verify state overrides are included
        assert!(requests[1].transport().deduplication_id().contains("code"));
        assert!(requests[1].transport().deduplication_id().contains("state"));
    }

    #[test]
    fn test_generate_balance_only_requests() {
        let generator =
            UniversalMetadataGenerator::new("https://eth-mainnet.alchemyapi.io/v2/test".to_string());
        let component = create_test_component();
        let block = create_test_block();

        let requests = generator
            .generate_balance_only_requests(&component, &block)
            .unwrap();

        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].component_id(), &component.id);
        assert_eq!(
            requests[0].request_type(),
            &MetadataRequestType::ComponentBalance { token_addresses: component.tokens.clone() }
        );
    }

    #[test]
    fn test_supported_metadata_types() {
        let generator =
            UniversalMetadataGenerator::new("https://eth-mainnet.alchemyapi.io/v2/test".to_string());
        let supported_types = generator.supported_metadata_types();

        let expected_types = vec![
            MetadataRequestType::ComponentBalance { token_addresses: vec![] },
            MetadataRequestType::Limits { token_pair: vec![] },
        ];

        assert_eq!(supported_types, expected_types);
    }

    #[test]
    fn test_parse_balance_response() {
        let parser = UniversalMetadataResponseParser;
        let component = create_test_component();
        let block = create_test_block();

        let generator =
            UniversalMetadataGenerator::new("https://eth-mainnet.alchemyapi.io/v2/test".to_string());
        let requests = generator
            .generate_balance_only_requests(&component, &block)
            .unwrap();
        let request = &requests[0];

        // Mock response: two uint256 values
        let mock_response = Value::String(
            "0x0000000000000000000000000000000000000000000000000000000030598d1300000000000000000000000000000000000000000000000000013ccb6410e36b"
                .to_string(),
        );

        let result = parser
            .parse_response(&component, request, &mock_response)
            .unwrap();

        if let MetadataValue::Balances(balances) = result {
            assert_eq!(balances.len(), 2);
            // Verify both tokens have balances
            let mut sorted_tokens = component.tokens.clone();
            sorted_tokens.sort_unstable();
            assert!(balances.contains_key(&sorted_tokens[0]));
            assert!(balances.contains_key(&sorted_tokens[1]));
        } else {
            panic!("Expected MetadataValue::Balances");
        }
    }

    #[test]
    fn test_parse_limits_response() {
        let parser = UniversalMetadataResponseParser;
        let component = create_test_component();
        let block = create_test_block();

        let generator =
            UniversalMetadataGenerator::new("https://eth-mainnet.alchemyapi.io/v2/test".to_string());
        let requests = generator.generate_requests(&component, &block).unwrap();
        let limits_request = &requests[1]; // First limits request

        // Mock response: two uint256 values for limits
        let mock_response = Value::String(
            "0x0000000000000000000000000000000000000000000000000000267d3cdc9cbf00000000000000000000000000000000000000000000000000013ccb6410e36b"
                .to_string(),
        );

        let result = parser
            .parse_response(&component, limits_request, &mock_response)
            .unwrap();

        if let MetadataValue::Limits(limits_data) = result {
            assert_eq!(limits_data.len(), 1);
            let (_token_pair, (limit_0, limit_1, entrypoint)) = &limits_data[0];
            assert!(!limit_0.is_empty());
            assert!(!limit_1.is_empty());
            assert!(entrypoint.is_some());

            if let Some(ep) = entrypoint {
                assert_eq!(ep.entry_point.signature, "getLimitsForPool(address,address)");
            }
        } else {
            panic!("Expected MetadataValue::Limits");
        }
    }

    #[tokio::test]
    async fn test_universal_metadata_roundtrip_mock() {
        let mut server = Server::new_async().await;
        let endpoint = server.url();

        let generator = UniversalMetadataGenerator::new(endpoint);
        let rpc_provider = RPCMetadataProvider::new(10);
        let parser = UniversalMetadataResponseParser;

        let component = ProtocolComponent {
            id: "0xc88b618c2c670c2e2a42e06b466b6f0e82a6e8a8".to_string(),
            protocol_system: "universal_swap".to_string(),
            protocol_type_name: "swap".to_string(),
            chain: Chain::Unichain,
            tokens: vec![
                Bytes::from("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"),
                Bytes::from("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"),
            ],
            contract_addresses: vec![],
            static_attributes: HashMap::from([(
                "hooks".to_string(),
                Bytes::from("0xc88b618c2c670c2e2a42e06b466b6f0e82a6e8a8"),
            )]),
            change: ChangeType::Creation,
            creation_tx: Bytes::from(
                "0x316209797c061712713d61cfa30c200dbe0211bec67d8ef3ddfef38c733bb1c0",
            ),
            created_at: NaiveDateTime::parse_from_str("2025-07-07T08:42:47", "%Y-%m-%dT%H:%M:%S")
                .unwrap(),
        };
        let block = Block {
            number: 22923196,
            chain: Chain::Unichain,
            hash: Bytes::from(
                "0x5dae08576aa4a6d8a84a677b93f6892c82e53bb05f6df6a2f968fc012b37136e",
            ),
            parent_hash: Bytes::from(
                "0x274607019d5d34329809c455db8230c3ef2cf038c15ddacc79e36beb645da02d",
            ),
            ts: NaiveDateTime::parse_from_str("2025-07-15T07:49:59", "%Y-%m-%dT%H:%M:%S").unwrap(),
        };

        let requests = generator.generate_requests(&component, &block).unwrap();

        // Create mock responses for each request
        let mut mock_responses = vec![];
        for request in &requests {
            let transport = request
                .transport()
                .as_any()
                .downcast_ref::<RpcTransport>()
                .unwrap();
            let id = transport.id();

            let response = match request.request_type() {
                MetadataRequestType::ComponentBalance { .. } => {
                    json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": "0x0000000000000000000000000000000000000000000000000000000030598d1300000000000000000000000000000000000000000000000000013ccb6410e36b"
                    })
                }
                MetadataRequestType::Limits { .. } => {
                    json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": "0x0000000000000000000000000000000000000000000000000000267d3cdc9cbf00000000000000000000000000000000000000000000000000013ccb6410e36b"
                    })
                }
                _ => panic!("Unexpected request type"),
            };

            mock_responses.push(response);
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
                .parse_response(&component, request, &result.expect("Request should be successful"))
                .unwrap();

            parsed_results.push(parsed_result);
        }

        assert_eq!(parsed_results.len(), requests.len());

        // Verify we got balance and limits responses
        let balance_found = parsed_results
            .iter()
            .any(|result| matches!(result, MetadataValue::Balances(_)));
        assert!(balance_found, "Balance response should be found");

        let limits_found = parsed_results
            .iter()
            .any(|result| matches!(result, MetadataValue::Limits(_)));
        assert!(limits_found, "Limits responses should be found");
    }
}
