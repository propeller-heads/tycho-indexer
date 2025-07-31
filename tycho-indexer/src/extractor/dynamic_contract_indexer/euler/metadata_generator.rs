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

use crate::extractor::dynamic_contract_indexer::component_metadata::{
    MetadataError, MetadataRequest, MetadataRequestGenerator, MetadataRequestType,
    MetadataResponseParser, MetadataValue, RpcTransport,
};

pub struct EulerMetadataGenerator {
    rpc_url: String,
}

impl EulerMetadataGenerator {
    #[allow(dead_code)]
    pub fn new(rpc_url: String) -> Self {
        Self { rpc_url }
    }
}

impl MetadataRequestGenerator for EulerMetadataGenerator {
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

        let token_0 = component.tokens[0]
            .to_string()
            .split_off(2);
        let token_1 = component.tokens[1]
            .to_string()
            .split_off(2);
        // Metadata is extracted by calling the hooks contract
        let target = component.static_attributes.get("hooks").expect("Hooks attribute not found");

        let limits_transport_0to1 = RpcTransport::new(
            self.rpc_url.clone(),
            "eth_call".to_string(),
            vec![
                json!({
                    "data": format!("0xaaed87a3000000000000000000000000{}000000000000000000000000{}", token_0, token_1),
                    "to": target
                }),
                json!(format!("0x{:x}", block.number)),
            ],
        );
        requests.push(MetadataRequest::new(
            "euler".to_string(),
            format!(
                "euler_limits_{}_{}_to_{}",
                target, component.tokens[0], component.tokens[1]
            ),
            component.id.clone(),
            // Euler swap only has pools with 2 tokens
            MetadataRequestType::Limits {
                token_pair: vec![(component.tokens[0].clone(), component.tokens[1].clone())],
            },
            Box::new(limits_transport_0to1),
        ));

        let limits_transport_1to0 = RpcTransport::new(
            self.rpc_url.clone(),
            "eth_call".to_string(),
            vec![
                json!({
                  "data": format!("0xaaed87a3000000000000000000000000{}000000000000000000000000{}", token_1, token_0),
                  "to": target
                }),
                json!(format!("0x{:x}", block.number)),
            ],
        );
        requests.push(MetadataRequest::new(
            "euler".to_string(),
            format!(
                "euler_limits_{}_{}_to_{}",
                target, component.tokens[1], component.tokens[0]
            ),
            component.id.clone(),
            // Euler swap only has pools with 2 tokens
            MetadataRequestType::Limits {
                token_pair: vec![(component.tokens[1].clone(), component.tokens[0].clone())],
            },
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
        // Balance is extracted by calling the hooks contract
        let target = component.static_attributes.get("hooks").expect("Hooks attribute not found");

        let balance_transport = RpcTransport::new(
            self.rpc_url.clone(),
            "eth_call".to_string(),
            vec![
                json!({
                    "data": "0x0902f1ac", // getReserves()
                    "to": target
                }),
                json!(format!("0x{:x}", block.number)),
            ],
        );
        requests.push(MetadataRequest::new(
            "euler".to_string(),
            format!("euler_balance_{target}"),
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

#[allow(dead_code)] //TODO: remove this once it's used
pub struct EulerMetadataResponseParser;

impl MetadataResponseParser for EulerMetadataResponseParser {
    fn parse_response(
        &self,
        component: &ProtocolComponent,
        request: &MetadataRequest,
        response: &Value,
    ) -> Result<MetadataValue, MetadataError> {
        match &request.request_type {
            MetadataRequestType::ComponentBalance { .. } => {
                let token_0 = component
                    .static_attributes
                    .get("token_0")
                    .ok_or(MetadataError::MissingData(
                        "token_0 static attribute".to_string(),
                        component.id.clone(),
                    ))?;

                let token_1 = component
                    .static_attributes
                    .get("token_1")
                    .ok_or(MetadataError::MissingData(
                        "token_1 static attribute".to_string(),
                        component.id.clone(),
                    ))?;

                let res_string = serde_json::from_value::<String>(response.clone()).unwrap();
                let res_str = res_string
                    .strip_prefix("0x")
                    .unwrap_or(&res_string);

                // Check if response has enough data
                if res_str.len() < 128 {
                    return Err(MetadataError::GenerationFailed(format!(
                        "Balance response too short: expected at least 128 characters, got {}",
                        res_str.len()
                    )));
                }

                let balance_0 = Bytes::from(&res_str[0..64]);
                let balance_1 = Bytes::from(&res_str[64..128]);

                let mut balances = HashMap::new();
                balances.insert(token_0.clone(), balance_0);
                balances.insert(token_1.clone(), balance_1);

                let res = MetadataValue::Balances(balances);
                Ok(res)
            }
            MetadataRequestType::Tvl => {
                Err(MetadataError::GenerationFailed("Tvl is not supported for Euler".to_string()))
            }
            MetadataRequestType::Limits { token_pair } => {
                let res_string = serde_json::from_value::<String>(response.clone()).unwrap();
                let res_str = res_string
                    .strip_prefix("0x")
                    .unwrap_or(&res_string);

                let entrypoint = (|| {
                    let request = request
                        .transport
                        .as_any()
                        .downcast_ref::<RpcTransport>()
                        .ok_or(MetadataError::UnknownError("Not RpcTransport".to_string()))?;

                    let params = &request.params[0];
                    let target = params["to"]
                        .as_str()
                        .ok_or(MetadataError::UnknownError("target not found".to_string()))?;

                    let calldata = params["data"]
                        .as_str()
                        .ok_or(MetadataError::UnknownError("calldata not found".to_string()))?;

                    Ok(EntryPointWithTracingParams {
                        entry_point: EntryPoint {
                            external_id: format!("{target}:getLimits(address,address)"),
                            target: Bytes::from(target),
                            signature: "getLimits(address,address)".into(),
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
    use crate::extractor::dynamic_contract_indexer::{
        component_metadata::{RequestProvider, RequestTransport},
        rpc_metadata_provider::RPCMetadataProvider,
    };

    fn create_test_component() -> ProtocolComponent {
        ProtocolComponent {
            id: "0xbeef".to_string(),
            tokens: vec![
                Bytes::from("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"), // USDC
                Bytes::from("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"), // WETH
            ],
            ..Default::default()
        }
    }

    fn create_test_block() -> Block {
        Block::new(
            12345,
            Chain::Ethereum,
            Bytes::from("0x1234567890123456789012345678901234567890123456789012345678901234"),
            Bytes::from("0x1234567890123456789012345678901234567890123456789012345678901233"),
            NaiveDateTime::parse_from_str("2023-01-01T00:00:00", "%Y-%m-%dT%H:%M:%S").unwrap(),
        )
    }

    #[test]
    fn test_generate_requests() {
        let generator =
            EulerMetadataGenerator::new("https://eth-mainnet.alchemyapi.io/v2/test".to_string());
        let component = create_test_component();
        let block = create_test_block();

        let requests = generator
            .generate_requests(&component, &block)
            .unwrap();

        assert_eq!(requests.len(), 3);

        // Balance request
        assert_eq!(requests[0].component_id, component.id);
        assert_eq!(
            requests[0].request_type,
            MetadataRequestType::ComponentBalance { token_addresses: component.tokens.clone() }
        );
        assert_eq!(requests[0].request_id, "euler_balance_0xbeef".to_string());
        assert_eq!(requests[0].transport.routing_key(), "rpc_default".to_string());
        assert_eq!(
            requests[0].transport.deduplication_id(),
            "eth_call_[{\"data\":\"0x0902f1ac\",\"to\":\"0xbeef\"},\"0x3039\"]".to_string()
        );

        // Limits request 0 to 1
        assert_eq!(requests[1].component_id, component.id);
        assert_eq!(
            requests[1].request_type,
            MetadataRequestType::Limits {
                token_pair: vec![(component.tokens[0].clone(), component.tokens[1].clone())]
            }
        );
        assert_eq!(
            requests[1].request_id,
            "euler_limits_0xbeef_0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48_to_0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2".to_string()
        );
        assert_eq!(requests[1].transport.routing_key(), "rpc_default".to_string());
        assert_eq!(
            requests[1].transport.deduplication_id(),
            "eth_call_[{\"data\":\"0xaaed87a3000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2\",\"to\":\"0xbeef\"},\"0x3039\"]".to_string()
        );

        // Limits request 1 to 0
        assert_eq!(requests[2].component_id, component.id);
        assert_eq!(
            requests[2].request_type,
            MetadataRequestType::Limits {
                token_pair: vec![(component.tokens[1].clone(), component.tokens[0].clone())]
            }
        );
        assert_eq!(
            requests[2].request_id,
            "euler_limits_0xbeef_0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2_to_0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48".to_string()
        );
        assert_eq!(requests[2].transport.routing_key(), "rpc_default".to_string());
        assert_eq!(
            requests[2].transport.deduplication_id(),
            "eth_call_[{\"data\":\"0xaaed87a3000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48\",\"to\":\"0xbeef\"},\"0x3039\"]".to_string()
        );
    }

    #[test]
    fn test_generate_balance_only_requests() {
        let generator =
            EulerMetadataGenerator::new("https://eth-mainnet.alchemyapi.io/v2/test".to_string());
        let component = create_test_component();
        let block = create_test_block();

        let requests = generator
            .generate_balance_only_requests(&component, &block)
            .unwrap();

        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].component_id, component.id);
        assert_eq!(
            requests[0].request_type,
            MetadataRequestType::ComponentBalance { token_addresses: component.tokens.clone() }
        );
        assert_eq!(requests[0].request_id, "euler_balance_0xbeef".to_string());
        assert_eq!(requests[0].transport.routing_key(), "rpc_default".to_string());
        assert_eq!(
            requests[0].transport.deduplication_id(),
            "eth_call_[{\"data\":\"0x0902f1ac\",\"to\":\"0xbeef\"},\"0x3039\"]".to_string()
        );
    }

    #[test]
    fn test_supported_metadata_types() {
        let generator =
            EulerMetadataGenerator::new("https://eth-mainnet.alchemyapi.io/v2/test".to_string());
        let supported_types = generator.supported_metadata_types();

        let expected_types = vec![
            MetadataRequestType::ComponentBalance { token_addresses: vec![] },
            MetadataRequestType::Limits { token_pair: vec![] },
        ];

        assert_eq!(supported_types, expected_types);
    }

    #[tokio::test]
    #[ignore = "This test requires a real RPC connection"]
    async fn test_euler_metadata_roundtrip() {
        let rpc_url = std::env::var("RPC_URL").expect("RPC_URL must be set");
        let generator = EulerMetadataGenerator::new(rpc_url);
        let rpc_provider = RPCMetadataProvider::new(10);
        let parser = EulerMetadataResponseParser;

        let component = ProtocolComponent {
            id: "0xc88b618c2c670c2e2a42e06b466b6f0e82a6e8a8".to_string(),
            protocol_system: "euler_swap".to_string(),
            protocol_type_name: "swap".to_string(),
            chain: Chain::Ethereum,
            tokens: vec![
                Bytes::from("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"),
                Bytes::from("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"),
            ],
            contract_addresses: vec![],
            static_attributes: HashMap::from([
                ("token_0".to_string(), Bytes::from("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48")),
                ("token_1".to_string(), Bytes::from("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2")),
            ]),
            change: ChangeType::Creation,
            creation_tx: Bytes::from(
                "0x316209797c061712713d61cfa30c200dbe0211bec67d8ef3ddfef38c733bb1c0",
            ),
            created_at: NaiveDateTime::parse_from_str("2025-07-07T08:42:47", "%Y-%m-%dT%H:%M:%S")
                .unwrap(),
        };
        let block = Block {
            number: 22923196,
            chain: Chain::Ethereum,
            hash: Bytes::from("0x5dae08576aa4a6d8a84a677b93f6892c82e53bb05f6df6a2f968fc012b37136e"),
            parent_hash: Bytes::from(
                "0x274607019d5d34329809c455db8230c3ef2cf038c15ddacc79e36beb645da02d",
            ),
            ts: NaiveDateTime::parse_from_str("2025-07-15T07:49:59", "%Y-%m-%dT%H:%M:%S").unwrap(),
        };

        let requests = generator
            .generate_requests(&component, &block)
            .unwrap();

        let id_to_request = requests
            .iter()
            .map(|request| (request.transport.deduplication_id(), request.clone()))
            .collect::<HashMap<String, MetadataRequest>>();

        let rpc_requests: Vec<Box<dyn RequestTransport>> = requests
            .iter()
            .map(|request| request.transport.clone_box())
            .collect();

        let results = rpc_provider
            .execute_batch(&rpc_requests)
            .await;

        assert_eq!(results.len(), requests.len());

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

        let expected_balances = {
            let mut map = HashMap::new();
            map.insert(
                Bytes::from("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"),
                Bytes::from("0x0000000000000000000000000000000000000000000000000000000030598d13"),
            );
            map.insert(
                Bytes::from("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"),
                Bytes::from("0x00000000000000000000000000000000000000000000000000013ccb6410e36b"),
            );
            map
        };

        let expected_value = MetadataValue::Balances(expected_balances);

        assert!(
            parsed_results.contains(&expected_value),
            "Expected balances not found in parsed_results"
        );

        assert!(parsed_results.contains(&MetadataValue::Limits(vec![(
            (
                Bytes::from("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"),
                Bytes::from("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"),
            ),
            (
                Bytes::from("0x0000000000000000000000000000000000000000000000000000267d3cdc9cbf"),
                Bytes::from("0x00000000000000000000000000000000000000000000000000013ccb6410e36b"),
                Some(EntryPointWithTracingParams {
                    entry_point: EntryPoint {
                        external_id: "0x0000000000000000000000000000000000000000000000000000000000000000:getLimits(address,address)".to_string(),
                        target: Bytes::from("0x0000000000000000000000000000000000000000000000000000000000000000"),
                        signature: "getLimits(address,address)".to_string(),
                    },
                    params: tycho_common::models::blockchain::TracingParams::RPCTracer(
                        RPCTracerParams {
                            caller: None,
                            calldata: Bytes::from("0xaaed87a3000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"),
                            state_overrides: None,
                            prune_addresses: None,
                        },
                    ),
                }),
            )
        )]),));

        assert!(parsed_results.contains(&MetadataValue::Limits(vec![(
            (
                Bytes::from("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"),
                Bytes::from("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"),
            ),
            (
                Bytes::from("0x000000000000000000000000000000000000000000000ecaa543f127a7d92880"),
                Bytes::from("0x0000000000000000000000000000000000000000000000000000000030598d13"),
                Some(EntryPointWithTracingParams {
                    entry_point: EntryPoint {
                        external_id: "0x0000000000000000000000000000000000000000000000000000000000000000:getLimits(address,address)".to_string(),
                        target: Bytes::from("0x0000000000000000000000000000000000000000000000000000000000000000"),
                        signature: "getLimits(address,address)".to_string(),
                    },
                    params: tycho_common::models::blockchain::TracingParams::RPCTracer(
                        RPCTracerParams {
                            caller: None,
                            calldata: Bytes::from("0xaaed87a3000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"),
                            state_overrides: None,
                            prune_addresses: None,
                        },
                    ),
                }),
            )
        )]),));
    }

    #[tokio::test]
    async fn test_euler_metadata_roundtrip_mock() {
        let mut server = Server::new_async().await;
        let endpoint = server.url();

        let generator = EulerMetadataGenerator::new(endpoint);
        let rpc_provider = RPCMetadataProvider::new(10);
        let parser = EulerMetadataResponseParser;

        let component = ProtocolComponent {
            id: "0xc88b618c2c670c2e2a42e06b466b6f0e82a6e8a8".to_string(),
            protocol_system: "euler_swap".to_string(),
            protocol_type_name: "swap".to_string(),
            chain: Chain::Ethereum,
            tokens: vec![
                Bytes::from("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"),
                Bytes::from("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"),
            ],
            contract_addresses: vec![],
            static_attributes: HashMap::from([
                ("token_0".to_string(), Bytes::from("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48")),
                ("token_1".to_string(), Bytes::from("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2")),
            ]),
            change: ChangeType::Creation,
            creation_tx: Bytes::from(
                "0x316209797c061712713d61cfa30c200dbe0211bec67d8ef3ddfef38c733bb1c0",
            ),
            created_at: NaiveDateTime::parse_from_str("2025-07-07T08:42:47", "%Y-%m-%dT%H:%M:%S")
                .unwrap(),
        };
        let block = Block {
            number: 22923196,
            chain: Chain::Ethereum,
            hash: Bytes::from("0x5dae08576aa4a6d8a84a677b93f6892c82e53bb05f6df6a2f968fc012b37136e"),
            parent_hash: Bytes::from(
                "0x274607019d5d34329809c455db8230c3ef2cf038c15ddacc79e36beb645da02d",
            ),
            ts: NaiveDateTime::parse_from_str("2025-07-15T07:49:59", "%Y-%m-%dT%H:%M:%S").unwrap(),
        };

        let requests = generator
            .generate_requests(&component, &block)
            .unwrap();

        // Create mock responses for each request
        let mut mock_responses = vec![];
        for request in &requests {
            let transport = request
                .transport
                .as_any()
                .downcast_ref::<RpcTransport>()
                .unwrap();
            let id = transport.id;

            let response = match request.request_id.as_str() {
                "euler_balance_0xc88b618c2c670c2e2a42e06b466b6f0e82a6e8a8" => {
                    json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": "0x0000000000000000000000000000000000000000000000000000000030598d1300000000000000000000000000000000000000000000000000013ccb6410e36b0000000000000000000000000000000000000000000000000000000000000001"
                    })
                }
                "euler_limits_0xc88b618c2c670c2e2a42e06b466b6f0e82a6e8a8_0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48_to_0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2" => {
                    // Mock limits response - empty for now
                    json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": "0x0000000000000000000000000000000000000000000000000000267d3cdc9cbf00000000000000000000000000000000000000000000000000013ccb6410e36b"
                    })
                }
                "euler_limits_0xc88b618c2c670c2e2a42e06b466b6f0e82a6e8a8_0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2_to_0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48" => {
                    json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": "0x000000000000000000000000000000000000000000000ecaa543f127a7d928800000000000000000000000000000000000000000000000000000000030598d13"
                    })
                }
                _ => panic!("Unexpected request ID: {}", request.request_id),
            };

            mock_responses.push(response);
        }
        let batch_responses: Vec<serde_json::Value> = mock_responses;

        let mock = server
            .mock("POST", "/")
            .with_body(serde_json::to_string(&batch_responses).unwrap())
            .expect(1)
            .create_async()
            .await;

        let id_to_request = requests
            .iter()
            .map(|request| (request.transport.deduplication_id(), request.clone()))
            .collect::<HashMap<String, MetadataRequest>>();

        let rpc_requests: Vec<Box<dyn RequestTransport>> = requests
            .iter()
            .map(|request| request.transport.clone_box())
            .collect();

        let results = rpc_provider
            .execute_batch(&rpc_requests)
            .await;

        // Assertions
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

        let expected_balances = {
            let mut map = HashMap::new();
            map.insert(
                Bytes::from("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"),
                Bytes::from("0x0000000000000000000000000000000000000000000000000000000030598d13"),
            );
            map.insert(
                Bytes::from("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"),
                Bytes::from("0x00000000000000000000000000000000000000000000000000013ccb6410e36b"),
            );
            map
        };

        let expected_value = MetadataValue::Balances(expected_balances);

        assert!(
            parsed_results.contains(&expected_value),
            "Expected balances not found in parsed_results"
        );

        assert!(parsed_results.contains(&MetadataValue::Limits(vec![(
            (
                Bytes::from("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"),
                Bytes::from("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"),
            ),
            (
                Bytes::from("0x0000000000000000000000000000000000000000000000000000267d3cdc9cbf"),
                Bytes::from("0x00000000000000000000000000000000000000000000000000013ccb6410e36b"),
                Some(EntryPointWithTracingParams {
                    entry_point: EntryPoint {
                        external_id: "0xc88b618c2c670c2e2a42e06b466b6f0e82a6e8a8:getLimits(address,address)".to_string(),
                        target: Bytes::from("0xc88b618c2c670c2e2a42e06b466b6f0e82a6e8a8"),
                        signature: "getLimits(address,address)".to_string(),
                    },
                    params: tycho_common::models::blockchain::TracingParams::RPCTracer(
                        RPCTracerParams {
                            caller: None,
                            calldata: Bytes::from("0xaaed87a3000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"),
                            state_overrides: None,
                            prune_addresses: None,
                        },
                    ),
                }),
            )
        )]),));

        assert!(parsed_results.contains(&MetadataValue::Limits(vec![(
            (
                Bytes::from("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"),
                Bytes::from("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"),
            ),
            (
                Bytes::from("0x000000000000000000000000000000000000000000000ecaa543f127a7d92880"),
                Bytes::from("0x0000000000000000000000000000000000000000000000000000000030598d13"),
                Some(EntryPointWithTracingParams {
                    entry_point: EntryPoint {
                        external_id: "0xc88b618c2c670c2e2a42e06b466b6f0e82a6e8a8:getLimits(address,address)".to_string(),
                        target: Bytes::from("0xc88b618c2c670c2e2a42e06b466b6f0e82a6e8a8"),
                        signature: "getLimits(address,address)".to_string(),
                    },
                    params: tycho_common::models::blockchain::TracingParams::RPCTracer(
                        RPCTracerParams {
                            caller: None,
                            calldata: Bytes::from("0xaaed87a3000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"),
                            state_overrides: None,
                            prune_addresses: None,
                        },
                    ),
                }),
            )
        )]),));
    }
}
