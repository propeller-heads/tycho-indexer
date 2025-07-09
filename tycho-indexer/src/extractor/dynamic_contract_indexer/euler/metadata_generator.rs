use tycho_common::models::{blockchain::Block, protocol::ProtocolComponent};

use crate::extractor::dynamic_contract_indexer::component_metadata::{
    MetadataError, MetadataRequest, MetadataRequestGenerator, MetadataRequestType, RpcTransport,
};

pub struct EulerMetadataGenerator {
    rpc_url: String,
}

impl EulerMetadataGenerator {
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

        let limits_transport_0to1 = RpcTransport::new(
            self.rpc_url.clone(),
            "eth_call".to_string(),
            vec![serde_json::json!([
              {
                "data": format!("0xaaed87a3000000000000000000000000{}000000000000000000000000{}", component.tokens[0], component.tokens[1]),
                "to": component.id
              },
              format!("0x{:x}", block.number)
            ])],
        );
        requests.push(MetadataRequest::new(
            format!(
                "euler_limits_{}_{}_to_{}",
                component.id, component.tokens[0], component.tokens[1]
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
            vec![serde_json::json!([
              {
                "data": format!("0xaaed87a3000000000000000000000000{}000000000000000000000000{}", component.tokens[1], component.tokens[0]),
                "to": component.id
              },
              format!("0x{:x}", block.number)
            ])],
        );
        requests.push(MetadataRequest::new(
            format!(
                "euler_limits_{}_{}_to_{}",
                component.id, component.tokens[1], component.tokens[0]
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

        let balance_transport = RpcTransport::new(
            self.rpc_url.clone(),
            "eth_call".to_string(),
            vec![serde_json::json!([
                  {
                    "data": "0x0902f1ac", // getReserves()
                    "to": component.id
                  },
                  format!("0x{:x}", block.number)
                ]
            )],
        );
        requests.push(MetadataRequest::new(
            format!("euler_balance_{}", component.id),
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

#[cfg(test)]
mod tests {
    use chrono::NaiveDateTime;
    use tycho_common::{models::Chain, Bytes};

    use super::*;

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
            "eth_call_[[{\"data\":\"0x0902f1ac\",\"to\":\"0xbeef\"},\"0x3039\"]]".to_string()
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
            "eth_call_[[{\"data\":\"0xaaed87a30000000000000000000000000xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb480000000000000000000000000xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2\",\"to\":\"0xbeef\"},\"0x3039\"]]".to_string()
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
            "eth_call_[[{\"data\":\"0xaaed87a30000000000000000000000000xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc20000000000000000000000000xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48\",\"to\":\"0xbeef\"},\"0x3039\"]]".to_string()
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
            "eth_call_[[{\"data\":\"0x0902f1ac\",\"to\":\"0xbeef\"},\"0x3039\"]]".to_string()
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

    //TODO: add RPC execution tests when the orchestrator logic is implemented
}
