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
    use tycho_common::{
        models::Chain,
        Bytes,
    };

    use super::*;

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
}
