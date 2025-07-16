#![allow(unused_variables)] // TODO: Remove this once the provider is implemented
#![allow(dead_code)] // TODO: Remove this once the provider is implemented

use std::{collections::HashMap, sync::Arc};

use reqwest::Client;
use serde_json::{json, Value};
use tonic::async_trait;
use tracing::warn;

use crate::extractor::dynamic_contract_indexer::component_metadata::{
    DeduplicationId, MetadataError, RequestProvider, RequestTransport, RpcTransport,
};

pub struct RPCMetadataProvider {
    client: Arc<Client>,
    batch_size_limit: usize,
}

impl RPCMetadataProvider {
    pub fn new(batch_size_limit: usize) -> Self {
        Self { client: Arc::new(Client::new()), batch_size_limit }
    }
}

#[async_trait]
impl RequestProvider for RPCMetadataProvider {
    async fn execute_batch(
        &self,
        requests: &[Box<dyn RequestTransport>],
    ) -> Vec<(DeduplicationId, Result<Value, MetadataError>)> {
        let mut results: HashMap<DeduplicationId, Result<Value, MetadataError>> =
            HashMap::with_capacity(requests.len());

        let batches = self.group_requests(requests, self.batch_size_limit);

        for batch in batches {
            let mut rpc_requests = Vec::new();

            for request in batch {
                match request
                    .as_any()
                    .downcast_ref::<RpcTransport>()
                {
                    Some(rpc_transport) => rpc_requests.push(rpc_transport.clone()),
                    None => {
                        results.insert(
                            request.deduplication_id(),
                            Err(MetadataError::ProviderFailed(
                                "Invalid rpc request transport".into(),
                            )),
                        );
                    }
                }
            }

            if rpc_requests.is_empty() {
                continue;
            }

            let endpoint = rpc_requests[0].endpoint.clone();
            let all_same_endpoint = rpc_requests
                .iter()
                .all(|rpc| rpc.endpoint == endpoint);

            // If the requests are not all to the same endpoint, we can't batch them
            // and we need to insert errors for each request
            // TODO: if the final design still include endpoint inside RpcTransport, we need to
            // handle this case by splitting the requests into multiple batches and emit a warning.
            if !all_same_endpoint {
                for rpc in rpc_requests {
                    results.insert(
                        rpc.deduplication_id(),
                        Err(MetadataError::ProviderFailed("Invalid rpc request transport".into())),
                    );
                }
                continue;
            }

            let mut rpc_id_to_transport: HashMap<u64, RpcTransport> = HashMap::new();

            let batch_json: Vec<Value> = rpc_requests
                .into_iter()
                .map(|rpc| {
                    rpc_id_to_transport.insert(rpc.id, rpc.clone());

                    json!({
                        "jsonrpc": "2.0",
                        "method": rpc.method,
                        "params": rpc.params,
                        "id": rpc.id
                    })
                })
                .collect();

            let client = Client::new();
            let response = client
                .post(endpoint)
                .json(&batch_json)
                .send()
                .await;

            let response_json: Vec<Value> = match response {
                Ok(resp) => {
                    match resp.text().await {
                        Ok(text) => {
                            // Try to parse as array first (batch response)
                            match serde_json::from_str::<Vec<Value>>(&text) {
                                Ok(data) => data,
                                Err(_) => {
                                    // If array parsing fails, try parsing as single object
                                    match serde_json::from_str::<Value>(&text) {
                                        Ok(single_response) => vec![single_response],
                                        Err(e) => {
                                            // Handle JSON decode failure by inserting errors for
                                            // entire batch
                                            for rpc in rpc_id_to_transport.values() {
                                                results.insert(
                                                    rpc.deduplication_id(),
                                                    Err(MetadataError::ProviderFailed(format!(
                                                        "Failed to parse JSON response: {e}"
                                                    ))),
                                                );
                                            }
                                            continue;
                                        }
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            for rpc in rpc_id_to_transport.values() {
                                results.insert(
                                    rpc.deduplication_id(),
                                    Err(MetadataError::ProviderFailed(format!(
                                        "Failed to extract response text: {e}"
                                    ))),
                                );
                            }
                            continue;
                        }
                    }
                }
                Err(e) => {
                    // HTTP request failed: insert errors for entire batch
                    for rpc in rpc_id_to_transport.values() {
                        results.insert(
                            rpc.deduplication_id(),
                            Err(MetadataError::ProviderFailed(format!("HTTP request failed: {e}"))),
                        );
                    }
                    continue;
                }
            };

            for resp in response_json {
                let id = resp.get("id").and_then(|v| v.as_u64());
                match id {
                    Some(actual_id) => {
                        let result = if let Some(error) = resp.get("error") {
                            Err(MetadataError::ProviderFailed(format!("RPC error: {error}")))
                        } else if let Some(result_value) = resp.get("result") {
                            Ok(result_value.clone())
                        } else {
                            Err(MetadataError::ProviderFailed(
                                "RPC response missing `result` and `error`".into(),
                            ))
                        };

                        if let Some(rpc) = rpc_id_to_transport.get(&actual_id) {
                            results.insert(rpc.deduplication_id(), result);
                        } else {
                            warn!(?actual_id, "Received unknown \"id\" in batch RPC response");
                        }
                    }
                    None => {
                        warn!(?resp, "Missing \"id\" in a batch RPCresponse");
                    }
                }
            }
        }

        results.into_iter().collect()
    }

    /// Group requests into batches of at most the `batch_size_limit`
    fn group_requests(
        &self,
        requests: &[Box<dyn RequestTransport>],
        batch_size_limit: usize,
    ) -> Vec<Vec<Box<dyn RequestTransport>>> {
        let mut grouped_batches = Vec::new();
        let mut current_batch = Vec::new();

        for request in requests {
            current_batch.push(request.clone_box());

            if current_batch.len() >= batch_size_limit {
                grouped_batches.push(std::mem::take(&mut current_batch));
            }
        }

        if !current_batch.is_empty() {
            grouped_batches.push(current_batch);
        }

        grouped_batches
    }
}

#[cfg(test)]
mod tests {
    use mockito::{Matcher, Server};

    use super::*;

    #[tokio::test]
    #[ignore = "Requires a real RPC endpoint"]
    async fn test_execute_batch() {
        let provider = RPCMetadataProvider::new(10);
        let endpoint = std::env::var("RPC_URL").expect("RPC_URL must be set");

        let req_map = HashMap::from([
            (
                "eth_blockNumber".to_string(),
                RpcTransport::new(endpoint.clone(), "eth_blockNumber".to_string(), vec![]),
            ),
            (
                "eth_gasPrice".to_string(),
                RpcTransport::new(endpoint.clone(), "eth_gasPrice".to_string(), vec![]),
            ),
            (
                "eth_hashrate".to_string(),
                RpcTransport::new(endpoint.clone(), "eth_hashrate".to_string(), vec![]),
            ),
            (
                "eth_getBalance".to_string(),
                RpcTransport::new(
                    endpoint.clone(),
                    "eth_getBalance".to_string(),
                    vec![json!("0x000000000000000000000000000000000000dEaD"), json!("latest")],
                ),
            ),
            (
                "eth_call".to_string(),
                RpcTransport::new(
                    endpoint.clone(),
                    "eth_call".to_string(),
                    vec![
                        json!({
                            "to": "0xB4e16d0168e52d35CaCD2c6185b44281Ec28C9Dc",
                            "data": "0x0902f1ac"
                        }),
                        json!("latest"),
                    ],
                ),
            ),
        ]);

        let requests = req_map
            .clone()
            .into_values()
            .map(|r| Box::new(r) as Box<dyn RequestTransport>)
            .collect::<Vec<_>>();

        let results = provider.execute_batch(&requests).await;

        // Assertions
        let results_map: std::collections::HashMap<_, _> = results.into_iter().collect();

        let block_number = results_map
            .get("eth_blockNumber_[]")
            .expect("eth_blockNumber missing");
        assert!(block_number.is_ok(), "eth_blockNumber failed");

        let gas_price = results_map
            .get("eth_gasPrice_[]")
            .expect("eth_gasPrice missing");
        assert!(gas_price.is_ok(), "eth_gasPrice failed");

        let hashrate = results_map
            .get("eth_hashrate_[]")
            .expect("eth_hashrate missing");
        assert_eq!(
            hashrate,
            &Err(MetadataError::ProviderFailed(
                "RPC error: {\"code\":-32601,\"message\":\"the method eth_hashrate does not exist/is not available\"}".into(),
            ))
        );

        let balance_result = results_map
            .get(
                &req_map
                    .get("eth_getBalance")
                    .unwrap()
                    .deduplication_id(),
            )
            .expect("eth_getBalance missing");
        assert!(balance_result.is_ok(), "eth_getBalance failed");

        let call_result = results_map
            .get(
                &req_map
                    .get("eth_call")
                    .unwrap()
                    .deduplication_id(),
            )
            .expect("eth_call missing");
        assert!(call_result.is_ok(), "eth_call failed");
    }

    #[tokio::test]
    async fn test_execute_batch_with_mock_batch_size_1() {
        let provider = RPCMetadataProvider::new(1);
        let mut server = Server::new_async().await;
        let endpoint = server.url();

        let req_map: HashMap<String, RpcTransport> = HashMap::from([
            (
                "eth_blockNumber".to_string(),
                RpcTransport::new(endpoint.to_string(), "eth_blockNumber".to_string(), vec![]),
            ),
            (
                "eth_getBalance".to_string(),
                RpcTransport::new(
                    endpoint.to_string(),
                    "eth_getBalance".to_string(),
                    vec![json!("0x000000000000000000000000000000000000dEaD"), json!("latest")],
                ),
            ),
            (
                "eth_call".to_string(),
                RpcTransport::new(
                    endpoint.to_string(),
                    "eth_call".to_string(),
                    vec![
                        json!({
                            "to": "0xB4e16d0168e52d35CaCD2c6185b44281Ec28C9Dc",
                            "data": "0x0902f1ac"
                        }),
                        json!("latest"),
                    ],
                ),
            ),
            (
                "eth_hashrate".to_string(),
                RpcTransport::new(endpoint.to_string(), "eth_hashrate".to_string(), vec![]),
            ),
            (
                "eth_gasPrice".to_string(),
                RpcTransport::new(endpoint.to_string(), "eth_gasPrice".to_string(), vec![]),
            ),
        ]);

        // Map ids from transports so we mimic real id values
        let mut responses = vec![];
        for transport in req_map.values() {
            let method = &transport.method;
            let id = transport.id;

            let resp = match method.as_str() {
                "eth_blockNumber" => json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": "0x15dac9b"
                }),
                "eth_getBalance" => json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": "0x2aca55e768e35fed455"
                }),
                "eth_call" => json!({
                                "jsonrpc": "2.0",
                                "id": id,
                                "result":
                "0x00000000000000000000000000000000000000000000000000000b63a126babc0000000000000000000000000000000000000000000000dfc818ada67f7a256b000000000000000000000000000000000000000000000000000000006874c0d3"
                            }),
                "eth_hashrate" => json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": {
                        "code": -32601,
                        "message": "the method eth_hashrate does not exist/is not available"
                    }
                }),
                "eth_gasPrice" => json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": "0x7a67f1da"
                }),
                _ => panic!("unexpected method"),
            };

            responses.push((method, resp));
        }

        let mut all_mocks = vec![];
        for (method, resp) in responses {
            let mock = server
                .mock("POST", "/")
                .match_body(Matcher::Regex(format!(r#""method"\s*:\s*"{method}""#)))
                .with_body(resp.to_string())
                .expect(1)
                .create_async()
                .await;
            all_mocks.push(mock);
        }

        let request_list: Vec<Box<dyn RequestTransport>> = req_map
            .values()
            .map(|t| Box::new(t.clone()) as Box<dyn RequestTransport>)
            .collect();

        let results = provider
            .execute_batch(&request_list)
            .await;

        // Assertions

        for mock in all_mocks {
            mock.assert();
        }

        let results_map: HashMap<_, _> = results.into_iter().collect();

        let block_number = results_map
            .get("eth_blockNumber_[]")
            .expect("eth_blockNumber missing");
        assert!(block_number.is_ok(), "eth_blockNumber failed");

        let gas_price = results_map
            .get("eth_gasPrice_[]")
            .expect("eth_gasPrice missing");
        assert!(gas_price.is_ok(), "eth_gasPrice failed");

        let hashrate = results_map
            .get("eth_hashrate_[]")
            .expect("eth_hashrate missing");
        assert_eq!(
            hashrate,
            &Err(MetadataError::ProviderFailed(
                "RPC error: {\"code\":-32601,\"message\":\"the method eth_hashrate does not exist/is not available\"}".into(),
            ))
        );

        let balance_result = results_map
            .get(
                &req_map
                    .get("eth_getBalance")
                    .unwrap()
                    .deduplication_id(),
            )
            .expect("eth_getBalance missing");
        assert!(balance_result.is_ok(), "eth_getBalance failed");

        let call_result = results_map
            .get(
                &req_map
                    .get("eth_call")
                    .unwrap()
                    .deduplication_id(),
            )
            .expect("eth_call missing");
        assert!(call_result.is_ok(), "eth_call failed");
    }

    #[tokio::test]
    async fn test_execute_batch_with_mock_batch_size_3() {
        let provider = RPCMetadataProvider::new(3);
        let mut server = Server::new_async().await;
        let endpoint = server.url();

        let req_map: HashMap<String, RpcTransport> = HashMap::from([
            (
                "eth_blockNumber".to_string(),
                RpcTransport::new(endpoint.to_string(), "eth_blockNumber".to_string(), vec![]),
            ),
            (
                "eth_getBalance".to_string(),
                RpcTransport::new(
                    endpoint.to_string(),
                    "eth_getBalance".to_string(),
                    vec![json!("0x000000000000000000000000000000000000dEaD"), json!("latest")],
                ),
            ),
            (
                "eth_call".to_string(),
                RpcTransport::new(
                    endpoint.to_string(),
                    "eth_call".to_string(),
                    vec![
                        json!({
                            "to": "0xB4e16d0168e52d35CaCD2c6185b44281Ec28C9Dc",
                            "data": "0x0902f1ac"
                        }),
                        json!("latest"),
                    ],
                ),
            ),
            (
                "eth_hashrate".to_string(),
                RpcTransport::new(endpoint.to_string(), "eth_hashrate".to_string(), vec![]),
            ),
            (
                "eth_gasPrice".to_string(),
                RpcTransport::new(endpoint.to_string(), "eth_gasPrice".to_string(), vec![]),
            ),
        ]);

        // Batch 1: eth_blockNumber, eth_call, eth_gasPrice (3 requests)
        let batch1_responses = vec![
            json!({
                "jsonrpc": "2.0",
                "id": req_map["eth_blockNumber"].id,
                "result": "0x15dac9b"
            }),
            json!({
                "jsonrpc": "2.0",
                "id": req_map["eth_call"].id,
                "result": "0x00000000000000000000000000000000000000000000000000000b63a126babc0000000000000000000000000000000000000000000000dfc818ada67f7a256b000000000000000000000000000000000000000000000000000000006874c0d3"
            }),
            json!({
                "jsonrpc": "2.0",
                "id": req_map["eth_gasPrice"].id,
                "result": "0x7a67f1da"
            }),
        ];

        // Batch 2: eth_hashrate, eth_getBalance (2 requests)
        let batch2_responses = vec![
            json!({
                "jsonrpc": "2.0",
                "id": req_map["eth_hashrate"].id,
                "error": {
                    "code": -32601,
                    "message": "the method eth_hashrate does not exist/is not available"
                }
            }),
            json!({
                "jsonrpc": "2.0",
                "id": req_map["eth_getBalance"].id,
                "result": "0x2aca55e768e35fed455"
            }),
        ];

        let mock1 = server
            .mock("POST", "/")
            .match_body(Matcher::Regex((r#""method"\s*:\s*"eth_blockNumber""#).to_string()))
            .match_body(Matcher::Regex((r#""method"\s*:\s*"eth_call""#).to_string()))
            .match_body(Matcher::Regex((r#""method"\s*:\s*"eth_gasPrice""#).to_string()))
            .with_body(serde_json::to_string(&batch1_responses).unwrap())
            .expect(1)
            .create_async()
            .await;

        let mock2 = server
            .mock("POST", "/")
            .match_body(Matcher::Regex((r#""method"\s*:\s*"eth_getBalance""#).to_string()))
            .match_body(Matcher::Regex((r#""method"\s*:\s*"eth_hashrate""#).to_string()))
            .with_body(serde_json::to_string(&batch2_responses).unwrap())
            .expect(1)
            .create_async()
            .await;

        let mut request_list: Vec<Box<dyn RequestTransport>> = req_map
            .values()
            .map(|t| Box::new(t.clone()) as Box<dyn RequestTransport>)
            .collect();

        // Need to sort the requests by deduplication id to ensure the order of the requests is
        // consistent. This is because we mock the batch requests in a certain order, and we need
        // to ensure the requests are given in the same order.
        request_list.sort_by_key(|r| r.deduplication_id());

        let results = provider
            .execute_batch(&request_list)
            .await;

        // Assertions
        mock1.assert();
        mock2.assert();

        let results_map: HashMap<_, _> = results.into_iter().collect();

        let block_number = results_map
            .get("eth_blockNumber_[]")
            .expect("eth_blockNumber missing");
        assert!(block_number.is_ok(), "eth_blockNumber failed");

        let gas_price = results_map
            .get("eth_gasPrice_[]")
            .expect("eth_gasPrice missing");
        assert!(gas_price.is_ok(), "eth_gasPrice failed");

        let hashrate = results_map
            .get("eth_hashrate_[]")
            .expect("eth_hashrate missing");
        assert_eq!(
            hashrate,
            &Err(MetadataError::ProviderFailed(
                "RPC error: {\"code\":-32601,\"message\":\"the method eth_hashrate does not exist/is not available\"}".into(),
            ))
        );

        let balance_result = results_map
            .get(
                &req_map
                    .get("eth_getBalance")
                    .unwrap()
                    .deduplication_id(),
            )
            .expect("eth_getBalance missing");
        assert!(balance_result.is_ok(), "eth_getBalance failed");

        let call_result = results_map
            .get(
                &req_map
                    .get("eth_call")
                    .unwrap()
                    .deduplication_id(),
            )
            .expect("eth_call missing");
        assert!(call_result.is_ok(), "eth_call failed");
    }

    #[test]
    fn test_group_requests() {
        let provider = RPCMetadataProvider::new(3);

        let requests: Vec<Box<dyn RequestTransport>> = vec![
            Box::new(RpcTransport::new(
                "http://localhost:8545".to_string(),
                "eth_blockNumber".to_string(),
                vec![],
            )),
            Box::new(RpcTransport::new(
                "http://localhost:8545".to_string(),
                "eth_gasPrice".to_string(),
                vec![],
            )),
            Box::new(RpcTransport::new(
                "http://localhost:8545".to_string(),
                "eth_getBalance".to_string(),
                vec![json!("0x123"), json!("latest")],
            )),
            Box::new(RpcTransport::new(
                "http://localhost:8545".to_string(),
                "eth_call".to_string(),
                vec![json!({"to": "0x456", "data": "0x789"}), json!("latest")],
            )),
            Box::new(RpcTransport::new(
                "http://localhost:8545".to_string(),
                "eth_chainId".to_string(),
                vec![],
            )),
        ];

        let batches = provider.group_requests(&requests, 3);

        assert_eq!(batches.len(), 2, "Should create 2 batches for 5 requests with batch size 3");
        assert_eq!(batches[0].len(), 3, "First batch should have 3 requests");
        assert_eq!(batches[1].len(), 2, "Second batch should have 2 requests");
    }
}
