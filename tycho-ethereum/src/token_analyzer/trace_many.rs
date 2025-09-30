use anyhow::{Context, Result};
use reqwest::Client as HttpClient;
use web3::types::{BlockNumber, BlockTrace, CallRequest, TraceType};

// Use the trace_callMany api https://openethereum.github.io/JSONRPC-trace-module#trace_callmany
// api to simulate these call requests applied together one after another.
// Err if communication with the node failed.
pub async fn trace_many(
    requests: Vec<CallRequest>,
    rpc_url: &str,
    block: BlockNumber,
) -> Result<Vec<BlockTrace>> {
    let client = HttpClient::new();
    let requests = requests
        .into_iter()
        .map(|request| {
            Ok(vec![serde_json::to_value(request)?, serde_json::to_value(vec![TraceType::Trace])?])
        })
        .collect::<Result<Vec<_>>>()?;
    let params = vec![serde_json::to_value(requests)?, serde_json::to_value(block)?];

    let rpc_request = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "trace_callMany",
        "params": params,
        "id": 1
    });

    let response = client
        .post(rpc_url)
        .json(&rpc_request)
        .send()
        .await
        .context("Failed to send trace_callMany request")?;

    let json_response: serde_json::Value = response
        .json()
        .await
        .context("Failed to parse response as JSON")?;

    if let Some(error) = json_response.get("error") {
        return Err(anyhow::anyhow!("RPC error: {}", error));
    }

    let result = json_response
        .get("result")
        .context("No result in response")?;

    serde_json::from_value(result.clone()).context("failed to decode trace_callMany response")
}

// Check the return value of trace_many for whether all top level transactions
// succeeded (did not revert).
// Err if the response is missing trace data.
// Ok(true) if transactions simulate without reverting
// Ok(false) if transactions simulate with at least one revert.
pub fn all_calls_succeeded(traces: &[BlockTrace]) -> Result<bool> {
    for trace in traces {
        let transaction_trace = trace
            .trace
            .as_ref()
            .context("trace not set")?;
        let first = transaction_trace
            .first()
            .context("expected at least one trace")?;
        if first.error.is_some() {
            return Ok(false);
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn ok_true() {
        let response: Vec<BlockTrace> = serde_json::from_value(json!(
        [{
            "output": "0x",
            "trace": [{
              "traceAddress": [],
              "subtraces": 0,
              "action": {
                "callType": "call",
                "from": "0x0000000000000000000000000000000000000000",
                "gas": "0x00",
                "input": "0x",
                "to": "0x0000000000000000000000000000000000000000",
                "value": "0x00"
              },
              "type": "call"
            }],
          }]))
        .unwrap();
        let result = all_calls_succeeded(&response);
        assert!(result.unwrap());
    }

    #[test]
    fn ok_false() {
        let response: Vec<BlockTrace> = serde_json::from_value(json!(
        [{
            "output": "0x",
            "trace": [{
              "traceAddress": [],
              "subtraces": 0,
              "action": {
                "callType": "call",
                "from": "0x0000000000000000000000000000000000000000",
                "gas": "0x00",
                "input": "0x",
                "to": "0x0000000000000000000000000000000000000000",
                "value": "0x00"
              },
              "type": "call",
              "error": "Reverted"
            }],
          }]))
        .unwrap();

        let result = all_calls_succeeded(&response);
        assert!(!result.unwrap());
    }
}
