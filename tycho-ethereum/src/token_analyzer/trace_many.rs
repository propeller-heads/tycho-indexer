use alloy::rpc::{
    client::ReqwestClient,
    types::{
        trace::parity::{TraceResults, TraceType},
        BlockNumberOrTag, TransactionRequest,
    },
};
use anyhow::{Context, Result};
use tycho_common::models::blockchain::BlockTag;

// Use the trace_callMany api https://openethereum.github.io/JSONRPC-trace-module#trace_callmany
// api to simulate these call requests applied together one after another.
// Err if communication with the node failed.
pub async fn trace_many(
    requests: Vec<TransactionRequest>,
    rpc: &ReqwestClient,
    block: BlockTag,
) -> Result<Vec<TraceResults>> {
    let block = match block {
        BlockTag::Finalized => BlockNumberOrTag::Finalized,
        BlockTag::Safe => BlockNumberOrTag::Safe,
        BlockTag::Latest => BlockNumberOrTag::Latest,
        BlockTag::Earliest => BlockNumberOrTag::Earliest,
        BlockTag::Pending => BlockNumberOrTag::Pending,
        BlockTag::Number(n) => BlockNumberOrTag::Number(n),
    };

    let trace_requests: Vec<(TransactionRequest, Vec<TraceType>)> = requests
        .into_iter()
        .map(|request| (request, vec![TraceType::Trace]))
        .collect();

    rpc.request("trace_callMany", (trace_requests, block))
        .await
        .context("Failed to send trace_callMany request")
}

// Check the return value of trace_many for whether all top level transactions
// succeeded (did not revert).
// Err if the response is missing trace data.
// Ok(true) if transactions simulate without reverting
// Ok(false) if transactions simulate with at least one revert.
pub fn all_calls_succeeded(traces: &[TraceResults]) -> Result<bool> {
    for trace in traces {
        let transaction_trace = &trace.trace;
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
        let response: Vec<TraceResults> = serde_json::from_value(json!(
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
        let response: Vec<TraceResults> = serde_json::from_value(json!(
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
