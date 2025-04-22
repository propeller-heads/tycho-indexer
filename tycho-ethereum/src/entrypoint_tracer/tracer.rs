use std::{collections::HashSet, str::FromStr};

use async_trait::async_trait;
use ethcontract::{H160, H256};
use ethers::{
    prelude::Middleware,
    providers::{Http, Provider},
    types::{
        Address as EthersAddress, BlockId, Bytes as EthersBytes, CallFrame,
        GethDebugBuiltInTracerType, GethDebugTracerType, GethDebugTracingCallOptions,
        GethDebugTracingOptions, GethTrace, GethTraceFrame, NameOrAddress, PreStateFrame,
        PreStateMode, TransactionRequest,
    },
};
use thiserror::Error;
use tycho_common::{
    keccak256,
    models::{
        blockchain::{EntryPointTracingData, EntryPointWithData, TracedEntryPoint, TracingResult},
        Address, BlockHash,
    },
    traits::EntryPointTracer,
    Bytes,
};

use crate::{BytesCodec, RPCError};

struct EVMEntrypointService {
    provider: Provider<Http>,
}

impl EVMEntrypointService {
    pub fn new_from_url(rpc_url: &str) -> Self {
        Self {
            provider: Provider::<Http>::try_from(rpc_url).expect("Error creating HTTP provider"),
        }
    }

    async fn trace_call(
        &self,
        target: &Address,
        caller: &Address,
        data: &Bytes,
        block_hash: &BlockHash,
        tracer_type: GethDebugBuiltInTracerType,
    ) -> Result<GethTrace, RPCError> {
        self.provider
            .debug_trace_call(
                TransactionRequest {
                    to: Some(NameOrAddress::Address(H160::from_bytes(target))),
                    from: Some(H160::from_bytes(caller)),
                    data: Some(EthersBytes::from(data.to_vec())),
                    ..Default::default()
                },
                Some(BlockId::Hash(H256::from_bytes(block_hash))),
                GethDebugTracingCallOptions {
                    tracing_options: GethDebugTracingOptions {
                        tracer: Some(GethDebugTracerType::BuiltInTracer(tracer_type)),
                        ..Default::default()
                    },
                    ..Default::default()
                },
            )
            .await
            .map_err(RPCError::RequestError)
    }
}

#[async_trait]
impl EntryPointTracer for EVMEntrypointService {
    type Error = RPCError;

    async fn trace(
        &self,
        block_hash: BlockHash,
        entry_points: Vec<EntryPointWithData>,
    ) -> Result<Vec<TracedEntryPoint>, Self::Error> {
        let mut results = Vec::new();
        for entry_point in &entry_points {
            match &entry_point.data {
                EntryPointTracingData::RPCTracer(ref rpc_entry_point) => {
                    let call_trace = self
                        .trace_call(
                            &entry_point.entry_point.target,
                            rpc_entry_point
                                .caller
                                .as_ref()
                                .unwrap_or(&EthersAddress::zero().to_bytes()),
                            &rpc_entry_point.data,
                            &block_hash,
                            GethDebugBuiltInTracerType::CallTracer,
                        )
                        .await?;

                    let called_addresses =
                        if let GethTrace::Known(GethTraceFrame::CallTracer(frame)) = call_trace {
                            flatten_calls(&frame)
                        } else {
                            return Err(RPCError::UnknownError("CallTracer failed".to_string()));
                        };

                    let pre_state_trace = self
                        .trace_call(
                            &entry_point.entry_point.target,
                            rpc_entry_point
                                .caller
                                .as_ref()
                                .unwrap_or(&EthersAddress::zero().to_bytes()),
                            &rpc_entry_point.data,
                            &block_hash,
                            GethDebugBuiltInTracerType::PreStateTracer,
                        )
                        .await?;

                    // Provides a very simplistic way of finding retriggers. A better way would
                    // involve using the structure of callframes. So basically iterate the call
                    // tree in a parent child manner then search the
                    // childs address in the prestate of parent.
                    let retriggers = if let GethTrace::Known(GethTraceFrame::PreStateTracer(
                        PreStateFrame::Default(PreStateMode(frame)),
                    )) = pre_state_trace
                    {
                        let mut retriggers = HashSet::new();
                        for (address, account) in frame.iter() {
                            if let Some(storage) = &account.storage {
                                for (slot, val) in storage.iter() {
                                    for call_address in called_addresses.iter() {
                                        let address_bytes = call_address.as_bytes();
                                        let value_bytes = val.as_bytes();
                                        if value_bytes
                                            .windows(address_bytes.len())
                                            .any(|window| window == address_bytes)
                                        {
                                            retriggers.insert((
                                                (*address).to_bytes(),
                                                (*slot).to_bytes(),
                                            ));
                                        }
                                    }
                                }
                            }
                        }
                        retriggers
                    } else {
                        return Err(RPCError::UnknownError("PreStateTracer failed".to_string()));
                    };
                    results.push(TracedEntryPoint::new(
                        entry_point.clone(),
                        block_hash.clone(),
                        TracingResult::new(
                            retriggers,
                            called_addresses
                                .into_iter()
                                .map(BytesCodec::to_bytes)
                                .collect(),
                        ),
                    ));
                }
            }
        }
        Ok(results)
    }
}

fn flatten_calls(call: &CallFrame) -> Vec<EthersAddress> {
    let to = if let Some(NameOrAddress::Address(a)) = &call.to { *a } else { return vec![] };
    let mut flat_calls = vec![to];
    if let Some(sub_calls) = &call.calls {
        for sub_call in sub_calls {
            flat_calls.extend(flatten_calls(sub_call));
        }
    }
    flat_calls
}

#[cfg(test)]
mod tests {
    use std::env;

    use tycho_common::{
        models::blockchain::{EntryPoint, RPCTracerEntryPoint},
        Bytes,
    };

    use super::*;

    #[tokio::test]
    #[ignore = "requires a RPC connection"]
    async fn test_trace_balancer_v3_stable_pool() {
        let url = env::var("RPC_URL").expect("RPC_URL is not set");
        let tracer = EVMEntrypointService::new_from_url(&url);
        let entry_points = vec![
            EntryPointWithData::new(
                EntryPoint::new(
                    Bytes::from_str("0xEdf63cce4bA70cbE74064b7687882E71ebB0e988").unwrap(),
                    "getRate()".to_string(),
                ),
                EntryPointTracingData::RPCTracer(RPCTracerEntryPoint::new(
                    None,
                    Bytes::from(keccak256("getRate()")),
                )),
            ),
            EntryPointWithData::new(
                EntryPoint::new(
                    Bytes::from_str("0x8f4E8439b970363648421C692dd897Fb9c0Bd1D9").unwrap(),
                    "getRate()".to_string(),
                ),
                EntryPointTracingData::RPCTracer(RPCTracerEntryPoint::new(
                    None,
                    Bytes::from(keccak256("getRate()")),
                )),
            ),
        ];
        let traced_entry_points = tracer
            .trace(
                Bytes::from_str(
                    "0x354c90a0a98912aff15b044bdff6ce3d4ace63a6fc5ac006ce53c8737d425ab2",
                )
                .unwrap(),
                entry_points.clone(),
            )
            .await
            .unwrap();

        assert_eq!(
            traced_entry_points,
            vec![
                TracedEntryPoint {
                    entry_point: entry_points[0].clone(),
                    detection_block_hash: Bytes::from_str("0x354c90a0a98912aff15b044bdff6ce3d4ace63a6fc5ac006ce53c8737d425ab2").unwrap(),
                    tracing_result: TracingResult::new(
                        HashSet::from([
                            (
                                Bytes::from_str("0x7bc3485026ac48b6cf9baf0a377477fff5703af8").unwrap(),
                            Bytes::from_str("0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc").unwrap(),
                        ),
                        (
                            Bytes::from_str("0x87870bca3f3fd6335c3f4ce8392d69350b4fa4e2").unwrap(),
                            Bytes::from_str("0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc").unwrap(),
                        ),
                    ]),
                    HashSet::from([
                        Bytes::from_str("0xef434e4573b90b6ecd4a00f4888381e4d0cc5ccd").unwrap(),
                        Bytes::from_str("0x487c2c53c0866f0a73ae317bd1a28f63adcd9ad1").unwrap(),
                        Bytes::from_str("0x87870bca3f3fd6335c3f4ce8392d69350b4fa4e2").unwrap(),
                        Bytes::from_str("0xedf63cce4ba70cbe74064b7687882e71ebb0e988").unwrap(),
                        Bytes::from_str("0x7bc3485026ac48b6cf9baf0a377477fff5703af8").unwrap(),
                        ]),
                    ),
                },
                TracedEntryPoint {
                    entry_point: entry_points[1].clone(),
                    detection_block_hash: Bytes::from_str("0x354c90a0a98912aff15b044bdff6ce3d4ace63a6fc5ac006ce53c8737d425ab2").unwrap(),
                    tracing_result: TracingResult::new(
                        HashSet::from([
                            (
                            Bytes::from_str("0xd4fa2d31b7968e448877f69a96de69f5de8cd23e").unwrap(),
                            Bytes::from_str("0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc").unwrap(),
                        ),
                        (
                            Bytes::from_str("0x87870bca3f3fd6335c3f4ce8392d69350b4fa4e2").unwrap(),
                            Bytes::from_str("0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc").unwrap(),
                        ),
                    ]),
                    HashSet::from([
                        Bytes::from_str("0x8f4e8439b970363648421c692dd897fb9c0bd1d9").unwrap(),
                        Bytes::from_str("0x487c2c53c0866f0a73ae317bd1a28f63adcd9ad1").unwrap(),
                        Bytes::from_str("0xd4fa2d31b7968e448877f69a96de69f5de8cd23e").unwrap(),
                        Bytes::from_str("0x87870bca3f3fd6335c3f4ce8392d69350b4fa4e2").unwrap(),
                        Bytes::from_str("0xef434e4573b90b6ecd4a00f4888381e4d0cc5ccd").unwrap(),
                    ]),
                ),
            },
            ]
        );
    }
}
