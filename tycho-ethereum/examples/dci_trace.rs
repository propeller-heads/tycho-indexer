use ethers::{
    prelude::{
        Address, BlockId, Bytes, CallFrame, GethDebugBuiltInTracerType, GethDebugTracerType,
        GethDebugTracingCallOptions, GethDebugTracingOptions, Http, Middleware, PreStateFrame,
        PreStateMode, Provider, TransactionRequest, H256,
    },
    types::{GethTrace, GethTraceFrame, NameOrAddress},
    utils::keccak256,
};
use primitive_types::H160;
use std::{collections::HashSet, str::FromStr};

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let rpc = std::env::var("RPC_URL").expect("RPC URL must be set for testing");
    let provider = Provider::<Http>::try_from(rpc)?;

    let blockhash = "0xb721da20d635d58ba0230cc8beabd4cc9081475d90f28e5dd04a14a2de9d4eb6";
    let address = "0x72D07D7DcA67b8A406aD1Ec34ce969c90bFEE768";
    let calldata = keccak256("getRate()".as_bytes());

    let call_trace = provider
        .debug_trace_call(
            TransactionRequest {
                to: Some(NameOrAddress::Address(H160::from_str(address)?)),
                data: Some(Bytes::from(calldata)),
                ..Default::default()
            },
            Some(BlockId::Hash(H256::from_str(blockhash)?)),
            GethDebugTracingCallOptions {
                tracing_options: GethDebugTracingOptions {
                    tracer: Some(GethDebugTracerType::BuiltInTracer(
                        GethDebugBuiltInTracerType::CallTracer,
                    )),
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .await?;

    let called_addresses = if let GethTrace::Known(GethTraceFrame::CallTracer(frame)) = call_trace {
        flatten_calls(&frame)
    } else {
        panic!("CallTracer failed")
    };

    let prestate_trace = provider
        .debug_trace_call(
            TransactionRequest {
                to: Some(NameOrAddress::Address(H160::from_str(address)?)),
                data: Some(Bytes::from(calldata)),
                ..Default::default()
            },
            Some(BlockId::Hash(H256::from_str(blockhash)?)),
            GethDebugTracingCallOptions {
                tracing_options: GethDebugTracingOptions {
                    tracer: Some(GethDebugTracerType::BuiltInTracer(
                        GethDebugBuiltInTracerType::PreStateTracer,
                    )),
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .await?;
    dbg!(&prestate_trace);

    // Provides a very simplistic way of finding retriggers. A better way would
    // involve using the structure of callframes. So basically iterate the call tree
    // in a parent child manner then search the childs address in the prestate of parent.
    let retriggers = if let GethTrace::Known(GethTraceFrame::PreStateTracer(
        PreStateFrame::Default(PreStateMode(frame)),
    )) = prestate_trace
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
                            retriggers.insert((address.clone(), slot.clone()));
                        }
                    }
                }
            }
        }
        retriggers
    } else {
        panic!("PreStateTracer failed")
    };

    println!("called addresses: {:?}", called_addresses);
    println!("retriggers: {:?}", retriggers);

    Ok(())
}

fn flatten_calls(call: &CallFrame) -> Vec<Address> {
    let to = if let Some(NameOrAddress::Address(a)) = &call.to { a.clone() } else { return vec![] };
    let mut flat_calls = vec![to];
    if let Some(sub_calls) = &call.calls {
        for sub_call in sub_calls {
            flat_calls.extend(flatten_calls(sub_call));
        }
    }
    flat_calls
}
