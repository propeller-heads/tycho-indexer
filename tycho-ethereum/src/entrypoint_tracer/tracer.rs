use std::{
    collections::{BTreeMap, HashMap, HashSet},
    str::FromStr,
};

use async_trait::async_trait;
use ethcontract::{H160, H256};
use ethers::{
    prelude::{spoof, Middleware},
    providers::{Http, Provider},
    types::{
        Address as EthersAddress, BlockId, Bytes as EthersBytes, CallFrame,
        GethDebugBuiltInTracerType, GethDebugTracerType, GethDebugTracingCallOptions,
        GethDebugTracingOptions, GethTrace, GethTraceFrame, NameOrAddress, PreStateFrame,
        PreStateMode, TransactionRequest, U256,
    },
};
use tracing::warn;
use tycho_common::{
    keccak256,
    models::{
        blockchain::{
            EntryPointWithTracingParams, RPCTracerParams, StorageOverride, TracedEntryPoint,
            TracingParams, TracingResult,
        },
        Address, BlockHash,
    },
    traits::EntryPointTracer,
    Bytes,
};

use crate::{BytesCodec, RPCError};

pub struct EVMEntrypointService {
    provider: Provider<Http>,
}

impl EVMEntrypointService {
    pub fn try_from_url(rpc_url: &str) -> Result<Self, RPCError> {
        Ok(Self {
            provider: Provider::<Http>::try_from(rpc_url)
                .map_err(|e| RPCError::SetupError(e.to_string()))?,
        })
    }

    async fn trace_call(
        &self,
        target: &Address,
        params: &RPCTracerParams,
        block_hash: &BlockHash,
        tracer_type: GethDebugBuiltInTracerType,
    ) -> Result<GethTrace, RPCError> {
        let caller = params
            .caller
            .as_ref()
            .map(H160::from_bytes);
        self.provider
            .debug_trace_call(
                TransactionRequest {
                    to: Some(NameOrAddress::Address(H160::from_bytes(target))),
                    from: caller,
                    data: Some(EthersBytes::from(params.calldata.to_vec())),
                    ..Default::default()
                },
                Some(BlockId::Hash(H256::from_bytes(block_hash))),
                GethDebugTracingCallOptions {
                    tracing_options: GethDebugTracingOptions {
                        tracer: Some(GethDebugTracerType::BuiltInTracer(tracer_type)),
                        ..Default::default()
                    },
                    state_overrides: params
                        .state_overrides
                        .as_ref()
                        .map(|s| {
                            let mut state = spoof::state();
                            s.iter()
                                .for_each(|(address, overrides)| {
                                    let account = state.account(H160::from_slice(address.as_ref()));
                                    account.storage = match overrides.slots.as_ref() {
                                        Some(StorageOverride::Diff(slots)) => {
                                            Some(spoof::Storage::Diff(convert_storage(slots)))
                                        }
                                        Some(StorageOverride::Replace(slots)) => {
                                            Some(spoof::Storage::Replace(convert_storage(slots)))
                                        }
                                        _ => None,
                                    };
                                    account.balance = overrides
                                        .native_balance
                                        .as_ref()
                                        .map(|b| U256::from_big_endian(b.as_ref()));
                                    account.code = overrides
                                        .code
                                        .as_ref()
                                        .map(|c| ethers::types::Bytes::from(c.to_vec()));
                                });
                            state
                        }),
                    ..Default::default()
                },
            )
            .await
            .map_err(RPCError::RequestError)
    }
}

fn convert_storage(slots: &BTreeMap<Bytes, Bytes>) -> HashMap<H256, H256> {
    slots
        .iter()
        .map(|(k, v)| (H256::from_slice(k.as_ref()), H256::from_slice(v.as_ref())))
        .collect()
}

#[async_trait]
impl EntryPointTracer for EVMEntrypointService {
    type Error = RPCError;

    async fn trace(
        &self,
        block_hash: BlockHash,
        entry_points: Vec<EntryPointWithTracingParams>,
    ) -> Result<Vec<TracedEntryPoint>, Self::Error> {
        let mut results = Vec::new();
        for entry_point in &entry_points {
            match &entry_point.params {
                TracingParams::RPCTracer(ref rpc_entry_point) => {
                    // First call to get the list of called addresses
                    // Perf: Can we only use one call to get the retriggers and called addresses?
                    // Maybe we can implement a custom tracer that can return both? (not supported
                    // by chainstack though) or maybe we can batch the calls?
                    let call_trace = self
                        .trace_call(
                            &entry_point.entry_point.target,
                            rpc_entry_point,
                            &block_hash,
                            GethDebugBuiltInTracerType::CallTracer,
                        )
                        .await?;

                    let called_addresses =
                        if let GethTrace::Known(GethTraceFrame::CallTracer(frame)) = call_trace {
                            flatten_calls(&frame)
                        } else {
                            return Err(RPCError::UnknownError(
                                "invalid trace result for CallTracer".to_string(),
                            ));
                        };

                    // Second call to get the retriggers
                    let pre_state_trace = self
                        .trace_call(
                            &entry_point.entry_point.target,
                            rpc_entry_point,
                            &block_hash,
                            GethDebugBuiltInTracerType::PreStateTracer,
                        )
                        .await?;

                    let mut accessed_slots = called_addresses
                        .iter()
                        .map(|address| (address.to_bytes(), HashSet::new()))
                        .collect::<HashMap<_, _>>();

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
                                    accessed_slots
                                        .entry(address.to_bytes())
                                        .and_modify(|slots| {
                                            slots.insert((*slot).to_bytes());
                                        });
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
                        return Err(RPCError::UnknownError(
                            "invalid trace result for PreStateTracer".to_string(),
                        ));
                    };
                    results.push(TracedEntryPoint::new(
                        entry_point.clone(),
                        block_hash.clone(),
                        TracingResult::new(retriggers, accessed_slots),
                    ));
                }
            }
        }
        Ok(results)
    }
}

fn flatten_calls(call: &CallFrame) -> Vec<EthersAddress> {
    if let Some(err) = &call.error {
        warn!("Error in call frame: {:?}", err);
    }
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
        models::blockchain::{AccountOverrides, EntryPoint, RPCTracerParams},
        Bytes,
    };

    use super::*;

    #[tokio::test]
    #[ignore = "requires a RPC connection"]
    async fn test_trace_balancer_v3_stable_pool() {
        let url = env::var("RPC_URL").expect("RPC_URL is not set");
        let tracer = EVMEntrypointService::try_from_url(&url).unwrap();
        let entry_points = vec![
            EntryPointWithTracingParams::new(
                EntryPoint::new(
                    "0xEdf63cce4bA70cbE74064b7687882E71ebB0e988:getRate()".to_string(),
                    Bytes::from_str("0xEdf63cce4bA70cbE74064b7687882E71ebB0e988").unwrap(),
                    "getRate()".to_string(),
                ),
                TracingParams::RPCTracer(RPCTracerParams::new(
                    None,
                    Bytes::from(&keccak256("getRate()").to_vec()[0..4]),
                )),
            ),
            EntryPointWithTracingParams::new(
                EntryPoint::new(
                    "0x8f4E8439b970363648421C692dd897Fb9c0Bd1D9:getRate()".to_string(),
                    Bytes::from_str("0x8f4E8439b970363648421C692dd897Fb9c0Bd1D9").unwrap(),
                    "getRate()".to_string(),
                ),
                TracingParams::RPCTracer(RPCTracerParams::new(
                    None,
                    Bytes::from(&keccak256("getRate()")[0..4]),
                )),
            ),
        ];
        let traced_entry_points = tracer
            .trace(
                // Block 22589134 hash
                Bytes::from_str(
                    "0x283666c6c90091fa168ebf52c0c61043d6ada7a2ffe10dc303b0e4ff111e172e",
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
                    entry_point_with_params: entry_points[0].clone(),
                    detection_block_hash: Bytes::from_str("0x283666c6c90091fa168ebf52c0c61043d6ada7a2ffe10dc303b0e4ff111e172e").unwrap(),
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
                    HashMap::from([
                        (Bytes::from_str("0x87870bca3f3fd6335c3f4ce8392d69350b4fa4e2").unwrap(), HashSet::from([
                            Bytes::from_str("0xca6decca4edae0c692b2b0c41376a54b812edb060282d36e07a7060ccb58244d").unwrap(),
                            Bytes::from_str("0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc").unwrap(),
                            Bytes::from_str("0xca6decca4edae0c692b2b0c41376a54b812edb060282d36e07a7060ccb58244f").unwrap(),
                        ])),
                        (Bytes::from_str("0x487c2c53c0866f0a73ae317bd1a28f63adcd9ad1").unwrap(), HashSet::new()),
                        (Bytes::from_str("0x9aeb8aaa1ca38634aa8c0c8933e7fb4d61091327").unwrap(), HashSet::new()),
                        (Bytes::from_str("0xedf63cce4ba70cbe74064b7687882e71ebb0e988").unwrap(), HashSet::new()),
                        (Bytes::from_str("0x7bc3485026ac48b6cf9baf0a377477fff5703af8").unwrap(), HashSet::from([
                            Bytes::from_str("0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc").unwrap(),
                            Bytes::from_str("0x0773e532dfede91f04b12a73d3d2acd361424f41f76b4fb79f090161e36b4e00").unwrap(),
                        ])),
                        ]),
                    ),
                },
                TracedEntryPoint {
                    entry_point_with_params: entry_points[1].clone(),
                    detection_block_hash: Bytes::from_str("0x283666c6c90091fa168ebf52c0c61043d6ada7a2ffe10dc303b0e4ff111e172e").unwrap(),
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
                    HashMap::from([
                        (Bytes::from_str("0x87870bca3f3fd6335c3f4ce8392d69350b4fa4e2").unwrap(), HashSet::from([
                            Bytes::from_str("0xed960c71bd5fa1333658850f076b35ec5565086b606556c3dd36a916b43ddf23").unwrap(),
                            Bytes::from_str("0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc").unwrap(),
                            Bytes::from_str("0xed960c71bd5fa1333658850f076b35ec5565086b606556c3dd36a916b43ddf21").unwrap(),
                        ])),
                        (Bytes::from_str("0x487c2c53c0866f0a73ae317bd1a28f63adcd9ad1").unwrap(), HashSet::new()),
                        (Bytes::from_str("0x9aeb8aaa1ca38634aa8c0c8933e7fb4d61091327").unwrap(), HashSet::new()),
                        (Bytes::from_str("0x8f4e8439b970363648421c692dd897fb9c0bd1d9").unwrap(), HashSet::new()),
                        (Bytes::from_str("0xd4fa2d31b7968e448877f69a96de69f5de8cd23e").unwrap(), HashSet::from([
                            Bytes::from_str("0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc").unwrap(),
                            Bytes::from_str("0x0773e532dfede91f04b12a73d3d2acd361424f41f76b4fb79f090161e36b4e00").unwrap(),
                        ])),
                        ]),
                    ),
                },
            ],
        );
    }

    #[tokio::test]
    #[ignore = "requires a RPC connection"]
    /// This test traces a UniswapV2Router02 swapExactTokensForTokens call
    /// It uses an account with no balance and relies on tracer overrides for setting custom values
    /// for POLS token balance and allowance attributes
    async fn test_trace_univ2_swap() {
        let url = env::var("RPC_URL").expect("RPC_URL is not set");
        let tracer = EVMEntrypointService::try_from_url(&url).unwrap();

        // Create state overrides for the POLS contract
        let mut state_overrides = BTreeMap::new();
        let pols_address = Bytes::from_str("0x83e6f1e41cdd28eaceb20cb649155049fac3d5aa").unwrap();

        // Create storage overrides
        let mut slots = BTreeMap::new();
        // Override POLS balance for the caller
        slots.insert(
            Bytes::from_str("0x563494035215327c9cc08a85694f34eab8bc22017bd383b01d83f2bb8c78aa91")
                .unwrap(),
            Bytes::from_str("0x00000000000000000000000000000000000000000000004c4c6e64f5134a0000")
                .unwrap(),
        );
        // Override POLS allowance for the caller to UniswapV2Router02 contract
        slots.insert(
            Bytes::from_str("0x6402d480789caf1f1824771fcdd31558cac90b7d044d14b2201c8ca95eae8955")
                .unwrap(),
            Bytes::from_str("0x00000000000000000000000000000000000000000000004c4c6e64f5134a0000")
                .unwrap(),
        );

        // Create account overrides
        let account_overrides = AccountOverrides {
            slots: Some(StorageOverride::Diff(slots)),
            native_balance: None,
            code: None,
        };

        // Add to the state overrides map
        state_overrides.insert(pols_address.clone(), account_overrides);

        // UniswapV2Router02 address on Ethereum mainnet
        let router_address = Bytes::from_str("0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D").unwrap();

        // Prepare swapExactTokensForTokens parameters
        // Function signature: swapExactTokensForTokens(uint amountIn, uint amountOutMin, address[]
        // path, address to, uint deadline) Function selector: 0x38ed1739

        // Parameters:
        // amountIn: 1407460000000000000000 - amount of POLS
        // amountOutMin: 105047450000000000 - minimum amount of WETH
        // path: [POLS, WETH] - token swap path
        // to: caller address - recipient of the swapped tokens
        // deadline: 1750085651

        let caller = Bytes::from_str("0xd0a3dAC187ab0CbAaE92127F143A31fB6badbabe").unwrap();

        // Construct calldata for swapExactTokensForTokens
        let calldata = Bytes::from(
            "0x38ed173900000000000000000000000000000000000000000000004c4c6e64f5134a00000000000000000000000000000000000000000000000000000175341965cf840000000000000000000000000000000000000000000000000000000000000000a0000000000000000000000000d0a3dac187ab0cbaae92127f143a31fb6badbabe0000000000000000000000000000000000000000000000000000000068503013000000000000000000000000000000000000000000000000000000000000000200000000000000000000000083e6f1e41cdd28eaceb20cb649155049fac3d5aa000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"
        );

        let entry_points = vec![EntryPointWithTracingParams::new(
            EntryPoint::new(
                "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D:swapExactTokensForTokens(uint amountIn, uint amountOutMin, address[] path, address to, uint deadline)"
                    .to_string(),
                router_address.clone(),
                "swapExactTokensForTokens(uint amountIn, uint amountOutMin, address[] path, address to, uint deadline)".to_string(),
            ),
            TracingParams::RPCTracer(RPCTracerParams::new(
                Some(caller.clone()),
                calldata,
            ).with_state_overrides(state_overrides)),
        )];

        let block_hash =
            Bytes::from_str("0xfebbe1110db8fd453b7125860a1c909561d00872aedb40765f54356ac4d7cc40")
                .unwrap();
        let traced_entry_points = tracer
            .trace(
                // 22717805 block hash
                block_hash.clone(),
                entry_points.clone(),
            )
            .await
            .unwrap();

        assert_eq!(
            traced_entry_points,
            vec ![
            TracedEntryPoint {
            entry_point_with_params: entry_points[0].clone(),
            detection_block_hash: block_hash,
            tracing_result: TracingResult::new(
            // Retriggers
            HashSet::from([
                    (
                        Bytes::from_str("0xffa98a091331df4600f87c9164cd27e8a5cd2405").unwrap(),
                        Bytes::from_str("0x0000000000000000000000000000000000000000000000000000000000000007").unwrap(),
                    ),
                    (
                        Bytes::from_str("0xffa98a091331df4600f87c9164cd27e8a5cd2405").unwrap(),
                        Bytes::from_str("0x0000000000000000000000000000000000000000000000000000000000000006").unwrap(),
                    ),
                ]),
            // Accessed slots
            HashMap::from([
            (
                Bytes::from_str("0xffa98a091331df4600f87c9164cd27e8a5cd2405").unwrap(),
                HashSet::from([
                    Bytes::from_str("0x0000000000000000000000000000000000000000000000000000000000000007").unwrap(),
                    Bytes::from_str("0x0000000000000000000000000000000000000000000000000000000000000009").unwrap(),
                    Bytes::from_str("0x0000000000000000000000000000000000000000000000000000000000000006").unwrap(),
                    Bytes::from_str("0x000000000000000000000000000000000000000000000000000000000000000c").unwrap(),
                    Bytes::from_str("0x000000000000000000000000000000000000000000000000000000000000000a").unwrap(),
                    Bytes::from_str("0x0000000000000000000000000000000000000000000000000000000000000008").unwrap(),
                ])
            ),
            (Bytes::from_str("0x7a250d5630b4cf539739df2c5dacb4c659f2488d").unwrap(), HashSet::new()),
            (
                Bytes::from_str("0x83e6f1e41cdd28eaceb20cb649155049fac3d5aa").unwrap(),
                HashSet::from([
                    Bytes::from_str("0x0000000000000000000000000000000000000000000000000000000000000003").unwrap(),
                    Bytes::from_str("0x563494035215327c9cc08a85694f34eab8bc22017bd383b01d83f2bb8c78aa91").unwrap(),
                    Bytes::from_str("0x6402d480789caf1f1824771fcdd31558cac90b7d044d14b2201c8ca95eae8955").unwrap(),
                    Bytes::from_str("0x517313a419aa2ecd2d81b1726218564c7f0e0ab3a7f7ab9d34edc89c63e5f354").unwrap(),
                ])
            ),
            (
                Bytes::from_str("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2").unwrap(),
                HashSet::from([
                    Bytes::from_str("0xcafe3db63107f22b0a41ab8ae57012c28217ebfcf75e49a58208dc6968d7ff57").unwrap(),
                    Bytes::from_str("0x732054380c06f66b946fe3c55339b1fc707995878c89c46f3c874fa55acf3188").unwrap(),
                ])
            ),
            ]),
            ),
            },
            ],
        );
    }

    #[tokio::test]
    async fn test_trace_balancer_v2_stable_pool() {
        let url = env::var("RPC_URL").expect("RPC_URL is not set");
        let tracer = EVMEntrypointService::try_from_url(&url).unwrap();
        let entry_points = vec![EntryPointWithTracingParams::new(
            EntryPoint::new(
                "1a8f81c256aee9c640e14bb0453ce247ea0dfe6f:getRate()".to_string(),
                Bytes::from_str("1a8f81c256aee9c640e14bb0453ce247ea0dfe6f").unwrap(),
                "getRate()".to_string(),
            ),
            TracingParams::RPCTracer(RPCTracerParams::new(
                None,
                Bytes::from(&keccak256("getRate()").to_vec()[0..4]),
            )),
        )];
        let traced_entry_points = tracer
            .trace(
                // Block 22589134 hash
                Bytes::from_str(
                    "0xf5e2c5bc64ba61e1230e34b2d5d8906416633100919b477d17a7c6fd69cde31d",
                )
                .unwrap(),
                entry_points.clone(),
            )
            .await
            .unwrap();

        assert_eq!(traced_entry_points, vec![]);
    }
}
