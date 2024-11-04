use ethers::types::H160;
use std::{
    collections::{hash_map::Entry, HashMap},
    str::FromStr,
    sync::{mpsc::Sender, Arc},
    time::Duration,
};
use tracing::{debug, info, warn};

use tycho_client::{
    deltas::DeltasClient,
    feed::{
        component_tracker::ComponentFilter, synchronizer::ProtocolStateSynchronizer,
        BlockSynchronizer,
    },
    rpc::RPCClient,
    HttpRPCClient, WsDeltasClient,
};
use tycho_core::dto::{Chain, ExtractorIdentity};

use protosim::{
    models::ERC20Token,
    protocol::{
        models::ProtocolComponent, state::ProtocolSim, uniswap_v2::state::UniswapV2State,
        uniswap_v3::state::UniswapV3State,
    },
};

use super::state::BlockState;

// TODO: Make extractors configurable
async fn process_messages(
    ws_url: String,
    rpc_url: String,
    auth_key: Option<&str>,
    state_tx: Sender<BlockState>,
    tvl_threshold: f64,
) {
    // Connect to Tycho
    let ws_client = WsDeltasClient::new(&ws_url, auth_key).unwrap();
    ws_client
        .connect()
        .await
        .expect("ws client connection error");

    let rpc_client = HttpRPCClient::new(&rpc_url, auth_key).unwrap();

    // Load all tokens from Tycho
    #[allow(clippy::mutable_key_type)]
    let mut all_tokens = rpc_client
        .get_all_tokens(Chain::Ethereum, Some(100), Some(42), 3_000)
        .await
        .expect("Unable to load tokens")
        .into_iter()
        .map(|token| {
            let token_clone = token.clone();
            (
                token.address.clone(),
                token.try_into().unwrap_or_else(|_| {
                    panic!("Couldn't convert {:?} into ERC20 token.", token_clone)
                }),
            )
        })
        .collect::<HashMap<_, ERC20Token>>();

    info!("Got {} tokens from Tycho", all_tokens.len());

    // Register UniswapV2 and UniswapV3 synchronizers
    let usv2_id = ExtractorIdentity { chain: Chain::Ethereum, name: "uniswap_v2".to_string() };
    let usv2_sync = ProtocolStateSynchronizer::new(
        usv2_id.clone(),
        false,
        ComponentFilter::with_tvl_range(tvl_threshold, tvl_threshold), /* TODO: adapt CLI to use
                                                                        * a range */
        3,
        true,
        rpc_client.clone(),
        ws_client.clone(),
    );

    let usv3_id = ExtractorIdentity { chain: Chain::Ethereum, name: "uniswap_v3".to_string() };
    let usv3_sync = ProtocolStateSynchronizer::new(
        usv3_id.clone(),
        false,
        ComponentFilter::with_tvl_range(tvl_threshold, tvl_threshold), /* TODO: adapt CLI to use
                                                                        * a range */
        3,
        true,
        rpc_client.clone(),
        ws_client.clone(),
    );

    let block_sync = BlockSynchronizer::new(Duration::from_secs(600), Duration::from_secs(1))
        .register_synchronizer(usv3_id.clone(), usv3_sync)
        .register_synchronizer(usv2_id.clone(), usv2_sync);

    info!("Subscribed to {} tycho synchronizer", usv3_id);
    info!("Subscribed to {} tycho synchronizer", usv2_id);

    let (jh, mut rx) = block_sync
        .run()
        .await
        .expect("block sync start error");

    // monitors the last block a protocol sent a message
    let mut active_protocols: HashMap<String, u64> = HashMap::new();

    // persist all protocol states between messages
    // note - the current tick implementation expects addresses (H160) as component ids
    let mut stored_states: HashMap<H160, Box<dyn ProtocolSim>> = HashMap::new();

    // Loop through tycho messages
    while let Some(msg) = rx.recv().await {
        // stores all states updated in this tick/msg
        let mut updated_states = HashMap::new();
        let mut new_pairs = HashMap::new();
        let mut removed_pairs = HashMap::new();

        let block_id = msg
            .state_msgs
            .values()
            .next()
            .expect("Missing sync messages!")
            .header
            .number;

        for (protocol, protocol_msg) in msg.state_msgs.iter() {
            if let Some(deltas) = protocol_msg.deltas.as_ref() {
                deltas
                    .new_tokens
                    .iter()
                    .for_each(|(addr, token)| {
                        if token.quality >= 51 {
                            all_tokens
                                .entry(addr.clone())
                                .or_insert_with(|| {
                                    token
                                        .clone()
                                        .try_into()
                                        .unwrap_or_else(|_| {
                                            panic!("Couldn't convert {:x} into ERC20 token.", addr)
                                        })
                                });
                        }
                    });
            }

            removed_pairs.extend(
                protocol_msg
                    .removed_components
                    .iter()
                    .flat_map(|(id, comp)| {
                        let tokens = comp
                            .tokens
                            .iter()
                            .flat_map(|addr| all_tokens.get(addr).cloned())
                            .collect::<Vec<_>>();
                        let id = H160::from_str(id.as_ref()).unwrap_or_else(|_| {
                            panic!("Failed parsing H160 from id string {}", id)
                        });
                        if tokens.len() == comp.tokens.len() {
                            Some((id, ProtocolComponent::new(id, tokens)))
                        } else {
                            None
                        }
                    }),
            );

            let mut new_components = HashMap::new();

            // snapshots
            for (id, snapshot) in protocol_msg
                .snapshots
                .get_states()
                .clone()
            {
                let id = H160::from_str(id.as_ref())
                    .unwrap_or_else(|_| panic!("Failed parsing H160 from id string {}", id));
                let mut pair_tokens = Vec::new();
                let mut skip_pool = false;

                for token in snapshot.component.tokens.clone() {
                    match all_tokens.get(&token) {
                        Some(token) => pair_tokens.push(token.clone()),
                        None => {
                            debug!(
                                "Token not found in all_tokens {}, ignoring pool {:x?}",
                                token, id
                            );
                            skip_pool = true;
                            break;
                        }
                    }
                }

                if !skip_pool {
                    new_pairs.insert(id, ProtocolComponent::new(id, pair_tokens));
                }

                let state: Box<dyn ProtocolSim> = match protocol.as_str() {
                    "uniswap_v3" => match UniswapV3State::try_from(snapshot) {
                        Ok(state) => Box::new(state),
                        Err(e) => {
                            warn!("Failed parsing uniswap-v3 snapshot! {} for pool {:x?}", e, id);
                            continue;
                        }
                    },
                    "uniswap_v2" => match UniswapV2State::try_from(snapshot) {
                        Ok(state) => Box::new(state),
                        Err(e) => {
                            warn!("Failed parsing uniswap-v2 snapshot! {} for pool {:x?}", e, id);
                            continue;
                        }
                    },
                    _ => panic!("VM snapshot not supported!"),
                };
                new_components.insert(id, state);
            }

            if !new_components.is_empty() {
                info!("Decoded {} snapshots for protocol {}", new_components.len(), protocol);
            }
            updated_states.extend(new_components);

            // deltas
            if let Some(deltas) = protocol_msg.deltas.clone() {
                for (id, update) in deltas.state_updates {
                    let id = H160::from_str(id.as_ref())
                        .unwrap_or_else(|_| panic!("Failed parsing H160 from id string {}", id));
                    match updated_states.entry(id) {
                        Entry::Occupied(mut entry) => {
                            // if state exists in updated_states, apply the delta to it
                            let state: &mut Box<dyn ProtocolSim> = entry.get_mut();
                            state
                                .delta_transition(update)
                                .expect("Failed applying state update!");
                        }
                        Entry::Vacant(_) => {
                            match stored_states.get(&id) {
                                // if state does not exist in updated_states, apply the delta to the stored state
                                Some(stored_state) => {
                                    let mut state = stored_state.clone();
                                    state
                                        .delta_transition(update)
                                        .expect("Failed applying state update!");
                                    updated_states.insert(id, state);
                                }
                                None => warn!(
                                    "Update could not be applied: missing stored state for id: {:x?}",
                                    id
                                ),
                            }
                        }
                    }
                }
            };

            // update active protocols
            active_protocols
                .entry(protocol.clone())
                .and_modify(|block| *block = block_id)
                .or_insert(block_id);
        }

        // checks all registered extractors have sent a message in the last 10 blocks
        active_protocols
            .iter()
            .for_each(|(protocol, last_block)| {
                if *last_block > block_id {
                    // old block message received - likely caused by a tycho-client restart. We don't skip processing the message
                    // as the restart provides a clean slate of new snapshots and corresponding deltas
                    warn!("Extractor {} sent an old block message. Last message at block {}, current block {}", protocol, block_id, last_block)
                } else if block_id - last_block > 10 {
                    panic!("Extractor {} has not sent a message in the last 10 blocks! Last message at block {}, current block {}", protocol, block_id, last_block);
                }
            });

        // Persist the newly added/updated states
        stored_states.extend(
            updated_states
                .iter()
                .map(|(id, state)| (*id, state.clone())),
        );

        // Send the tick with all updated states
        let state =
            BlockState::new(block_id, updated_states, new_pairs).set_removed_pairs(removed_pairs);

        state_tx
            .send(state)
            .expect("Sending tick failed!")
    }

    jh.await.unwrap();
}

pub fn start(
    tycho_url: String,
    auth_key: Option<String>,
    state_tx: Sender<BlockState>,
    tvl_threshold: f64,
) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    info!("Starting tycho data feed...");

    let ws_url = format!("wss://{tycho_url}");
    let rpc_url = format!("https://{tycho_url}");

    // Wrap `auth_key` in an Arc<Option<String>> to make it 'static
    let auth_key = Arc::new(auth_key);

    rt.block_on(async {
        let auth_key_clone = Arc::clone(&auth_key);

        tokio::spawn(async move {
            process_messages(
                ws_url,
                rpc_url,
                auth_key_clone.as_deref(), /* `as_deref` converts `Option<String>` to
                                            * `Option<&str>` */
                state_tx,
                tvl_threshold,
            )
            .await;
        })
        .await
        .unwrap();
    });
}
