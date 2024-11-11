use alloy_primitives::Address;
use chrono::Utc;
use ethers::{prelude::H256, types::H160};
use std::{
    collections::{hash_map::Entry, HashMap, HashSet},
    str::FromStr,
};
use tokio::sync::mpsc::Sender;
use tracing::{debug, info, warn};

use tycho_client::{
    feed::{component_tracker::ComponentFilter, synchronizer::ComponentWithState},
    rpc::RPCClient,
    stream::TychoStreamBuilder,
    HttpRPCClient,
};
use tycho_core::{dto::Chain, Bytes};

use tycho_simulation::{
    evm::{
        simulation_db::BlockHeader,
        tycho_models::{AccountUpdate, ResponseAccount},
    },
    models::ERC20Token,
    protocol::{
        models::ProtocolComponent,
        state::ProtocolSim,
        uniswap_v2::state::UniswapV2State,
        uniswap_v3::state::UniswapV3State,
        vm::{
            engine::{update_engine, SHARED_TYCHO_DB},
            state::VMPoolState,
            tycho_decoder::TryFromWithBlock,
        },
        BytesConvertible,
    },
};

use crate::data_feed::state::BlockState;
use once_cell::sync::Lazy;
use tycho_simulation::evm::tycho_db::PreCachedDB;

static UNSUPPORTED_BALANCER_POOL_TYPES: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    [
        "ERC4626LinearPoolFactory",
        "EulerLinearPoolFactory",
        "SiloLinearPoolFactory",
        "YearnLinearPoolFactory",
        "ComposableStablePoolFactory",
    ]
    .iter()
    .cloned()
    .collect()
});

const ZERO_ADDRESS: &str = "0x0000000000000000000000000000000000000000";

fn balancer_pool_filter(component: &ComponentWithState) -> bool {
    // Check for rate_providers in static_attributes
    info!("Checking Balancer pool {}", component.component.id);
    if let Some(rate_providers_data) = component
        .component
        .static_attributes
        .get("rate_providers")
    {
        let rate_providers_str = rate_providers_data.clone().to_string();
        if let Ok(rate_providers) = serde_json::from_str::<Vec<String>>(&rate_providers_str) {
            if rate_providers
                .iter()
                .any(|provider| provider != ZERO_ADDRESS)
            {
                info!(
                    "Filtering out Balancer pool {} because it has dynamic rate_providers",
                    component.component.id
                );
                return false;
            }
        }
    }

    // Check pool_type in static_attributes
    if let Some(pool_type_data) = component
        .component
        .static_attributes
        .get("pool_type")
    {
        let pool_type = pool_type_data.clone().to_string();
        if UNSUPPORTED_BALANCER_POOL_TYPES.contains(&pool_type.as_str()) {
            debug!(
                "Filtering out Balancer pool {} because it has type {}",
                component.component.id, pool_type
            );
            return false;
        }
    }
    info!("Balancer pool will not be filtered out.");
    true
}

// TODO: Make extractors configurable
pub async fn process_messages(
    tycho_url: String,
    auth_key: Option<String>,
    state_tx: Sender<BlockState>,
    tvl_threshold: f64,
) {
    // TODO remove
    info!("1 - processing messages");
    // Connect to Tycho
    let (jh, mut tycho_stream) = TychoStreamBuilder::new(&tycho_url, Chain::Ethereum)
        // .exchange("uniswap_v2", ComponentFilter::with_tvl_range(tvl_threshold, tvl_threshold))
        // .exchange("uniswap_v3", ComponentFilter::with_tvl_range(tvl_threshold, tvl_threshold))
        .exchange(
            "vm:balancer",
            ComponentFilter::Ids(vec![
                "0x5c6ee304399dbdb9c8ef030ab642b10820db8f56000200000000000000000014".to_string(),
            ]),
        )
        .auth_key(auth_key.clone())
        .build()
        .await
        .expect("Failed to build tycho stream");

    // TODO remove
    // It doesn't get this far without failing with "not all synchronizers on same block!"
    info!("2 - built tycho stream");
    let mut all_tokens = load_all_tokens(tycho_url.as_str(), auth_key.as_deref()).await;

    // maps protocols to the the last block we've seen a message for it
    let mut active_protocols: HashMap<String, u64> = HashMap::new();

    // persist all protocol states between messages
    // note - the current tick implementation expects addresses (H160) as component ids
    let mut stored_states: HashMap<Bytes, Box<dyn ProtocolSim>> = HashMap::new();

    // TODO remove
    info!("3 - loaded all tokens");
    // Loop through tycho messages
    while let Some(msg) = tycho_stream.recv().await {
        // stores all states updated in this tick/msg
        let mut updated_states = HashMap::new();
        let mut new_pairs = HashMap::new();
        let mut removed_pairs = HashMap::new();

        let header = msg
            .state_msgs
            .values()
            .next()
            .expect("Missing sync messages!")
            .header
            .clone();
        info!("Received block {}", header.number);
        let block_id = header.clone().number;
        let block_hash = header.clone().hash;
        let block = BlockHeader {
            number: block_id,
            hash: H256::from_slice(&block_hash[..]),
            timestamp: Utc::now().timestamp() as u64,
        };

        for (protocol, protocol_msg) in msg.state_msgs.iter() {
            if let Some(deltas) = protocol_msg.deltas.as_ref() {
                deltas
                    .new_tokens
                    .iter()
                    .for_each(|(addr, token)| {
                        if token.quality >= 51 {
                            all_tokens
                                .entry(H160::from_bytes(addr))
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
                    .flat_map(|(&ref id, comp)| {
                        let tokens = comp
                            .tokens
                            .iter()
                            .flat_map(|addr| {
                                all_tokens
                                    .get(&H160::from_bytes(addr))
                                    .cloned()
                            })
                            .collect::<Vec<_>>();
                        let id = Bytes::from_str(id).unwrap_or_else(|_| {
                            panic!("Failed parsing H160 from id string {}", id)
                        });
                        if tokens.len() == comp.tokens.len() {
                            Some((id.clone(), ProtocolComponent::new(id, tokens)))
                        } else {
                            None
                        }
                    }),
            );

            let mut new_components = HashMap::new();

            // UPDATE ENGINE
            let storage_by_address: HashMap<Address, ResponseAccount> = protocol_msg
                .clone()
                .snapshots
                .get_vm_storage()
                .into_iter()
                .map(|(key, value)| (Address::from_slice(&key[..20]), value.clone().into()))
                .collect();
            info!("Updating engine with snapshot");
            update_engine(SHARED_TYCHO_DB.clone(), block, Some(storage_by_address), HashMap::new())
                .await;
            info!("Engine updated with snapshot");

            // PROCESS SNAPSHOTS
            for (id, snapshot) in protocol_msg
                .snapshots
                .get_states()
                .clone()
            {
                info!("Processing snapshot");
                let id = Bytes::from_str(&id)
                    .unwrap_or_else(|_| panic!("Failed parsing H160 from id string {}", id));
                let mut pair_tokens = Vec::new();
                let mut skip_pool = false;

                for token in snapshot.component.tokens.clone() {
                    match all_tokens.get(&H160::from_bytes(&token)) {
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
                    new_pairs.insert(id.clone(), ProtocolComponent::new(id.clone(), pair_tokens));
                }

                let state: Box<dyn ProtocolSim> = match protocol.as_str() {
                    "uniswap_v3" => match UniswapV3State::try_from(snapshot.clone()) {
                        Ok(state) => Box::new(state),
                        Err(e) => {
                            debug!("Failed parsing uniswap-v3 snapshot! {} for pool {:x?}", e, id);
                            continue;
                        }
                    },
                    "uniswap_v2" => match UniswapV2State::try_from(snapshot.clone()) {
                        Ok(state) => Box::new(state),
                        Err(e) => {
                            warn!("Failed parsing uniswap-v2 snapshot! {} for pool {:x?}", e, id);
                            continue;
                        }
                    },
                    "vm:balancer" => {
                        match VMPoolState::try_from_with_block(
                            snapshot.clone(),
                            header.clone(),
                            all_tokens.clone(),
                        )
                        .await
                        {
                            Ok(state) => {
                                // Skip balancer pool if it doesn't pass the filter
                                if !balancer_pool_filter(&snapshot) {
                                    continue;
                                }
                                Box::new(state)
                            }
                            Err(e) => {
                                warn!(
                                    "Failed parsing balancer-v2 snapshot! {} for pool {:x?}",
                                    e, id
                                );
                                continue;
                            }
                        }
                    }
                    _ => panic!("VM snapshot not supported!"),
                };
                new_components.insert(id, state);
            }

            if !new_components.is_empty() {
                info!("Decoded {} snapshots for protocol {}", new_components.len(), protocol);
            }
            updated_states.extend(new_components);

            // PROCESS DELTAS

            if let Some(deltas) = protocol_msg.deltas.clone() {
                let account_update_by_address: HashMap<Address, AccountUpdate> = deltas
                    .account_updates
                    .clone()
                    .into_iter()
                    .map(|(key, value)| (Address::from_slice(&key[..20]), value.into()))
                    .collect();
                info!("Updating engine with deltas");
                update_engine(SHARED_TYCHO_DB.clone(), block, None, account_update_by_address)
                    .await;
                info!("Engine updated with deltas");

                for (id, update) in deltas.state_updates {
                    info!("Processing deltas");
                    let id = Bytes::from_str(&id)
                        .unwrap_or_else(|_| panic!("Failed parsing H160 from id string {}", id));
                    match updated_states.entry(id.clone()) {
                        Entry::Occupied(mut entry) => {
                            // if state exists in updated_states, apply the delta to it
                            let state: &mut Box<dyn ProtocolSim> = entry.get_mut();
                            if let Some(mut vm_state) = state
                                .as_any_mut()
                                .downcast_mut::<VMPoolState<PreCachedDB>>()
                            {
                                let tokens: Vec<ERC20Token> = vm_state
                                    .tokens
                                    .iter()
                                    .filter_map(|token_address| all_tokens.get(token_address))
                                    .cloned()
                                    .collect();

                                vm_state
                                    .delta_transition(update, tokens)
                                    .expect("Failed applying state update!");
                            } else {
                                state
                                    .delta_transition(update, vec![])
                                    .expect("Failed applying state update!");
                            }
                        }
                        Entry::Vacant(_) => {
                            match stored_states.get(&id.clone()) {
                                // if state does not exist in updated_states, apply the delta to the stored state
                                Some(stored_state) => {
                                    let mut state = stored_state.clone();
                                    if let Some(mut vm_state) = state.as_any_mut()
                                        .downcast_mut::<VMPoolState<PreCachedDB>>() {
                                        let tokens: Vec<ERC20Token> = vm_state.tokens
                                            .iter()
                                            .filter_map(|token_address| all_tokens.get(token_address))
                                            .cloned()
                                            .collect();

                                        // TODO SIMULATION HAPPENS HERE
                                        vm_state.delta_transition(update, tokens)
                                            .expect("Failed applying state update!");
                                    } else {
                                        state
                                            .delta_transition(update, vec![])
                                            .expect("Failed applying state update!");
                                    }

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
                .map(|(id, state)| (id.clone(), state.clone())),
        );

        // Send the tick with all updated states
        let state =
            BlockState::new(block_id, updated_states, new_pairs).set_removed_pairs(removed_pairs);

        state_tx
            .send(state)
            .await
            .expect("Sending tick failed!")
    }

    jh.await.unwrap();
}

pub async fn load_all_tokens(tycho_url: &str, auth_key: Option<&str>) -> HashMap<H160, ERC20Token> {
    let rpc_url = format!("https://{tycho_url}");
    let rpc_client = HttpRPCClient::new(rpc_url.as_str(), auth_key).unwrap();

    #[allow(clippy::mutable_key_type)]
    rpc_client
        .get_all_tokens(Chain::Ethereum, Some(100), Some(42), 3_000)
        .await
        .expect("Unable to load tokens")
        .into_iter()
        .map(|token| {
            let token_clone = token.clone();
            (
                H160::from_bytes(&token.address),
                token.try_into().unwrap_or_else(|_| {
                    panic!("Couldn't convert {:?} into ERC20 token.", token_clone)
                }),
            )
        })
        .collect::<HashMap<_, ERC20Token>>()
}

pub fn start(
    tycho_url: String,
    auth_key: Option<String>,
    state_tx: Sender<BlockState>,
    tvl_threshold: f64,
) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    info!("Starting tycho data feed...");

    rt.block_on(async {
        tokio::spawn(async move {
            process_messages(tycho_url, auth_key, state_tx, tvl_threshold).await;
        })
        .await
        .unwrap();
    });
}
