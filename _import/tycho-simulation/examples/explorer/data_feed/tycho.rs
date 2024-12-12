use std::{
    collections::{hash_map::Entry, HashMap, HashSet},
    str,
    str::FromStr,
};

use alloy_primitives::{Address, B256};
use chrono::Utc;
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
        engine_db::{
            simulation_db::BlockHeader, tycho_db::PreCachedDB, update_engine, SHARED_TYCHO_DB,
        },
        protocol::{
            uniswap_v2::state::UniswapV2State, uniswap_v3::state::UniswapV3State,
            vm::state::EVMPoolState,
        },
        tycho_models::{AccountUpdate, ResponseAccount},
    },
    models::ERC20Token,
    protocol::{
        models::{ProtocolComponent, TryFromWithBlock},
        state::ProtocolSim,
    },
};

use crate::data_feed::state::BlockState;

const ZERO_ADDRESS: &str = "0x0000000000000000000000000000000000000000";

fn balancer_pool_filter(component: &ComponentWithState) -> bool {
    // Check for rate_providers in static_attributes
    info!("Checking Balancer pool {}", component.component.id);
    if component.component.protocol_system != "vm:balancer" {
        return true;
    }
    if let Some(rate_providers_data) = component
        .component
        .static_attributes
        .get("rate_providers")
    {
        let rate_providers_str = str::from_utf8(rate_providers_data).expect("Invalid UTF-8 data");
        let parsed_rate_providers =
            serde_json::from_str::<Vec<String>>(rate_providers_str).expect("Invalid JSON format");

        info!("Parsed rate providers: {:?}", parsed_rate_providers);
        let has_dynamic_rate_provider = parsed_rate_providers
            .iter()
            .any(|provider| provider != ZERO_ADDRESS);

        info!("Has dynamic rate provider: {:?}", has_dynamic_rate_provider);
        if has_dynamic_rate_provider {
            info!(
                "Filtering out Balancer pool {} because it has dynamic rate_providers",
                component.component.id
            );
            return false;
        }
    } else {
        info!("Balancer pool does not have `rate_providers` attribute");
    }
    let unsupported_pool_types: HashSet<&str> = [
        "ERC4626LinearPoolFactory",
        "EulerLinearPoolFactory",
        "SiloLinearPoolFactory",
        "YearnLinearPoolFactory",
        "ComposableStablePoolFactory",
    ]
    .iter()
    .cloned()
    .collect();

    // Check pool_type in static_attributes
    if let Some(pool_type_data) = component
        .component
        .static_attributes
        .get("pool_type")
    {
        // Convert the decoded bytes to a UTF-8 string
        let pool_type = str::from_utf8(pool_type_data).expect("Invalid UTF-8 data");
        if unsupported_pool_types.contains(pool_type) {
            info!(
                "Filtering out Balancer pool {} because it has type {}",
                component.component.id, pool_type
            );
            return false;
        } else {
            info!("Balancer pool with type {} will not be filtered out.", pool_type);
        }
    }
    info!(
        "Balancer pool with static attributes {:?} will not be filtered out.",
        component.component.static_attributes
    );
    info!("Balancer pool will not be filtered out.");
    true
}

pub async fn process_messages(
    tycho_url: String,
    auth_key: Option<String>,
    state_tx: Sender<BlockState>,
    tvl_threshold: f64,
) {
    // Connect to Tycho
    let (jh, mut tycho_stream) = TychoStreamBuilder::new(&tycho_url, Chain::Ethereum)
        .exchange("uniswap_v2", ComponentFilter::with_tvl_range(tvl_threshold, tvl_threshold))
        .exchange("uniswap_v3", ComponentFilter::with_tvl_range(tvl_threshold, tvl_threshold))
        // .exchange("vm:balancer", ComponentFilter::with_tvl_range(tvl_threshold, tvl_threshold))
        .auth_key(auth_key.clone())
        .build()
        .await
        .expect("Failed to build tycho stream");

    let mut all_tokens = load_all_tokens(tycho_url.as_str(), auth_key.as_deref()).await;

    // maps protocols to the last block we've seen a message for it
    let mut active_protocols: HashMap<String, u64> = HashMap::new();

    // persist all protocol states between messages
    // note - the current tick implementation expects addresses (H160) as component ids
    let mut stored_states: HashMap<Bytes, Box<dyn ProtocolSim>> = HashMap::new();

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
            hash: B256::from_slice(&block_hash[..]),
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
                                .entry(Address::from_slice(addr))
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
                            .flat_map(|addr| {
                                all_tokens
                                    .get(&Address::from_slice(addr))
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
                .iter()
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
                    .unwrap_or_else(|_| panic!("Failed parsing Bytes from id string {}", id));
                let mut pair_tokens = Vec::new();
                let mut skip_pool = false;

                for token in snapshot.component.tokens.clone() {
                    match all_tokens.get(&Address::from_slice(&token)) {
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

                // Skip balancer pool if it doesn't pass the filter
                if !skip_pool && !balancer_pool_filter(&snapshot) {
                    skip_pool = true;
                }

                if !skip_pool {
                    new_pairs.insert(id.clone(), ProtocolComponent::new(id.clone(), pair_tokens));

                    let state: Box<dyn ProtocolSim> = match protocol.as_str() {
                        "uniswap_v3" => match UniswapV3State::try_from_with_block(
                            snapshot,
                            header.clone(),
                            HashMap::new(),
                        )
                        .await
                        {
                            Ok(state) => Box::new(state),
                            Err(e) => {
                                debug!(
                                    "Failed parsing uniswap-v3 snapshot! {} for pool {:x?}",
                                    e, id
                                );
                                continue;
                            }
                        },
                        "uniswap_v2" => match UniswapV2State::try_from_with_block(
                            snapshot,
                            header.clone(),
                            HashMap::new(),
                        )
                        .await
                        {
                            Ok(state) => Box::new(state),
                            Err(e) => {
                                warn!(
                                    "Failed parsing uniswap-v2 snapshot! {} for pool {:x?}",
                                    e, id
                                );
                                continue;
                            }
                        },
                        "vm:balancer" => {
                            match EVMPoolState::try_from_with_block(
                                snapshot,
                                header.clone(),
                                all_tokens.clone(),
                            )
                            .await
                            {
                                Ok(state) => Box::new(state),
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
                    .iter()
                    .map(|(key, value)| (Address::from_slice(&key[..20]), value.clone().into()))
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
                            if let Some(vm_state) = state
                                .as_any_mut()
                                .downcast_mut::<EVMPoolState<PreCachedDB>>()
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
                                    if let Some(vm_state) = state.as_any_mut()
                                        .downcast_mut::<EVMPoolState<PreCachedDB>>() {
                                        let tokens: Vec<ERC20Token> = vm_state.tokens
                                            .iter()
                                            .filter_map(|token_address| all_tokens.get(token_address))
                                            .cloned()
                                            .collect();

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
                info!("Finished processing delta state updates.");
            };

            // update active protocols
            active_protocols
                .entry(protocol.clone())
                .and_modify(|block| *block = header.number)
                .or_insert(header.number);
        }

        // checks all registered extractors have sent a message in the last 10 blocks
        active_protocols
            .iter()
            .for_each(|(protocol, last_block)| {
                if *last_block > header.number {
                    // old block message received - likely caused by a tycho-client restart. We don't skip processing the message
                    // as the restart provides a clean slate of new snapshots and corresponding deltas
                    warn!("Extractor {} sent an old block message. Last message at block {}, current block {}", protocol, header.number, last_block)
                } else if header.number - last_block > 10 {
                    panic!("Extractor {} has not sent a message in the last 10 blocks! Last message at block {}, current block {}", protocol, header.number, last_block);
                }
            });

        // Persist the newly added/updated states
        stored_states.extend(
            updated_states
                .iter()
                .map(|(id, state)| (id.clone(), state.clone())),
        );

        // Send the tick with all updated states
        let state = BlockState::new(header.number, updated_states, new_pairs)
            .set_removed_pairs(removed_pairs);

        info!("Sending tick!");
        state_tx
            .send(state)
            .await
            .expect("Sending tick failed!");
    }

    jh.await.unwrap();
}

pub async fn load_all_tokens(
    tycho_url: &str,
    auth_key: Option<&str>,
) -> HashMap<Address, ERC20Token> {
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
                Address::from_slice(&token.address),
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
