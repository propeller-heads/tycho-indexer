use async_trait::async_trait;
use serde::Serialize;
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::Duration,
};

use tokio::{
    select,
    sync::{
        mpsc::{channel, Receiver, Sender},
        oneshot, Mutex,
    },
    task::JoinHandle,
    time::timeout,
};
use tracing::{debug, error, info, instrument, trace, warn};
use tycho_core::{
    dto::{
        BlockChanges, BlockParam, ContractId, ExtractorIdentity, ProtocolComponent, ProtocolId,
        ResponseAccount, ResponseProtocolState, StateRequestBody, StateRequestParameters,
        VersionParam,
    },
    Bytes,
};

use super::Header;
use crate::{
    deltas::{DeltasClient, SubscriptionOptions},
    feed::component_tracker::{ComponentFilter, ComponentTracker},
    rpc::RPCClient,
};

pub type SyncResult<T> = anyhow::Result<T>;

#[derive(Clone)]
pub struct ProtocolStateSynchronizer<R: RPCClient, D: DeltasClient> {
    extractor_id: ExtractorIdentity,
    #[allow(dead_code)]
    retrieve_balances: bool,
    rpc_client: R,
    deltas_client: D,
    max_retries: u64,
    include_snapshots: bool,
    component_filter: ComponentFilter,
    shared: Arc<Mutex<SharedState>>,
    end_tx: Arc<Mutex<Option<oneshot::Sender<()>>>>,
}

#[derive(Debug, Default)]
struct SharedState {
    last_synced_block: Option<Header>,
}

#[derive(Clone, PartialEq, Debug, Serialize)]
pub struct ComponentWithState {
    pub state: ResponseProtocolState,
    pub component: ProtocolComponent,
}

#[derive(Clone, PartialEq, Debug, Default, Serialize)]
pub struct Snapshot {
    states: HashMap<String, ComponentWithState>,
    vm_storage: HashMap<Bytes, ResponseAccount>,
}

impl Snapshot {
    fn extend(&mut self, other: Snapshot) {
        self.states.extend(other.states);
        self.vm_storage.extend(other.vm_storage);
    }

    pub fn get_states(&self) -> &HashMap<String, ComponentWithState> {
        &self.states
    }
}

#[derive(Clone, PartialEq, Debug, Default, Serialize)]
pub struct StateSyncMessage {
    /// The block number for this update.
    pub header: Header,
    /// Snapshot for new components.
    pub snapshots: Snapshot,
    /// A single delta contains state updates for all tracked components, as well as additional
    /// information about the system components e.g. newly added components (even below tvl), tvl
    /// updates, balance updates.
    pub deltas: Option<BlockChanges>,
    /// Components that stopped being tracked.
    pub removed_components: HashMap<String, ProtocolComponent>,
}

impl StateSyncMessage {
    pub fn merge(mut self, other: Self) -> Self {
        // be careful with removed and snapshots attributes here, these can be ambiguous.
        self.removed_components
            .retain(|k, _| !other.snapshots.states.contains_key(k));
        self.snapshots
            .states
            .retain(|k, _| !other.removed_components.contains_key(k));

        self.snapshots.extend(other.snapshots);
        let deltas = match (self.deltas, other.deltas) {
            (Some(l), Some(r)) => Some(l.merge(r)),
            (None, Some(r)) => Some(r),
            (Some(l), None) => Some(l),
            (None, None) => None,
        };
        self.removed_components
            .extend(other.removed_components);
        Self {
            header: other.header,
            snapshots: self.snapshots,
            deltas,
            removed_components: self.removed_components,
        }
    }
}

/// StateSynchronizer
///
/// Used to synchronize the state of a single protocol. The synchronizer is responsible for
/// delivering messages to the client that let him reconstruct subsets of the protocol state.
///
/// This involves deciding which components to track according to the clients preferences,
/// retrieving & emitting snapshots of components which the client has not seen yet and subsequently
/// delivering delta messages for the components that have changed.
#[async_trait]
pub trait StateSynchronizer: Send + Sync + 'static {
    /// Starts the state synchronization.
    async fn start(&self) -> SyncResult<(JoinHandle<SyncResult<()>>, Receiver<StateSyncMessage>)>;
    /// Ends the sychronization loop.
    async fn close(&mut self) -> SyncResult<()>;
}

impl<R, D> ProtocolStateSynchronizer<R, D>
where
    // TODO: Consider moving these constraints directly to the
    //  client...
    R: RPCClient + Clone + Send + Sync + 'static,
    D: DeltasClient + Clone + Send + Sync + 'static,
{
    /// Creates a new state synchronizer.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        extractor_id: ExtractorIdentity,
        retrieve_balances: bool,
        component_filter: ComponentFilter,
        max_retries: u64,
        include_snapshots: bool,
        rpc_client: R,
        deltas_client: D,
    ) -> Self {
        Self {
            extractor_id,
            retrieve_balances,
            rpc_client,
            include_snapshots,
            deltas_client,
            component_filter,
            max_retries,
            shared: Arc::new(Mutex::new(SharedState::default())),
            end_tx: Arc::new(Mutex::new(None)),
        }
    }

    /// Retrieves state snapshots of the requested components
    async fn get_snapshots<'a, I: IntoIterator<Item = &'a String>>(
        &self,
        header: Header,
        tracked_components: &ComponentTracker<R>,
        ids: Option<I>,
    ) -> SyncResult<StateSyncMessage> {
        if !self.include_snapshots {
            return Ok(StateSyncMessage { header, ..Default::default() });
        }
        let version = VersionParam::new(
            None,
            Some(BlockParam {
                chain: Some(self.extractor_id.chain),
                hash: None,
                number: Some(header.number as i64),
            }),
        );

        // Use given ids or use all if not passed
        let request_ids = ids
            .map(|it| {
                it.into_iter()
                    .map(|id| ProtocolId { id: id.clone(), chain: self.extractor_id.chain })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_else(|| tracked_components.get_tracked_component_ids());

        let component_ids = request_ids
            .iter()
            .map(|protocol_id| &protocol_id.id)
            .collect::<HashSet<_>>();

        if component_ids.is_empty() {
            return Ok(StateSyncMessage { header, ..Default::default() });
        }

        let mut protocol_states = self
            .rpc_client
            .get_protocol_states_paginated(self.extractor_id.chain, &request_ids, &version, 50, 4)
            .await?
            .states
            .into_iter()
            .map(|state| (state.component_id.clone(), state))
            .collect::<HashMap<_, _>>();

        trace!(states=?&protocol_states, "Retrieved ProtocolStates");
        let states = tracked_components
            .components
            .values()
            .filter_map(|component| {
                if let Some(state) = protocol_states.remove(&component.id) {
                    Some((
                        component.id.clone(),
                        ComponentWithState { state, component: component.clone() },
                    ))
                } else if component_ids.contains(&&component.id) {
                    // only emit error event if we requested this component
                    let component_id = &component.id;
                    error!(?component_id, "Missing state for native component!");
                    None
                } else {
                    None
                }
            })
            .collect();

        let contract_ids = tracked_components.get_contracts_by_component(component_ids.clone());
        let vm_storage = if !contract_ids.is_empty() {
            let contract_states = self
                .rpc_client
                .get_contract_state(
                    self.extractor_id.chain,
                    &StateRequestParameters::new(false),
                    &StateRequestBody::new(
                        Some(
                            contract_ids
                                .clone()
                                .into_iter()
                                .map(|id| ContractId::new(self.extractor_id.chain, id))
                                .collect(),
                        ),
                        version,
                    ),
                )
                .await?
                .accounts
                .into_iter()
                .map(|acc| (acc.address.clone(), acc))
                .collect::<HashMap<_, _>>();

            trace!(states=?&contract_states, "Retrieved ContractState");

            let contract_address_to_components = tracked_components
                .components
                .iter()
                .filter_map(|(id, comp)| {
                    if component_ids.contains(&id) {
                        Some(
                            comp.contract_ids
                                .iter()
                                .map(|address| (address.clone(), comp.id.clone())),
                        )
                    } else {
                        None
                    }
                })
                .flatten()
                .fold(HashMap::<Bytes, Vec<String>>::new(), |mut acc, (addr, c_id)| {
                    acc.entry(addr).or_default().push(c_id);
                    acc
                });

            contract_ids
                .iter()
                .filter_map(|address| {
                    if let Some(state) = contract_states.get(address) {
                        Some((address.clone(), state.clone()))
                    } else if let Some(ids) = contract_address_to_components.get(address) {
                        // only emit error even if we did actually request this address
                        error!(
                            ?address,
                            ?ids,
                            "Component with lacking contract storage encountered!"
                        );
                        None
                    } else {
                        None
                    }
                })
                .collect()
        } else {
            HashMap::new()
        };

        Ok(StateSyncMessage {
            header,
            snapshots: Snapshot { states, vm_storage },
            deltas: None,
            removed_components: HashMap::new(),
        })
    }

    /// Main method that does all the work.
    #[instrument(skip(self, block_tx),fields(extractor_id = %self.extractor_id))]
    async fn state_sync(self, block_tx: &mut Sender<StateSyncMessage>) -> SyncResult<()> {
        // initialisation
        let mut tracker = ComponentTracker::new(
            self.extractor_id.chain,
            self.extractor_id.name.as_str(),
            self.component_filter.clone(),
            self.rpc_client.clone(),
        );
        info!("Retrieving relevant protocol components");
        tracker.initialise_components().await?;

        info!(
            n_components = tracker.components.len(),
            n_contracts = tracker.contracts.len(),
            "Finished retrieving components",
        );
        let subscription_options = SubscriptionOptions::new().with_state(self.include_snapshots);
        let (_, mut msg_rx) = self
            .deltas_client
            .subscribe(self.extractor_id.clone(), subscription_options)
            .await?;

        info!("Waiting for deltas...");
        // we need to wait 2 messages because of cache gateways insertion delay.
        let first_msg = timeout(Duration::from_secs(360), msg_rx.recv())
            .await?
            .ok_or_else(|| anyhow::format_err!("Subscription ended too soon"))?;
        let mut second_msg = timeout(Duration::from_secs(360), msg_rx.recv())
            .await?
            .ok_or_else(|| anyhow::format_err!("Subscription ended too soon"))?;

        self.filter_deltas(&mut second_msg, &tracker);

        // initial snapshot
        let block = first_msg.get_block().clone();
        info!(height = &block.number, "Deltas received. Retrieving snapshot");
        let header = Header::from_block(first_msg.get_block(), first_msg.is_revert());
        let snapshot = self
            .get_snapshots::<Vec<&String>>(Header::from_block(&block, false), &tracker, None)
            .await
            .map_err(|rpc_err| anyhow::format_err!("failed to get initial snapshot: {}", rpc_err))?
            .merge(StateSyncMessage {
                header: Header::from_block(second_msg.get_block(), second_msg.is_revert()),
                snapshots: Default::default(),
                deltas: Some(second_msg),
                removed_components: Default::default(),
            });

        let n_components = tracker.components.len();
        let n_snapshots = snapshot.snapshots.states.len();
        info!(n_components, n_snapshots, "Initial snapshot retrieved, starting delta message feed");

        {
            let mut shared = self.shared.lock().await;
            block_tx.send(snapshot).await?;
            shared.last_synced_block = Some(header.clone());
        }

        loop {
            if let Some(mut deltas) = msg_rx.recv().await {
                let header = Header::from_block(deltas.get_block(), deltas.is_revert());
                debug!(block_number=?header.number, "Received delta message");
                let (snapshots, removed_components) = {
                    match &self.component_filter {
                        ComponentFilter::Ids(_) => (Default::default(), Default::default()),
                        ComponentFilter::MinimumTVL(min_tvl) => {
                            // 1. Remove components based on tvl changes
                            // 2. Add components based on tvl changes, query those for snapshots
                            let (to_add, to_remove): (Vec<_>, Vec<_>) = deltas
                                .component_tvl
                                .iter()
                                .partition(|(_, &tvl)| tvl > *min_tvl);

                            // Only components we don't track yet need a snapshot,
                            let requiring_snapshot = to_add
                                .iter()
                                .filter_map(|(k, _)| {
                                    if tracker.components.contains_key(*k) {
                                        None
                                    } else {
                                        Some(*k)
                                    }
                                })
                                .collect::<Vec<_>>();
                            debug!(components=?requiring_snapshot, "SnapshotRequest");
                            tracker
                                .start_tracking(&requiring_snapshot)
                                .await?;
                            let snapshots = self
                                .get_snapshots(header.clone(), &tracker, Some(requiring_snapshot))
                                .await?
                                .snapshots;

                            let removed_components = if !to_remove.is_empty() {
                                tracker.stop_tracking(to_remove.iter().map(|(id, _)| *id))
                            } else {
                                Default::default()
                            };
                            (snapshots, removed_components)
                        }
                    }
                };

                // 3. Filter deltas by currently tracked components / contracts
                self.filter_deltas(&mut deltas, &tracker);
                let n_changes = deltas.n_changes();

                let next = StateSyncMessage {
                    header: header.clone(),
                    snapshots,
                    deltas: Some(deltas),
                    removed_components,
                };
                block_tx.send(next).await?;
                {
                    let mut shared = self.shared.lock().await;
                    shared.last_synced_block = Some(header.clone());
                }

                debug!(block_number=?header.number, n_changes, "Finished processing delta message");
            } else {
                let mut shared = self.shared.lock().await;
                warn!(shared = ?&shared, "Deltas channel closed, resetting shared state.");
                shared.last_synced_block = None;

                return Err(anyhow::format_err!("Deltas channel closed!"));
            }
        }
    }

    fn filter_deltas(&self, second_msg: &mut BlockChanges, tracker: &ComponentTracker<R>) {
        second_msg.filter_by_component(|id| tracker.components.contains_key(id));
        second_msg.filter_by_contract(|id| tracker.contracts.contains(id));
    }
}

#[async_trait]
impl<R, D> StateSynchronizer for ProtocolStateSynchronizer<R, D>
where
    R: RPCClient + Clone + Send + Sync + 'static,
    D: DeltasClient + Clone + Send + Sync + 'static,
{
    async fn start(&self) -> SyncResult<(JoinHandle<SyncResult<()>>, Receiver<StateSyncMessage>)> {
        let (mut tx, rx) = channel(15);

        let this = self.clone();
        let jh = tokio::spawn(async move {
            let mut retry_count = 0;
            while retry_count < this.max_retries {
                info!(extractor_id=%&this.extractor_id, retry_count, "(Re)starting synchronization loop");
                let (end_tx, end_rx) = oneshot::channel::<()>();
                {
                    let mut end_tx_guard = this.end_tx.lock().await;
                    *end_tx_guard = Some(end_tx);
                }

                select! {
                    res = this.clone().state_sync(&mut tx) => {
                        match  res
                        {
                            Err(e) => {
                                error!(
                                    extractor_id=%&this.extractor_id,
                                    retry_count,
                                    error=%e,
                                    "State synchronization errored!"
                                );
                            }
                            _ => {
                                warn!(
                                    extractor_id=%&this.extractor_id,
                                    retry_count,
                                    "State sync exited with Ok(())"
                                );
                            }
                        }
                    },
                    _ = end_rx => {
                        info!(
                            extractor_id=%&this.extractor_id,
                            retry_count,
                            "StateSynchronizer received close signal. Stopping"
                        );
                        return Ok(())
                    }
                }
                retry_count += 1;
            }
            Err(anyhow::format_err!("Max retries exceeded giving up"))
        });

        Ok((jh, rx))
    }

    async fn close(&mut self) -> SyncResult<()> {
        let mut end_tx = self.end_tx.lock().await;
        if let Some(tx) = end_tx.take() {
            let _ = tx.send(());
            Ok(())
        } else {
            Err(anyhow::format_err!("Not started"))
        }
    }
}

#[cfg(test)]
mod test {
    use crate::{
        deltas::{DeltasClient, MockDeltasClient, SubscriptionOptions},
        feed::{
            component_tracker::{ComponentFilter, ComponentTracker},
            synchronizer::{
                ComponentWithState, ProtocolStateSynchronizer, Snapshot, StateSyncMessage,
                StateSynchronizer,
            },
            Header,
        },
        rpc::{MockRPCClient, RPCClient},
        DeltasError, RPCError,
    };
    use async_trait::async_trait;
    use mockall::predicate::always;
    use std::{collections::HashMap, sync::Arc, time::Duration};
    use test_log::test;
    use tokio::{
        sync::mpsc::{channel, Receiver, Sender},
        task::JoinHandle,
        time::timeout,
    };
    use tycho_core::{
        dto::{
            Block, BlockChanges, Chain, ExtractorIdentity, ProtocolComponent,
            ProtocolComponentRequestParameters, ProtocolComponentRequestResponse,
            ProtocolComponentsRequestBody, ProtocolId, ProtocolStateRequestBody,
            ProtocolStateRequestResponse, ResponseAccount, ResponseProtocolState, StateRequestBody,
            StateRequestParameters, StateRequestResponse, TokensRequestBody, TokensRequestResponse,
        },
        Bytes,
    };
    use uuid::Uuid;

    // Required for mock client to implement clone
    struct ArcRPCClient<T>(Arc<T>);

    // Default derive(Clone) does require T to be Clone as well.
    impl<T> Clone for ArcRPCClient<T> {
        fn clone(&self) -> Self {
            ArcRPCClient(self.0.clone())
        }
    }

    #[async_trait]
    impl<T> RPCClient for ArcRPCClient<T>
    where
        T: RPCClient + Sync + Send + 'static,
    {
        async fn get_tokens(
            &self,
            chain: &Chain,
            request: &TokensRequestBody,
        ) -> Result<TokensRequestResponse, RPCError> {
            self.0.get_tokens(chain, request).await
        }

        async fn get_contract_state(
            &self,
            chain: Chain,
            filters: &StateRequestParameters,
            request: &StateRequestBody,
        ) -> Result<StateRequestResponse, RPCError> {
            self.0
                .get_contract_state(chain, filters, request)
                .await
        }

        async fn get_protocol_components(
            &self,
            chain: Chain,
            filters: &ProtocolComponentRequestParameters,
            request: &ProtocolComponentsRequestBody,
        ) -> Result<ProtocolComponentRequestResponse, RPCError> {
            self.0
                .get_protocol_components(chain, filters, request)
                .await
        }

        async fn get_protocol_states(
            &self,
            chain: Chain,
            filters: &StateRequestParameters,
            request: &ProtocolStateRequestBody,
        ) -> Result<ProtocolStateRequestResponse, RPCError> {
            self.0
                .get_protocol_states(chain, filters, request)
                .await
        }
    }

    // Required for mock client to implement clone
    struct ArcDeltasClient<T>(Arc<T>);

    // Default derive(Clone) does require T to be Clone as well.
    impl<T> Clone for ArcDeltasClient<T> {
        fn clone(&self) -> Self {
            ArcDeltasClient(self.0.clone())
        }
    }

    #[async_trait]
    impl<T> DeltasClient for ArcDeltasClient<T>
    where
        T: DeltasClient + Sync + Send + 'static,
    {
        async fn subscribe(
            &self,
            extractor_id: ExtractorIdentity,
            options: SubscriptionOptions,
        ) -> Result<(Uuid, Receiver<BlockChanges>), DeltasError> {
            self.0
                .subscribe(extractor_id, options)
                .await
        }

        async fn unsubscribe(&self, subscription_id: Uuid) -> Result<(), DeltasError> {
            self.0
                .unsubscribe(subscription_id)
                .await
        }

        async fn connect(&self) -> Result<JoinHandle<Result<(), DeltasError>>, DeltasError> {
            self.0.connect().await
        }

        async fn close(&self) -> Result<(), DeltasError> {
            self.0.close().await
        }
    }

    fn with_mocked_clients(
        native: bool,
        rpc_client: Option<MockRPCClient>,
        deltas_client: Option<MockDeltasClient>,
    ) -> ProtocolStateSynchronizer<ArcRPCClient<MockRPCClient>, ArcDeltasClient<MockDeltasClient>>
    {
        let rpc_client = ArcRPCClient(Arc::new(rpc_client.unwrap_or_default()));
        let deltas_client = ArcDeltasClient(Arc::new(deltas_client.unwrap_or_default()));

        ProtocolStateSynchronizer::new(
            ExtractorIdentity::new(Chain::Ethereum, "uniswap-v2"),
            native,
            ComponentFilter::MinimumTVL(50.0),
            1,
            true,
            rpc_client,
            deltas_client,
        )
    }

    fn state_snapshot_native() -> ProtocolStateRequestResponse {
        ProtocolStateRequestResponse {
            states: vec![ResponseProtocolState {
                component_id: "Component1".to_string(),
                ..Default::default()
            }],
        }
    }

    #[test(tokio::test)]
    async fn test_get_snapshots_native() {
        let header = Header::default();
        let mut rpc = MockRPCClient::new();
        rpc.expect_get_protocol_states()
            .returning(|_, _, _| Ok(state_snapshot_native()));
        let state_sync = with_mocked_clients(true, Some(rpc), None);
        let mut tracker = ComponentTracker::new(
            Chain::Ethereum,
            "uniswap-v2",
            ComponentFilter::MinimumTVL(0.0),
            state_sync.rpc_client.clone(),
        );
        let component = ProtocolComponent { id: "Component1".to_string(), ..Default::default() };
        tracker
            .components
            .insert("Component1".to_string(), component.clone());
        let components_arg = ["Component1".to_string()];
        let exp = StateSyncMessage {
            header: header.clone(),
            snapshots: Snapshot {
                states: state_snapshot_native()
                    .states
                    .into_iter()
                    .map(|state| {
                        (
                            state.component_id.clone(),
                            ComponentWithState { state, component: component.clone() },
                        )
                    })
                    .collect(),
                vm_storage: HashMap::new(),
            },
            deltas: None,
            removed_components: Default::default(),
        };

        let snap = state_sync
            .get_snapshots(header, &tracker, Some(&components_arg))
            .await
            .expect("Retrieving snapshot failed");

        assert_eq!(snap, exp);
    }

    fn state_snapshot_vm() -> StateRequestResponse {
        StateRequestResponse {
            accounts: vec![
                ResponseAccount { address: Bytes::from("0x0badc0ffee"), ..Default::default() },
                ResponseAccount { address: Bytes::from("0xbabe42"), ..Default::default() },
            ],
        }
    }

    #[test(tokio::test)]
    async fn test_get_snapshots_vm() {
        let header = Header::default();
        let mut rpc = MockRPCClient::new();
        rpc.expect_get_protocol_states()
            .returning(|_, _, _| Ok(state_snapshot_native()));
        rpc.expect_get_contract_state()
            .returning(|_, _, _| Ok(state_snapshot_vm()));
        let state_sync = with_mocked_clients(false, Some(rpc), None);
        let mut tracker = ComponentTracker::new(
            Chain::Ethereum,
            "uniswap-v2",
            ComponentFilter::MinimumTVL(0.0),
            state_sync.rpc_client.clone(),
        );
        let component = ProtocolComponent {
            id: "Component1".to_string(),
            contract_ids: vec![Bytes::from("0x0badc0ffee"), Bytes::from("0xbabe42")],
            ..Default::default()
        };
        tracker
            .components
            .insert("Component1".to_string(), component.clone());
        let components_arg = ["Component1".to_string()];
        let exp = StateSyncMessage {
            header: header.clone(),
            snapshots: Snapshot {
                states: [(
                    component.id.clone(),
                    ComponentWithState {
                        state: ResponseProtocolState {
                            component_id: "Component1".to_string(),
                            ..Default::default()
                        },
                        component: component.clone(),
                    },
                )]
                .into_iter()
                .collect(),
                vm_storage: state_snapshot_vm()
                    .accounts
                    .into_iter()
                    .map(|state| (state.address.clone(), state))
                    .collect(),
            },
            deltas: None,
            removed_components: Default::default(),
        };

        let snap = state_sync
            .get_snapshots(header, &tracker, Some(&components_arg))
            .await
            .expect("Retrieving snapshot failed");

        assert_eq!(snap, exp);
    }

    fn mock_clients_for_state_sync() -> (MockRPCClient, MockDeltasClient, Sender<BlockChanges>) {
        let mut rpc_client = MockRPCClient::new();
        // Mocks for the start_tracking call, these need to come first because they are more
        // specific, see: https://docs.rs/mockall/latest/mockall/#matching-multiple-calls
        rpc_client
            .expect_get_protocol_components()
            .with(
                always(),
                always(),
                mockall::predicate::function(
                    move |request_params: &ProtocolComponentsRequestBody| {
                        if let Some(ids) = request_params.component_ids.as_ref() {
                            ids.contains(&"Component3".to_string())
                        } else {
                            false
                        }
                    },
                ),
            )
            .returning(|_, _, _| {
                // return Component3
                Ok(ProtocolComponentRequestResponse {
                    protocol_components: vec![
                        // this component shall have a tvl update above threshold
                        ProtocolComponent { id: "Component3".to_string(), ..Default::default() },
                    ],
                })
            });
        rpc_client
            .expect_get_protocol_states()
            .with(
                always(),
                always(),
                mockall::predicate::function(move |request_params: &ProtocolStateRequestBody| {
                    let expected_id =
                        ProtocolId { chain: Chain::Ethereum, id: "Component3".to_string() };
                    if let Some(ids) = request_params.protocol_ids.as_ref() {
                        ids.contains(&expected_id)
                    } else {
                        false
                    }
                }),
            )
            .returning(|_, _, _| {
                // return Component3 state
                Ok(ProtocolStateRequestResponse {
                    states: vec![ResponseProtocolState {
                        component_id: "Component3".to_string(),
                        ..Default::default()
                    }],
                })
            });

        // mock calls for the initial state snapshots
        rpc_client
            .expect_get_protocol_components()
            .returning(|_, _, _| {
                // Initial sync of components
                Ok(ProtocolComponentRequestResponse {
                    protocol_components: vec![
                        // this component shall have a tvl update above threshold
                        ProtocolComponent { id: "Component1".to_string(), ..Default::default() },
                        // this component shall have a tvl update below threshold.
                        ProtocolComponent { id: "Component2".to_string(), ..Default::default() },
                        // a third component will have a tvl update above threshold
                    ],
                })
            });
        rpc_client
            .expect_get_protocol_states()
            .returning(|_, _, _| {
                // Initial state snapshot
                Ok(ProtocolStateRequestResponse {
                    states: vec![
                        ResponseProtocolState {
                            component_id: "Component1".to_string(),
                            ..Default::default()
                        },
                        ResponseProtocolState {
                            component_id: "Component2".to_string(),
                            ..Default::default()
                        },
                    ],
                })
            });
        // Mock deltas client and messages
        let mut deltas_client = MockDeltasClient::new();
        let (tx, rx) = channel(1);
        deltas_client
            .expect_subscribe()
            .return_once(move |_, _| {
                // Return subscriber id and a channel
                Ok((Uuid::default(), rx))
            });
        (rpc_client, deltas_client, tx)
    }

    /// Test strategy
    ///
    /// - initial snapshot retrieval returns two component1 and component2 as snapshots
    /// - send 2 dummy messages, containing only blocks
    /// - third message contains a new component with some significant tvl, one initial component
    ///   slips below tvl threshold, another one is above tvl but does not get re-requested.
    #[test(tokio::test)]
    async fn test_state_sync() {
        let (rpc_client, deltas_client, tx) = mock_clients_for_state_sync();
        let deltas = [
            BlockChanges {
                extractor: "uniswap-v2".to_string(),
                chain: Chain::Ethereum,
                block: Block {
                    number: 1,
                    hash: Bytes::from("0x01"),
                    parent_hash: Bytes::from("0x00"),
                    chain: Chain::Ethereum,
                    ts: Default::default(),
                },
                revert: false,
                ..Default::default()
            },
            BlockChanges {
                extractor: "uniswap-v2".to_string(),
                chain: Chain::Ethereum,
                block: Block {
                    number: 2,
                    hash: Bytes::from("0x02"),
                    parent_hash: Bytes::from("0x01"),
                    chain: Chain::Ethereum,
                    ts: Default::default(),
                },
                revert: false,
                ..Default::default()
            },
            BlockChanges {
                extractor: "uniswap-v2".to_string(),
                chain: Chain::Ethereum,
                block: Block {
                    number: 3,
                    hash: Bytes::from("0x03"),
                    parent_hash: Bytes::from("0x02"),
                    chain: Chain::Ethereum,
                    ts: Default::default(),
                },
                revert: false,
                component_tvl: [
                    ("Component1".to_string(), 100.0),
                    ("Component2".to_string(), 0.0),
                    ("Component3".to_string(), 1000.0),
                ]
                .into_iter()
                .collect(),
                ..Default::default()
            },
        ];
        let mut state_sync = with_mocked_clients(true, Some(rpc_client), Some(deltas_client));

        // Test starts here
        let (jh, mut rx) = state_sync
            .start()
            .await
            .expect("Failed to start state synchronizer");
        tx.send(deltas[0].clone())
            .await
            .expect("deltas channel msg 0 closed!");
        tx.send(deltas[1].clone())
            .await
            .expect("deltas channel msg 1 closed!");
        let first_msg = timeout(Duration::from_millis(100), rx.recv())
            .await
            .expect("waiting for first state msg timed out!")
            .expect("state sync block sender closed!");
        tx.send(deltas[2].clone())
            .await
            .expect("deltas channel msg 2 closed!");
        let second_msg = timeout(Duration::from_millis(100), rx.recv())
            .await
            .expect("waiting for second state msg timed out!")
            .expect("state sync block sender closed!");
        let _ = state_sync.close().await;
        let exit = jh
            .await
            .expect("state sync task panicked!");

        // assertions
        let exp = StateSyncMessage {
            header: Header {
                number: 2,
                hash: Bytes::from("0x02"),
                parent_hash: Bytes::from("0x01"),
                revert: false,
            },
            snapshots: Snapshot {
                states: [
                    (
                        "Component1".to_string(),
                        ComponentWithState {
                            state: ResponseProtocolState {
                                component_id: "Component1".to_string(),
                                ..Default::default()
                            },
                            component: ProtocolComponent {
                                id: "Component1".to_string(),
                                ..Default::default()
                            },
                        },
                    ),
                    (
                        "Component2".to_string(),
                        ComponentWithState {
                            state: ResponseProtocolState {
                                component_id: "Component2".to_string(),
                                ..Default::default()
                            },
                            component: ProtocolComponent {
                                id: "Component2".to_string(),
                                ..Default::default()
                            },
                        },
                    ),
                ]
                .into_iter()
                .collect(),
                vm_storage: HashMap::new(),
            },
            deltas: Some(deltas[1].clone()),
            removed_components: Default::default(),
        };

        let exp2 = StateSyncMessage {
            header: Header {
                number: 3,
                hash: Bytes::from("0x03"),
                parent_hash: Bytes::from("0x02"),
                revert: false,
            },
            snapshots: Snapshot {
                states: [
                    // This is the new component we queried once it passed the tvl threshold.
                    (
                        "Component3".to_string(),
                        ComponentWithState {
                            state: ResponseProtocolState {
                                component_id: "Component3".to_string(),
                                ..Default::default()
                            },
                            component: ProtocolComponent {
                                id: "Component3".to_string(),
                                ..Default::default()
                            },
                        },
                    ),
                ]
                .into_iter()
                .collect(),
                vm_storage: HashMap::new(),
            },
            // Our deltas are empty and since merge methods are
            // tested in tycho-core we don't have much to do here.
            deltas: Some(BlockChanges {
                extractor: "uniswap-v2".to_string(),
                chain: Chain::Ethereum,
                block: Block {
                    number: 3,
                    hash: Bytes::from("0x03"),
                    parent_hash: Bytes::from("0x02"),
                    chain: Chain::Ethereum,
                    ts: Default::default(),
                },
                revert: false,
                component_tvl: [
                    // "Component2" should not show here.
                    ("Component1".to_string(), 100.0),
                    ("Component3".to_string(), 1000.0),
                ]
                .into_iter()
                .collect(),
                ..Default::default()
            }),
            // "Component2" was removed, because it's tvl changed to 0.
            removed_components: [(
                "Component2".to_string(),
                ProtocolComponent { id: "Component2".to_string(), ..Default::default() },
            )]
            .into_iter()
            .collect(),
        };
        assert_eq!(first_msg, exp);
        assert_eq!(second_msg, exp2);
        assert!(exit.is_ok());
    }
}
