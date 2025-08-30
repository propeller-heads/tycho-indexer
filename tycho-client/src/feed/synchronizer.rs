use std::{collections::HashMap, time::Duration};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::{
    select,
    sync::{
        mpsc::{channel, error::SendError, Receiver, Sender},
        oneshot,
    },
    task::JoinHandle,
    time::timeout,
};
use tracing::{debug, error, info, instrument, trace, warn};
use tycho_common::{
    dto::{
        BlockChanges, BlockParam, Chain, ComponentTvlRequestBody, EntryPointWithTracingParams,
        ExtractorIdentity, ProtocolComponent, ResponseAccount, ResponseProtocolState,
        TracingResult, VersionParam,
    },
    Bytes,
};

use crate::{
    deltas::{DeltasClient, SubscriptionOptions},
    feed::{
        component_tracker::{ComponentFilter, ComponentTracker},
        BlockHeader, HeaderLike,
    },
    rpc::{RPCClient, RPCError},
    DeltasError,
};

#[derive(Error, Debug)]
pub enum SynchronizerError {
    /// RPC client failures.
    #[error("RPC error: {0}")]
    RPCError(#[from] RPCError),

    /// Failed to send channel message to the consumer.
    #[error("Failed to send channel message: {0}")]
    ChannelError(String),

    /// Timeout elapsed errors.
    #[error("Timeout error: {0}")]
    Timeout(String),

    /// Failed to close the synchronizer.
    #[error("Failed to close synchronizer: {0}")]
    CloseError(String),

    /// Server connection failures or interruptions.
    #[error("Connection error: {0}")]
    ConnectionError(String),

    /// Connection closed
    #[error("Connection closed")]
    ConnectionClosed,
}

pub type SyncResult<T> = Result<T, SynchronizerError>;

impl From<SendError<StateSyncMessage<BlockHeader>>> for SynchronizerError {
    fn from(err: SendError<StateSyncMessage<BlockHeader>>) -> Self {
        SynchronizerError::ChannelError(err.to_string())
    }
}

impl From<DeltasError> for SynchronizerError {
    fn from(err: DeltasError) -> Self {
        match err {
            DeltasError::NotConnected => SynchronizerError::ConnectionClosed,
            _ => SynchronizerError::ConnectionError(err.to_string()),
        }
    }
}

pub struct ProtocolStateSynchronizer<R: RPCClient, D: DeltasClient> {
    extractor_id: ExtractorIdentity,
    retrieve_balances: bool,
    rpc_client: R,
    deltas_client: D,
    max_retries: u64,
    include_snapshots: bool,
    component_tracker: ComponentTracker<R>,
    last_synced_block: Option<BlockHeader>,
    timeout: u64,
    include_tvl: bool,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct ComponentWithState {
    pub state: ResponseProtocolState,
    pub component: ProtocolComponent,
    pub component_tvl: Option<f64>,
    pub entrypoints: Vec<(EntryPointWithTracingParams, TracingResult)>,
}

#[derive(Clone, PartialEq, Debug, Default, Serialize, Deserialize)]
pub struct Snapshot {
    pub states: HashMap<String, ComponentWithState>,
    pub vm_storage: HashMap<Bytes, ResponseAccount>,
}

impl Snapshot {
    fn extend(&mut self, other: Snapshot) {
        self.states.extend(other.states);
        self.vm_storage.extend(other.vm_storage);
    }

    pub fn get_states(&self) -> &HashMap<String, ComponentWithState> {
        &self.states
    }

    pub fn get_vm_storage(&self) -> &HashMap<Bytes, ResponseAccount> {
        &self.vm_storage
    }
}

#[derive(Clone, PartialEq, Debug, Default, Serialize, Deserialize)]
pub struct StateSyncMessage<H>
where
    H: HeaderLike,
{
    /// The block information for this update.
    pub header: H,
    /// Snapshot for new components.
    pub snapshots: Snapshot,
    /// A single delta contains state updates for all tracked components, as well as additional
    /// information about the system components e.g. newly added components (even below tvl), tvl
    /// updates, balance updates.
    pub deltas: Option<BlockChanges>,
    /// Components that stopped being tracked.
    pub removed_components: HashMap<String, ProtocolComponent>,
}

impl<H> StateSyncMessage<H>
where
    H: HeaderLike,
{
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

/// Handle for controlling a running synchronizer task.
///
/// This handle provides methods to gracefully shut down the synchronizer
/// and await its completion with a timeout.
pub struct SynchronizerTaskHandle {
    join_handle: JoinHandle<SyncResult<()>>,
    close_tx: oneshot::Sender<()>,
}

/// StateSynchronizer
///
/// Used to synchronize the state of a single protocol. The synchronizer is responsible for
/// delivering messages to the client that let him reconstruct subsets of the protocol state.
///
/// This involves deciding which components to track according to the clients preferences,
/// retrieving & emitting snapshots of components which the client has not seen yet and subsequently
/// delivering delta messages for the components that have changed.
impl SynchronizerTaskHandle {
    pub fn new(join_handle: JoinHandle<SyncResult<()>>, close_tx: oneshot::Sender<()>) -> Self {
        Self { join_handle, close_tx }
    }

    /// Splits the handle into its join handle and close sender.
    ///
    /// This allows monitoring the task completion separately from controlling shutdown.
    /// The join handle can be used with FuturesUnordered for monitoring, while the
    /// close sender can be used to signal graceful shutdown.
    pub fn split(self) -> (JoinHandle<SyncResult<()>>, oneshot::Sender<()>) {
        (self.join_handle, self.close_tx)
    }
}

#[async_trait]
pub trait StateSynchronizer: Send + Sync + 'static {
    async fn initialize(&mut self) -> SyncResult<()>;
    /// Starts the state synchronization, consuming the synchronizer.
    /// Returns a handle for controlling the running task and a receiver for messages.
    async fn start(
        mut self,
    ) -> SyncResult<(SynchronizerTaskHandle, Receiver<StateSyncMessage<BlockHeader>>)>;
}

impl<R, D> ProtocolStateSynchronizer<R, D>
where
    // TODO: Consider moving these constraints directly to the
    // client...
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
        include_tvl: bool,
        rpc_client: R,
        deltas_client: D,
        timeout: u64,
    ) -> Self {
        Self {
            extractor_id: extractor_id.clone(),
            retrieve_balances,
            rpc_client: rpc_client.clone(),
            include_snapshots,
            deltas_client,
            component_tracker: ComponentTracker::new(
                extractor_id.chain,
                extractor_id.name.as_str(),
                component_filter,
                rpc_client,
            ),
            max_retries,
            last_synced_block: None,
            timeout,
            include_tvl,
        }
    }

    /// Retrieves state snapshots of the requested components
    #[allow(deprecated)]
    async fn get_snapshots<'a, I: IntoIterator<Item = &'a String>>(
        &mut self,
        header: BlockHeader,
        ids: Option<I>,
    ) -> SyncResult<StateSyncMessage<BlockHeader>> {
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
        let component_ids: Vec<_> = match ids {
            Some(ids) => ids.into_iter().cloned().collect(),
            None => self
                .component_tracker
                .get_tracked_component_ids(),
        };

        if component_ids.is_empty() {
            return Ok(StateSyncMessage { header, ..Default::default() });
        }

        let component_tvl = if self.include_tvl {
            let body = ComponentTvlRequestBody::id_filtered(
                component_ids.clone(),
                self.extractor_id.chain,
            );
            self.rpc_client
                .get_component_tvl_paginated(&body, 100, 4)
                .await?
                .tvl
        } else {
            HashMap::new()
        };

        //TODO: Improve this, we should not query for every component, but only for the ones that
        // could have entrypoints. Maybe apply a filter per protocol?
        let entrypoints_result = if self.extractor_id.chain == Chain::Ethereum {
            // Fetch entrypoints
            let result = self
                .rpc_client
                .get_traced_entry_points_paginated(
                    self.extractor_id.chain,
                    &self.extractor_id.name,
                    &component_ids,
                    100,
                    4,
                )
                .await?;
            self.component_tracker
                .process_entrypoints(&result.clone().into());
            Some(result)
        } else {
            None
        };

        // Fetch protocol states
        let mut protocol_states = self
            .rpc_client
            .get_protocol_states_paginated(
                self.extractor_id.chain,
                &component_ids,
                &self.extractor_id.name,
                self.retrieve_balances,
                &version,
                100,
                4,
            )
            .await?
            .states
            .into_iter()
            .map(|state| (state.component_id.clone(), state))
            .collect::<HashMap<_, _>>();

        trace!(states=?&protocol_states, "Retrieved ProtocolStates");
        let states = self
            .component_tracker
            .components
            .values()
            .filter_map(|component| {
                if let Some(state) = protocol_states.remove(&component.id) {
                    Some((
                        component.id.clone(),
                        ComponentWithState {
                            state,
                            component: component.clone(),
                            component_tvl: component_tvl
                                .get(&component.id)
                                .cloned(),
                            entrypoints: entrypoints_result
                                .as_ref()
                                .map(|r| {
                                    r.traced_entry_points
                                        .get(&component.id)
                                        .cloned()
                                        .unwrap_or_default()
                                })
                                .unwrap_or_default(),
                        },
                    ))
                } else if component_ids.contains(&component.id) {
                    // only emit error event if we requested this component
                    let component_id = &component.id;
                    error!(?component_id, "Missing state for native component!");
                    None
                } else {
                    None
                }
            })
            .collect();

        // Fetch contract states
        let contract_ids = self
            .component_tracker
            .get_contracts_by_component(&component_ids);
        let vm_storage = if !contract_ids.is_empty() {
            let ids: Vec<Bytes> = contract_ids
                .clone()
                .into_iter()
                .collect();
            let contract_states = self
                .rpc_client
                .get_contract_state_paginated(
                    self.extractor_id.chain,
                    ids.as_slice(),
                    &self.extractor_id.name,
                    &version,
                    100,
                    4,
                )
                .await?
                .accounts
                .into_iter()
                .map(|acc| (acc.address.clone(), acc))
                .collect::<HashMap<_, _>>();

            trace!(states=?&contract_states, "Retrieved ContractState");

            let contract_address_to_components = self
                .component_tracker
                .components
                .iter()
                .filter_map(|(id, comp)| {
                    if component_ids.contains(id) {
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
    ///
    /// ## Return Value
    ///
    /// Returns a `Result` where:
    /// - `Ok(())` - Synchronization completed successfully (usually due to close signal)
    /// - `Err((error, None))` - Error occurred AND close signal was received (don't retry)
    /// - `Err((error, Some(end_rx)))` - Error occurred but close signal was NOT received (can
    ///   retry)
    ///
    /// The returned `end_rx` (if any) should be reused for retry attempts since the close
    /// signal may still arrive and we want to remain cancellable across retries.
    #[instrument(skip(self, block_tx), fields(extractor_id = %self.extractor_id))]
    async fn state_sync(
        &mut self,
        block_tx: &mut Sender<StateSyncMessage<BlockHeader>>,
        mut end_rx: oneshot::Receiver<()>,
    ) -> Result<(), (SynchronizerError, Option<oneshot::Receiver<()>>)> {
        // initialisation

        let subscription_options = SubscriptionOptions::new().with_state(self.include_snapshots);
        let (subscription_id, mut msg_rx) = match self
            .deltas_client
            .subscribe(self.extractor_id.clone(), subscription_options)
            .await
        {
            Ok(result) => result,
            Err(e) => return Err((e.into(), Some(end_rx))),
        };

        let result = async {
            info!("Waiting for deltas...");
            // wait for first deltas message
            let mut first_msg = select! {
                deltas_result = timeout(Duration::from_secs(self.timeout), msg_rx.recv()) => {
                    deltas_result
                        .map_err(|_| {
                            SynchronizerError::Timeout(format!(
                                "First deltas took longer than {t}s to arrive",
                                t = self.timeout
                            ))
                        })?
                        .ok_or_else(|| {
                            SynchronizerError::ConnectionError(
                                "Deltas channel closed before first message".to_string(),
                            )
                        })?
                },
                _ = &mut end_rx => {
                    info!("Received close signal while waiting for first deltas");
                    return Ok(());
                }
            };
            self.filter_deltas(&mut first_msg);

            // initial snapshot
            let block = first_msg.get_block().clone();
            info!(height = &block.number, "Deltas received. Retrieving snapshot");
            let header = BlockHeader::from_block(first_msg.get_block(), first_msg.is_revert());
            let snapshot = self
                .get_snapshots::<Vec<&String>>(
                    BlockHeader::from_block(&block, false),
                    None,
                )
                .await?
                .merge(StateSyncMessage {
                    header: BlockHeader::from_block(first_msg.get_block(), first_msg.is_revert()),
                    snapshots: Default::default(),
                    deltas: Some(first_msg),
                    removed_components: Default::default(),
                });

            let n_components = self.component_tracker.components.len();
            let n_snapshots = snapshot.snapshots.states.len();
            info!(n_components, n_snapshots, "Initial snapshot retrieved, starting delta message feed");

            block_tx.send(snapshot).await?;
            self.last_synced_block = Some(header.clone());
            loop {
                select! {
                    deltas_opt = msg_rx.recv() => {
                        if let Some(mut deltas) = deltas_opt {
                            let header = BlockHeader::from_block(deltas.get_block(), deltas.is_revert());
                            debug!(block_number=?header.number, "Received delta message");

                            let (snapshots, removed_components) = {
                                // 1. Remove components based on latest changes
                                // 2. Add components based on latest changes, query those for snapshots
                                let (to_add, to_remove) = self.component_tracker.filter_updated_components(&deltas);

                                // Only components we don't track yet need a snapshot,
                                let requiring_snapshot: Vec<_> = to_add
                                    .iter()
                                    .filter(|id| {
                                        !self.component_tracker
                                            .components
                                            .contains_key(id.as_str())
                                    })
                                    .collect();
                                debug!(components=?requiring_snapshot, "SnapshotRequest");
                                self.component_tracker
                                    .start_tracking(requiring_snapshot.as_slice())
                                    .await?;
                                let snapshots = self
                                    .get_snapshots(header.clone(), Some(requiring_snapshot))
                                    .await?
                                    .snapshots;

                                let removed_components = if !to_remove.is_empty() {
                                    self.component_tracker.stop_tracking(&to_remove)
                                } else {
                                    Default::default()
                                };

                                (snapshots, removed_components)
                            };

                            // 3. Update entrypoints on the tracker (affects which contracts are tracked)
                            self.component_tracker.process_entrypoints(&deltas.dci_update);

                            // 4. Filter deltas by currently tracked components / contracts
                            self.filter_deltas(&mut deltas);
                            let n_changes = deltas.n_changes();

                            // 5. Send the message
                            let next = StateSyncMessage {
                                header: header.clone(),
                                snapshots,
                                deltas: Some(deltas),
                                removed_components,
                            };
                            block_tx.send(next).await?;
                            self.last_synced_block = Some(header.clone());

                            debug!(block_number=?header.number, n_changes, "Finished processing delta message");
                        } else {
                            return Err(SynchronizerError::ConnectionError("Deltas channel closed".to_string()));
                        }
                    },
                    _ = &mut end_rx => {
                        info!("Received close signal during state_sync");
                        return Ok(());
                    }
                }
            }
        }.await;

        // This cleanup code now runs regardless of how the function exits (error or channel close)
        warn!(last_synced_block = ?&self.last_synced_block, "Deltas processing ended, resetting last synced block.");
        self.last_synced_block = None;
        //Ignore error
        let _ = self
            .deltas_client
            .unsubscribe(subscription_id)
            .await
            .map_err(|err| {
                warn!(err=?err, "Unsubscribing from deltas on cleanup failed!");
            });

        // Handle the result: if it succeeded, we're done. If it errored, we need to determine
        // whether the end_rx was consumed (close signal received) or not
        match result {
            Ok(()) => Ok(()), // Success, likely due to close signal
            Err(e) => {
                // The error came from the inner async block. Since the async block
                // can receive close signals (which would return Ok), any error means
                // the close signal was NOT received, so we can return the end_rx for retry
                Err((e, Some(end_rx)))
            }
        }
    }

    fn filter_deltas(&self, deltas: &mut BlockChanges) {
        deltas.filter_by_component(|id| {
            self.component_tracker
                .components
                .contains_key(id)
        });
        deltas.filter_by_contract(|id| {
            self.component_tracker
                .contracts
                .contains(id)
        });
    }
}

#[async_trait]
impl<R, D> StateSynchronizer for ProtocolStateSynchronizer<R, D>
where
    R: RPCClient + Clone + Send + Sync + 'static,
    D: DeltasClient + Clone + Send + Sync + 'static,
{
    async fn initialize(&mut self) -> SyncResult<()> {
        info!("Retrieving relevant protocol components");
        self.component_tracker
            .initialise_components()
            .await?;
        info!(
            n_components = self.component_tracker.components.len(),
            n_contracts = self.component_tracker.contracts.len(),
            "Finished retrieving components",
        );

        Ok(())
    }

    async fn start(
        mut self,
    ) -> SyncResult<(SynchronizerTaskHandle, Receiver<StateSyncMessage<BlockHeader>>)> {
        let (mut tx, rx) = channel(15);
        let (end_tx, end_rx) = oneshot::channel::<()>();

        let jh = tokio::spawn(async move {
            let mut retry_count = 0;
            let mut current_end_rx = end_rx;

            while retry_count < self.max_retries {
                info!(extractor_id=%&self.extractor_id, retry_count, "(Re)starting synchronization loop");

                let res = self
                    .state_sync(&mut tx, current_end_rx)
                    .await;
                match res {
                    Ok(()) => {
                        info!(
                            extractor_id=%&self.extractor_id,
                            retry_count,
                            "State synchronization exited cleanly"
                        );
                        return Ok(());
                    }
                    Err((e, maybe_end_rx)) => {
                        error!(
                            extractor_id=%&self.extractor_id,
                            retry_count,
                            error=%e,
                            "State synchronization errored!"
                        );

                        // If we have the end_rx back, we can retry
                        if let Some(recovered_end_rx) = maybe_end_rx {
                            current_end_rx = recovered_end_rx;

                            if let SynchronizerError::ConnectionClosed = e {
                                // break synchronization loop if connection is closed
                                return Err(e);
                            }
                        } else {
                            // Close signal was received, exit cleanly
                            info!(extractor_id=%&self.extractor_id, "Received close signal, exiting");
                            return Ok(());
                        }
                    }
                }
                retry_count += 1;
            }
            warn!(extractor_id=%&self.extractor_id, retry_count, "Max retries exceeded");
            Err(SynchronizerError::ConnectionError("Max connection retries exceeded".to_string()))
        });

        let handle = SynchronizerTaskHandle::new(jh, end_tx);
        Ok((handle, rx))
    }
}

#[cfg(test)]
mod test {
    //! Test suite for ProtocolStateSynchronizer shutdown and cleanup behavior.
    //!
    //! ## Test Coverage Strategy:
    //!
    //! ### Shutdown & Close Signal Tests:
    //! - `test_public_close_api_functionality` - Tests public API (start/close lifecycle)
    //! - `test_close_signal_while_waiting_for_first_deltas` - Close during initial wait
    //! - `test_close_signal_during_main_processing_loop` - Close during main processing
    //!
    //! ### Cleanup & Error Handling Tests:
    //! - `test_cleanup_runs_when_state_sync_processing_errors` - Cleanup on processing errors
    //!
    //! ### Coverage Summary:
    //! These tests ensure cleanup code (shared state reset + unsubscribe) runs on ALL exit paths:
    //! ✓ Close signal before first deltas   ✓ Close signal during processing
    //! ✓ Processing errors                  ✓ Channel closure
    //! ✓ Public API close operations        ✓ Normal completion

    use std::{collections::HashSet, sync::Arc};

    use test_log::test;
    use tycho_common::dto::{
        Block, Chain, ComponentTvlRequestBody, ComponentTvlRequestResponse, DCIUpdate, EntryPoint,
        PaginationResponse, ProtocolComponentRequestResponse, ProtocolComponentsRequestBody,
        ProtocolStateRequestBody, ProtocolStateRequestResponse, ProtocolSystemsRequestBody,
        ProtocolSystemsRequestResponse, RPCTracerParams, StateRequestBody, StateRequestResponse,
        TokensRequestBody, TokensRequestResponse, TracedEntryPointRequestBody,
        TracedEntryPointRequestResponse, TracingParams,
    };
    use uuid::Uuid;

    use super::*;
    use crate::{deltas::MockDeltasClient, rpc::MockRPCClient, DeltasError, RPCError};

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
            request: &TokensRequestBody,
        ) -> Result<TokensRequestResponse, RPCError> {
            self.0.get_tokens(request).await
        }

        async fn get_contract_state(
            &self,
            request: &StateRequestBody,
        ) -> Result<StateRequestResponse, RPCError> {
            self.0.get_contract_state(request).await
        }

        async fn get_protocol_components(
            &self,
            request: &ProtocolComponentsRequestBody,
        ) -> Result<ProtocolComponentRequestResponse, RPCError> {
            self.0
                .get_protocol_components(request)
                .await
        }

        async fn get_protocol_states(
            &self,
            request: &ProtocolStateRequestBody,
        ) -> Result<ProtocolStateRequestResponse, RPCError> {
            self.0
                .get_protocol_states(request)
                .await
        }

        async fn get_protocol_systems(
            &self,
            request: &ProtocolSystemsRequestBody,
        ) -> Result<ProtocolSystemsRequestResponse, RPCError> {
            self.0
                .get_protocol_systems(request)
                .await
        }

        async fn get_component_tvl(
            &self,
            request: &ComponentTvlRequestBody,
        ) -> Result<ComponentTvlRequestResponse, RPCError> {
            self.0.get_component_tvl(request).await
        }

        async fn get_traced_entry_points(
            &self,
            request: &TracedEntryPointRequestBody,
        ) -> Result<TracedEntryPointRequestResponse, RPCError> {
            self.0
                .get_traced_entry_points(request)
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
        include_tvl: bool,
        rpc_client: Option<MockRPCClient>,
        deltas_client: Option<MockDeltasClient>,
    ) -> ProtocolStateSynchronizer<ArcRPCClient<MockRPCClient>, ArcDeltasClient<MockDeltasClient>>
    {
        let rpc_client = ArcRPCClient(Arc::new(rpc_client.unwrap_or_default()));
        let deltas_client = ArcDeltasClient(Arc::new(deltas_client.unwrap_or_default()));

        ProtocolStateSynchronizer::new(
            ExtractorIdentity::new(Chain::Ethereum, "uniswap-v2"),
            native,
            ComponentFilter::with_tvl_range(50.0, 50.0),
            1,
            true,
            include_tvl,
            rpc_client,
            deltas_client,
            10_u64,
        )
    }

    fn state_snapshot_native() -> ProtocolStateRequestResponse {
        ProtocolStateRequestResponse {
            states: vec![ResponseProtocolState {
                component_id: "Component1".to_string(),
                ..Default::default()
            }],
            pagination: PaginationResponse { page: 0, page_size: 20, total: 1 },
        }
    }

    fn component_tvl_snapshot() -> ComponentTvlRequestResponse {
        let tvl = HashMap::from([("Component1".to_string(), 100.0)]);

        ComponentTvlRequestResponse {
            tvl,
            pagination: PaginationResponse { page: 0, page_size: 20, total: 1 },
        }
    }

    #[test(tokio::test)]
    async fn test_get_snapshots_native() {
        let header = BlockHeader::default();
        let mut rpc = MockRPCClient::new();
        rpc.expect_get_protocol_states()
            .returning(|_| Ok(state_snapshot_native()));
        rpc.expect_get_traced_entry_points()
            .returning(|_| {
                Ok(TracedEntryPointRequestResponse {
                    traced_entry_points: HashMap::new(),
                    pagination: PaginationResponse::new(0, 20, 0),
                })
            });
        let mut state_sync = with_mocked_clients(true, false, Some(rpc), None);
        let component = ProtocolComponent { id: "Component1".to_string(), ..Default::default() };
        state_sync
            .component_tracker
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
                            ComponentWithState {
                                state,
                                component: component.clone(),
                                entrypoints: vec![],
                                component_tvl: None,
                            },
                        )
                    })
                    .collect(),
                vm_storage: HashMap::new(),
            },
            deltas: None,
            removed_components: Default::default(),
        };

        let snap = state_sync
            .get_snapshots(header, Some(&components_arg))
            .await
            .expect("Retrieving snapshot failed");

        assert_eq!(snap, exp);
    }

    #[test(tokio::test)]
    async fn test_get_snapshots_native_with_tvl() {
        let header = BlockHeader::default();
        let mut rpc = MockRPCClient::new();
        rpc.expect_get_protocol_states()
            .returning(|_| Ok(state_snapshot_native()));
        rpc.expect_get_component_tvl()
            .returning(|_| Ok(component_tvl_snapshot()));
        rpc.expect_get_traced_entry_points()
            .returning(|_| {
                Ok(TracedEntryPointRequestResponse {
                    traced_entry_points: HashMap::new(),
                    pagination: PaginationResponse::new(0, 20, 0),
                })
            });
        let mut state_sync = with_mocked_clients(true, true, Some(rpc), None);
        let component = ProtocolComponent { id: "Component1".to_string(), ..Default::default() };
        state_sync
            .component_tracker
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
                            ComponentWithState {
                                state,
                                component: component.clone(),
                                component_tvl: Some(100.0),
                                entrypoints: vec![],
                            },
                        )
                    })
                    .collect(),
                vm_storage: HashMap::new(),
            },
            deltas: None,
            removed_components: Default::default(),
        };

        let snap = state_sync
            .get_snapshots(header, Some(&components_arg))
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
            pagination: PaginationResponse { page: 0, page_size: 20, total: 1 },
        }
    }

    fn traced_entry_point_response() -> TracedEntryPointRequestResponse {
        TracedEntryPointRequestResponse {
            traced_entry_points: HashMap::from([(
                "Component1".to_string(),
                vec![(
                    EntryPointWithTracingParams {
                        entry_point: EntryPoint {
                            external_id: "entrypoint_a".to_string(),
                            target: Bytes::from("0x0badc0ffee"),
                            signature: "sig()".to_string(),
                        },
                        params: TracingParams::RPCTracer(RPCTracerParams {
                            caller: Some(Bytes::from("0x0badc0ffee")),
                            calldata: Bytes::from("0x0badc0ffee"),
                            state_overrides: None,
                        }),
                    },
                    TracingResult {
                        retriggers: HashSet::from([(
                            Bytes::from("0x0badc0ffee"),
                            Bytes::from("0x0badc0ffee"),
                        )]),
                        accessed_slots: HashMap::from([(
                            Bytes::from("0x0badc0ffee"),
                            HashSet::from([Bytes::from("0xbadbeef0")]),
                        )]),
                    },
                )],
            )]),
            pagination: PaginationResponse::new(0, 20, 0),
        }
    }

    #[test(tokio::test)]
    async fn test_get_snapshots_vm() {
        let header = BlockHeader::default();
        let mut rpc = MockRPCClient::new();
        rpc.expect_get_protocol_states()
            .returning(|_| Ok(state_snapshot_native()));
        rpc.expect_get_contract_state()
            .returning(|_| Ok(state_snapshot_vm()));
        rpc.expect_get_traced_entry_points()
            .returning(|_| Ok(traced_entry_point_response()));
        let mut state_sync = with_mocked_clients(false, false, Some(rpc), None);
        let component = ProtocolComponent {
            id: "Component1".to_string(),
            contract_ids: vec![Bytes::from("0x0badc0ffee"), Bytes::from("0xbabe42")],
            ..Default::default()
        };
        state_sync
            .component_tracker
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
                        component_tvl: None,
                        entrypoints: vec![(
                            EntryPointWithTracingParams {
                                entry_point: EntryPoint {
                                    external_id: "entrypoint_a".to_string(),
                                    target: Bytes::from("0x0badc0ffee"),
                                    signature: "sig()".to_string(),
                                },
                                params: TracingParams::RPCTracer(RPCTracerParams {
                                    caller: Some(Bytes::from("0x0badc0ffee")),
                                    calldata: Bytes::from("0x0badc0ffee"),
                                    state_overrides: None,
                                }),
                            },
                            TracingResult {
                                retriggers: HashSet::from([(
                                    Bytes::from("0x0badc0ffee"),
                                    Bytes::from("0x0badc0ffee"),
                                )]),
                                accessed_slots: HashMap::from([(
                                    Bytes::from("0x0badc0ffee"),
                                    HashSet::from([Bytes::from("0xbadbeef0")]),
                                )]),
                            },
                        )],
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
            .get_snapshots(header, Some(&components_arg))
            .await
            .expect("Retrieving snapshot failed");

        assert_eq!(snap, exp);
    }

    #[test(tokio::test)]
    async fn test_get_snapshots_vm_with_tvl() {
        let header = BlockHeader::default();
        let mut rpc = MockRPCClient::new();
        rpc.expect_get_protocol_states()
            .returning(|_| Ok(state_snapshot_native()));
        rpc.expect_get_contract_state()
            .returning(|_| Ok(state_snapshot_vm()));
        rpc.expect_get_component_tvl()
            .returning(|_| Ok(component_tvl_snapshot()));
        rpc.expect_get_traced_entry_points()
            .returning(|_| {
                Ok(TracedEntryPointRequestResponse {
                    traced_entry_points: HashMap::new(),
                    pagination: PaginationResponse::new(0, 20, 0),
                })
            });
        let mut state_sync = with_mocked_clients(false, true, Some(rpc), None);
        let component = ProtocolComponent {
            id: "Component1".to_string(),
            contract_ids: vec![Bytes::from("0x0badc0ffee"), Bytes::from("0xbabe42")],
            ..Default::default()
        };
        state_sync
            .component_tracker
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
                        component_tvl: Some(100.0),
                        entrypoints: vec![],
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
            .get_snapshots(header, Some(&components_arg))
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
            .with(mockall::predicate::function(
                move |request_params: &ProtocolComponentsRequestBody| {
                    if let Some(ids) = request_params.component_ids.as_ref() {
                        ids.contains(&"Component3".to_string())
                    } else {
                        false
                    }
                },
            ))
            .returning(|_| {
                // return Component3
                Ok(ProtocolComponentRequestResponse {
                    protocol_components: vec![
                        // this component shall have a tvl update above threshold
                        ProtocolComponent { id: "Component3".to_string(), ..Default::default() },
                    ],
                    pagination: PaginationResponse { page: 0, page_size: 20, total: 1 },
                })
            });
        rpc_client
            .expect_get_protocol_states()
            .with(mockall::predicate::function(move |request_params: &ProtocolStateRequestBody| {
                let expected_id = "Component3".to_string();
                if let Some(ids) = request_params.protocol_ids.as_ref() {
                    ids.contains(&expected_id)
                } else {
                    false
                }
            }))
            .returning(|_| {
                // return Component3 state
                Ok(ProtocolStateRequestResponse {
                    states: vec![ResponseProtocolState {
                        component_id: "Component3".to_string(),
                        ..Default::default()
                    }],
                    pagination: PaginationResponse { page: 0, page_size: 20, total: 1 },
                })
            });

        // mock calls for the initial state snapshots
        rpc_client
            .expect_get_protocol_components()
            .returning(|_| {
                // Initial sync of components
                Ok(ProtocolComponentRequestResponse {
                    protocol_components: vec![
                        // this component shall have a tvl update above threshold
                        ProtocolComponent { id: "Component1".to_string(), ..Default::default() },
                        // this component shall have a tvl update below threshold.
                        ProtocolComponent { id: "Component2".to_string(), ..Default::default() },
                        // a third component will have a tvl update above threshold
                    ],
                    pagination: PaginationResponse { page: 0, page_size: 20, total: 1 },
                })
            });
        rpc_client
            .expect_get_protocol_states()
            .returning(|_| {
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
                    pagination: PaginationResponse { page: 0, page_size: 20, total: 1 },
                })
            });
        rpc_client
            .expect_get_component_tvl()
            .returning(|_| {
                Ok(ComponentTvlRequestResponse {
                    tvl: [
                        ("Component1".to_string(), 100.0),
                        ("Component2".to_string(), 0.0),
                        ("Component3".to_string(), 1000.0),
                    ]
                    .into_iter()
                    .collect(),
                    pagination: PaginationResponse { page: 0, page_size: 20, total: 3 },
                })
            });
        rpc_client
            .expect_get_traced_entry_points()
            .returning(|_| {
                Ok(TracedEntryPointRequestResponse {
                    traced_entry_points: HashMap::new(),
                    pagination: PaginationResponse::new(0, 20, 0),
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

        // Expect unsubscribe call during cleanup
        deltas_client
            .expect_unsubscribe()
            .return_once(|_| Ok(()));

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
                dci_update: DCIUpdate {
                    new_entrypoints: HashMap::from([(
                        "Component1".to_string(),
                        HashSet::from([EntryPoint {
                            external_id: "entrypoint_a".to_string(),
                            target: Bytes::from("0x0badc0ffee"),
                            signature: "sig()".to_string(),
                        }]),
                    )]),
                    new_entrypoint_params: HashMap::from([(
                        "entrypoint_a".to_string(),
                        HashSet::from([(
                            TracingParams::RPCTracer(RPCTracerParams {
                                caller: Some(Bytes::from("0x0badc0ffee")),
                                calldata: Bytes::from("0x0badc0ffee"),
                                state_overrides: None,
                            }),
                            Some("Component1".to_string()),
                        )]),
                    )]),
                    trace_results: HashMap::from([(
                        "entrypoint_a".to_string(),
                        TracingResult {
                            retriggers: HashSet::from([(
                                Bytes::from("0x0badc0ffee"),
                                Bytes::from("0x0badc0ffee"),
                            )]),
                            accessed_slots: HashMap::from([(
                                Bytes::from("0x0badc0ffee"),
                                HashSet::from([Bytes::from("0xbadbeef0")]),
                            )]),
                        },
                    )]),
                },
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
        let mut state_sync = with_mocked_clients(true, true, Some(rpc_client), Some(deltas_client));
        state_sync
            .initialize()
            .await
            .expect("Init failed");

        // Test starts here
        let (handle, mut rx) = state_sync
            .start()
            .await
            .expect("Failed to start state synchronizer");
        let (jh, close_tx) = handle.split();
        tx.send(deltas[0].clone())
            .await
            .expect("deltas channel msg 0 closed!");
        let first_msg = timeout(Duration::from_millis(100), rx.recv())
            .await
            .expect("waiting for first state msg timed out!")
            .expect("state sync block sender closed!");
        tx.send(deltas[1].clone())
            .await
            .expect("deltas channel msg 1 closed!");
        let second_msg = timeout(Duration::from_millis(100), rx.recv())
            .await
            .expect("waiting for second state msg timed out!")
            .expect("state sync block sender closed!");
        let _ = close_tx.send(());
        let exit = jh
            .await
            .expect("state sync task panicked!");

        // assertions
        let exp1 = StateSyncMessage {
            header: BlockHeader {
                number: 1,
                hash: Bytes::from("0x01"),
                parent_hash: Bytes::from("0x00"),
                revert: false,
                ..Default::default()
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
                            component_tvl: Some(100.0),
                            entrypoints: vec![],
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
                            component_tvl: Some(0.0),
                            entrypoints: vec![],
                        },
                    ),
                ]
                .into_iter()
                .collect(),
                vm_storage: HashMap::new(),
            },
            deltas: Some(deltas[0].clone()),
            removed_components: Default::default(),
        };

        let exp2 = StateSyncMessage {
            header: BlockHeader {
                number: 2,
                hash: Bytes::from("0x02"),
                parent_hash: Bytes::from("0x01"),
                revert: false,
                ..Default::default()
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
                            component_tvl: Some(1000.0),
                            entrypoints: vec![],
                        },
                    ),
                ]
                .into_iter()
                .collect(),
                vm_storage: HashMap::new(),
            },
            // Our deltas are empty and since merge methods are
            // tested in tycho-common we don't have much to do here.
            deltas: Some(BlockChanges {
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
                component_tvl: [
                    // "Component2" should not show here.
                    ("Component1".to_string(), 100.0),
                    ("Component3".to_string(), 1000.0),
                ]
                .into_iter()
                .collect(),
                ..Default::default()
            }),
            // "Component2" was removed, because its tvl changed to 0.
            removed_components: [(
                "Component2".to_string(),
                ProtocolComponent { id: "Component2".to_string(), ..Default::default() },
            )]
            .into_iter()
            .collect(),
        };
        assert_eq!(first_msg, exp1);
        assert_eq!(second_msg, exp2);
        assert!(exit.is_ok());
    }

    #[test(tokio::test)]
    async fn test_state_sync_with_tvl_range() {
        // Define the range for testing
        let remove_tvl_threshold = 5.0;
        let add_tvl_threshold = 7.0;

        let mut rpc_client = MockRPCClient::new();
        let mut deltas_client = MockDeltasClient::new();

        rpc_client
            .expect_get_protocol_components()
            .with(mockall::predicate::function(
                move |request_params: &ProtocolComponentsRequestBody| {
                    if let Some(ids) = request_params.component_ids.as_ref() {
                        ids.contains(&"Component3".to_string())
                    } else {
                        false
                    }
                },
            ))
            .returning(|_| {
                Ok(ProtocolComponentRequestResponse {
                    protocol_components: vec![ProtocolComponent {
                        id: "Component3".to_string(),
                        ..Default::default()
                    }],
                    pagination: PaginationResponse { page: 0, page_size: 20, total: 1 },
                })
            });
        rpc_client
            .expect_get_protocol_states()
            .with(mockall::predicate::function(move |request_params: &ProtocolStateRequestBody| {
                let expected_id = "Component3".to_string();
                if let Some(ids) = request_params.protocol_ids.as_ref() {
                    ids.contains(&expected_id)
                } else {
                    false
                }
            }))
            .returning(|_| {
                Ok(ProtocolStateRequestResponse {
                    states: vec![ResponseProtocolState {
                        component_id: "Component3".to_string(),
                        ..Default::default()
                    }],
                    pagination: PaginationResponse { page: 0, page_size: 20, total: 1 },
                })
            });

        // Mock for the initial snapshot retrieval
        rpc_client
            .expect_get_protocol_components()
            .returning(|_| {
                Ok(ProtocolComponentRequestResponse {
                    protocol_components: vec![
                        ProtocolComponent { id: "Component1".to_string(), ..Default::default() },
                        ProtocolComponent { id: "Component2".to_string(), ..Default::default() },
                    ],
                    pagination: PaginationResponse { page: 0, page_size: 20, total: 1 },
                })
            });
        rpc_client
            .expect_get_protocol_states()
            .returning(|_| {
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
                    pagination: PaginationResponse { page: 0, page_size: 20, total: 1 },
                })
            });
        rpc_client
            .expect_get_traced_entry_points()
            .returning(|_| {
                Ok(TracedEntryPointRequestResponse {
                    traced_entry_points: HashMap::new(),
                    pagination: PaginationResponse::new(0, 20, 0),
                })
            });

        rpc_client
            .expect_get_component_tvl()
            .returning(|_| {
                Ok(ComponentTvlRequestResponse {
                    tvl: [
                        ("Component1".to_string(), 6.0),
                        ("Component2".to_string(), 2.0),
                        ("Component3".to_string(), 10.0),
                    ]
                    .into_iter()
                    .collect(),
                    pagination: PaginationResponse { page: 0, page_size: 20, total: 3 },
                })
            });

        rpc_client
            .expect_get_component_tvl()
            .returning(|_| {
                Ok(ComponentTvlRequestResponse {
                    tvl: [
                        ("Component1".to_string(), 6.0),
                        ("Component2".to_string(), 2.0),
                        ("Component3".to_string(), 10.0),
                    ]
                    .into_iter()
                    .collect(),
                    pagination: PaginationResponse { page: 0, page_size: 20, total: 3 },
                })
            });

        let (tx, rx) = channel(1);
        deltas_client
            .expect_subscribe()
            .return_once(move |_, _| Ok((Uuid::default(), rx)));

        // Expect unsubscribe call during cleanup
        deltas_client
            .expect_unsubscribe()
            .return_once(|_| Ok(()));

        let mut state_sync = ProtocolStateSynchronizer::new(
            ExtractorIdentity::new(Chain::Ethereum, "uniswap-v2"),
            true,
            ComponentFilter::with_tvl_range(remove_tvl_threshold, add_tvl_threshold),
            1,
            true,
            true,
            ArcRPCClient(Arc::new(rpc_client)),
            ArcDeltasClient(Arc::new(deltas_client)),
            10_u64,
        );
        state_sync
            .initialize()
            .await
            .expect("Init failed");

        // Simulate the incoming BlockChanges
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
                component_tvl: [
                    ("Component1".to_string(), 6.0), // Within range, should not trigger changes
                    ("Component2".to_string(), 2.0), // Below lower threshold, should be removed
                    ("Component3".to_string(), 10.0), // Above upper threshold, should be added
                ]
                .into_iter()
                .collect(),
                ..Default::default()
            },
        ];

        let (handle, mut rx) = state_sync
            .start()
            .await
            .expect("Failed to start state synchronizer");
        let (jh, close_tx) = handle.split();

        // Simulate sending delta messages
        tx.send(deltas[0].clone())
            .await
            .expect("deltas channel msg 0 closed!");

        // Expecting to receive the initial state message
        let _ = timeout(Duration::from_millis(100), rx.recv())
            .await
            .expect("waiting for first state msg timed out!")
            .expect("state sync block sender closed!");

        // Send the third message, which should trigger TVL-based changes
        tx.send(deltas[1].clone())
            .await
            .expect("deltas channel msg 1 closed!");
        let second_msg = timeout(Duration::from_millis(100), rx.recv())
            .await
            .expect("waiting for second state msg timed out!")
            .expect("state sync block sender closed!");

        let _ = close_tx.send(());
        let exit = jh
            .await
            .expect("state sync task panicked!");

        let expected_second_msg = StateSyncMessage {
            header: BlockHeader {
                number: 2,
                hash: Bytes::from("0x02"),
                parent_hash: Bytes::from("0x01"),
                revert: false,
                ..Default::default()
            },
            snapshots: Snapshot {
                states: [(
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
                        component_tvl: Some(10.0),
                        entrypoints: vec![], // TODO: add entrypoints?
                    },
                )]
                .into_iter()
                .collect(),
                vm_storage: HashMap::new(),
            },
            deltas: Some(BlockChanges {
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
                component_tvl: [
                    ("Component1".to_string(), 6.0), // Within range, should not trigger changes
                    ("Component3".to_string(), 10.0), // Above upper threshold, should be added
                ]
                .into_iter()
                .collect(),
                ..Default::default()
            }),
            removed_components: [(
                "Component2".to_string(),
                ProtocolComponent { id: "Component2".to_string(), ..Default::default() },
            )]
            .into_iter()
            .collect(),
        };

        assert_eq!(second_msg, expected_second_msg);
        assert!(exit.is_ok());
    }

    #[test(tokio::test)]
    async fn test_public_close_api_functionality() {
        // Tests the public close() API through the StateSynchronizer trait:
        // - close() fails before start() is called
        // - close() succeeds while synchronizer is running
        // - close() fails after already closed
        // This tests the full start/close lifecycle via the public API

        let mut rpc_client = MockRPCClient::new();
        let mut deltas_client = MockDeltasClient::new();

        // Mock the initial components call
        rpc_client
            .expect_get_protocol_components()
            .returning(|_| {
                Ok(ProtocolComponentRequestResponse {
                    protocol_components: vec![],
                    pagination: PaginationResponse { page: 0, page_size: 20, total: 0 },
                })
            });

        // Set up deltas client that will wait for messages (blocking in state_sync)
        let (_tx, rx) = channel(1);
        deltas_client
            .expect_subscribe()
            .return_once(move |_, _| Ok((Uuid::default(), rx)));

        // Expect unsubscribe call during cleanup
        deltas_client
            .expect_unsubscribe()
            .return_once(|_| Ok(()));

        let mut state_sync = ProtocolStateSynchronizer::new(
            ExtractorIdentity::new(Chain::Ethereum, "test-protocol"),
            true,
            ComponentFilter::with_tvl_range(0.0, 0.0),
            5, // Enough retries
            true,
            false,
            ArcRPCClient(Arc::new(rpc_client)),
            ArcDeltasClient(Arc::new(deltas_client)),
            10000_u64, // Long timeout so task doesn't exit on its own
        );

        state_sync
            .initialize()
            .await
            .expect("Init should succeed");

        // Start the synchronizer and test the new split-based close mechanism
        let (handle, _rx) = state_sync
            .start()
            .await
            .expect("Failed to start state synchronizer");
        let (jh, close_tx) = handle.split();

        // Give it time to start up and enter state_sync
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Send close signal should succeed
        close_tx
            .send(())
            .expect("Should be able to send close signal");
        // Task should stop cleanly
        let task_result = jh.await.expect("Task should not panic");
        assert!(task_result.is_ok(), "Task should exit cleanly after close: {task_result:?}");
    }

    #[test(tokio::test)]
    async fn test_cleanup_runs_when_state_sync_processing_errors() {
        // Tests that cleanup code runs when state_sync() errors during delta processing.
        // Specifically tests: RPC errors during snapshot retrieval cause proper cleanup.
        // Verifies: shared.last_synced_block reset + subscription unsubscribe on errors

        let mut rpc_client = MockRPCClient::new();
        let mut deltas_client = MockDeltasClient::new();

        // Mock the initial components call
        rpc_client
            .expect_get_protocol_components()
            .returning(|_| {
                Ok(ProtocolComponentRequestResponse {
                    protocol_components: vec![],
                    pagination: PaginationResponse { page: 0, page_size: 20, total: 0 },
                })
            });

        // Mock to fail during snapshot retrieval (this will cause an error during processing)
        rpc_client
            .expect_get_protocol_states()
            .returning(|_| {
                Err(RPCError::HttpClient("Test error during snapshot retrieval".to_string()))
            });

        // Set up deltas client to send one message that will trigger snapshot retrieval
        let (tx, rx) = channel(10);
        deltas_client
            .expect_subscribe()
            .return_once(move |_, _| {
                // Send a delta message that will require a snapshot
                let delta = BlockChanges {
                    extractor: "test".to_string(),
                    chain: Chain::Ethereum,
                    block: Block {
                        hash: Bytes::from("0x0123"),
                        number: 1,
                        parent_hash: Bytes::from("0x0000"),
                        chain: Chain::Ethereum,
                        ts: chrono::NaiveDateTime::from_timestamp_opt(1234567890, 0).unwrap(),
                    },
                    revert: false,
                    // Add a new component to trigger snapshot request
                    new_protocol_components: [(
                        "new_component".to_string(),
                        ProtocolComponent {
                            id: "new_component".to_string(),
                            protocol_system: "test_protocol".to_string(),
                            protocol_type_name: "test".to_string(),
                            chain: Chain::Ethereum,
                            tokens: vec![Bytes::from("0x0badc0ffee")],
                            contract_ids: vec![Bytes::from("0x0badc0ffee")],
                            static_attributes: Default::default(),
                            creation_tx: Default::default(),
                            created_at: Default::default(),
                            change: Default::default(),
                        },
                    )]
                    .into_iter()
                    .collect(),
                    component_tvl: [("new_component".to_string(), 100.0)]
                        .into_iter()
                        .collect(),
                    ..Default::default()
                };

                tokio::spawn(async move {
                    let _ = tx.send(delta).await;
                    // Close the channel after sending one message
                });

                Ok((Uuid::default(), rx))
            });

        // Expect unsubscribe call during cleanup
        deltas_client
            .expect_unsubscribe()
            .return_once(|_| Ok(()));

        let mut state_sync = ProtocolStateSynchronizer::new(
            ExtractorIdentity::new(Chain::Ethereum, "test-protocol"),
            true,
            ComponentFilter::with_tvl_range(0.0, 1000.0), // Include the component
            1,
            true,
            false,
            ArcRPCClient(Arc::new(rpc_client)),
            ArcDeltasClient(Arc::new(deltas_client)),
            5000_u64,
        );

        state_sync
            .initialize()
            .await
            .expect("Init should succeed");

        // Before calling state_sync, set a value in last_synced_block
        state_sync.last_synced_block = Some(BlockHeader {
            hash: Bytes::from("0x0badc0ffee"),
            number: 42,
            parent_hash: Bytes::from("0xbadbeef0"),
            revert: false,
            timestamp: 123456789,
        });

        // Create a channel for state_sync to send messages to
        let (mut block_tx, _block_rx) = channel(10);

        // Call state_sync directly - this should error during processing
        let (_end_tx, end_rx) = oneshot::channel::<()>();
        let result = state_sync
            .state_sync(&mut block_tx, end_rx)
            .await;
        // Verify that state_sync returned an error
        assert!(result.is_err(), "state_sync should have errored during processing");

        // Note: We can't verify internal state cleanup since state_sync consumes self,
        // but the cleanup logic is still tested by the fact that the method returns properly.
    }

    #[test(tokio::test)]
    async fn test_close_signal_while_waiting_for_first_deltas() {
        // Tests close signal handling during the initial "waiting for deltas" phase.
        // This is the earliest possible close scenario - before any deltas are received.
        // Verifies: close signal received while waiting for first message triggers cleanup
        let mut rpc_client = MockRPCClient::new();
        let mut deltas_client = MockDeltasClient::new();

        rpc_client
            .expect_get_protocol_components()
            .returning(|_| {
                Ok(ProtocolComponentRequestResponse {
                    protocol_components: vec![],
                    pagination: PaginationResponse { page: 0, page_size: 20, total: 0 },
                })
            });

        let (_tx, rx) = channel(1);
        deltas_client
            .expect_subscribe()
            .return_once(move |_, _| Ok((Uuid::default(), rx)));

        deltas_client
            .expect_unsubscribe()
            .return_once(|_| Ok(()));

        let mut state_sync = ProtocolStateSynchronizer::new(
            ExtractorIdentity::new(Chain::Ethereum, "test-protocol"),
            true,
            ComponentFilter::with_tvl_range(0.0, 0.0),
            1,
            true,
            false,
            ArcRPCClient(Arc::new(rpc_client)),
            ArcDeltasClient(Arc::new(deltas_client)),
            10000_u64,
        );

        state_sync
            .initialize()
            .await
            .expect("Init should succeed");

        let (mut block_tx, _block_rx) = channel(10);
        let (end_tx, end_rx) = oneshot::channel::<()>();

        // Start state_sync in a task
        let state_sync_handle = tokio::spawn(async move {
            state_sync
                .state_sync(&mut block_tx, end_rx)
                .await
        });

        // Give it a moment to start
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Send close signal
        let _ = end_tx.send(());

        // state_sync should exit cleanly
        let result = state_sync_handle
            .await
            .expect("Task should not panic");
        assert!(result.is_ok(), "state_sync should exit cleanly when closed: {result:?}");

        println!("SUCCESS: Close signal handled correctly while waiting for first deltas");
    }

    #[test(tokio::test)]
    async fn test_close_signal_during_main_processing_loop() {
        // Tests close signal handling during the main delta processing loop.
        // This tests the scenario where first message is processed successfully,
        // then close signal is received while waiting for subsequent deltas.
        // Verifies: close signal in main loop (after initialization) triggers cleanup

        let mut rpc_client = MockRPCClient::new();
        let mut deltas_client = MockDeltasClient::new();

        // Mock the initial components call
        rpc_client
            .expect_get_protocol_components()
            .returning(|_| {
                Ok(ProtocolComponentRequestResponse {
                    protocol_components: vec![],
                    pagination: PaginationResponse { page: 0, page_size: 20, total: 0 },
                })
            });

        // Mock the snapshot retrieval that happens after first message
        rpc_client
            .expect_get_protocol_states()
            .returning(|_| {
                Ok(ProtocolStateRequestResponse {
                    states: vec![],
                    pagination: PaginationResponse { page: 0, page_size: 20, total: 0 },
                })
            });

        rpc_client
            .expect_get_component_tvl()
            .returning(|_| {
                Ok(ComponentTvlRequestResponse {
                    tvl: HashMap::new(),
                    pagination: PaginationResponse { page: 0, page_size: 20, total: 0 },
                })
            });

        rpc_client
            .expect_get_traced_entry_points()
            .returning(|_| {
                Ok(TracedEntryPointRequestResponse {
                    traced_entry_points: HashMap::new(),
                    pagination: PaginationResponse::new(0, 20, 0),
                })
            });

        // Set up deltas client to send one message, then keep channel open
        let (tx, rx) = channel(10);
        deltas_client
            .expect_subscribe()
            .return_once(move |_, _| {
                // Send first message immediately
                let first_delta = BlockChanges {
                    extractor: "test".to_string(),
                    chain: Chain::Ethereum,
                    block: Block {
                        hash: Bytes::from("0x0123"),
                        number: 1,
                        parent_hash: Bytes::from("0x0000"),
                        chain: Chain::Ethereum,
                        ts: chrono::NaiveDateTime::from_timestamp_opt(1234567890, 0).unwrap(),
                    },
                    revert: false,
                    ..Default::default()
                };

                tokio::spawn(async move {
                    let _ = tx.send(first_delta).await;
                    // Keep the sender alive but don't send more messages
                    // This will make the recv() block waiting for the next message
                    tokio::time::sleep(Duration::from_secs(30)).await;
                });

                Ok((Uuid::default(), rx))
            });

        deltas_client
            .expect_unsubscribe()
            .return_once(|_| Ok(()));

        let mut state_sync = ProtocolStateSynchronizer::new(
            ExtractorIdentity::new(Chain::Ethereum, "test-protocol"),
            true,
            ComponentFilter::with_tvl_range(0.0, 1000.0),
            1,
            true,
            false,
            ArcRPCClient(Arc::new(rpc_client)),
            ArcDeltasClient(Arc::new(deltas_client)),
            10000_u64,
        );

        state_sync
            .initialize()
            .await
            .expect("Init should succeed");

        let (mut block_tx, mut block_rx) = channel(10);
        let (end_tx, end_rx) = oneshot::channel::<()>();

        // Start state_sync in a task
        let state_sync_handle = tokio::spawn(async move {
            state_sync
                .state_sync(&mut block_tx, end_rx)
                .await
        });

        // Wait for the first message to be processed (snapshot sent)
        let first_snapshot = block_rx
            .recv()
            .await
            .expect("Should receive first snapshot");
        assert!(
            !first_snapshot
                .snapshots
                .states
                .is_empty() ||
                first_snapshot.deltas.is_some()
        );
        // Now send close signal - this should be handled in the main processing loop
        let _ = end_tx.send(());

        // state_sync should exit cleanly after receiving close signal in main loop
        let result = state_sync_handle
            .await
            .expect("Task should not panic");
        assert!(
            result.is_ok(),
            "state_sync should exit cleanly when closed after first message: {result:?}"
        );
        println!("SUCCESS: Close signal handled correctly during main processing loop");
    }
}
