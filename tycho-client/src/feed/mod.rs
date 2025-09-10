use std::{
    collections::{HashMap, HashSet},
    time::Duration,
};

use chrono::{Duration as ChronoDuration, Local, NaiveDateTime};
use futures03::{
    future::{join_all, try_join_all},
    stream::FuturesUnordered,
    StreamExt,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::{
    select,
    sync::{
        mpsc::{self, Receiver},
        oneshot,
    },
    task::JoinHandle,
    time::timeout,
};
use tracing::{debug, error, info, trace, warn};
use tycho_common::{
    dto::{Block, ExtractorIdentity},
    Bytes,
};

use crate::feed::{
    block_history::{BlockHistory, BlockHistoryError, BlockPosition},
    synchronizer::{StateSyncMessage, StateSynchronizer, SyncResult, SynchronizerError},
};

mod block_history;
pub mod component_tracker;
pub mod synchronizer;

/// A trait representing a minimal interface for types that behave like a block header.
///
/// This abstraction allows working with either full block headers (`BlockHeader`)
/// or simplified structures that only provide a timestamp (e.g., for RFQ logic).
pub trait HeaderLike {
    fn block(self) -> Option<BlockHeader>;
    fn block_number_or_timestamp(self) -> u64;
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize, Eq, Hash)]
pub struct BlockHeader {
    pub hash: Bytes,
    pub number: u64,
    pub parent_hash: Bytes,
    pub revert: bool,
    pub timestamp: u64,
}

impl BlockHeader {
    fn from_block(block: &Block, revert: bool) -> Self {
        Self {
            hash: block.hash.clone(),
            number: block.number,
            parent_hash: block.parent_hash.clone(),
            revert,
            timestamp: block.ts.and_utc().timestamp() as u64,
        }
    }
}

impl HeaderLike for BlockHeader {
    fn block(self) -> Option<BlockHeader> {
        Some(self)
    }

    fn block_number_or_timestamp(self) -> u64 {
        self.number
    }
}

#[derive(Error, Debug)]
pub enum BlockSynchronizerError {
    #[error("Failed to initialize synchronizer: {0}")]
    InitializationError(#[from] SynchronizerError),

    #[error("Failed to process new block: {0}")]
    BlockHistoryError(#[from] BlockHistoryError),

    #[error("Not a single synchronizer was ready")]
    NoReadySynchronizers,

    #[error("No synchronizers were set")]
    NoSynchronizers,

    #[error("Failed to convert duration: {0}")]
    DurationConversionError(String),
}

type BlockSyncResult<T> = Result<T, BlockSynchronizerError>;

/// Aligns multiple StateSynchronizers on the block dimension.
///
/// ## Purpose
/// The purpose of this component is to handle streams from multiple state synchronizers and
/// align/merge them according to their blocks. Ideally this should be done in a fault-tolerant way,
/// meaning we can recover from a state synchronizer suffering from timing issues. E.g. a delayed or
/// unresponsive state synchronizer might recover again, or an advanced state synchronizer can be
/// included again once we reach the block it is at.
///
/// ## Limitations
/// - Supports only chains with fixed blocks time for now due to the lock step mechanism.
///
/// ## Initialisation
/// Queries all registered synchronizers for their first message and evaluates the state of each
/// synchronizer. If a synchronizer's first message is an older block, it is marked as delayed.
// TODO: what is the startup timeout
/// If no message is received within the startup timeout, the synchronizer is marked as stale and is
/// closed.
///
/// ## Main loop
/// Once started, the synchronizers are queried concurrently for messages in lock step:
/// the main loop queries all synchronizers in ready for the last emitted data, builds the
/// `FeedMessage` and emits it, then it schedules the wait procedure for the next block.
///
/// ## Synchronization Logic
///
/// To classify a synchronizer as delayed, we need to first define the current block. The highest
/// block number of all ready synchronizers is considered the current block.
///
/// Once we have the current block we can easily determine which block we expect next. And if a
/// synchronizer delivers an older block we can classify it as delayed.
///
/// If any synchronizer is not in the ready state we will try to bring it back to the ready state.
/// This is done by trying to empty any buffers of a delayed synchronizer or waiting to reach
/// the height of an advanced synchronizer (and flagging it as such in the meantime).
///
/// Of course, we can't wait forever for a synchronizer to reply/recover. All of this must happen
/// within the block production step of the blockchain:
/// The wait procedure consists of waiting for any of the individual ProtocolStateSynchronizers
/// to emit a new message (within a max timeout - several multiples of the block time). Once a
/// message is received a very short timeout starts for the remaining synchronizers, to deliver a
/// message. Any synchronizer failing to do so is transitioned to delayed.
///
/// ### Note
/// The described process above is the goal. It is currently not implemented like that. Instead we
/// simply wait `block_time` + `wait_time`. Synchronizers are expected to respond within that
/// timeout. This is simpler but only works well on chains with fixed block times.
pub struct BlockSynchronizer<S> {
    synchronizers: Option<HashMap<ExtractorIdentity, S>>,
    block_time: std::time::Duration,
    max_wait: std::time::Duration,
    max_messages: Option<usize>,
    max_missed_blocks: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "lowercase")]
pub enum SynchronizerState {
    Started,
    Ready(BlockHeader),
    // no progress, we consider it stale at that point we should purge it.
    Stale(BlockHeader),
    Delayed(BlockHeader),
    // For this to happen we must have a gap, and a gap usually means a new snapshot from the
    // StateSynchronizer. This can only happen if we are processing too slow and one of the
    // synchronizers restarts e.g. because Tycho ended the subscription.
    Advanced(BlockHeader),
    Ended,
}

pub struct SynchronizerStream {
    extractor_id: ExtractorIdentity,
    state: SynchronizerState,
    modify_ts: NaiveDateTime,
    rx: Receiver<StateSyncMessage<BlockHeader>>,
}

impl SynchronizerStream {
    async fn try_advance(
        &mut self,
        block_history: &BlockHistory,
        max_wait: std::time::Duration,
        stale_threshold: std::time::Duration,
    ) -> BlockSyncResult<Option<StateSyncMessage<BlockHeader>>> {
        let extractor_id = self.extractor_id.clone();
        let latest_block = block_history.latest();
        match &self.state {
            SynchronizerState::Started | SynchronizerState::Ended => {
                warn!(state=?&self.state, "Advancing Synchronizer in this state not supported!");
                Ok(None)
            }
            SynchronizerState::Advanced(b) => {
                let future_block = b.clone();
                // Transition to ready once we arrived at the expected height
                self.transition(future_block, block_history, stale_threshold)?;
                Ok(None)
            }
            SynchronizerState::Ready(previous_block) => {
                // Try to recv the next expected block, update state accordingly.
                self.try_recv_next_expected(
                    max_wait,
                    block_history,
                    previous_block.clone(),
                    stale_threshold,
                )
                .await
                // TODO: if we entered advanced state we need to buffer the message for a while.
            }
            SynchronizerState::Delayed(old_block) | SynchronizerState::Stale(old_block) => {
                // try to catch up all currently queued blocks until the expected block
                debug!(
                    ?old_block,
                    ?latest_block,
                    %extractor_id,
                    "Trying to catch up to latest block"
                );
                self.try_catch_up(block_history, max_wait, stale_threshold)
                    .await
            }
        }
    }

    /// Standard way to advance a well-behaved state synchronizer.
    ///
    /// Will wait for a new block on the synchronizer within a timeout. And modify its state based
    /// on the outcome.
    async fn try_recv_next_expected(
        &mut self,
        max_wait: std::time::Duration,
        block_history: &BlockHistory,
        previous_block: BlockHeader,
        stale_threshold: std::time::Duration,
    ) -> BlockSyncResult<Option<StateSyncMessage<BlockHeader>>> {
        let extractor_id = self.extractor_id.clone();
        match timeout(max_wait, self.rx.recv()).await {
            Ok(Some(msg)) => {
                self.transition(msg.header.clone(), block_history, stale_threshold)?;
                Ok(Some(msg))
            }
            Ok(None) => {
                error!(
                    %extractor_id,
                    ?previous_block,
                    "SynchronizerStream terminated: channel closed!"
                );
                self.state = SynchronizerState::Ended;
                self.modify_ts = Local::now().naive_utc();
                Ok(None)
            }
            Err(_) => {
                // trying to advance a block timed out
                debug!(%extractor_id, ?previous_block, "No block received within time limit.");

                match &self.state {
                    SynchronizerState::Ready(_) => {
                        // First timeout: always transition to Delayed
                        self.state = SynchronizerState::Delayed(previous_block.clone());
                        self.modify_ts = Local::now().naive_utc();
                    }
                    SynchronizerState::Delayed(_) => {
                        // Already delayed, check if we should go stale
                        // DON'T update modify_ts here - we want to track time since first delay
                        self.check_and_transition_to_stale_if_needed(
                            stale_threshold,
                            Some(previous_block.clone()),
                        )?;
                    }
                    _ => {
                        // For other states, use the stale check
                        if !self.check_and_transition_to_stale_if_needed(
                            stale_threshold,
                            Some(previous_block.clone()),
                        )? {
                            self.state = SynchronizerState::Delayed(previous_block.clone());
                            self.modify_ts = Local::now().naive_utc();
                        }
                    }
                }
                Ok(None)
            }
        }
    }

    /// Tries to catch up a delayed state synchronizer.
    ///
    /// If a synchronizer is delayed, this method will try to catch up to the next expected block
    /// by consuming all waiting messages in its queue and waiting for any new block messages
    /// within a timeout. Finally, all update messages are merged into one and returned.
    async fn try_catch_up(
        &mut self,
        block_history: &BlockHistory,
        max_wait: std::time::Duration,
        stale_threshold: std::time::Duration,
    ) -> BlockSyncResult<Option<StateSyncMessage<BlockHeader>>> {
        let mut results = Vec::new();
        let extractor_id = self.extractor_id.clone();

        // Set a deadline for the overall catch-up operation
        let deadline = std::time::Instant::now() + max_wait;

        while std::time::Instant::now() < deadline {
            match timeout(
                deadline.saturating_duration_since(std::time::Instant::now()),
                self.rx.recv(),
            )
            .await
            {
                Ok(Some(msg)) => {
                    debug!(%extractor_id, block_num=?msg.header.number, "Received new message during catch-up");
                    let block_pos = block_history.determine_block_position(&msg.header)?;
                    results.push(msg);
                    if matches!(block_pos, BlockPosition::NextExpected) {
                        break;
                    }
                }
                Ok(None) => {
                    warn!(%extractor_id, "Channel closed during catch-up");
                    self.state = SynchronizerState::Ended;
                    return Ok(None);
                }
                Err(_) => {
                    debug!(%extractor_id, "Timed out waiting for catch-up");
                    break;
                }
            }
        }

        let merged = results
            .into_iter()
            .reduce(|l, r| l.merge(r));

        if let Some(msg) = merged {
            // we were able to get at least one block out
            debug!(?extractor_id, "Delayed extractor made progress!");
            self.transition(msg.header.clone(), block_history, stale_threshold)?;
            Ok(Some(msg))
        } else {
            // No progress made during catch-up, check if we should go stale
            self.check_and_transition_to_stale_if_needed(stale_threshold, None)?;
            Ok(None)
        }
    }

    /// Helper method to check if synchronizer should transition to stale based on time elapsed
    fn check_and_transition_to_stale_if_needed(
        &mut self,
        stale_threshold: std::time::Duration,
        fallback_header: Option<BlockHeader>,
    ) -> Result<bool, BlockSynchronizerError> {
        let now = Local::now().naive_utc();
        let wait_duration = now.signed_duration_since(self.modify_ts);
        let stale_threshold_chrono = ChronoDuration::from_std(stale_threshold)
            .map_err(|e| BlockSynchronizerError::DurationConversionError(e.to_string()))?;

        if wait_duration > stale_threshold_chrono {
            let header_to_use = match (&self.state, fallback_header) {
                (SynchronizerState::Ready(h), _) |
                (SynchronizerState::Delayed(h), _) |
                (SynchronizerState::Stale(h), _) => h.clone(),
                (_, Some(h)) => h,
                _ => BlockHeader::default(),
            };

            warn!(
                extractor_id=%self.extractor_id,
                last_message_at=?self.modify_ts,
                "SynchronizerStream transition to stale due to timeout."
            );
            self.state = SynchronizerState::Stale(header_to_use);
            self.modify_ts = now;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Logic to transition a state synchronizer based on newly received block
    ///
    /// Updates the synchronizer's state according to the position of the received block:
    /// - Next expected block -> Ready state
    /// - Latest/Delayed block -> Either Delayed or Stale (if >60s since last update)
    /// - Advanced block -> Advanced state (block ahead of expected position)
    fn transition(
        &mut self,
        latest_retrieved: BlockHeader,
        block_history: &BlockHistory,
        stale_threshold: std::time::Duration,
    ) -> Result<(), BlockSynchronizerError> {
        let extractor_id = self.extractor_id.clone();
        let last_message_at = self.modify_ts;
        let block = &latest_retrieved;

        match block_history.determine_block_position(&latest_retrieved)? {
            BlockPosition::NextExpected => {
                self.state = SynchronizerState::Ready(latest_retrieved.clone());
                trace!(
                    next = ?latest_retrieved,
                    extractor = ?extractor_id,
                    "SynchronizerStream transition to next expected"
                )
            }
            BlockPosition::Latest | BlockPosition::Delayed => {
                if !self.check_and_transition_to_stale_if_needed(
                    stale_threshold,
                    Some(latest_retrieved.clone()),
                )? {
                    warn!(
                        ?extractor_id,
                        ?last_message_at,
                        ?block,
                        "SynchronizerStream transition transition to delayed."
                    );
                    self.state = SynchronizerState::Delayed(latest_retrieved.clone());
                }
            }
            BlockPosition::Advanced => {
                error!(
                    ?extractor_id,
                    ?last_message_at,
                    latest = ?block_history.latest(),
                    ?block,
                    "SynchronizerStream transition to advanced."
                );
                self.state = SynchronizerState::Advanced(latest_retrieved.clone());
            }
        }
        self.modify_ts = Local::now().naive_utc();
        Ok(())
    }
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct FeedMessage<H = BlockHeader>
where
    H: HeaderLike,
{
    pub state_msgs: HashMap<String, StateSyncMessage<H>>,
    pub sync_states: HashMap<String, SynchronizerState>,
}

impl<H> FeedMessage<H>
where
    H: HeaderLike,
{
    fn new(
        state_msgs: HashMap<String, StateSyncMessage<H>>,
        sync_states: HashMap<String, SynchronizerState>,
    ) -> Self {
        Self { state_msgs, sync_states }
    }
}

impl<S> BlockSynchronizer<S>
where
    S: StateSynchronizer,
{
    pub fn new(
        block_time: std::time::Duration,
        max_wait: std::time::Duration,
        max_missed_blocks: u64,
    ) -> Self {
        Self { synchronizers: None, max_messages: None, block_time, max_wait, max_missed_blocks }
    }

    pub fn max_messages(&mut self, val: usize) {
        self.max_messages = Some(val);
    }

    pub fn register_synchronizer(mut self, id: ExtractorIdentity, synchronizer: S) -> Self {
        let mut registered = self.synchronizers.unwrap_or_default();
        registered.insert(id, synchronizer);
        self.synchronizers = Some(registered);
        self
    }

    #[cfg(test)]
    pub fn with_short_timeouts() -> Self {
        Self::new(Duration::from_millis(10), Duration::from_millis(10), 3)
    }

    /// Cleanup function for shutting down remaining synchronizers when the nanny detects an error.
    /// Sends close signals to all remaining synchronizers and waits for them to complete.
    async fn cleanup_synchronizers(
        mut state_sync_tasks: FuturesUnordered<JoinHandle<SyncResult<()>>>,
        sync_close_senders: Vec<oneshot::Sender<()>>,
    ) {
        // Send close signals to all remaining synchronizers
        for close_sender in sync_close_senders {
            let _ = close_sender.send(());
        }

        // Await remaining tasks with timeout
        let mut completed_tasks = 0;
        while let Ok(Some(_)) = timeout(Duration::from_secs(5), state_sync_tasks.next()).await {
            completed_tasks += 1;
        }

        // Warn if any synchronizers timed out during cleanup
        let remaining_tasks = state_sync_tasks.len();
        if remaining_tasks > 0 {
            warn!(
                completed = completed_tasks,
                timed_out = remaining_tasks,
                "Some synchronizers timed out during cleanup and may not have shut down cleanly"
            );
        }
    }

    pub async fn run(
        mut self,
    ) -> BlockSyncResult<(JoinHandle<()>, Receiver<FeedMessage<BlockHeader>>)> {
        trace!("Starting BlockSynchronizer...");
        let mut state_sync_tasks = FuturesUnordered::new();
        let mut synchronizers = self
            .synchronizers
            .take()
            .ok_or(BlockSynchronizerError::NoSynchronizers)?;
        // init synchronizers
        let init_tasks = synchronizers
            .values_mut()
            .map(|s| s.initialize())
            .collect::<Vec<_>>();
        try_join_all(init_tasks).await?;

        let mut sync_streams = HashMap::with_capacity(synchronizers.len());
        let mut sync_close_senders = Vec::new();
        for (extractor_id, synchronizer) in synchronizers.drain() {
            let (handle, rx) = synchronizer.start().await?;
            let (join_handle, close_sender) = handle.split();
            state_sync_tasks.push(join_handle);
            sync_close_senders.push(close_sender);

            sync_streams.insert(
                extractor_id.clone(),
                SynchronizerStream {
                    extractor_id,
                    state: SynchronizerState::Started,
                    modify_ts: Local::now().naive_utc(),
                    rx,
                },
            );
        }

        // startup, schedule first set of futures and wait for them to return to initialise
        // synchronizers.
        debug!("Waiting for initial synchronizer messages...");
        let mut startup_futures = Vec::new();
        for (id, sh) in sync_streams.iter_mut() {
            let fut = async {
                let res = timeout(self.block_time + self.max_wait, sh.rx.recv()).await;
                (id.clone(), res)
            };
            startup_futures.push(fut);
        }
        let mut ready_sync_msgs = HashMap::new();
        let initial_headers = join_all(startup_futures)
            .await
            .into_iter()
            .filter_map(|(extractor_id, res)| {
                let synchronizer = sync_streams
                .get_mut(&extractor_id)
                .unwrap();
            match res {
                Ok(Some(msg)) => {
                    debug!(%extractor_id, height=?&msg.header.number, "Synchronizer started successfully!");
                    // initially default all synchronizers to Ready
                    synchronizer.state = SynchronizerState::Ready(msg.header.clone());
                    synchronizer.modify_ts = Local::now().naive_utc();
                    ready_sync_msgs.insert(extractor_id.name.clone(), msg.clone());
                    Some(msg.header)
                }
                Ok(None) => {
                    warn!(%extractor_id, "Dead synchronizer at startup will be purged!");
                    synchronizer.state = SynchronizerState::Ended;
                    synchronizer.modify_ts = Local::now().naive_utc();
                    None
                }
                Err(_) => {
                    warn!(%extractor_id, "Timed out waiting for first message: Stale synchronizer at startup will be purged!");
                    synchronizer.state = SynchronizerState::Stale(BlockHeader::default());
                    synchronizer.modify_ts = Local::now().naive_utc();
                    None
                }
            }
        })
        .collect::<HashSet<_>>() // remove duplicates
        .into_iter()
        .collect::<Vec<_>>();

        let mut block_history = BlockHistory::new(initial_headers, 15)?;

        // Determine the starting header for synchronization
        let start_header = block_history
            .latest()
            .ok_or(BlockSynchronizerError::NoReadySynchronizers)?;
        info!(
            start_block=?start_header,
            n_healthy=?ready_sync_msgs.len(),
            "Block synchronization started successfully!"
        );

        // Purge any stale synchronizers
        // All synchronizers that did not timeout on start up are initialized as Ready, including
        // those that are Delayed. Delayed synchronizers are identified and updated accordingly in
        // the next step.
        sync_streams.retain(|_, v| matches!(v.state, SynchronizerState::Ready(_)));

        // Determine correct state for each remaining synchronizer, based on their header vs the
        // latest one
        for (_, stream) in sync_streams.iter_mut() {
            if let SynchronizerState::Ready(header) = &stream.state.clone() {
                if header.number < start_header.number {
                    stream.state = SynchronizerState::Delayed(header.clone());
                    debug!(
                        extractor_id=%stream.extractor_id,
                        synchronizer_block=?header.number,
                        current_block=?start_header.number,
                        "Marking synchronizer as delayed during initialization"
                    );
                }
            }
        }

        let (sync_tx, sync_rx) = mpsc::channel(30);
        let main_loop_jh: JoinHandle<anyhow::Result<()>> = tokio::spawn(async move {
            let mut n_iter = 1;
            loop {
                // Send retrieved data to receivers.
                sync_tx
                    .send(FeedMessage::new(
                        std::mem::take(&mut ready_sync_msgs),
                        sync_streams
                            .iter()
                            .map(|(a, b)| (a.name.to_string(), b.state.clone()))
                            .collect(),
                    ))
                    .await?;

                // Check if we have reached the max messages
                if let Some(max_messages) = self.max_messages {
                    if n_iter >= max_messages {
                        info!(max_messages, "StreamEnd");
                        return Ok(());
                    }
                }
                n_iter += 1;

                // Here we simply wait block_time + max_wait. This will not work for chains with
                // unknown block times but is simple enough for now.
                // If we would like to support unknown block times we could: Instruct all handles to
                // await the max block time, if a header arrives within that time transition as
                // usual, but via a select statement get notified (using e.g. Notify) if any other
                // handle finishes before the timeout. Then await again but this time only for
                // max_wait and then proceed as usual. So basically each try_advance task would have
                // a select statement that allows it to exit the first timeout preemptively if any
                // other try_advance task finished earlier.
                let mut recv_futures = Vec::new();
                for (extractor_id, sh) in sync_streams.iter_mut() {
                    recv_futures.push(async {
                        let res = sh
                            .try_advance(
                                &block_history,
                                self.block_time + self.max_wait,
                                self.block_time
                                    .mul_f64(self.max_missed_blocks as f64),
                            )
                            .await?;
                        Ok::<_, BlockSynchronizerError>(
                            res.map(|msg| (extractor_id.name.clone(), msg)),
                        )
                    });
                }
                ready_sync_msgs.extend(
                    join_all(recv_futures)
                        .await
                        .into_iter()
                        .collect::<Result<Vec<_>, _>>()?
                        .into_iter()
                        .flatten(),
                );

                // Purge any bad synchronizers, respective warnings have already been issued at
                // transition time.
                sync_streams.retain(|_, v| match v.state {
                    SynchronizerState::Started | SynchronizerState::Ended => false,
                    SynchronizerState::Stale(_) => false,
                    SynchronizerState::Ready(_) => true,
                    SynchronizerState::Delayed(_) => true,
                    SynchronizerState::Advanced(_) => true,
                });

                // Check if we have any active synchronizers (Ready, Delayed, or Advanced)
                // If all synchronizers have been purged (Stale/Ended), exit the main loop
                if sync_streams.is_empty() {
                    error!("No healthy SynchronizerStream remain");
                    return Err(BlockSynchronizerError::NoReadySynchronizers.into());
                }

                // Find the latest connected block header to advance history
                if let Some(header) = sync_streams
                    .values()
                    .filter_map(|v| match &v.state {
                        SynchronizerState::Ready(b) | SynchronizerState::Delayed(b) => Some(b),
                        _ => None,
                    })
                    .max_by_key(|b| b.number)
                {
                    block_history.push(header.clone())?;
                } else {
                    // No Ready or Delayed synchronizers, but we still have some synchronizers
                    // we can probably recover here but since this is unlikely we error for now
                    error!("Only advanced SynchronizerStreams remain");
                    return Err(BlockSynchronizerError::NoReadySynchronizers.into());
                }
            }
        });

        let nanny_jh = tokio::spawn(async move {
            select! {
                error = state_sync_tasks.select_next_some() => {
                    Self::cleanup_synchronizers(state_sync_tasks, sync_close_senders).await;
                    error!(?error, "State synchronizer exited");
                },
                error = main_loop_jh => {
                    Self::cleanup_synchronizers(state_sync_tasks, sync_close_senders).await;
                    error!(?error, "Feed main loop exited");
                }
            }
        });
        Ok((nanny_jh, sync_rx))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use async_trait::async_trait;
    use test_log::test;
    use tokio::sync::{oneshot, Mutex};
    use tycho_common::dto::Chain;

    use super::*;
    use crate::feed::synchronizer::{SyncResult, SynchronizerTaskHandle};

    #[derive(Clone, Debug)]
    enum MockBehavior {
        Normal,          // Exit successfully when receiving close signal
        FailOnExit,      // Exit with error when receiving close signal
        IgnoreClose,     // Ignore close signals and hang (for timeout testing)
        ExitImmediately, // Exit immediately after first message (for quick failure testing)
    }

    #[derive(Clone)]
    struct MockStateSync {
        header_tx: mpsc::Sender<StateSyncMessage<BlockHeader>>,
        header_rx: Arc<Mutex<Option<Receiver<StateSyncMessage<BlockHeader>>>>>,
        close_received: Arc<Mutex<bool>>,
        behavior: MockBehavior,
        // For testing: store the close sender so tests can trigger close signals
        close_tx: Arc<Mutex<Option<oneshot::Sender<()>>>>,
    }

    impl MockStateSync {
        fn new() -> Self {
            Self::with_behavior(MockBehavior::Normal)
        }

        fn with_behavior(behavior: MockBehavior) -> Self {
            let (tx, rx) = mpsc::channel(1);
            Self {
                header_tx: tx,
                header_rx: Arc::new(Mutex::new(Some(rx))),
                close_received: Arc::new(Mutex::new(false)),
                behavior,
                close_tx: Arc::new(Mutex::new(None)),
            }
        }

        async fn was_close_received(&self) -> bool {
            *self.close_received.lock().await
        }

        async fn send_header(&self, header: StateSyncMessage<BlockHeader>) -> Result<(), String> {
            self.header_tx
                .send(header)
                .await
                .map_err(|e| format!("sending header failed: {e}"))
        }

        // For testing: trigger a close signal to make the synchronizer exit
        async fn trigger_close(&self) {
            if let Some(close_tx) = self.close_tx.lock().await.take() {
                let _ = close_tx.send(());
            }
        }
    }

    #[async_trait]
    impl StateSynchronizer for MockStateSync {
        async fn initialize(&mut self) -> SyncResult<()> {
            Ok(())
        }

        async fn start(
            mut self,
        ) -> SyncResult<(SynchronizerTaskHandle, Receiver<StateSyncMessage<BlockHeader>>)> {
            let block_rx = {
                let mut guard = self.header_rx.lock().await;
                guard
                    .take()
                    .expect("Block receiver was not set!")
            };

            // Create close channel - we need to store one sender for testing and give one to the
            // handle
            let (close_tx_for_handle, close_rx) = oneshot::channel();
            let (close_tx_for_test, close_rx_for_test) = oneshot::channel();

            // Store the test close sender
            {
                let mut guard = self.close_tx.lock().await;
                *guard = Some(close_tx_for_test);
            }

            let close_received_clone = self.close_received.clone();
            let behavior = self.behavior.clone();

            let jh = tokio::spawn(async move {
                match behavior {
                    MockBehavior::IgnoreClose => {
                        // Infinite loop to simulate a hung synchronizer that doesn't respond to
                        // close signals
                        loop {
                            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                        }
                    }
                    MockBehavior::ExitImmediately => {
                        // Exit immediately with error to simulate immediate task failure
                        SyncResult::Err(SynchronizerError::ConnectionError(
                            "Simulated immediate task failure".to_string(),
                        ))
                    }
                    MockBehavior::Normal | MockBehavior::FailOnExit => {
                        // Wait for close signal from either handle or test, then respond based on
                        // behavior
                        let result = tokio::select! {
                            result = close_rx => result,
                            result = close_rx_for_test => result,
                        };

                        match result {
                            Ok(()) => {
                                // Mark that close signal was received
                                let mut guard = close_received_clone.lock().await;
                                *guard = true;

                                match behavior {
                                    MockBehavior::Normal => SyncResult::Ok(()),
                                    MockBehavior::FailOnExit => {
                                        SyncResult::Err(SynchronizerError::ConnectionError(
                                            "Simulated task failure on close".to_string(),
                                        ))
                                    }
                                    _ => unreachable!(),
                                }
                            }
                            Err(_) => {
                                // Close signal sender was dropped
                                match behavior {
                                    MockBehavior::Normal => SyncResult::Ok(()),
                                    MockBehavior::FailOnExit => {
                                        SyncResult::Err(SynchronizerError::ConnectionError(
                                            "Simulated task failure on close sender drop"
                                                .to_string(),
                                        ))
                                    }
                                    _ => unreachable!(),
                                }
                            }
                        }
                    }
                }
            });

            let handle = SynchronizerTaskHandle::new(jh, close_tx_for_handle);
            Ok((handle, block_rx))
        }
    }

    #[test(tokio::test)]
    async fn test_two_ready_synchronizers() {
        let v2_sync = MockStateSync::new();
        let v3_sync = MockStateSync::new();
        let block_sync = BlockSynchronizer::with_short_timeouts()
            .register_synchronizer(
                ExtractorIdentity { chain: Chain::Ethereum, name: "uniswap-v2".to_string() },
                v2_sync.clone(),
            )
            .register_synchronizer(
                ExtractorIdentity { chain: Chain::Ethereum, name: "uniswap-v3".to_string() },
                v3_sync.clone(),
            );
        let start_msg = StateSyncMessage {
            header: BlockHeader { number: 1, ..Default::default() },
            ..Default::default()
        };
        v2_sync
            .send_header(start_msg.clone())
            .await
            .expect("send_header failed");
        v3_sync
            .send_header(start_msg.clone())
            .await
            .expect("send_header failed");

        let (_jh, mut rx) = block_sync
            .run()
            .await
            .expect("BlockSynchronizer failed to start.");
        let first_feed_msg = rx
            .recv()
            .await
            .expect("header channel was closed");
        let second_msg = StateSyncMessage {
            header: BlockHeader { number: 2, ..Default::default() },
            ..Default::default()
        };
        v2_sync
            .send_header(second_msg.clone())
            .await
            .expect("send_header failed");
        v3_sync
            .send_header(second_msg.clone())
            .await
            .expect("send_header failed");
        let second_feed_msg = rx
            .recv()
            .await
            .expect("header channel was closed!");

        let exp1 = FeedMessage {
            state_msgs: [
                ("uniswap-v2".to_string(), start_msg.clone()),
                ("uniswap-v3".to_string(), start_msg.clone()),
            ]
            .into_iter()
            .collect(),
            sync_states: [
                ("uniswap-v3".to_string(), SynchronizerState::Ready(start_msg.header.clone())),
                ("uniswap-v2".to_string(), SynchronizerState::Ready(start_msg.header.clone())),
            ]
            .into_iter()
            .collect(),
        };
        let exp2 = FeedMessage {
            state_msgs: [
                ("uniswap-v2".to_string(), second_msg.clone()),
                ("uniswap-v3".to_string(), second_msg.clone()),
            ]
            .into_iter()
            .collect(),
            sync_states: [
                ("uniswap-v3".to_string(), SynchronizerState::Ready(second_msg.header.clone())),
                ("uniswap-v2".to_string(), SynchronizerState::Ready(second_msg.header.clone())),
            ]
            .into_iter()
            .collect(),
        };
        assert_eq!(first_feed_msg, exp1);
        assert_eq!(second_feed_msg, exp2);
    }

    #[test(tokio::test)]
    async fn test_delayed_synchronizer_catches_up() {
        let v2_sync = MockStateSync::new();
        let v3_sync = MockStateSync::new();
        let block_sync = BlockSynchronizer::with_short_timeouts()
            .register_synchronizer(
                ExtractorIdentity { chain: Chain::Ethereum, name: "uniswap-v2".to_string() },
                v2_sync.clone(),
            )
            .register_synchronizer(
                ExtractorIdentity { chain: Chain::Ethereum, name: "uniswap-v3".to_string() },
                v3_sync.clone(),
            );

        // Initial messages - both synchronizers are at block 1
        let block1_msg = StateSyncMessage {
            header: BlockHeader {
                number: 1,
                hash: Bytes::from(vec![1]),
                parent_hash: Bytes::from(vec![0]),
                revert: false,
                ..Default::default()
            },
            ..Default::default()
        };
        v2_sync
            .send_header(block1_msg.clone())
            .await
            .expect("send_header failed");
        v3_sync
            .send_header(block1_msg.clone())
            .await
            .expect("send_header failed");

        // Start the block synchronizer
        let (_jh, mut rx) = block_sync
            .run()
            .await
            .expect("BlockSynchronizer failed to start.");

        // Consume the first message
        let first_feed_msg = rx
            .recv()
            .await
            .expect("header channel was closed");
        assert_eq!(first_feed_msg.state_msgs.len(), 2);
        assert!(matches!(
            first_feed_msg
                .sync_states
                .get("uniswap-v2")
                .unwrap(),
            SynchronizerState::Ready(_)
        ));
        assert!(matches!(
            first_feed_msg
                .sync_states
                .get("uniswap-v3")
                .unwrap(),
            SynchronizerState::Ready(_)
        ));

        // Send block 2 to v2 synchronizer only
        let block2_msg = StateSyncMessage {
            header: BlockHeader {
                number: 2,
                hash: Bytes::from(vec![2]),
                parent_hash: Bytes::from(vec![1]),
                revert: false,
                ..Default::default()
            },
            ..Default::default()
        };
        v2_sync
            .send_header(block2_msg.clone())
            .await
            .expect("send_header failed");

        // Consume second message - v3 should be delayed
        let second_feed_msg = rx
            .recv()
            .await
            .expect("header channel was closed");
        debug!("Consumed second message for v2");

        assert!(second_feed_msg
            .state_msgs
            .contains_key("uniswap-v2"));
        assert!(matches!(
            second_feed_msg.sync_states.get("uniswap-v2").unwrap(),
            SynchronizerState::Ready(header) if header.number == 2
        ));
        assert!(!second_feed_msg
            .state_msgs
            .contains_key("uniswap-v3"));
        assert!(matches!(
            second_feed_msg.sync_states.get("uniswap-v3").unwrap(),
            SynchronizerState::Delayed(header) if header.number == 1
        ));

        // Now v3 catches up to block 2
        v3_sync
            .send_header(block2_msg.clone())
            .await
            .expect("send_header failed");

        // Both advance to block 3
        let block3_msg = StateSyncMessage {
            header: BlockHeader {
                number: 3,
                hash: Bytes::from(vec![3]),
                parent_hash: Bytes::from(vec![2]),
                revert: false,
                ..Default::default()
            },
            ..Default::default()
        };
        v2_sync
            .send_header(block3_msg.clone())
            .await
            .expect("send_header failed");
        v3_sync
            .send_header(block3_msg)
            .await
            .expect("send_header failed");

        // Consume messages until we get both synchronizers on block 3
        // We may get an intermediate message for v3's catch-up or a combined message
        let mut third_feed_msg = rx
            .recv()
            .await
            .expect("header channel was closed");

        // If this message doesn't have both univ2, it's an intermediate message, so we get the next
        // one
        if !third_feed_msg
            .state_msgs
            .contains_key("uniswap-v2")
        {
            third_feed_msg = rx
                .recv()
                .await
                .expect("header channel was closed");
        }
        assert!(third_feed_msg
            .state_msgs
            .contains_key("uniswap-v2"));
        assert!(third_feed_msg
            .state_msgs
            .contains_key("uniswap-v3"));
        assert!(matches!(
            third_feed_msg.sync_states.get("uniswap-v2").unwrap(),
            SynchronizerState::Ready(header) if header.number == 3
        ));
        assert!(matches!(
            third_feed_msg.sync_states.get("uniswap-v3").unwrap(),
            SynchronizerState::Ready(header) if header.number == 3
        ));
    }

    #[test(tokio::test)]
    async fn test_different_start_blocks() {
        let v2_sync = MockStateSync::new();
        let v3_sync = MockStateSync::new();
        let block_sync = BlockSynchronizer::with_short_timeouts()
            .register_synchronizer(
                ExtractorIdentity { chain: Chain::Ethereum, name: "uniswap-v2".to_string() },
                v2_sync.clone(),
            )
            .register_synchronizer(
                ExtractorIdentity { chain: Chain::Ethereum, name: "uniswap-v3".to_string() },
                v3_sync.clone(),
            );

        // Initial messages - synchronizers at different blocks
        let block1_msg = StateSyncMessage {
            header: BlockHeader {
                number: 1,
                hash: Bytes::from(vec![1]),
                parent_hash: Bytes::from(vec![0]),
                revert: false,
                ..Default::default()
            },
            ..Default::default()
        };
        let block2_msg = StateSyncMessage {
            header: BlockHeader {
                number: 2,
                hash: Bytes::from(vec![2]),
                parent_hash: Bytes::from(vec![1]),
                revert: false,
                ..Default::default()
            },
            ..Default::default()
        };

        let _ = v2_sync
            .send_header(block1_msg.clone())
            .await;
        v3_sync
            .send_header(block2_msg.clone())
            .await
            .expect("send_header failed");

        // Start the block synchronizer - it should use block 2 as the starting block
        let (_jh, mut rx) = block_sync
            .run()
            .await
            .expect("BlockSynchronizer failed to start.");

        // Consume first message
        let first_feed_msg = rx
            .recv()
            .await
            .expect("header channel was closed");
        assert!(matches!(
            first_feed_msg.sync_states.get("uniswap-v2").unwrap(),
            SynchronizerState::Delayed(header) if header.number == 1
        ));
        assert!(matches!(
            first_feed_msg.sync_states.get("uniswap-v3").unwrap(),
            SynchronizerState::Ready(header) if header.number == 2
        ));

        // Now v2 catches up to block 2
        v2_sync
            .send_header(block2_msg.clone())
            .await
            .expect("send_header failed");

        // Both advance to block 3
        let block3_msg = StateSyncMessage {
            header: BlockHeader {
                number: 3,
                hash: Bytes::from(vec![3]),
                parent_hash: Bytes::from(vec![2]),
                revert: false,
                ..Default::default()
            },
            ..Default::default()
        };
        let _ = v2_sync
            .send_header(block3_msg.clone())
            .await;
        v3_sync
            .send_header(block3_msg.clone())
            .await
            .expect("send_header failed");

        // Consume third message - both should be on block 3
        let second_feed_msg = rx
            .recv()
            .await
            .expect("header channel was closed");
        assert_eq!(second_feed_msg.state_msgs.len(), 2);
        assert!(matches!(
            second_feed_msg.sync_states.get("uniswap-v2").unwrap(),
            SynchronizerState::Ready(header) if header.number == 3
        ));
        assert!(matches!(
            second_feed_msg.sync_states.get("uniswap-v3").unwrap(),
            SynchronizerState::Ready(header) if header.number == 3
        ));
    }

    #[test(tokio::test)]
    async fn test_synchronizer_task_failure_triggers_cleanup() {
        // Test Case 1: Verify that when a synchronizer task fails,
        // the nanny properly cleans up all other synchronizers

        let v2_sync = MockStateSync::with_behavior(MockBehavior::ExitImmediately);
        let v3_sync = MockStateSync::new(); // Normal behavior

        let block_sync = BlockSynchronizer::with_short_timeouts()
            .register_synchronizer(
                ExtractorIdentity { chain: Chain::Ethereum, name: "uniswap-v2".to_string() },
                v2_sync.clone(),
            )
            .register_synchronizer(
                ExtractorIdentity { chain: Chain::Ethereum, name: "uniswap-v3".to_string() },
                v3_sync.clone(),
            );

        // Send initial messages
        let start_msg = StateSyncMessage {
            header: BlockHeader { number: 1, ..Default::default() },
            ..Default::default()
        };
        v2_sync
            .send_header(start_msg.clone())
            .await
            .expect("send_header failed");
        v3_sync
            .send_header(start_msg.clone())
            .await
            .expect("send_header failed");

        // Start BlockSynchronizer - v2_sync will exit immediately with error
        let (nanny_handle, mut sync_rx) = block_sync
            .run()
            .await
            .expect("BlockSynchronizer failed to start");

        // Consume first message to ensure at least one synchronizer is running
        let first_msg = sync_rx
            .recv()
            .await
            .expect("Should receive first message");
        // v2_sync might have already failed, so we might only get v3_sync message
        assert!(!first_msg.state_msgs.is_empty());

        // Wait for nanny to detect task failure and execute cleanup
        let result = timeout(Duration::from_secs(2), nanny_handle).await;
        assert!(result.is_ok(), "Nanny should complete when synchronizer task exits");

        // Give cleanup time to execute
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Verify that the remaining synchronizer received close signal during cleanup
        assert!(
            v3_sync.was_close_received().await,
            "v3_sync should have received close signal during cleanup"
        );
    }

    #[test(tokio::test)]
    async fn test_synchronizer_task_exit_triggers_cleanup() {
        // Test Case 2: StateSynchronizer task exits with error on close, triggering nanny cleanup
        // This tests the first branch of the nanny's select statement

        let v2_sync = MockStateSync::with_behavior(MockBehavior::FailOnExit);
        let v3_sync = MockStateSync::new();

        let block_sync = BlockSynchronizer::with_short_timeouts()
            .register_synchronizer(
                ExtractorIdentity { chain: Chain::Ethereum, name: "uniswap-v2".to_string() },
                v2_sync.clone(),
            )
            .register_synchronizer(
                ExtractorIdentity { chain: Chain::Ethereum, name: "uniswap-v3".to_string() },
                v3_sync.clone(),
            );

        // Send initial messages
        let start_msg = StateSyncMessage {
            header: BlockHeader { number: 1, ..Default::default() },
            ..Default::default()
        };
        v2_sync
            .send_header(start_msg.clone())
            .await
            .expect("send_header failed");
        v3_sync
            .send_header(start_msg.clone())
            .await
            .expect("send_header failed");

        // Start BlockSynchronizer
        let (nanny_handle, mut sync_rx) = block_sync
            .run()
            .await
            .expect("BlockSynchronizer failed to start");

        // Consume first message
        let first_msg = sync_rx
            .recv()
            .await
            .expect("Should receive first message");
        assert_eq!(first_msg.state_msgs.len(), 2);

        // Send a close signal to v2_sync to make it exit with error (due to FailOnExit behavior)
        // This should trigger the first branch of the nanny's select statement
        v2_sync.trigger_close().await;

        // Wait for nanny to detect synchronizer task exit and complete cleanup
        let result = timeout(Duration::from_secs(2), nanny_handle).await;
        assert!(result.is_ok(), "Nanny should complete when synchronizer task exits");

        // Give cleanup time to execute
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Verify cleanup was triggered - v3_sync should have received close signal
        assert!(
            v3_sync.was_close_received().await,
            "v3_sync should have received close signal during cleanup"
        );
    }

    #[test(tokio::test)]
    async fn test_main_loop_timeout_triggers_cleanup() {
        // Test Case 3: Main loop times out waiting for synchronizers
        // This simulates synchronizers becoming unresponsive

        let v2_sync = MockStateSync::new();
        let v3_sync = MockStateSync::new();

        let block_sync = BlockSynchronizer::with_short_timeouts()
            .register_synchronizer(
                ExtractorIdentity { chain: Chain::Ethereum, name: "uniswap-v2".to_string() },
                v2_sync.clone(),
            )
            .register_synchronizer(
                ExtractorIdentity { chain: Chain::Ethereum, name: "uniswap-v3".to_string() },
                v3_sync.clone(),
            );

        // Send initial messages
        let start_msg = StateSyncMessage {
            header: BlockHeader { number: 1, ..Default::default() },
            ..Default::default()
        };
        v2_sync
            .send_header(start_msg.clone())
            .await
            .expect("send_header failed");
        v3_sync
            .send_header(start_msg.clone())
            .await
            .expect("send_header failed");

        // Start BlockSynchronizer
        let (nanny_handle, mut sync_rx) = block_sync
            .run()
            .await
            .expect("BlockSynchronizer failed to start");

        // Consume first message
        let first_msg = sync_rx
            .recv()
            .await
            .expect("Should receive first message");
        assert_eq!(first_msg.state_msgs.len(), 2);

        // Don't send any more messages - synchronizers will become stale and eventually cause
        // main loop to error when no ready synchronizers remain

        // Wait for main loop to error due to no ready synchronizers
        let result = timeout(Duration::from_secs(3), nanny_handle).await;
        assert!(
            result.is_ok(),
            "Nanny should complete when main loop errors due to no ready synchronizers"
        );

        // Give cleanup time to execute
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Verify cleanup was triggered
        assert!(
            v2_sync.was_close_received().await,
            "v2_sync should have received close signal during cleanup"
        );
        assert!(
            v3_sync.was_close_received().await,
            "v3_sync should have received close signal during cleanup"
        );
    }

    #[test(tokio::test)]
    async fn test_cleanup_timeout_warning() {
        // Verify that cleanup_synchronizers emits a warning when synchronizers timeout during
        // cleanup

        let v2_sync = MockStateSync::with_behavior(MockBehavior::ExitImmediately);
        let v3_sync = MockStateSync::with_behavior(MockBehavior::IgnoreClose);

        let block_sync = BlockSynchronizer::with_short_timeouts()
            .register_synchronizer(
                ExtractorIdentity { chain: Chain::Ethereum, name: "uniswap-v2".to_string() },
                v2_sync.clone(),
            )
            .register_synchronizer(
                ExtractorIdentity { chain: Chain::Ethereum, name: "uniswap-v3".to_string() },
                v3_sync.clone(),
            );

        // Send initial messages
        let start_msg = StateSyncMessage {
            header: BlockHeader { number: 1, ..Default::default() },
            ..Default::default()
        };
        v2_sync
            .send_header(start_msg.clone())
            .await
            .expect("send_header failed");
        v3_sync
            .send_header(start_msg.clone())
            .await
            .expect("send_header failed");

        // Start BlockSynchronizer - v2_sync will exit immediately, triggering cleanup
        // v3_sync will ignore close signals and timeout during cleanup
        let (nanny_handle, mut sync_rx) = block_sync
            .run()
            .await
            .expect("BlockSynchronizer failed to start");

        // Might not get any messages if v2_sync fails before producing output
        let _ = sync_rx.recv().await;

        // Wait for nanny to complete - cleanup should timeout on v3_sync but still complete
        let result = timeout(Duration::from_secs(10), nanny_handle).await;
        assert!(
            result.is_ok(),
            "Nanny should complete even when some synchronizers timeout during cleanup"
        );

        // Note: In a real test environment, we would capture log output to verify the warning was
        // emitted. Since this is a unit test without log capture setup, we just verify that
        // cleanup completes even when some synchronizers timeout.
    }

    #[test(tokio::test)]
    async fn test_one_synchronizer_goes_stale_while_other_works() {
        // Test Case 1: One protocol goes stale and is removed while another protocol works normally

        let v2_sync = MockStateSync::new();
        let v3_sync = MockStateSync::new();

        // Use reasonable timeouts to observe proper state transitions
        let mut block_sync = BlockSynchronizer::new(
            Duration::from_millis(20), // block_time
            Duration::from_millis(10), // max_wait
            2,                         // max_missed_blocks (stale threshold = 20ms * 2 = 40ms)
        );
        block_sync.max_messages(5); // Limit messages for test

        let block_sync = block_sync
            .register_synchronizer(
                ExtractorIdentity { chain: Chain::Ethereum, name: "uniswap-v2".to_string() },
                v2_sync.clone(),
            )
            .register_synchronizer(
                ExtractorIdentity { chain: Chain::Ethereum, name: "uniswap-v3".to_string() },
                v3_sync.clone(),
            );

        // Send initial messages to both synchronizers
        let block1_msg = StateSyncMessage {
            header: BlockHeader {
                number: 1,
                hash: Bytes::from(vec![1]),
                parent_hash: Bytes::from(vec![0]),
                revert: false,
                timestamp: 1000,
            },
            ..Default::default()
        };
        let _ = v2_sync
            .send_header(block1_msg.clone())
            .await;
        let _ = v3_sync
            .send_header(block1_msg.clone())
            .await;

        // Start the block synchronizer
        let (nanny_handle, mut rx) = block_sync
            .run()
            .await
            .expect("BlockSynchronizer failed to start");

        // Consume the first message - both should be ready
        let first_feed_msg = rx
            .recv()
            .await
            .expect("Should receive first message");
        assert_eq!(first_feed_msg.state_msgs.len(), 2);
        assert!(matches!(
            first_feed_msg
                .sync_states
                .get("uniswap-v2")
                .unwrap(),
            SynchronizerState::Ready(_)
        ));
        assert!(matches!(
            first_feed_msg
                .sync_states
                .get("uniswap-v3")
                .unwrap(),
            SynchronizerState::Ready(_)
        ));

        // Send block 2 only to v3, v2 will timeout and become delayed
        let block2_msg = StateSyncMessage {
            header: BlockHeader {
                number: 2,
                hash: Bytes::from(vec![2]),
                parent_hash: Bytes::from(vec![1]),
                revert: false,
                timestamp: 2000,
            },
            ..Default::default()
        };
        let _ = v3_sync
            .send_header(block2_msg.clone())
            .await;
        // Don't send to v2_sync - it will timeout

        // Consume second message - v2 should be delayed, v3 ready
        let second_feed_msg = rx
            .recv()
            .await
            .expect("Should receive second message");
        assert!(second_feed_msg
            .state_msgs
            .contains_key("uniswap-v3"));
        assert!(!second_feed_msg
            .state_msgs
            .contains_key("uniswap-v2"));
        assert!(matches!(
            second_feed_msg
                .sync_states
                .get("uniswap-v3")
                .unwrap(),
            SynchronizerState::Ready(_)
        ));
        // v2 should be delayed (if still present) - check nanny is still running
        if let Some(v2_state) = second_feed_msg
            .sync_states
            .get("uniswap-v2")
        {
            if matches!(v2_state, SynchronizerState::Delayed(_)) {
                // Verify nanny is still running when synchronizer is just delayed
                assert!(
                    !nanny_handle.is_finished(),
                    "Nanny should still be running when synchronizer is delayed (not stale yet)"
                );
            }
        }

        // Wait a bit, then continue sending blocks to v3 but not v2
        tokio::time::sleep(Duration::from_millis(15)).await;

        // Continue sending blocks only to v3 to keep it healthy while v2 goes stale
        let block3_msg = StateSyncMessage {
            header: BlockHeader {
                number: 3,
                hash: Bytes::from(vec![3]),
                parent_hash: Bytes::from(vec![2]),
                revert: false,
                timestamp: 3000,
            },
            ..Default::default()
        };
        let _ = v3_sync
            .send_header(block3_msg.clone())
            .await;

        // Wait more time for v2 to go stale
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Consume remaining messages until we see v2 is removed
        let mut found_removed = false;

        for _ in 0..3 {
            if let Some(msg) = rx.recv().await {
                if !msg
                    .sync_states
                    .contains_key("uniswap-v2")
                {
                    // v2 has been removed from sync_states
                    found_removed = true;
                }

                // v3 should still be working (can be Ready, Delayed, or Advanced)
                if let Some(v3_state) = msg.sync_states.get("uniswap-v3") {
                    assert!(
                        !matches!(v3_state, SynchronizerState::Stale(_) | SynchronizerState::Ended),
                        "v3 should not be stale or ended, but was: {v3_state:?}"
                    );
                }

                if found_removed {
                    break;
                }
            } else {
                break;
            }
        }

        // v2 should be removed (it may go stale briefly but get purged immediately)
        assert!(found_removed, "v2 synchronizer should be removed after going stale");
        // Note: found_stale might be false if the stale synchronizer is purged immediately
    }

    #[test(tokio::test)]
    async fn test_all_synchronizers_go_stale_main_loop_exits() {
        // Test Case 2: All protocols go stale and main loop exits gracefully

        let v2_sync = MockStateSync::new();
        let v3_sync = MockStateSync::new();

        // Use reasonable timeouts to observe proper state transitions
        let mut block_sync = BlockSynchronizer::new(
            Duration::from_millis(20), // block_time
            Duration::from_millis(10), // max_wait
            3,                         // max_missed_blocks (stale threshold = 20ms * 3 = 60ms)
        );
        block_sync.max_messages(10); // Allow enough messages to see the progression

        let block_sync = block_sync
            .register_synchronizer(
                ExtractorIdentity { chain: Chain::Ethereum, name: "uniswap-v2".to_string() },
                v2_sync.clone(),
            )
            .register_synchronizer(
                ExtractorIdentity { chain: Chain::Ethereum, name: "uniswap-v3".to_string() },
                v3_sync.clone(),
            );

        // Send initial messages to both synchronizers
        let block1_msg = StateSyncMessage {
            header: BlockHeader {
                number: 1,
                hash: Bytes::from(vec![1]),
                parent_hash: Bytes::from(vec![0]),
                revert: false,
                timestamp: 1000,
            },
            ..Default::default()
        };
        let _ = v2_sync
            .send_header(block1_msg.clone())
            .await;
        let _ = v3_sync
            .send_header(block1_msg.clone())
            .await;

        // Start the block synchronizer
        let (nanny_handle, mut rx) = block_sync
            .run()
            .await
            .expect("BlockSynchronizer failed to start");

        // Consume the first message - both should be ready
        let first_feed_msg = rx
            .recv()
            .await
            .expect("Should receive first message");
        assert_eq!(first_feed_msg.state_msgs.len(), 2);
        assert!(matches!(
            first_feed_msg
                .sync_states
                .get("uniswap-v2")
                .unwrap(),
            SynchronizerState::Ready(_)
        ));
        assert!(matches!(
            first_feed_msg
                .sync_states
                .get("uniswap-v3")
                .unwrap(),
            SynchronizerState::Ready(_)
        ));

        // Stop sending messages to both synchronizers - they should both timeout and go stale
        // Don't send any more messages, let them timeout and become delayed, then stale

        // Monitor the state transitions to ensure proper delayed -> stale progression
        let mut seen_delayed = false;

        // Consume messages and track state transitions
        // Give enough time for the synchronizers to transition through states
        let timeout_duration = Duration::from_millis(500); // Generous timeout
        let start_time = tokio::time::Instant::now();

        while let Ok(Some(msg)) = tokio::time::timeout(Duration::from_millis(50), rx.recv()).await {
            // Track when synchronizers transition to delayed
            if !seen_delayed {
                let v2_state = msg.sync_states.get("uniswap-v2");
                let v3_state = msg.sync_states.get("uniswap-v3");

                if matches!(v2_state, Some(SynchronizerState::Delayed(_))) ||
                    matches!(v3_state, Some(SynchronizerState::Delayed(_)))
                {
                    seen_delayed = true;
                    // Verify nanny is still running when synchronizers are just delayed
                    assert!(!nanny_handle.is_finished(),
                        "Nanny should still be running when synchronizers are delayed (not stale yet)");
                    // Once we've seen delayed and verified nanny is running, we can break
                    break;
                }
            }

            // Safety timeout to avoid infinite loop
            if start_time.elapsed() > timeout_duration {
                break;
            }
        }

        // Wait for the main loop to complete (all synchronizers should eventually go stale)
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Consume any remaining messages until channel closes
        while rx.recv().await.is_some() {
            // Just drain the channel
        }
        // Channel is now closed

        // The nanny should complete when the main loop exits due to no ready synchronizers
        let nanny_result = timeout(Duration::from_secs(2), nanny_handle).await;
        assert!(nanny_result.is_ok(), "Nanny should complete when main loop exits");

        // Verify that synchronizers went through proper state transitions
        assert!(seen_delayed, "Synchronizers should transition to Delayed state first");
        // Note: We might not see the Stale state because stale synchronizers are immediately purged
        // The important thing is that they stayed in Delayed for the proper duration before being
        // removed

        // If we reach here, the channel was closed, indicating the main loop exited gracefully

        // Give cleanup time to execute
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Verify cleanup was triggered for both synchronizers
        assert!(
            v2_sync.was_close_received().await,
            "v2_sync should have received close signal during cleanup"
        );
        assert!(
            v3_sync.was_close_received().await,
            "v3_sync should have received close signal during cleanup"
        );
    }
}
