use std::collections::{HashMap, HashSet};

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
    sync::mpsc::{self, Receiver},
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
    synchronizer::{StateSyncMessage, StateSynchronizer, SynchronizerError},
};

mod block_history;
pub mod component_tracker;
pub mod synchronizer;

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize, Eq, Hash)]
pub struct Header {
    pub hash: Bytes,
    pub number: u64,
    pub parent_hash: Bytes,
    pub revert: bool,
}

impl Header {
    fn from_block(block: &Block, revert: bool) -> Self {
        Self {
            hash: block.hash.clone(),
            number: block.number,
            parent_hash: block.parent_hash.clone(),
            revert,
        }
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
/// The wait procedure consists of waiting for any of the receivers to emit a new message (within a
/// max timeout - several multiples of the block time). Once a message is received a very short
/// timeout start for the remaining synchronizers, to deliver a message. Any synchronizer failing to
/// do so is transitioned to delayed.
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
    Ready(Header),
    // no progress, we consider it stale at that point we should purge it.
    Stale(Header),
    Delayed(Header),
    // For this to happen we must have a gap, and a gap usually means a new snapshot from the
    // StateSynchronizer. This can only happen if we are processing too slow and one of the
    // synchronizers restarts e.g. because Tycho ended the subscription.
    Advanced(Header),
    Ended,
}

pub struct SynchronizerStream {
    extractor_id: ExtractorIdentity,
    state: SynchronizerState,
    modify_ts: NaiveDateTime,
    rx: Receiver<StateSyncMessage>,
}

impl SynchronizerStream {
    async fn try_advance(
        &mut self,
        block_history: &BlockHistory,
        max_wait: std::time::Duration,
        stale_threshold: std::time::Duration,
    ) -> BlockSyncResult<Option<StateSyncMessage>> {
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
            SynchronizerState::Delayed(old_block) => {
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
            SynchronizerState::Stale(old_block) => {
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
    /// Will wait for a new block on the synchronizer within a timeout. And modify it's state based
    /// on the outcome.
    async fn try_recv_next_expected(
        &mut self,
        max_wait: std::time::Duration,
        block_history: &BlockHistory,
        previous_block: Header,
        stale_threshold: std::time::Duration,
    ) -> BlockSyncResult<Option<StateSyncMessage>> {
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
                    "Extractor terminated: channel closed!"
                );
                self.state = SynchronizerState::Ended;
                self.modify_ts = Local::now().naive_utc();
                Ok(None)
            }
            Err(_) => {
                // trying to advance a block timed out
                debug!(%extractor_id, ?previous_block, "Extractor did not check in within time.");
                self.state = SynchronizerState::Delayed(previous_block.clone());
                Ok(None)
            }
        }
    }

    /// Tries to catch up a delayed state synchronizer.
    ///
    /// If a synchronizer is delayed, this method will try to catch up to the next expected block
    /// by consuming all waiting messages in it's queue and waiting for any new block messages
    /// within a timeout. Finally, all update messages are merged into one and returned.
    async fn try_catch_up(
        &mut self,
        block_history: &BlockHistory,
        max_wait: std::time::Duration,
        stale_threshold: std::time::Duration,
    ) -> BlockSyncResult<Option<StateSyncMessage>> {
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
            Ok(None)
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
        latest_retrieved: Header,
        block_history: &BlockHistory,
        stale_threshold: std::time::Duration,
    ) -> Result<(), BlockSynchronizerError> {
        let extractor_id = self.extractor_id.clone();
        let last_message_at = self.modify_ts;
        let block = &latest_retrieved;

        match block_history.determine_block_position(&latest_retrieved)? {
            BlockPosition::NextExpected => {
                self.state = SynchronizerState::Ready(latest_retrieved.clone());
            }
            BlockPosition::Latest | BlockPosition::Delayed => {
                let now = Local::now().naive_utc();
                let wait_duration = self
                    .modify_ts
                    .signed_duration_since(now);
                let stale_threshold_chrono = ChronoDuration::from_std(stale_threshold)
                    .map_err(|e| BlockSynchronizerError::DurationConversionError(e.to_string()))?;
                if wait_duration > stale_threshold_chrono {
                    warn!(
                        ?extractor_id,
                        ?last_message_at,
                        ?block,
                        "Extractor transition to stale."
                    );
                    self.state = SynchronizerState::Stale(latest_retrieved.clone());
                } else {
                    warn!(
                        ?extractor_id,
                        ?last_message_at,
                        ?block,
                        "Extractor transition to delayed."
                    );
                    self.state = SynchronizerState::Delayed(latest_retrieved.clone());
                }
            }
            BlockPosition::Advanced => {
                error!(
                    ?extractor_id,
                    ?last_message_at,
                    ?block,
                    "Extractor transition to advanced."
                );
                self.state = SynchronizerState::Advanced(latest_retrieved.clone());
            }
        }
        self.modify_ts = Local::now().naive_utc();
        Ok(())
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct FeedMessage {
    pub state_msgs: HashMap<String, StateSyncMessage>,
    pub sync_states: HashMap<String, SynchronizerState>,
}

impl FeedMessage {
    fn new(
        state_msgs: HashMap<String, StateSyncMessage>,
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
    pub async fn run(mut self) -> BlockSyncResult<(JoinHandle<()>, Receiver<FeedMessage>)> {
        trace!("Starting BlockSynchronizer...");
        let mut state_sync_tasks = FuturesUnordered::new();
        let mut synchronizers = self
            .synchronizers
            .take()
            .ok_or(BlockSynchronizerError::NoSynchronizers)?;
        // init synchronizers
        let init_tasks = synchronizers
            .values()
            .map(|s| s.initialize())
            .collect::<Vec<_>>();
        try_join_all(init_tasks).await?;

        let mut sync_streams = HashMap::with_capacity(synchronizers.len());
        let mut sync_handles = Vec::new();
        for (extractor_id, synchronizer) in synchronizers.drain() {
            let (jh, rx) = synchronizer.start().await?;
            state_sync_tasks.push(jh);
            sync_handles.push(synchronizer);

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
                    synchronizer.state = SynchronizerState::Stale(Header::default());
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

                block_history.push(
                    sync_streams
                        .values()
                        .filter_map(|v| match &v.state {
                            SynchronizerState::Ready(b) => Some(b),
                            _ => None,
                        })
                        .next()
                        // no synchronizers are ready
                        .ok_or(BlockSynchronizerError::NoReadySynchronizers)?
                        .clone(),
                )?;
            }
        });

        let nanny_jh = tokio::spawn(async move {
            select! {
                error = state_sync_tasks.select_next_some() => {
                    for s in sync_handles.iter_mut() {
                        if let Err(e) = s.close().await {
                            error!(error=?e, "Failed to close synchronizer: was not started!");
                        }
                    }
                    error!(?error, "State synchronizer exited");
                },
                error = main_loop_jh => {
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

    use super::{synchronizer::SynchronizerError, *};
    use crate::feed::synchronizer::SyncResult;

    #[derive(Clone)]
    struct MockStateSync {
        header_tx: mpsc::Sender<StateSyncMessage>,
        header_rx: Arc<Mutex<Option<Receiver<StateSyncMessage>>>>,
        end_tx: Arc<Mutex<Option<oneshot::Sender<()>>>>,
    }

    impl MockStateSync {
        fn new() -> Self {
            let (tx, rx) = mpsc::channel(1);
            Self {
                header_tx: tx,
                header_rx: Arc::new(Mutex::new(Some(rx))),
                end_tx: Arc::new(Mutex::new(None)),
            }
        }
        async fn send_header(&self, header: StateSyncMessage) {
            self.header_tx
                .send(header)
                .await
                .expect("sending header failed");
        }
    }

    #[async_trait]
    impl StateSynchronizer for MockStateSync {
        async fn initialize(&self) -> SyncResult<()> {
            Ok(())
        }

        async fn start(
            &self,
        ) -> SyncResult<(JoinHandle<SyncResult<()>>, Receiver<StateSyncMessage>)> {
            let block_rx = {
                let mut guard = self.header_rx.lock().await;
                guard
                    .take()
                    .expect("Block receiver was not set!")
            };

            let end_rx = {
                let (end_tx, end_rx) = oneshot::channel();
                let mut guard = self.end_tx.lock().await;
                *guard = Some(end_tx);
                end_rx
            };

            let jh = tokio::spawn(async move {
                let _ = end_rx.await;
                SyncResult::Ok(())
            });

            Ok((jh, block_rx))
        }

        async fn close(&mut self) -> SyncResult<()> {
            let mut guard = self.end_tx.lock().await;
            if let Some(tx) = guard.take() {
                tx.send(())
                    .expect("end channel closed!");
                Ok(())
            } else {
                Err(SynchronizerError::CloseError("Not Started".to_string()))
            }
        }
    }

    #[test(tokio::test)]
    async fn test_two_ready_synchronizers() {
        let v2_sync = MockStateSync::new();
        let v3_sync = MockStateSync::new();
        let block_sync = BlockSynchronizer::new(
            std::time::Duration::from_millis(500),
            std::time::Duration::from_millis(50),
            10,
        )
        .register_synchronizer(
            ExtractorIdentity { chain: Chain::Ethereum, name: "uniswap-v2".to_string() },
            v2_sync.clone(),
        )
        .register_synchronizer(
            ExtractorIdentity { chain: Chain::Ethereum, name: "uniswap-v3".to_string() },
            v3_sync.clone(),
        );
        let start_msg = StateSyncMessage {
            header: Header { number: 1, ..Default::default() },
            ..Default::default()
        };
        v2_sync
            .send_header(start_msg.clone())
            .await;
        v3_sync
            .send_header(start_msg.clone())
            .await;

        let (_jh, mut rx) = block_sync
            .run()
            .await
            .expect("BlockSynchronizer failed to start.");
        let first_feed_msg = rx
            .recv()
            .await
            .expect("header channel was closed");
        let second_msg = StateSyncMessage {
            header: Header { number: 2, ..Default::default() },
            ..Default::default()
        };
        v2_sync
            .send_header(second_msg.clone())
            .await;
        v3_sync
            .send_header(second_msg.clone())
            .await;
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
        let block_sync = BlockSynchronizer::new(
            std::time::Duration::from_millis(500),
            std::time::Duration::from_millis(50),
            10,
        )
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
            header: Header {
                number: 1,
                hash: Bytes::from(vec![1]),
                parent_hash: Bytes::from(vec![0]),
                revert: false,
            },
            ..Default::default()
        };
        v2_sync
            .send_header(block1_msg.clone())
            .await;
        v3_sync
            .send_header(block1_msg.clone())
            .await;

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
            header: Header {
                number: 2,
                hash: Bytes::from(vec![2]),
                parent_hash: Bytes::from(vec![1]),
                revert: false,
            },
            ..Default::default()
        };
        v2_sync
            .send_header(block2_msg.clone())
            .await;

        // Consume second message - v3 should be delayed
        let second_feed_msg = rx
            .recv()
            .await
            .expect("header channel was closed");
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
            .await;

        // Both advance to block 3
        let block3_msg = StateSyncMessage {
            header: Header {
                number: 3,
                hash: Bytes::from(vec![3]),
                parent_hash: Bytes::from(vec![2]),
                revert: false,
            },
            ..Default::default()
        };
        v2_sync
            .send_header(block3_msg.clone())
            .await;
        v3_sync.send_header(block3_msg).await;

        // Consume third message - both should be on block 3
        let third_feed_msg = rx
            .recv()
            .await
            .expect("header channel was closed");
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
        let block_sync = BlockSynchronizer::new(
            std::time::Duration::from_millis(500),
            std::time::Duration::from_millis(50),
            10,
        )
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
            header: Header {
                number: 1,
                hash: Bytes::from(vec![1]),
                parent_hash: Bytes::from(vec![0]),
                revert: false,
            },
            ..Default::default()
        };
        let block2_msg = StateSyncMessage {
            header: Header {
                number: 2,
                hash: Bytes::from(vec![2]),
                parent_hash: Bytes::from(vec![1]),
                revert: false,
            },
            ..Default::default()
        };

        v2_sync
            .send_header(block1_msg.clone())
            .await;
        v3_sync
            .send_header(block2_msg.clone())
            .await;

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
            .await;

        // Both advance to block 3
        let block3_msg = StateSyncMessage {
            header: Header {
                number: 3,
                hash: Bytes::from(vec![3]),
                parent_hash: Bytes::from(vec![2]),
                revert: false,
            },
            ..Default::default()
        };
        v2_sync
            .send_header(block3_msg.clone())
            .await;
        v3_sync
            .send_header(block3_msg.clone())
            .await;

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
}
