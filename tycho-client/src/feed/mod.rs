use std::collections::HashMap;

use chrono::{Local, NaiveDateTime};
use futures03::{
    future::{join_all, try_join_all},
    stream::FuturesUnordered,
    StreamExt,
};
use serde::Serialize;
use tokio::{
    select,
    sync::mpsc::{self, Receiver},
    task::JoinHandle,
    time::timeout,
};
use tracing::{debug, error, info, trace, warn};
use tycho_core::{
    dto::{Block, ExtractorIdentity},
    Bytes,
};

use self::{
    block_history::{BlockHistory, BlockPosition},
    synchronizer::{StateSyncMessage, StateSynchronizer},
};

mod block_history;
pub mod component_tracker;
pub mod synchronizer;

#[derive(Debug, Clone, PartialEq, Default, Serialize)]
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

type BlockSyncResult<T> = anyhow::Result<T>;

/// Aligns multiple StateSynchronizers on the block dimension.
///
/// ## Purpose
///
/// The purpose of this component is to handle streams from multiple state synchronizers and
/// basically align/merge them according to their blocks. Ideally this should be done in a
/// fault-tolerant way meaning we can recover from a state synchronizer suffering from timing
/// issues. E.g. a delayed or unresponsive state synchronizer might recover again. An advanced state
/// synchronizer can be included again once we reach the block it is at.
///
/// ## Limitations
/// - Supports only chains with fixed blocks time for now due to the lock step mechanism
///
/// ## Initialisation
/// Queries all registered synchronizers for their first message. It expects all synchronizers to
/// return a message from the same header. If this is not the case the run method will error.
///
/// ## Main loop
/// Once started, the synchronizers are queried concurrently for messages in lock step:
/// the main loop queries all synchronizers in ready for the last emitted data, builds the
/// `FeedMessage` and emits it, then it schedules the wait procedure for the
/// next block.
///
/// ## Synchronization Logic
///
/// To classify a synchronizer as delayed or advanced, we need to first define the current
/// block. Currently, we simply expect all synchronizer to be at the same block at startup. The
/// block they are at is then simply taken as the current block.
///
/// Once we heave the current block we can easily determine which block we expect next. And if a
/// state synchronizer delivers a different block from that we can classify it as delayed or
/// advanced.
///
/// If any synchronizer is in not ready state we will try to bring it back to the ready state. This
/// is done by trying to empty any buffers of a delayed synchronizer or waiting to reach
/// the height of an advanced synchronizer (and flagging it as such in the meantime).
///
/// Of course, we can't wait forever for a synchronizer to reply/recover. All of this must happen
/// within the block production step of the blockchain:
/// The wait procedure consists in waiting for any of the receivers to emit a new message (within a
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
}

#[derive(Clone, Debug, PartialEq, Serialize)]
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
    ) -> Option<StateSyncMessage> {
        let extractor_id = &self.extractor_id;
        let latest_block = block_history.latest();
        match &self.state {
            SynchronizerState::Started | SynchronizerState::Ended => {
                warn!(state=?&self.state, "Advancing Synchronizer in this state not supported!");
                None
            }
            SynchronizerState::Advanced(b) => {
                let future_block = b.clone();
                // Transition to ready once we arrived at the expected height
                self.transition(future_block, block_history);
                None
            }
            SynchronizerState::Ready(previous_block) => {
                // Try to recv the next expected block, update state accordingly.
                self.try_recv_next_expected(max_wait, block_history, previous_block.clone())
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
                self.try_catch_up(block_history, max_wait)
                    .await
            }
            SynchronizerState::Stale(old_block) => {
                debug!(
                    ?old_block,
                    ?latest_block,
                    %extractor_id,
                    "Trying to catch up to latest block"
                );
                self.try_catch_up(block_history, max_wait)
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
    ) -> Option<StateSyncMessage> {
        let extractor_id = &self.extractor_id;
        match timeout(max_wait, self.rx.recv()).await {
            Ok(Some(msg)) => {
                self.transition(msg.header.clone(), block_history);
                Some(msg)
            }
            Ok(None) => {
                error!(
                    %extractor_id,
                    ?previous_block,
                    "Extractor terminated: channel closed!"
                );
                self.state = SynchronizerState::Ended;
                self.modify_ts = Local::now().naive_utc();
                None
            }
            Err(_) => {
                // trying to advance a block timed out
                debug!(%extractor_id, ?previous_block, "Extractor did not check in within time.");
                self.state = SynchronizerState::Delayed(previous_block.clone());
                None
            }
        }
    }

    /// Tries to catch up a delayed state synchronizer.
    ///
    /// If a synchronizer is delayed, this method will try to remove any as many waiting values in
    /// it's queue until it caught up to the latest block, then it will try to wait for the next
    /// expected block within a timeout. Finally the state is updated based on the outcome.
    async fn try_catch_up(
        &mut self,
        block_history: &BlockHistory,
        max_wait: std::time::Duration,
    ) -> Option<StateSyncMessage> {
        let mut results = Vec::new();
        let extractor_id = &self.extractor_id;
        while let Ok(msg) = self.rx.try_recv() {
            let block_pos = block_history
                .determine_block_position(&msg.header)
                .unwrap();
            results.push(Ok(Some(msg)));
            if matches!(block_pos, BlockPosition::Latest) {
                debug!(?extractor_id, "Extractor managed to catch up to latest state!");
                break;
            }
        }
        results.push(timeout(max_wait, self.rx.recv()).await);

        let merged = results
            .into_iter()
            .filter_map(|e| match e {
                Ok(Some(b)) => Some(b),
                _ => None,
            })
            .reduce(|l, r| l.merge(r));

        if let Some(msg) = merged {
            // we were able to get at least one block out
            debug!(?extractor_id, "Delayed extractor made progress!");
            self.transition(msg.header.clone(), block_history);
            Some(msg)
        } else {
            None
        }
    }

    /// Logic for transition a state synchronizer.
    ///
    /// Given a newly received block from a state synchronizer, this method transitions it's state
    /// accordingly.
    fn transition(&mut self, latest_retrieved: Header, block_history: &BlockHistory) {
        let extractor_id = &self.extractor_id;
        let last_message_at = self.modify_ts;
        let block = &latest_retrieved;
        match block_history
            .determine_block_position(&latest_retrieved)
            .expect("Block positiion could not be determined.")
        {
            BlockPosition::NextExpected => {
                self.state = SynchronizerState::Ready(latest_retrieved.clone());
            }
            BlockPosition::Latest | BlockPosition::Delayed => {
                let now = Local::now().naive_utc();
                if self
                    .modify_ts
                    .signed_duration_since(now) >
                    chrono::Duration::seconds(60)
                {
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
    }
}

#[derive(Debug, PartialEq, Serialize)]
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
    pub fn new(block_time: std::time::Duration, max_wait: std::time::Duration) -> Self {
        Self { synchronizers: None, max_messages: None, block_time, max_wait }
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
            .expect("No synchronizers set!");
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
                let res = timeout(self.block_time, sh.rx.recv()).await;
                (id.clone(), res)
            };
            startup_futures.push(fut);
        }
        let mut ready_sync_msgs = HashMap::new();
        join_all(startup_futures)
            .await
            .into_iter()
            .for_each(|(extractor_id, res)| {
                let synchronizer = sync_streams
                    .get_mut(&extractor_id)
                    .unwrap();
                match res {
                    Ok(Some(msg)) => {
                        debug!(%extractor_id, height=?&msg.header.number, "Synchronizer started successfully!");
                        synchronizer.state = SynchronizerState::Ready(msg.header.clone());
                        ready_sync_msgs.insert(extractor_id.name.clone(), msg);
                    }
                    Ok(None) => {
                        warn!(%extractor_id, "Dead synchronizer at startup will be purged!");
                        synchronizer.state = SynchronizerState::Ended;
                    }
                    Err(_) => {
                        warn!(%extractor_id, "Stale synchronizer at startup will be purged!");
                        synchronizer.state = SynchronizerState::Ended;
                    }
                }
            });

        // Purge any stale synchronizers, require rest to be ready on the same block, else fail.
        // It's probably worth doing more complex things here if this is problematic e.g. setting
        // some as delayed and waiting for those to catch up, but I want to go with the simplest
        // solution first.
        sync_streams.retain(|_, v| matches!(v.state, SynchronizerState::Ready(_)));
        let start_header = if let Some(first) = ready_sync_msgs.values().next() {
            if !ready_sync_msgs
                .values()
                .all(|v| first.header == v.header)
            {
                anyhow::bail!("not all synchronizers on same block!")
            }
            info!(start_block=?&first.header, n_healthy=?ready_sync_msgs.len(), "Block synchronisation started successfully!");
            first.header.clone()
        } else {
            anyhow::bail!("Not a single synchronizer healthy!")
        };

        let mut block_history = BlockHistory::new(vec![start_header], 15);
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
                            .try_advance(&block_history, self.block_time + self.max_wait)
                            .await;
                        res.map(|msg| (extractor_id.name.clone(), msg))
                    });
                }
                ready_sync_msgs.extend(
                    join_all(recv_futures)
                        .await
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

                block_history
                    .push(
                        sync_streams
                            .values()
                            .filter_map(|v| match &v.state {
                                SynchronizerState::Ready(b) => Some(b),
                                _ => None,
                            })
                            .next()
                            // no synchronizers is ready
                            .ok_or_else(|| {
                                anyhow::format_err!("Not a single synchronizer was ready.")
                            })?
                            .clone(),
                    )
                    .map_err(|err| anyhow::format_err!("Failed processing new block: {}", err))?;
            }
        });

        let nanny_jh = tokio::spawn(async move {
            select! {
                error = state_sync_tasks.select_next_some() => {
                    for s in sync_handles.iter_mut() {
                        s.close().await.expect("StateSynchronizer was not started!");
                    }
                    error!(?error, "state synchronizer exited");
                },
                error = main_loop_jh => {
                    error!(?error, "feed main loop exited");
                }
            }
        });
        Ok((nanny_jh, sync_rx))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feed::synchronizer::SyncResult;
    use async_trait::async_trait;
    use std::sync::Arc;
    use test_log::test;
    use tokio::sync::{oneshot, Mutex};
    use tycho_core::dto::Chain;

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
                _ = end_rx.await;
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
                Err(anyhow::format_err!("Not connected"))
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
}
