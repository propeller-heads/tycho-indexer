use anyhow::{anyhow, Error};
use async_stream::try_stream;
use futures03::{Stream, StreamExt};
use once_cell::sync::Lazy;
use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::sleep;
use tokio_retry::strategy::ExponentialBackoff;
use tracing::{error, info, info_span, trace, warn};

use crate::pb::sf::substreams::{
    rpc::v2::{response::Message, BlockScopedData, BlockUndoSignal, Request, Response},
    v1::Modules,
};

use crate::substreams::SubstreamsEndpoint;

pub enum BlockResponse {
    New(BlockScopedData),
    Undo(BlockUndoSignal),
}

pub struct SubstreamsStream {
    stream: Pin<Box<dyn Stream<Item = Result<BlockResponse, Error>> + Send>>,
}

impl SubstreamsStream {
    pub fn new(
        endpoint: Arc<SubstreamsEndpoint>,
        cursor: Option<String>,
        modules: Option<Modules>,
        output_module_name: String,
        start_block: i64,
        end_block: u64,
        final_blocks_only: bool,
    ) -> Self {
        SubstreamsStream {
            stream: Box::pin(stream_blocks(
                endpoint,
                cursor,
                modules,
                output_module_name,
                start_block,
                end_block,
                final_blocks_only,
            )),
        }
    }
}

static DEFAULT_BACKOFF: Lazy<ExponentialBackoff> =
    Lazy::new(|| ExponentialBackoff::from_millis(500).max_delay(Duration::from_secs(45)));

// Create the Stream implementation that streams blocks with auto-reconnection.
fn stream_blocks(
    endpoint: Arc<SubstreamsEndpoint>,
    cursor: Option<String>,
    modules: Option<Modules>,
    output_module_name: String,
    start_block_num: i64,
    stop_block_num: u64,
    final_blocks_only: bool,
) -> impl Stream<Item = Result<BlockResponse, Error>> {
    let mut latest_cursor = cursor.unwrap_or_default();
    let mut retry_count = 0;
    let mut backoff = DEFAULT_BACKOFF.clone();

    let span =
        info_span!("substreams_stream", %endpoint, %start_block_num, %latest_cursor, %retry_count);
    let _enter = span.enter();
    try_stream! {
        'retry_loop: loop {
            if retry_count > 0 {
                warn!("Blockstreams disconnected, connecting again");
            }

            let result = endpoint.clone().substreams(Request {
                start_block_num,
                start_cursor: latest_cursor.clone(),
                stop_block_num,
                final_blocks_only,
                modules: modules.clone(),
                output_module: output_module_name.clone(),
                // There is usually no good reason for you to consume the stream development mode (so switching `true`
                // to `false`). If you do switch it, be aware that more than one output module will be send back to you,
                // and the current code in `process_block_scoped_data` (within your 'main.rs' file) expects a single
                // module.
                production_mode: true,
                debug_initial_store_snapshot_for_modules: vec![],
            }).await;

            match result {
                Ok(stream) => {
                    info!("Blockstreams connected");

                    for await response in stream {
                        match process_substreams_response(response).await {
                            BlockProcessedResult::BlockScopedData(block_scoped_data) => {
                                // Reset backoff because we got a good value from the stream
                                backoff = DEFAULT_BACKOFF.clone();

                                let cursor = block_scoped_data.cursor.clone();
                                yield BlockResponse::New(block_scoped_data);

                                latest_cursor = cursor;
                            },
                            BlockProcessedResult::BlockUndoSignal(block_undo_signal) => {
                                // Reset backoff because we got a good value from the stream
                                backoff = DEFAULT_BACKOFF.clone();

                                let cursor = block_undo_signal.last_valid_cursor.clone();
                                yield BlockResponse::Undo(block_undo_signal);

                                latest_cursor = cursor;
                            },
                            BlockProcessedResult::Skip() => {},
                            BlockProcessedResult::TonicError(status) => {
                                // Unauthenticated errors are not retried, we forward the error back to the
                                // stream consumer which handles it
                                if status.code() == tonic::Code::Unauthenticated {
                                    return Err(anyhow::Error::new(status.clone()))?;
                                }

                                error!("Received tonic error {:#}", status);

                                // If we reach this point, we must wait a bit before retrying
                                if let Some(duration) = backoff.next() {
                                    info!("Will try to reconnect after {:?}", duration);
                                    sleep(duration).await;
                                    retry_count += 1;
                                } else {
                                    return Err(anyhow!("Backoff requested to stop retrying, quitting"))?;
                                }

                                continue 'retry_loop;
                            },
                        }
                    }

                    info!("Stream completed, reached end block");
                    return;
                },
                Err(e) => {
                    // We failed to connect and will try again; this is another
                    // case where we actually _want_ to back off in case we keep
                    // having connection errors.

                    error!("Unable to connect to endpoint: {:#}", e);
                }
            }
        }
    }
}

enum BlockProcessedResult {
    Skip(),
    BlockScopedData(BlockScopedData),
    BlockUndoSignal(BlockUndoSignal),
    TonicError(tonic::Status),
}

async fn process_substreams_response(
    result: Result<Response, tonic::Status>,
) -> BlockProcessedResult {
    let response = match result {
        Ok(v) => v,
        Err(e) => return BlockProcessedResult::TonicError(e),
    };

    match response.message {
        Some(Message::BlockScopedData(block_scoped_data)) => {
            BlockProcessedResult::BlockScopedData(block_scoped_data)
        }
        Some(Message::BlockUndoSignal(block_undo_signal)) => {
            BlockProcessedResult::BlockUndoSignal(block_undo_signal)
        }
        Some(Message::Progress(progress)) => {
            // The `ModulesProgress` messages goal is to report active parallel processing happening
            // either to fill up backward (relative to your request's start block) some missing
            // state or pre-process forward blocks (again relative).
            //
            // You could log that in trace or accumulate to push as metrics. Here a snippet of code
            // that prints progress to standard out. If your `BlockScopedData` messages seems to
            // never arrive in production mode, it's because progresses is happening but
            // not yet for the output module you requested.
            //
            // let progresses: Vec<_> = progress
            //     .modules
            //     .iter()
            //     .filter_map(|module| {
            //         use crate::pb::sf::substreams::rpc::v2::module_progress::Type;

            //         if let Type::ProcessedRanges(range) = module.r#type.as_ref().unwrap() {
            //             Some(format!(
            //                 "{} @ [{}]",
            //                 module.name,
            //                 range
            //                     .processed_ranges
            //                     .iter()
            //                     .map(|x| x.to_string())
            //                     .collect::<Vec<_>>()
            //                     .join(", ")
            //             ))
            //         } else {
            //             None
            //         }
            //     })
            //     .collect();

            trace!("Progress {:?}", progress);

            BlockProcessedResult::Skip()
        }
        None => {
            warn!("Got None on substream message");
            BlockProcessedResult::Skip()
        }
        _ => BlockProcessedResult::Skip(),
    }
}

impl Stream for SubstreamsStream {
    type Item = Result<BlockResponse, Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.stream.poll_next_unpin(cx)
    }
}
