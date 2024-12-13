use std::{collections::HashMap, sync::Arc};

use futures::{Stream, StreamExt};
use tokio_stream::wrappers::ReceiverStream;
use tycho_client::{
    feed::{component_tracker::ComponentFilter, synchronizer::ComponentWithState},
    stream::{StreamError, TychoStreamBuilder},
};
use tycho_core::{dto::Chain, Bytes};

use crate::{
    evm::decoder::{StreamDecodeError, TychoStreamDecoder},
    models::Token,
    protocol::{
        errors::InvalidSnapshotError,
        models::{BlockUpdate, TryFromWithBlock},
        state::ProtocolSim,
    },
};

pub struct ProtocolStreamBuilder {
    decoder: TychoStreamDecoder,
    stream_builder: TychoStreamBuilder,
}

/// Builds the protocol stream, providing a `BlockUpdate` for each block received.
///
/// Each `BlockUpdate` can then be used at a higher level to retrieve important information from
/// the block, such as the updated states of protocol components, which can in turn be used
/// to obtain spot price information for a desired component and token pair.
///
/// # Returns
/// A result containing a stream of decoded block updates, where each item is either:
/// - `Ok(BlockUpdate)` if decoding succeeds.
/// - `Err(StreamDecodeError)` if a decoding error occurs.
///
/// # Errors
/// Returns a `StreamError` if the underlying stream builder fails to initialize.
impl ProtocolStreamBuilder {
    pub fn new(tycho_url: &str, chain: Chain) -> Self {
        Self {
            decoder: TychoStreamDecoder::new(),
            stream_builder: TychoStreamBuilder::new(tycho_url, chain),
        }
    }

    /// Adds an exchange and its corresponding filter to the Tycho client and decoder.
    ///
    /// These are the exchanges for which `BlockUpdate`s will be provided.
    pub fn exchange<T>(
        mut self,
        name: &str,
        filter: ComponentFilter,
        filter_fn: Option<fn(&ComponentWithState) -> bool>,
    ) -> Self
    where
        T: ProtocolSim
            + TryFromWithBlock<ComponentWithState, Error = InvalidSnapshotError>
            + Send
            + 'static,
    {
        self.stream_builder = self
            .stream_builder
            .exchange(name, filter);
        self.decoder.register_decoder::<T>(name);
        if let Some(predicate) = filter_fn {
            self.decoder
                .register_filter(name, predicate);
        }
        self
    }

    /// Sets the block time for the Tycho client.
    pub fn block_time(mut self, block_time: u64) -> Self {
        self.stream_builder = self
            .stream_builder
            .block_time(block_time);
        self
    }

    /// Sets the timeout duration for network operations.
    pub fn timeout(mut self, timeout: u64) -> Self {
        self.stream_builder = self.stream_builder.timeout(timeout);
        self
    }

    /// Configures the client to exclude state updates from the stream.
    pub fn no_state(mut self, no_state: bool) -> Self {
        self.stream_builder = self.stream_builder.no_state(no_state);
        self
    }

    /// Sets the API key for authenticating with the Tycho server.
    pub fn auth_key(mut self, auth_key: Option<String>) -> Self {
        self.stream_builder = self.stream_builder.auth_key(auth_key);
        self
    }

    /// Disables TLS/ SSL for the connection, using http and ws protocols.
    pub fn no_tls(mut self, no_tls: bool) -> Self {
        self.stream_builder = self.stream_builder.no_tls(no_tls);
        self
    }

    /// Sets the currently known tokens which to be considered during decoding.
    ///
    /// Protocol components containing tokens which are not included in this initial list, or
    /// added when applying deltas, will not be decoded.
    pub async fn set_tokens(self, tokens: HashMap<Bytes, Token>) -> Self {
        self.decoder.set_tokens(tokens).await;
        self
    }

    pub async fn build(
        self,
    ) -> Result<impl Stream<Item = Result<BlockUpdate, StreamDecodeError>>, StreamError> {
        let (_, rx) = self.stream_builder.build().await?;
        let decoder = Arc::new(self.decoder);

        Ok(Box::pin(ReceiverStream::new(rx).then({
            let decoder = decoder.clone(); // Clone the decoder for the closure
            move |msg| {
                let decoder = decoder.clone(); // Clone again for the async block
                async move { decoder.decode(msg).await }
            }
        })))
    }
}
