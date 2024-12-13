use crate::{
    evm::decoder::{StreamDecodeError, TychoStreamDecoder},
    models::Token,
    protocol::{
        errors::InvalidSnapshotError,
        models::{BlockUpdate, TryFromWithBlock},
        state::ProtocolSim,
    },
};
use futures::{Stream, StreamExt};
use std::{collections::HashMap, sync::Arc};
use tokio_stream::wrappers::ReceiverStream;
use tycho_client::{
    feed::{component_tracker::ComponentFilter, synchronizer::ComponentWithState},
    stream::{StreamError, TychoStreamBuilder},
};
use tycho_core::{dto::Chain, Bytes};

pub struct ProtocolStreamBuilder {
    decoder: TychoStreamDecoder,
    stream_builder: TychoStreamBuilder,
}

impl ProtocolStreamBuilder {
    pub fn new(tycho_url: &str, chain: Chain) -> Self {
        Self {
            decoder: TychoStreamDecoder::new(),
            stream_builder: TychoStreamBuilder::new(tycho_url, chain),
        }
    }

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

    pub fn block_time(mut self, block_time: u64) -> Self {
        self.stream_builder = self
            .stream_builder
            .block_time(block_time);
        self
    }

    pub fn timeout(mut self, timeout: u64) -> Self {
        self.stream_builder = self.stream_builder.timeout(timeout);
        self
    }

    pub fn no_state(mut self, no_state: bool) -> Self {
        self.stream_builder = self.stream_builder.no_state(no_state);
        self
    }

    pub fn auth_key(mut self, auth_key: Option<String>) -> Self {
        self.stream_builder = self.stream_builder.auth_key(auth_key);
        self
    }

    pub fn no_tls(mut self, no_tls: bool) -> Self {
        self.stream_builder = self.stream_builder.no_tls(no_tls);
        self
    }

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
