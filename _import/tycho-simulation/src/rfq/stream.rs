// TODO: remove this
#![allow(dead_code)]

use std::collections::HashMap;

use futures::{stream::select_all, StreamExt};
use tycho_client::feed::{synchronizer::ComponentWithState, FeedMessage};
use tycho_common::simulation::protocol_sim::ProtocolSim;

use crate::{
    evm::decoder::TychoStreamDecoder,
    protocol::{
        errors::InvalidSnapshotError,
        models::{TryFromWithBlock, Update},
    },
    rfq::{client::RFQClient, models::TimestampHeader},
};

#[derive(Default)]
pub struct RFQStreamBuilder {
    clients: Vec<Box<dyn RFQClient>>,
    decoder: TychoStreamDecoder<TimestampHeader>,
}

impl RFQStreamBuilder {
    pub fn new() -> Self {
        Self { clients: Vec::new(), decoder: TychoStreamDecoder::new() }
    }

    pub fn add_client<T>(mut self, name: &str, provider: Box<dyn RFQClient>) -> Self
    where
        T: ProtocolSim
            + TryFromWithBlock<ComponentWithState, TimestampHeader, Error = InvalidSnapshotError>
            + Send
            + 'static,
    {
        self.clients.push(provider);
        self.decoder.register_decoder::<T>(name);
        self
    }

    pub async fn build(self, tx: tokio::sync::mpsc::Sender<Update>) {
        let streams: Vec<_> = self
            .clients
            .into_iter()
            .map(|provider| provider.stream())
            .collect();

        let mut merged = select_all(streams);

        while let Some((provider, msg)) = merged.next().await {
            let update = self
                .decoder
                .decode(FeedMessage {
                    state_msgs: HashMap::from([(provider.clone(), msg)]),
                    sync_states: HashMap::new(),
                })
                .await
                .unwrap();

            tx.send(update).await.unwrap();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{any::Any, time::Duration};

    use async_trait::async_trait;
    use futures::stream::BoxStream;
    use num_bigint::BigUint;
    use tokio::sync::mpsc;
    use tokio_stream::wrappers::IntervalStream;
    use tycho_client::feed::synchronizer::{Snapshot, StateSyncMessage};
    use tycho_common::{
        dto::{ProtocolComponent, ProtocolStateDelta, ResponseProtocolState},
        models::token::Token,
        simulation::{
            errors::{SimulationError, TransitionError},
            protocol_sim::{Balances, GetAmountOutResult},
        },
        Bytes,
    };

    use super::*;
    use crate::rfq::{
        errors::RFQError, indicatively_priced::SignedQuote, models::GetAmountOutParams,
    };

    #[derive(Clone, Debug)]
    pub struct DummyProtocol;

    impl ProtocolSim for DummyProtocol {
        fn fee(&self) -> f64 {
            unimplemented!("Not needed for this test")
        }

        fn spot_price(&self, _base: &Token, _quote: &Token) -> Result<f64, SimulationError> {
            unimplemented!("Not needed for this test")
        }

        fn get_amount_out(
            &self,
            _amount_in: BigUint,
            _token_in: &Token,
            _token_out: &Token,
        ) -> Result<GetAmountOutResult, SimulationError> {
            unimplemented!("Not needed for this test")
        }

        fn get_limits(
            &self,
            _sell_token: Bytes,
            _buy_token: Bytes,
        ) -> Result<(BigUint, BigUint), SimulationError> {
            unimplemented!("Not needed for this test")
        }

        fn delta_transition(
            &mut self,
            _delta: ProtocolStateDelta,
            _tokens: &HashMap<Bytes, Token>,
            _balances: &Balances,
        ) -> Result<(), TransitionError<String>> {
            unimplemented!("Not needed for this test")
        }

        fn clone_box(&self) -> Box<dyn ProtocolSim> {
            Box::new(self.clone())
        }

        fn as_any(&self) -> &dyn Any {
            self
        }

        fn as_any_mut(&mut self) -> &mut dyn Any {
            self
        }
        fn eq(&self, _other: &dyn ProtocolSim) -> bool {
            unimplemented!("Not needed for this test")
        }
    }

    impl TryFromWithBlock<ComponentWithState, TimestampHeader> for DummyProtocol {
        type Error = InvalidSnapshotError;
        async fn try_from_with_block(
            _value: ComponentWithState,
            _header: TimestampHeader,
            _account_balances: &HashMap<Bytes, HashMap<Bytes, Bytes>>,
            _all_tokens: &HashMap<Bytes, Token>,
        ) -> Result<Self, Self::Error> {
            Ok(DummyProtocol)
        }
    }

    // Mock RFQClient implementation
    pub struct MockRFQClient {
        name: String,
        interval: Duration,
    }

    impl MockRFQClient {
        pub fn new(name: &str, interval: Duration) -> Self {
            Self { name: name.to_string(), interval }
        }
    }

    #[async_trait]
    impl RFQClient for MockRFQClient {
        fn stream(&self) -> BoxStream<'static, (String, StateSyncMessage<TimestampHeader>)> {
            let name = self.name.clone();
            let mut current_time = 0;
            let interval =
                IntervalStream::new(tokio::time::interval(self.interval)).map(move |_| {
                    let protocol_component =
                        ProtocolComponent { protocol_system: name.clone(), ..Default::default() };

                    let snapshot = Snapshot {
                        states: HashMap::from([(
                            name.clone(),
                            ComponentWithState {
                                state: ResponseProtocolState {
                                    component_id: name.clone(),
                                    attributes: HashMap::new(),
                                    balances: HashMap::new(),
                                },
                                component: protocol_component,
                                component_tvl: None,
                                entrypoints: vec![],
                            },
                        )]),
                        vm_storage: HashMap::new(),
                    };

                    let msg = StateSyncMessage {
                        header: TimestampHeader { timestamp: current_time },
                        snapshots: snapshot,
                        ..Default::default()
                    };

                    current_time += 1;
                    (name.clone(), msg)
                });
            Box::pin(interval)
        }

        async fn request_binding_quote(
            &self,
            _params: &GetAmountOutParams,
        ) -> Result<SignedQuote, RFQError> {
            unimplemented!("Not needed for this test")
        }
    }

    #[tokio::test]
    async fn test_rfq_stream_builder() {
        // This test has two mocked RFQ clients
        // 1. Bebop client that emits a message every second
        // 2. Hashflow client that emits a message every 2 seconds
        let (tx, mut rx) = mpsc::channel::<Update>(10);

        let builder = RFQStreamBuilder::new()
            .add_client::<DummyProtocol>(
                "bebop",
                Box::new(MockRFQClient::new("bebop", Duration::from_secs(1))),
            )
            .add_client::<DummyProtocol>(
                "hashflow",
                Box::new(MockRFQClient::new("hashflow", Duration::from_secs(2))),
            );

        tokio::spawn(builder.build(tx));

        // Collect only the first 5 messages
        let mut updates = Vec::new();
        for _ in 0..5 {
            let update = rx.recv().await.unwrap();
            updates.push(update);
        }

        assert!(
            updates[0]
                .new_pairs
                .contains_key("bebop") ||
                updates[0]
                    .new_pairs
                    .contains_key("hashflow"),
        );

        assert!(
            updates[1]
                .new_pairs
                .contains_key("bebop") ||
                updates[1]
                    .new_pairs
                    .contains_key("hashflow"),
        );

        // Collect all timestamps per provider
        let bebop_updates: Vec<_> = updates
            .iter()
            .filter(|u| u.new_pairs.contains_key("bebop"))
            .collect();
        let hashflow_updates: Vec<_> = updates
            .iter()
            .filter(|u| u.new_pairs.contains_key("hashflow"))
            .collect();

        assert_eq!(bebop_updates[0].block_number_or_timestamp, 0,);
        assert_eq!(hashflow_updates[0].block_number_or_timestamp, 0,);
        assert_eq!(bebop_updates[1].block_number_or_timestamp, 1);
        assert_eq!(hashflow_updates[1].block_number_or_timestamp, 1,);
        assert_eq!(bebop_updates[2].block_number_or_timestamp, 2);
    }
}
