use std::collections::HashMap;

use futures::{Stream, StreamExt};
use miette::{miette, IntoDiagnostic, WrapErr};
use tokio::{sync::mpsc::Sender, task::JoinHandle};
use tracing::{info, warn};
use tycho_client::feed::component_tracker::ComponentFilter;
use tycho_common::{
    models::{token::Token, Chain},
    Bytes,
};
use tycho_simulation::{
    evm::{
        decoder::StreamDecodeError,
        engine_db::tycho_db::PreCachedDB,
        protocol::{
            ekubo::state::EkuboState,
            filters::{
                balancer_v2_pool_filter, curve_pool_filter, uniswap_v4_pool_with_euler_hook_filter,
                uniswap_v4_pool_with_hook_filter,
            },
            pancakeswap_v2::state::PancakeswapV2State,
            uniswap_v2::state::UniswapV2State,
            uniswap_v3::state::UniswapV3State,
            uniswap_v4::state::UniswapV4State,
            vm::state::EVMPoolState,
        },
        stream::ProtocolStreamBuilder,
    },
    protocol::models::Update,
};

use crate::stream_processor::{StreamUpdate, UpdateType};

pub struct ProtocolStreamProcessor {
    chain: Chain,
    tycho_url: String,
    tycho_api_key: String,
    tvl_threshold: f64,
}

impl ProtocolStreamProcessor {
    pub fn new(
        chain: Chain,
        tycho_url: String,
        tycho_api_key: String,
        tvl_threshold: f64,
    ) -> miette::Result<Self> {
        Ok(Self { chain, tycho_url, tycho_api_key, tvl_threshold })
    }

    pub async fn run_stream(
        &self,
        all_tokens: &HashMap<Bytes, Token>,
        tx: Sender<miette::Result<StreamUpdate>>,
    ) -> miette::Result<JoinHandle<()>> {
        info!("Starting protocol stream processor for chain {:?}", self.chain);
        let mut stream = self.build_stream(all_tokens).await?;
        let handle = tokio::spawn(async move {
            info!("Protocol stream processor started");
            let mut is_first_update = true;
            while let Some(res) = stream.next().await {
                let update = match res {
                    Ok(msg) => msg,
                    Err(e) => {
                        if tx
                            .send(Err(
                                miette!(e).wrap_err("Error receiving message from protocol stream")
                            ))
                            .await
                            .is_err()
                        {
                            warn!("Receiver dropped, stopping stream processor");
                            break;
                        }
                        continue;
                    }
                };
                let received_at =
                    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
                        Ok(duration) => duration,
                        Err(e) => {
                            if tx
                                .send(Err(miette!(e).wrap_err("Error getting current timestamp")))
                                .await
                                .is_err()
                            {
                                warn!("Receiver dropped, stopping stream processor");
                                break;
                            }
                            continue;
                        }
                    };
                let update = StreamUpdate {
                    update_type: UpdateType::Protocol,
                    update,
                    is_first_update,
                    received_at,
                };
                if is_first_update {
                    is_first_update = false;
                }
                if tx.send(Ok(update)).await.is_err() {
                    warn!("Receiver dropped, stopping stream processor");
                    break;
                }
            }
        });
        Ok(handle)
    }

    async fn build_stream(
        &self,
        all_tokens: &HashMap<Bytes, Token>,
    ) -> miette::Result<impl Stream<Item = Result<Update, StreamDecodeError>>> {
        let mut protocol_stream = ProtocolStreamBuilder::new(&self.tycho_url, self.chain);
        let tvl_filter = ComponentFilter::with_tvl_range(self.tvl_threshold, self.tvl_threshold);
        match self.chain {
            Chain::Ethereum => {
                protocol_stream = protocol_stream
                    .exchange::<UniswapV2State>("uniswap_v2", tvl_filter.clone(), None)
                    .exchange::<UniswapV2State>("sushiswap_v2", tvl_filter.clone(), None)
                    .exchange::<PancakeswapV2State>("pancakeswap_v2", tvl_filter.clone(), None)
                    .exchange::<UniswapV3State>("uniswap_v3", tvl_filter.clone(), None)
                    .exchange::<UniswapV3State>("pancakeswap_v3", tvl_filter.clone(), None)
                    .exchange::<EVMPoolState<PreCachedDB>>(
                        "vm:balancer_v2",
                        tvl_filter.clone(),
                        Some(balancer_v2_pool_filter),
                    )
                    .exchange::<UniswapV4State>(
                        "uniswap_v4",
                        tvl_filter.clone(),
                        Some(uniswap_v4_pool_with_hook_filter),
                    )
                    .exchange::<EkuboState>("ekubo_v2", tvl_filter.clone(), None)
                    .exchange::<EVMPoolState<PreCachedDB>>(
                        "vm:curve",
                        tvl_filter.clone(),
                        Some(curve_pool_filter),
                    )
                    .exchange::<UniswapV4State>(
                        "uniswap_v4_hooks",
                        tvl_filter.clone(),
                        Some(uniswap_v4_pool_with_euler_hook_filter),
                    );
            }
            Chain::Base => {
                protocol_stream = protocol_stream
                    .exchange::<UniswapV2State>("uniswap_v2", tvl_filter.clone(), None)
                    .exchange::<UniswapV3State>("uniswap_v3", tvl_filter.clone(), None)
                    .exchange::<UniswapV4State>(
                        "uniswap_v4",
                        tvl_filter.clone(),
                        Some(uniswap_v4_pool_with_hook_filter),
                    )
            }
            Chain::Unichain => {
                protocol_stream = protocol_stream
                    .exchange::<UniswapV2State>("uniswap_v2", tvl_filter.clone(), None)
                    .exchange::<UniswapV3State>("uniswap_v3", tvl_filter.clone(), None)
                    .exchange::<UniswapV4State>(
                        "uniswap_v4",
                        tvl_filter.clone(),
                        Some(uniswap_v4_pool_with_hook_filter),
                    )
            }
            _ => {}
        }
        protocol_stream
            .auth_key(Some(self.tycho_api_key.clone()))
            .skip_state_decode_failures(true)
            .set_tokens(all_tokens.clone())
            .await
            .build()
            .await
            .into_diagnostic()
            .wrap_err("Failed building protocol stream")
    }
}
