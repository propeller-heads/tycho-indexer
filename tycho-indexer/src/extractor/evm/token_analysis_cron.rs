use crate::cli::AnalyzeTokenArgs;
use futures03::{future::try_join_all, FutureExt};
use std::{collections::HashMap, str::FromStr, sync::Arc, time::Instant};
use tokio::sync::Semaphore;
use tracing::{debug, info, warn};
use tycho_core::{
    models::{
        blockchain::BlockTag,
        token::{CurrencyToken, TokenOwnerStore, TokenQuality},
        Chain, PaginationParams,
    },
    storage::ProtocolGateway,
    traits::TokenAnalyzer,
    Bytes,
};
use tycho_ethereum::{
    token_analyzer::trace_call::TraceCallDetector, token_pre_processor::map_vault,
};

pub async fn analyze_tokens(
    analyze_args: AnalyzeTokenArgs,
    gw: Arc<dyn ProtocolGateway + Send + Sync>,
) -> anyhow::Result<()> {
    let mut tokens = Vec::new();
    let mut page = 0;
    let page_size = analyze_args.fetch_batch_size as i64;
    loop {
        let start = Instant::now();
        let pagination_params = PaginationParams::new(page, page_size);
        tokens.clone_from(
            &(gw.get_tokens(analyze_args.chain, None, None, None, Some(&pagination_params))
                .await?),
        );
        let sem = Arc::new(Semaphore::new(analyze_args.concurrency));
        let tasks = tokens
            .chunks(analyze_args.update_batch_size)
            .map(|chunk| {
                analyze_batch(
                    analyze_args.chain,
                    analyze_args.rpc_url.clone(),
                    chunk.to_vec(),
                    sem.clone(),
                    gw.clone(),
                )
                .boxed()
            })
            .collect::<Vec<_>>();

        _ = try_join_all(tasks).await?;
        let duration = Instant::now().duration_since(start);
        info!(processed = tokens.len(), page = page, duration = duration.as_secs(), "Progress");

        page += 1;
        if tokens.len() < (page_size as usize) {
            break;
        }
    }

    Ok(())
}

async fn analyze_batch(
    chain: Chain,
    eth_rpc_url: String,
    mut tokens: Vec<CurrencyToken>,
    sem: Arc<Semaphore>,
    gw: Arc<dyn ProtocolGateway + Send + Sync>,
) -> anyhow::Result<()> {
    let _guard = sem.acquire().await?;
    let addresses = tokens
        .iter()
        .map(|t| t.address.clone())
        .collect::<Vec<_>>();
    let token_owner = gw
        .get_token_owners(&chain, &addresses, Some(100_000f64))
        .await?;
    let component_ids = token_owner
        .values()
        .map(|(cid, _)| cid.as_str())
        .collect::<Vec<_>>();
    let components = gw
        .get_protocol_components(&chain, None, Some(&component_ids), None)
        .await?
        .into_iter()
        .map(|pc| (pc.id.clone(), pc))
        .collect::<HashMap<_, _>>();

    let liquidity_token_owners = token_owner
        .into_iter()
        .filter_map(|(address, (cid, balance))| {
            if let Some(pc) = components.get(&cid) {
                let liq_owner = map_vault(&pc.protocol_system).or_else(|| {
                    pc.contract_ids
                        // TODO: Currently, it's assumed that the pool is always the first
                        // contract in the protocol component. This approach is a temporary
                        // workaround and needs to be revisited for a more robust solution.
                        .first()
                        .cloned()
                        .or_else(|| Bytes::from_str(&pc.id).ok())
                });

                liq_owner.map(|liq_owner| (address, (liq_owner, balance)))
            } else {
                warn!(component_id=?cid, "Failed to find component for id!");
                None
            }
        })
        .collect::<HashMap<_, _>>();
    let analyzer = TraceCallDetector::new(
        eth_rpc_url.as_str(),
        Arc::new(TokenOwnerStore::new(liquidity_token_owners)),
    );
    for t in tokens.iter_mut() {
        // Skip tokens that failed previously and ones we already analyzed successfully.
        if t.quality <= 5 || !t.gas.is_empty() {
            continue;
        }

        debug!(?t.address, "Analyzing token");
        let (token_quality, gas, tax) = match analyzer
            .analyze(t.address.clone(), BlockTag::Latest)
            .await
        {
            Ok(t) => t,
            Err(error) => {
                warn!(?error, "Token quality detection failed");
                continue;
            }
        };

        if let TokenQuality::Bad { reason } = token_quality {
            debug!(?t.address, ?reason, "Token quality detected as bad!");
            // Don't try to analyze again.
            t.quality = 5;
        };

        // If it's a fee token, set quality to 50
        if tax.map_or(false, |tax_value| tax_value > 0) {
            t.quality = 50;
        }

        t.tax = tax.unwrap_or(0);
        t.gas = gas
            .map(|g| vec![Some(g)])
            .unwrap_or_else(Vec::new);
    }

    if !tokens.is_empty() {
        gw.update_tokens(&tokens).await?;
    }
    Ok(())
}

#[cfg(test)]
mod test {
    use crate::{
        extractor::evm::token_analysis_cron::{analyze_tokens, AnalyzeTokenArgs},
        testing,
    };
    use chrono::NaiveDateTime;
    use std::{collections::HashMap, sync::Arc};
    use tycho_core::{
        models::{protocol::ProtocolComponent, token::CurrencyToken, Chain, ChangeType},
        Bytes,
    };

    // requires a running ethereum node
    #[ignore]
    #[test_log::test(tokio::test)]
    async fn test_analyze_tokens() {
        let args = AnalyzeTokenArgs {
            chain: Chain::Ethereum,
            concurrency: 10,
            update_batch_size: 100,
            fetch_batch_size: 100,
            rpc_url:
                "https://ethereum-mainnet.core.chainstack.com/71bdd37d35f18d55fed5cc5d138a8fac"
                    .to_string(),
        };
        let mut gw = testing::MockGateway::new();
        gw.expect_get_tokens()
            .returning(|_, _, _, _, _| {
                Box::pin(async {
                    Ok(vec![CurrencyToken::new(
                        &Bytes::from("0x45804880de22913dafe09f4980848ece6ecbaf78"),
                        "PAXG",
                        18,
                        0,
                        &[],
                        Chain::Ethereum,
                        10,
                    )])
                })
            });
        let exp = vec![CurrencyToken::new(
            &Bytes::from("0x45804880de22913dafe09f4980848ece6ecbaf78"),
            "PAXG",
            18,
            1,
            &[Some(59_264)],
            Chain::Ethereum,
            50,
        )];
        gw.expect_get_token_owners()
            .returning(|_, _, _| {
                Box::pin(async move {
                    Ok(HashMap::from([(
                        Bytes::from("0x45804880de22913dafe09f4980848ece6ecbaf78"),
                        (
                            "0xe25a329d385f77df5d4ed56265babe2b99a5436e".to_string(),
                            Bytes::from("0x0186a0"),
                        ),
                    )]))
                })
            });
        gw.expect_get_protocol_components()
            .returning(|_, _, _, _| {
                Box::pin(async move {
                    Ok(vec![ProtocolComponent::new(
                        "0xe25a329d385f77df5d4ed56265babe2b99a5436e",
                        "uniswap_v2",
                        "pool",
                        Chain::Ethereum,
                        vec![Bytes::from("0x45804880de22913dafe09f4980848ece6ecbaf78")],
                        vec![],
                        HashMap::new(),
                        ChangeType::Creation,
                        Bytes::from("0x00"),
                        NaiveDateTime::default(),
                    )])
                })
            });
        gw.expect_update_tokens()
            .once()
            .returning(move |updated| {
                assert_eq!(updated, &exp);
                Box::pin(async { Ok(()) })
            });

        analyze_tokens(args, Arc::new(gw))
            .await
            .expect("analyze tokens failed");
    }
}
