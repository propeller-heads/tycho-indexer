#![doc = include_str!("../../Readme.md")]

use ethrpc::{http::HttpTransport, Web3, Web3Transport};
use futures03::future::select_all;
use reqwest::Client;
use serde::Deserialize;
use std::{collections::HashMap, fs::File, io::Read, str::FromStr, sync::Arc};
use tracing_subscriber::EnvFilter;
use url::Url;

use extractor::{
    evm::token_pre_processor::TokenPreProcessor,
    runner::{ExtractorBuilder, ExtractorHandle},
};

use actix_web::dev::ServerHandle;
use chrono::{NaiveDateTime, Utc};
use clap::Parser;
use ethers::{
    prelude::{Http, Provider},
    providers::Middleware,
};
use tokio::{select, task::JoinHandle};
use tracing::{info, warn};

use tycho_core::models::{Chain, ImplementationType};
use tycho_indexer::{
    cli::{AnalyzeTokenArgs, Cli, Command, GlobalArgs, IndexArgs, RunSpkgArgs},
    extractor::{
        self,
        evm::{
            chain_state::ChainState, protocol_cache::ProtocolMemoryCache,
            token_analysis_cron::analyze_tokens,
        },
        runner::{ExtractorConfig, HandleResult, ProtocolTypeConfig},
        ExtractionError,
    },
    services::ServicesBuilder,
};
use tycho_storage::postgres::{builder::GatewayBuilder, cache::CachedGateway};

mod ot;

// TODO: We need to use `use pretty_assertions::{assert_eq, assert_ne}` per test module.
#[allow(unused_imports)]
#[cfg(test)]
#[macro_use]
extern crate pretty_assertions;

#[derive(Debug, Deserialize)]
struct ExtractorConfigs {
    extractors: std::collections::HashMap<String, ExtractorConfig>,
}

impl ExtractorConfigs {
    fn new(extractors: std::collections::HashMap<String, ExtractorConfig>) -> Self {
        Self { extractors }
    }

    fn from_yaml(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let mut file = File::open(path)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        let config: ExtractorConfigs = serde_yaml::from_str(&contents)?;
        Ok(config)
    }
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let cli: Cli = Cli::parse();
    let global_args = cli.args();

    // Set up the subscriber
    let console_flag = std::env::var("ENABLE_CONSOLE").unwrap_or_else(|_| "false".to_string());
    if console_flag == "true" {
        console_subscriber::init();
    } else {
        // OLTP endpoint is set, construct OLTP pipeline
        if let Ok(otlp_exporter_endpoint) = std::env::var("OLTP_EXPORTER_ENDPOINT") {
            let config = ot::TracingConfig { otlp_exporter_endpoint };
            ot::init_tracing(config)?;
        } else {
            warn!("OLTP_EXPORTER_ENDPOINT not set defaulting to stdout subscriber!");
            let format = tracing_subscriber::fmt::format()
                .with_level(true)
                .with_target(false)
                .compact();
            tracing_subscriber::fmt()
                .event_format(format)
                .with_env_filter(EnvFilter::from_default_env())
                .init();
        }
    }

    match cli.command() {
        Command::Run(run_args) => run_spkg(global_args, run_args).await?,
        Command::Index(indexer_args) => {
            run_indexer(global_args, indexer_args).await?;
        }
        Command::AnalyzeTokens(analyze_args) => {
            run_token_analyzer(global_args, analyze_args).await?;
        }
        Command::Rpc => run_rpc(global_args).await?,
    }
    Ok(())
}

async fn run_indexer(
    global_args: GlobalArgs,
    index_args: IndexArgs,
) -> Result<(), ExtractionError> {
    info!("Starting Tycho");
    let extractors_config = ExtractorConfigs::from_yaml(&index_args.extractors_config)
        .map_err(|e| ExtractionError::Setup(format!("Failed to load extractors.yaml. {}", e)))?;

    let retention_horizon: NaiveDateTime = index_args
        .retention_horizon
        .parse()
        .expect("Failed to parse retention horizon");

    let tasks = create_indexing_tasks(
        &global_args,
        &index_args.substreams_args.rpc_url,
        &index_args
            .chains
            .iter()
            .map(|chain_str| {
                Chain::from_str(chain_str).unwrap_or_else(|_| panic!("Unknown chain {}", chain_str))
            })
            .collect::<Vec<_>>(),
        retention_horizon,
        extractors_config,
    )
    .await?;

    let (res, _, _) = select_all(tasks).await;
    res.expect("Extractor- nor ServiceTasks should panic!")
}

async fn run_spkg(global_args: GlobalArgs, run_args: RunSpkgArgs) -> Result<(), ExtractionError> {
    info!("Starting Tycho");

    let config = ExtractorConfigs::new(HashMap::from([(
        "test_protocol".to_string(),
        ExtractorConfig::new(
            "test_protocol".to_string(),
            Chain::from_str(&run_args.chain).unwrap(),
            ImplementationType::Vm,
            1, /* TODO: if we want to increase this, we need to commit the cache when we reached
                * `end_block` */
            run_args.start_block,
            run_args.stop_block(),
            run_args
                .protocol_type_names
                .into_iter()
                .map(|name| ProtocolTypeConfig::new(name, tycho_core::models::FinancialType::Swap))
                .collect::<Vec<_>>(),
            run_args.spkg,
            run_args.module,
        ),
    )]));

    let tasks = create_indexing_tasks(
        &global_args,
        &run_args.substreams_args.rpc_url,
        &[Chain::from_str(&run_args.chain).unwrap()],
        Utc::now().naive_utc(),
        config,
    )
    .await?;

    let (res, _, _) = select_all(tasks).await;
    res.expect("Extractor- nor ServiceTasks should panic!")
}

async fn run_rpc(global_args: GlobalArgs) -> Result<(), ExtractionError> {
    let cached_gw = GatewayBuilder::new(&global_args.database_url)
        .build_gw()
        .await?;

    info!("Starting Tycho RPC");
    let server_url = format!("http://{}:{}", global_args.server_ip, global_args.server_port);
    let (server_handle, server_task) = ServicesBuilder::new(cached_gw)
        .prefix(&global_args.server_version_prefix)
        .bind(&global_args.server_ip)
        .port(global_args.server_port)
        .register_extractors(vec![])
        .run()?;
    info!(server_url, "Http and Ws server started");
    let shutdown_task = tokio::spawn(shutdown_handler(server_handle, vec![], None));
    let (res, _, _) = select_all([server_task, shutdown_task]).await;
    res.expect("ServiceTasks shouldn't panic!")
}

/// Creates extraction and server tasks.
async fn create_indexing_tasks(
    global_args: &GlobalArgs,
    rpc_url: &str,
    chains: &[Chain],
    retention_horizon: NaiveDateTime,
    extractors_config: ExtractorConfigs,
) -> Result<Vec<JoinHandle<Result<(), ExtractionError>>>, ExtractionError> {
    let rpc_client: Provider<Http> =
        Provider::<Http>::try_from(rpc_url).expect("Error creating HTTP provider");
    let block_number = rpc_client
        .get_block_number()
        .await
        .expect("Error getting block number")
        .as_u64();

    let chain_state = ChainState::new(chrono::Local::now().naive_utc(), block_number);

    let protocol_systems: Vec<String> = extractors_config
        .extractors
        .keys()
        .cloned()
        .collect();

    let (cached_gw, gw_writer_thread) = GatewayBuilder::new(&global_args.database_url)
        .set_chains(chains)
        .set_protocol_systems(&protocol_systems)
        .set_retention_horizon(retention_horizon)
        .build()
        .await?;
    let transport = Web3Transport::new(HttpTransport::new(
        Client::new(),
        Url::from_str(rpc_url).unwrap(),
        "transport".to_owned(),
    ));
    let w3 = Web3::new(transport);
    let token_processor = TokenPreProcessor::new(
        rpc_client,
        w3,
        *chains
            .first()
            .expect("No chain provided"), //TODO: handle multichain?
    );
    let (mut tasks, extractor_handles): (Vec<_>, Vec<_>) =
        // TODO: accept substreams configuration from cli.
        build_all_extractors(&extractors_config, chain_state, chains, &global_args.endpoint_url, &cached_gw, &token_processor)
            .await
            .map_err(|e| ExtractionError::Setup(format!("Failed to create extractors: {}", e)))?
            .into_iter()
            .unzip();

    let server_url = format!("http://{}:{}", global_args.server_ip, global_args.server_port);
    let (server_handle, server_task) = ServicesBuilder::new(cached_gw.clone())
        .prefix(&global_args.server_version_prefix)
        .bind(&global_args.server_ip)
        .port(global_args.server_port)
        .register_extractors(extractor_handles.clone())
        .run()?;
    info!(server_url, "Http and Ws server started");

    let shutdown_task = tokio::spawn(shutdown_handler(
        server_handle,
        extractor_handles
            .into_iter()
            .map(|h| h.0)
            .collect::<Vec<_>>(),
        Some(gw_writer_thread),
    ));

    tasks.extend(vec![server_task, shutdown_task]);

    Ok(tasks)
}

async fn build_all_extractors(
    config: &ExtractorConfigs,
    chain_state: ChainState,
    chains: &[Chain],
    endpoint_url: &str,
    cached_gw: &CachedGateway,
    token_pre_processor: &TokenPreProcessor,
) -> Result<Vec<HandleResult>, ExtractionError> {
    let mut extractor_handles = Vec::new();

    info!("Building protocol cache");
    let protocol_cache = ProtocolMemoryCache::new(
        *chains
            .first()
            .expect("No chain provided"), //TODO: handle multichain?
        chrono::Duration::seconds(900),
        Arc::new(cached_gw.clone()),
    );
    protocol_cache.populate().await?;

    for extractor_config in config.extractors.values() {
        let (task, handle) = ExtractorBuilder::new(extractor_config, endpoint_url)
            .build(chain_state, cached_gw, token_pre_processor, &protocol_cache)
            .await?
            .run()
            .await?;

        info!("Extractor {} started!", handle.0.get_id());
        extractor_handles.push((task, handle));
    }

    Ok(extractor_handles)
}

async fn shutdown_handler(
    server_handle: ServerHandle,
    extractors: Vec<ExtractorHandle>,
    db_write_executor_handle: Option<JoinHandle<()>>,
) -> Result<(), ExtractionError> {
    // listen for ctrl-c
    tokio::signal::ctrl_c().await.unwrap();
    for e in extractors.iter() {
        e.stop().await.unwrap();
    }
    server_handle.stop(true).await;
    if let Some(handle) = db_write_executor_handle {
        handle.abort();
    }
    Ok(())
}

async fn run_token_analyzer(
    global_args: GlobalArgs,
    analyzer_args: AnalyzeTokenArgs,
) -> Result<(), anyhow::Error> {
    let (cached_gw, gw_writer_thread) = GatewayBuilder::new(&global_args.database_url)
        .set_chains(&[analyzer_args.chain])
        .build()
        .await?;
    let cached_gw = Arc::new(cached_gw);
    let analyze_thread = analyze_tokens(analyzer_args, cached_gw.clone());
    select! {
         res = analyze_thread => {
            res?;
         },
         res = gw_writer_thread => {
            res?;
        }
    }
    Ok(())
}
