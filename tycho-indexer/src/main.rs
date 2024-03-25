#![doc = include_str!("../../Readme.md")]

use futures03::future::select_all;
use serde::Deserialize;
use std::{env, fs::File, io::Read};

use extractor::{
    evm::token_pre_processor::TokenPreProcessor,
    runner::{ExtractorBuilder, ExtractorHandle},
};

use actix_web::dev::ServerHandle;
use clap::Parser;
use ethers::{
    prelude::{Http, Provider},
    providers::Middleware,
};
use tokio::task::JoinHandle;
use tracing::info;

use tycho_core::models::Chain;
use tycho_indexer::{
    extractor::{
        self,
        evm::chain_state::ChainState,
        runner::{ExtractorConfig, HandleResult},
        ExtractionError,
    },
    services::ServicesBuilder,
};
use tycho_storage::postgres::{builder::GatewayBuilder, cache::CachedGateway};

#[cfg(test)]
#[macro_use]
extern crate pretty_assertions;

/// Tycho Indexer using Substreams
///
/// Extracts state from the Ethereum blockchain and stores it in a Postgres database.
#[derive(Parser, Debug, Clone, PartialEq, Eq)]
#[clap(version = "0.1.0")]
struct CliArgs {
    /// Substreams API endpoint URL
    #[clap(name = "endpoint", long)]
    endpoint_url: String,

    /// Substreams API token
    ///
    /// Defaults to SUBSTREAMS_API_TOKEN env var.
    #[clap(long, env, hide_env_values = true, alias = "api_token")]
    substreams_api_token: String,

    /// DB Connection Url
    ///
    /// Defaults to DATABASE_URL env var.
    #[clap(long, env, hide_env_values = true, alias = "db_url")]
    database_url: String,

    /// Substreams Package file
    #[clap(long)]
    spkg: String,

    /// Substreams Module name
    #[clap(long)]
    module: String,

    /// Substreams start block
    /// Defaults to START_BLOCK env var or default_value below.
    #[clap(long, env, default_value = "17361664")]
    start_block: i64,

    /// Substreams stop block
    ///
    /// Optional. If not provided, the extractor will run until the latest block.
    /// If prefixed with a `+` the value is interpreted as an increment to the start block.
    /// Defaults to STOP_BLOCK env var or None.
    #[clap(long, env)]
    stop_block: Option<String>,
}

impl CliArgs {
    #[allow(dead_code)]
    fn stop_block(&self) -> Option<i64> {
        if let Some(s) = &self.stop_block {
            if s.starts_with('+') {
                let increment: i64 = s
                    .strip_prefix('+')
                    .expect("stripped stop block value")
                    .parse()
                    .expect("stop block value");
                Some(self.start_block + increment)
            } else {
                Some(s.parse().expect("stop block value"))
            }
        } else {
            None
        }
    }
}

#[derive(Debug, Deserialize)]
struct ExtractorConfigs {
    extractors: std::collections::HashMap<String, ExtractorConfig>,
}

impl ExtractorConfigs {
    fn from_yaml(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let mut file = File::open(path)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        let config: ExtractorConfigs = serde_yaml::from_str(&contents)?;
        Ok(config)
    }
}

#[tokio::main]
async fn main() -> Result<(), ExtractionError> {
    // Set up the subscriber
    tracing_subscriber::fmt::init();

    let args: CliArgs = CliArgs::parse();

    info!("Starting Tycho");

    let rpc_url = env::var("ETH_RPC_URL").expect("ETH_RPC_URL is not set");
    let rpc_client: Provider<Http> =
        Provider::<Http>::try_from(rpc_url).expect("Error creating HTTP provider");
    let block_number = rpc_client
        .get_block_number()
        .await
        .expect("Error getting block number")
        .as_u64();

    let chain_state = ChainState::new(chrono::Local::now().naive_utc(), block_number);

    let config_path = env::var("TYCHO_CONFIG").unwrap_or("./extractors.yaml".to_string());
    let extractors_config = ExtractorConfigs::from_yaml(config_path.as_str())
        .map_err(|e| ExtractionError::Setup(format!("Failed to load extractors.yaml. {}", e)))?;

    let protocol_systems: Vec<String> = extractors_config
        .extractors
        .keys()
        .cloned()
        .collect();

    let (cached_gw, gw_writer_thread) = GatewayBuilder::new(&args.database_url)
        .set_chains(&[Chain::Ethereum])
        .set_protocol_systems(&protocol_systems)
        .build()
        .await?;

    let token_processor = TokenPreProcessor::new(rpc_client);

    let (mut tasks, extractor_handles): (Vec<_>, Vec<_>) =
        build_all_extractors(&extractors_config, chain_state, &cached_gw, &token_processor)
            .await
            .map_err(|e| ExtractionError::Setup(format!("Failed to create extractors: {}", e)))?
            .into_iter()
            .unzip();

    // TODO: read from env variable
    let server_addr = "0.0.0.0";
    let server_port = 4242;
    let server_version_prefix = "v1";
    let server_url = format!("http://{}:{}", server_addr, server_port);
    let (server_handle, server_task) = ServicesBuilder::new(cached_gw.clone())
        .prefix(server_version_prefix)
        .bind(server_addr)
        .port(server_port)
        .register_extractors(extractor_handles.clone())
        .run()?;
    info!(server_url, "Http and Ws server started");

    let shutdown_task =
        tokio::spawn(shutdown_handler(server_handle, extractor_handles, gw_writer_thread));

    tasks.extend(vec![server_task, shutdown_task]);

    let (res, _, _) = select_all(tasks).await;
    res.expect("Extractor- nor ServiceTasks should panic!")
}

async fn build_all_extractors(
    config: &ExtractorConfigs,
    chain_state: ChainState,
    cached_gw: &CachedGateway,
    token_pre_processor: &TokenPreProcessor,
) -> Result<Vec<HandleResult>, ExtractionError> {
    let mut extractor_handles = Vec::new();

    for extractor_config in config.extractors.values() {
        let (task, handle) = ExtractorBuilder::new(extractor_config)
            .only_final_blocks() //TODO: Remove when RevertBuffer is implemented for both native and vm
            .build(chain_state, cached_gw, token_pre_processor)
            .await?
            .run()
            .await?;

        info!("Extractor {} started!", handle.get_id());
        extractor_handles.push((task, handle));
    }

    Ok(extractor_handles)
}

async fn shutdown_handler(
    server_handle: ServerHandle,
    extractors: Vec<ExtractorHandle>,
    db_write_executor_handle: JoinHandle<()>,
) -> Result<(), ExtractionError> {
    // listen for ctrl-c
    tokio::signal::ctrl_c().await.unwrap();
    for e in extractors.iter() {
        e.stop().await.unwrap();
    }
    server_handle.stop(true).await;
    db_write_executor_handle.abort();
    Ok(())
}

#[cfg(test)]
mod cli_tests {
    use std::env;

    use clap::Parser;

    use super::CliArgs;

    #[tokio::test]
    #[ignore]
    // This test needs to be run independently because it temporarily changes env variables.
    async fn test_arg_parsing_long_from_env() {
        // Save previous values of the environment variables.
        let prev_api_token = env::var("SUBSTREAMS_API_TOKEN");
        let prev_db_url = env::var("DATABASE_URL");
        // Set the SUBSTREAMS_API_TOKEN environment variable for testing.
        env::set_var("SUBSTREAMS_API_TOKEN", "your_api_token");
        env::set_var("DATABASE_URL", "my_db");
        let args = CliArgs::try_parse_from(vec![
            "tycho-indexer",
            "--endpoint",
            "http://example.com",
            "--spkg",
            "package.spkg",
            "--module",
            "module_name",
        ]);

        // Restore the environment variables.
        if let Ok(val) = prev_api_token {
            env::set_var("SUBSTREAMS_API_TOKEN", val);
        } else {
            env::remove_var("SUBSTREAMS_API_TOKEN");
        }
        if let Ok(val) = prev_db_url {
            env::set_var("DATABASE_URL", val);
        } else {
            env::remove_var("DATABASE_URL");
        }

        assert!(args.is_ok());
        let args = args.unwrap();
        let expected_args = CliArgs {
            endpoint_url: "http://example.com".to_string(),
            substreams_api_token: "your_api_token".to_string(),
            database_url: "my_db".to_string(),
            spkg: "package.spkg".to_string(),
            module: "module_name".to_string(),
            start_block: 17361664,
            stop_block: None,
        };

        assert_eq!(args, expected_args);
    }

    #[tokio::test]
    async fn test_arg_parsing_long() {
        let args = CliArgs::try_parse_from(vec![
            "tycho-indexer",
            "--endpoint",
            "http://example.com",
            "--api_token",
            "your_api_token",
            "--db_url",
            "my_db",
            "--spkg",
            "package.spkg",
            "--module",
            "module_name",
        ]);

        assert!(args.is_ok());
        let args = args.unwrap();
        let expected_args = CliArgs {
            endpoint_url: "http://example.com".to_string(),
            substreams_api_token: "your_api_token".to_string(),
            database_url: "my_db".to_string(),
            spkg: "package.spkg".to_string(),
            module: "module_name".to_string(),
            start_block: 17361664,
            stop_block: None,
        };

        assert_eq!(args, expected_args);
    }

    #[tokio::test]
    async fn test_arg_parsing_missing_val() {
        let args = CliArgs::try_parse_from(vec![
            "tycho-indexer",
            "--spkg",
            "package.spkg",
            "--module",
            "module_name",
        ]);

        assert!(args.is_err());
    }
}
