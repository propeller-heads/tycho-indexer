#![doc = include_str!("../../Readme.md")]

use diesel_async::{pooled_connection::deadpool::Pool, AsyncPgConnection};
use futures03::future::select_all;

use extractor::{
    evm::ambient::{AmbientContractExtractor, AmbientPgGateway},
    runner::{ExtractorHandle, ExtractorRunnerBuilder},
};
use models::Chain;

use crate::{
    extractor::{evm, ExtractionError},
    services::ServicesBuilder,
    storage::postgres::{self, cache::CachedGateway, PostgresGateway},
};
use actix_web::dev::ServerHandle;
use clap::Parser;
use std::sync::Arc;
use tokio::{sync::mpsc, task, task::JoinHandle};
use tracing::{error, info};

mod extractor;
mod hex_bytes;
mod models;
mod pb;
mod serde_helpers;
mod services;
mod storage;
mod substreams;

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

#[tokio::main]
async fn main() -> Result<(), ExtractionError> {
    // Set up the subscriber
    tracing_subscriber::fmt::init();

    let args = CliArgs::parse();

    let pool = postgres::connect(&args.database_url).await?;
    postgres::ensure_chains(&[Chain::Ethereum], pool.clone()).await;
    // TODO: Find a dynamic way to load protocol systems into the application.
    postgres::ensure_protocol_systems(&["ambient".to_string()], pool.clone()).await;
    let evm_gw = PostgresGateway::<
        evm::Block,
        evm::Transaction,
        evm::Account,
        evm::AccountUpdate,
        evm::ERC20Token,
    >::new(pool.clone())
    .await?;

    info!("Starting Tycho");
    let mut extractor_handles = Vec::new();
    let (tx, rx) = mpsc::channel(10);
    let (err_tx, mut err_rx) = mpsc::channel(10);

    // Spawn a new task that listens to err_rx
    task::spawn(async move {
        if let Some(msg) = err_rx.recv().await {
            panic!("Database write error received: {}", msg);
        }
    });

    let write_executor = crate::storage::postgres::cache::DBCacheWriteExecutor::new(
        "ethereum".to_owned(),
        Chain::Ethereum,
        pool.clone(),
        evm_gw.clone(),
        rx,
        err_tx,
    );

    let handle = write_executor.run();
    let cached_gw = CachedGateway::new(tx, pool.clone(), evm_gw.clone());
    let (ambient_task, ambient_handle) =
        start_ambient_extractor(&args, pool.clone(), cached_gw).await?;
    extractor_handles.push(ambient_handle.clone());
    info!("Extractor {} started!", ambient_handle.get_id());

    // TODO: read from env variable
    let server_addr = "0.0.0.0";
    let server_port = 4242;
    let server_version_prefix = "v1";
    let server_url = format!("http://{}:{}", server_addr, server_port);
    let (server_handle, server_task) = ServicesBuilder::new(evm_gw, pool)
        .prefix(server_version_prefix)
        .bind(server_addr)
        .port(server_port)
        .register_extractor(ambient_handle)
        .run()?;
    info!(server_url, "Http and Ws server started");

    let shutdown_task = tokio::spawn(shutdown_handler(server_handle, extractor_handles, handle));
    let (res, _, _) = select_all([ambient_task, server_task, shutdown_task]).await;
    res.expect("Extractor- nor ServiceTasks should panic!")
}

async fn start_ambient_extractor(
    args: &CliArgs,
    pool: Pool<AsyncPgConnection>,
    cached_gw: CachedGateway,
) -> Result<(JoinHandle<Result<(), ExtractionError>>, ExtractorHandle), ExtractionError> {
    let ambient_name = "vm:ambient";
    let ambient_gw = AmbientPgGateway::new(ambient_name, Chain::Ethereum, pool, cached_gw);
    let extractor =
        AmbientContractExtractor::new(ambient_name, Chain::Ethereum, ambient_gw).await?;

    let start_block = args.start_block;
    let stop_block = args.stop_block();
    let spkg = &args.spkg;
    let block_span = stop_block.map(|stop| stop - start_block);
    info!(%ambient_name, %start_block, ?stop_block, ?block_span, %spkg, "Starting Ambient extractor");
    let mut builder =
        ExtractorRunnerBuilder::new(&args.spkg, Arc::new(extractor)).start_block(start_block);
    if let Some(stop_block) = stop_block {
        builder = builder.end_block(stop_block)
    };
    builder.run().await
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
