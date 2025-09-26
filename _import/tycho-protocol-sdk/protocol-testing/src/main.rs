mod adapter_builder;
mod config;
mod encoding;
mod execution;
mod rpc;
mod state_registry;
mod test_runner;
mod traces;
mod tycho_rpc;
mod tycho_runner;
mod utils;

use std::{env, fmt::Display, path::PathBuf};

use clap::Parser;
use dotenv::dotenv;
use miette::{miette, IntoDiagnostic, WrapErr};
use tracing::info;
use tracing_subscriber::EnvFilter;

use crate::test_runner::TestRunner;

#[derive(Parser, Debug)]
#[command(version, about = "Run indexer within a specified range of blocks")]
struct Args {
    /// Path to the root directory containing all packages. If not provided, it will look for
    /// packages in the current working directory.
    #[arg(long)]
    root_path: Option<PathBuf>,

    /// Name of the package to test
    #[arg(long)]
    package: String,

    /// If provided, only run the tests with a matching name
    #[arg(long)]
    match_test: Option<String>,

    /// Postgres database URL for the Tycho indexer
    #[arg(long, default_value = "postgres://postgres:mypassword@localhost:5431/tycho_indexer_0")]
    db_url: String,

    /// Enable tracing during vm simulations
    #[arg(long, default_value_t = false)]
    vm_simulation_traces: bool,

    /// Enable tracing during execution simulations
    #[arg(long, default_value_t = false)]
    execution_traces: bool,
}

impl Args {
    fn root_path(&self) -> miette::Result<PathBuf> {
        match self.root_path.as_ref() {
            Some(path) => Ok(path.clone()),
            None => {
                let current_dir = std::env::current_dir()
                    .into_diagnostic()
                    .wrap_err("Failed to get current directory")?;
                let expected_child_dirs = ["evm", "proto", "substreams"];
                if expected_child_dirs
                    .iter()
                    .all(|dir| current_dir.join(dir).exists())
                {
                    return Ok(current_dir);
                }
                let parent_dir = current_dir
                    .parent()
                    .ok_or_else(|| miette!("Current directory has no parent directory"))?;
                if expected_child_dirs
                    .iter()
                    .all(|dir| parent_dir.join(dir).exists())
                {
                    return Ok(parent_dir.to_path_buf());
                }
                Err(miette!("Couldn't find a valid path from {}", current_dir.display()))
            }
        }
    }
}

fn main() -> miette::Result<()> {
    // Load .env file before setting up logging
    dotenv().ok();

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_target(false)
        .init();

    let version = Version::from_env()?;
    if std::env::args().any(|arg| arg == "--version") {
        println!("{version}");
        return Ok(());
    }
    info!("{version}");

    let rpc_url = env::var("RPC_URL")
        .into_diagnostic()
        .wrap_err("Missing RPC_URL in environment")?;

    let args = Args::parse();

    let test_runner = TestRunner::new(
        args.root_path()?,
        args.package,
        args.match_test,
        args.db_url,
        args.vm_simulation_traces,
        args.execution_traces,
        rpc_url,
    )?;

    test_runner.run_tests()
}

struct Version {
    version: String,
    hash: String,
}

impl Version {
    fn from_env() -> miette::Result<Self> {
        let version = option_env!("CARGO_PKG_VERSION")
            .unwrap_or("unknown")
            .to_string();
        let hash = option_env!("GIT_HASH")
            .unwrap_or("unknown")
            .to_string();
        Ok(Self { version, hash })
    }
}

impl Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let bin_name = option_env!("CARGO_PKG_NAME").unwrap_or_default();
        write!(f, "{bin_name} version: {}, hash: {}", self.version, self.hash)
    }
}
