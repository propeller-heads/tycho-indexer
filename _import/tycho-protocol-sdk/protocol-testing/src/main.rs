mod adapter_builder;
mod config;
mod encoding;
mod rpc;
mod test_runner;
mod tycho_rpc;
mod tycho_runner;
mod utils;

use std::{path::PathBuf, process::Command};

use clap::Parser;
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

    /// Enable tycho logs
    #[arg(long, default_value_t = false)]
    tycho_logs: bool,

    /// Postgres database URL for the Tycho indexer
    #[arg(long, default_value = "postgres://postgres:mypassword@localhost:5431/tycho_indexer_0")]
    db_url: String,

    /// Enable tracing during vm simulations
    #[arg(long, default_value_t = false)]
    vm_traces: bool,
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
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_target(false)
        .init();

    let version = Version::from_env()?;
    info!("version: {}, hash: {}", version.version, version.hash);

    let args = Args::parse();

    let test_runner = TestRunner::new(
        args.root_path()?,
        args.package,
        args.match_test,
        args.tycho_logs,
        args.db_url,
        args.vm_traces,
    );

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
        let hash = {
            let output = Command::new("git")
                .args(["rev-parse", "HEAD"])
                .output()
                .into_diagnostic()?;
            String::from_utf8(output.stdout).into_diagnostic()?
        };
        Ok(Self { version, hash })
    }
}
