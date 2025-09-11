mod adapter_builder;
mod config;
mod encoding;
mod rpc;
mod test_runner;
mod tycho_rpc;
mod tycho_runner;
mod utils;

use std::path::{Path, PathBuf};

use clap::Parser;
use miette::miette;
use tracing_subscriber::EnvFilter;

use crate::test_runner::TestRunner;

#[derive(Parser, Debug)]
#[command(version, about = "Run indexer within a specified range of blocks")]
struct Args {
    /// Name of the package to test
    #[arg(long, required_unless_present = "package_path", conflicts_with = "package_path")]
    package: Option<String>,

    /// Path to the package to test
    #[arg(long, required_unless_present = "package", conflicts_with = "package")]
    package_path: Option<String>,

    /// Path to the evm directory. If not provided, it will look for it in `../evm`
    #[arg(long)]
    evm_path: Option<PathBuf>,

    /// If provided, only run the tests with a matching name
    #[arg(long)]
    match_test: Option<String>,

    /// Enable tycho logs
    #[arg(long, default_value_t = true)]
    tycho_logs: bool,

    /// Postgres database URL for the Tycho indexer
    #[arg(long, default_value = "postgres://postgres:mypassword@localhost:5431/tycho_indexer_0")]
    db_url: String,

    /// Enable tracing during vm simulations
    #[arg(long, default_value_t = false)]
    vm_traces: bool,
}

impl Args {
    fn package_path(&self) -> miette::Result<PathBuf> {
        match (self.package_path.as_ref(), self.package.as_ref()) {
            (Some(path), _) => Ok(Path::new(path).to_path_buf()),
            (_, Some(package)) => Ok(Path::new("../substreams").join(package)),
            _ => Err(miette!("Either package or package_path must be provided")),
        }
    }

    fn evm_path(&self) -> miette::Result<PathBuf> {
        match self.evm_path.as_ref() {
            Some(path) => Ok(path.clone()),
            None => {
                let current_dir = std::env::current_dir()
                    .map_err(|e| miette!("Failed to get current directory: {}", e))?;
                let mut evm_dir = current_dir.join("../evm");
                if !evm_dir.exists() {
                    evm_dir = current_dir.join("evm");
                    if !evm_dir.exists() {
                        return Err(miette!("evm directory not found"));
                    }
                }
                Ok(evm_dir)
            }
        }
    }
}

fn main() -> miette::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_target(false)
        .init();

    let args = Args::parse();

    let test_runner = TestRunner::new(
        args.package_path()?,
        args.evm_path()?,
        args.match_test,
        args.tycho_logs,
        args.db_url,
        args.vm_traces,
    );

    test_runner.run_tests()
}
