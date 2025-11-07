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

use std::{fmt::Display, path::PathBuf};

use clap::{Args, Parser, Subcommand};
use dotenv::dotenv;
use miette::{miette, IntoDiagnostic, WrapErr};
use tracing_subscriber::EnvFilter;
use tycho_simulation::tycho_common::dto::Chain;

use crate::test_runner::{TestRunner, TestType, TestTypeFull, TestTypeRange};

#[derive(Parser)]
#[command(version, long_version = Version::clap_long(), subcommand_required = false, arg_required_else_help = true)]
struct TestsCli {
    #[command(subcommand)]
    subcommand: Option<TestSubcommand>,
}

#[derive(Subcommand)]
enum TestSubcommand {
    Full(FullTestCommand),
    Range(RangeTestCommand),
}

/// Run a test from a specific initial block to the latest block
#[derive(Args)]
pub struct FullTestCommand {
    #[command(flatten)]
    common_args: CommonArgs,

    /// Start the test from this block number.
    /// If not provided, it will use the first initial block defined in the protocol's substream
    /// configuration.
    #[arg(long)]
    initial_block: Option<u64>,

    /// Stop the test at this block number.
    /// If not provided, it will use the latest block fetched from the protocol.
    #[arg(long)]
    stop_block: Option<u64>,
}

impl FullTestCommand {
    fn run(self) -> miette::Result<()> {
        let args = self.common_args;
        TestRunner::new(
            TestType::Full(TestTypeFull {
                initial_block: self.initial_block,
                stop_block: self.stop_block,
            }),
            args.root_path()?,
            args.chain,
            args.package,
            args.db_url,
            args.rpc_url,
            args.vm_simulation_traces,
            args.execution_traces,
        )?
        .run()
    }
}

/// Run the tests defined in the protocol's integration_test.tycho.yaml file
#[derive(Args)]
pub struct RangeTestCommand {
    #[command(flatten)]
    common_args: CommonArgs,

    /// If provided, only run the tests with a matching name
    #[arg(long)]
    match_test: Option<String>,
}

impl RangeTestCommand {
    fn run(self) -> miette::Result<()> {
        let args = self.common_args;
        TestRunner::new(
            TestType::Range(TestTypeRange { match_test: self.match_test.clone() }),
            args.root_path()?,
            args.chain,
            args.package,
            args.db_url,
            args.rpc_url,
            args.vm_simulation_traces,
            args.execution_traces,
        )?
        .run()
    }
}

#[derive(Args)]
struct CommonArgs {
    /// Path to the root directory containing all packages. If not provided, it will look for
    /// packages in the current working directory.
    root_path: Option<PathBuf>,

    /// Name of the package to test
    #[arg(long)]
    package: String,

    /// Name of the chain to test
    #[arg(long, default_value = "ethereum")]
    chain: Chain,

    /// Postgres database URL for the Tycho indexer
    #[arg(
        long,
        env = "DATABASE_URL",
        default_value = "postgres://postgres:mypassword@localhost:5431/tycho_indexer_0"
    )]
    db_url: String,

    #[arg(long, env = "RPC_URL")]
    rpc_url: String,

    /// Enable tracing during vm simulations
    #[arg(long, default_value_t = false)]
    vm_simulation_traces: bool,

    /// Enable tracing during execution simulations
    #[arg(long, default_value_t = false)]
    execution_traces: bool,
}

impl CommonArgs {
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

    fn clap_long() -> &'static str {
        Box::leak(
            Self::from_env()
                .expect("Failed to get binary version")
                .to_string()
                .into_boxed_str(),
        )
    }
}

impl Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "version: {}, hash: {}", self.version, self.hash)
    }
}

fn main() -> miette::Result<()> {
    dotenv().ok();

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_target(false)
        .init();

    let cli = TestsCli::parse();
    match cli.subcommand {
        Some(TestSubcommand::Full(cmd)) => cmd.run(),
        Some(TestSubcommand::Range(cmd)) => cmd.run(),
        None => Err(miette!("No subcommand provided. Use --help for more information.")),
    }
}
