mod config;
mod rpc;
mod test_runner;
mod tycho_runner;
mod utils;
mod tycho_rpc;

use clap::Parser;
use tracing_subscriber::EnvFilter;

use crate::test_runner::TestRunner;

#[derive(Parser, Debug)]
#[command(version, about = "Run indexer within a specified range of blocks")]
struct Args {
    /// Name of the package to test
    #[arg(long)]
    package: String,

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

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_target(false)
        .init();

    let args = Args::parse();

    let test_runner = TestRunner::new(args.package, args.tycho_logs, args.db_url, args.vm_traces);

    test_runner.run_tests();
}
