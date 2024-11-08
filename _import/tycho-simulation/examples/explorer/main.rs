pub mod data_feed;
mod ui;

extern crate tycho_simulation;

use clap::Parser;
use data_feed::{state::BlockState, tycho};
use futures::future::select_all;
use std::env;
use tokio::{sync::mpsc, task::JoinHandle};
use tracing::info;
use tracing_subscriber::{fmt, EnvFilter};

#[derive(Parser)]
struct Cli {
    /// The tvl threshold to filter the graph by
    #[arg(short, long, default_value_t = 1000.0)]
    tvl_threshold: f64,
}

#[tokio::main]
async fn main() {
    // Parse command-line arguments into a Cli struct
    let format = fmt::format()
        .with_level(true) // Show log levels
        .with_target(false) // Hide module paths
        .compact(); // Use a compact format

    fmt()
        .event_format(format)
        .with_env_filter(EnvFilter::from_default_env()) // Use RUST_LOG for log levels
        .init();
    let cli = Cli::parse();

    let tycho_url =
        env::var("TYCHO_URL").unwrap_or_else(|_| "tycho-beta.propellerheads.xyz".to_string());
    let tycho_api_key: String =
        env::var("TYCHO_API_KEY").unwrap_or_else(|_| "sampletoken".to_string());

    // Create communication channels for inter-thread communication
    let (tick_tx, tick_rx) = mpsc::channel::<BlockState>(12);

    let tycho_message_processor: JoinHandle<anyhow::Result<()>> = tokio::spawn(async move {
        tycho::process_messages(tycho_url, Some(tycho_api_key), tick_tx, cli.tvl_threshold).await;
        anyhow::Result::Ok(())
    });

    // let terminal = ratatui::init();
    // let terminal_app = tokio::spawn(async move {
    //     ui::App::new(tick_rx)
    //         .run(terminal)
    //         .await
    // });
    let tasks = [tycho_message_processor];
    let _ = select_all(tasks).await;
    info!("Is it over?");
    // ratatui::restore();
}
