use tycho_client::cli::run_cli;

#[tokio::main]
async fn main() {
    run_cli().await.unwrap_or_else(|e| {
        eprintln!("Error: {e}");
        std::process::exit(1);
    });
}
