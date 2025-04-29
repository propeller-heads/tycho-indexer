#[tokio::main]
async fn main() {
    if let Err(e) = tycho_client::cli::run_cli().await {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}
