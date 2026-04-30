use tycho_client::cli::run_cli;

#[tokio::main]
async fn main() {
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        rustls::crypto::aws_lc_rs::default_provider()
            .install_default()
            .expect("install aws-lc-rs default crypto provider");
    }

    run_cli().await.unwrap_or_else(|e| {
        eprintln!("Error: {e}");
        std::process::exit(1);
    });
}
