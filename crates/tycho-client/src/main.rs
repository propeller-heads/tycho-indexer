use tycho_client::cli::run_cli;

#[tokio::main]
async fn main() {
    install_default_crypto_provider();

    if let Err(e) = run_cli().await {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

#[cfg(feature = "tls-aws-lc-rs")]
fn install_default_crypto_provider() {
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        rustls::crypto::aws_lc_rs::default_provider()
            .install_default()
            .expect("install aws-lc-rs default crypto provider");
    }
}

#[cfg(all(feature = "tls-ring", not(feature = "tls-aws-lc-rs")))]
fn install_default_crypto_provider() {
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        rustls::crypto::ring::default_provider()
            .install_default()
            .expect("install ring default crypto provider");
    }
}

#[cfg(not(any(feature = "tls-aws-lc-rs", feature = "tls-ring")))]
fn install_default_crypto_provider() {}
