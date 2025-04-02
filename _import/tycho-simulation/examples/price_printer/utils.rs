use tracing_subscriber::{fmt, EnvFilter};
use tycho_common::models::Chain;

pub fn setup_tracing() {
    let writer = tracing_appender::rolling::daily("logs", "price_printer.log");
    // Create a subscriber with the file appender
    let subscriber = fmt()
        .with_writer(writer)
        .with_env_filter(EnvFilter::from_default_env())
        .finish();
    // Set the subscriber as the global default
    tracing::subscriber::set_global_default(subscriber).unwrap();
}

pub(super) fn get_default_url(chain: &Chain) -> Option<String> {
    match chain {
        Chain::Ethereum => Some("tycho-beta.propellerheads.xyz".to_string()),
        Chain::Base => Some("tycho-base-beta.propellerheads.xyz".to_string()),
        Chain::Unichain => Some("tycho-unichain-beta.propellerheads.xyz".to_string()),
        _ => None,
    }
}
