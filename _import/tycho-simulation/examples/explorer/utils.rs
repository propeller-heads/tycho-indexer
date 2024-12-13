use std::collections::HashMap;

use tracing_subscriber::{fmt, EnvFilter};
use tycho_client::{rpc::RPCClient, HttpRPCClient};
use tycho_core::{dto::Chain, Bytes};
use tycho_simulation::models::Token;

pub async fn load_all_tokens(tycho_url: &str, auth_key: Option<&str>) -> HashMap<Bytes, Token> {
    let rpc_url = format!("https://{tycho_url}");
    let rpc_client = HttpRPCClient::new(rpc_url.as_str(), auth_key).unwrap();

    #[allow(clippy::mutable_key_type)]
    rpc_client
        .get_all_tokens(Chain::Ethereum, Some(100), Some(42), 3_000)
        .await
        .expect("Unable to load tokens")
        .into_iter()
        .map(|token| {
            let token_clone = token.clone();
            (
                token.address.clone(),
                token.try_into().unwrap_or_else(|_| {
                    panic!("Couldn't convert {:?} into ERC20 token.", token_clone)
                }),
            )
        })
        .collect::<HashMap<_, Token>>()
}

pub fn setup_tracing() {
    let writer = tracing_appender::rolling::daily("logs", "explorer.log");
    // Create a subscriber with the file appender
    let subscriber = fmt()
        .with_writer(writer)
        .with_env_filter(EnvFilter::from_default_env())
        .finish();
    // Set the subscriber as the global default
    tracing::subscriber::set_global_default(subscriber).unwrap();
}
