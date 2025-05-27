use std::collections::HashMap;

use tracing::info;
use tycho_client::{rpc::RPCClient, HttpRPCClient};
use tycho_common::{models::Chain, Bytes};

use crate::{models::Token, protocol::errors::SimulationError};

/// Converts a hexadecimal string into a `Vec<u8>`.
///
/// This function accepts a hexadecimal string with or without the `0x` prefix. If the prefix
/// is present, it is removed before decoding. The remaining string is expected to be a valid
/// hexadecimal representation, otherwise an error is returned.
///
/// # Arguments
///
/// * `hexstring` - A string slice containing the hexadecimal string. It may optionally start with
///   `0x`.
///
/// # Returns
///
/// * `Ok(Vec<u8>)` - A vector of bytes decoded from the hexadecimal string.
/// * `Err(SimulationError)` - An error if the input string is not a valid hexadecimal
///   representation.
///
/// # Errors
///
/// This function returns a `SimulationError::EncodingError` if:
/// - The string contains invalid hexadecimal characters.
/// - The string is empty or malformed.
pub fn hexstring_to_vec(hexstring: &str) -> Result<Vec<u8>, SimulationError> {
    let hexstring_no_prefix =
        if let Some(stripped) = hexstring.strip_prefix("0x") { stripped } else { hexstring };
    let bytes = hex::decode(hexstring_no_prefix)
        .map_err(|_| SimulationError::FatalError(format!("Invalid hex string: {hexstring}")))?;
    Ok(bytes)
}

/// Loads all tokens from Tycho and returns them as a Hashmap of address->Token.
///
/// # Arguments
///
/// * `tycho_url` - The URL of the Tycho RPC (do not include the url prefix e.g. 'https://').
/// * `no_tls` - Whether to use HTTP instead of HTTPS.
/// * `auth_key` - The API key to use for authentication.
/// * `chain` - The chain to load tokens from.
/// * `min_quality` - The minimum quality of tokens to load. Defaults to 100 if not provided.
/// * `max_days_since_last_trade` - The max number of days since the token was last traded. Defaults
///   are chain specific and applied if not provided.
pub async fn load_all_tokens(
    tycho_url: &str,
    no_tls: bool,
    auth_key: Option<&str>,
    chain: Chain,
    min_quality: Option<i32>,
    max_days_since_last_trade: Option<u64>,
) -> HashMap<Bytes, Token> {
    info!("Loading tokens from Tycho...");
    let rpc_url =
        if no_tls { format!("http://{tycho_url}") } else { format!("https://{tycho_url}") };
    let rpc_client = HttpRPCClient::new(rpc_url.as_str(), auth_key).unwrap();

    // Chain specific defaults for special case chains. Otherwise defaults to 42 days.
    let default_min_days = HashMap::from([(Chain::Base, 1_u64)]);

    #[allow(clippy::mutable_key_type)]
    rpc_client
        .get_all_tokens(
            chain.into(),
            min_quality.or(Some(100)),
            max_days_since_last_trade.or(default_min_days
                .get(&chain)
                .or(Some(&42))
                .copied()),
            3_000,
        )
        .await
        .expect("Unable to load tokens")
        .into_iter()
        .map(|token| {
            let token_clone = token.clone();
            (
                token.address.clone(),
                token.try_into().unwrap_or_else(|_| {
                    panic!("Couldn't convert {token_clone:?} into ERC20 token.")
                }),
            )
        })
        .collect::<HashMap<_, Token>>()
}
