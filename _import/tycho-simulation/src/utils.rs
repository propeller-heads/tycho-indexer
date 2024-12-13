use crate::{models::Token, protocol::errors::SimulationError};
use std::collections::HashMap;
use tycho_client::{rpc::RPCClient, HttpRPCClient};
use tycho_core::{dto::Chain, Bytes};

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
        .map_err(|_| SimulationError::FatalError(format!("Invalid hex string: {}", hexstring)))?;
    Ok(bytes)
}

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
