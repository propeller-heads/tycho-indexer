use std::fmt::Debug;
use substreams::prelude::BigInt;

/// Encodes a value to bytes using json.
///
/// ## Panics
/// In case the serialisation to json fails.
pub fn json_serialize_value<T: serde::Serialize + Debug>(v: T) -> Vec<u8> {
    serde_json::to_value(v)
        .unwrap_or_else(|e| panic!("Failed to encode value as json {e}"))
        .to_string()
        .as_bytes()
        .to_vec()
}

/// Encodes a list of addresses (in byte representation) into json.
///
/// Converts each address to a 0x prefixed hex string and then serializes
/// the list of strings as a json.
///
/// ## Panics
/// In case the serialisation to json fails.
pub fn json_serialize_address_list(addresses: &[Vec<u8>]) -> Vec<u8> {
    json_serialize_value(
        addresses
            .iter()
            .map(|a| format!("0x{encoded}", encoded = hex::encode(a)))
            .collect::<Vec<_>>(),
    )
}

/// Encodes a list of BigInt values into json.
///
/// Converts each integer to a 0x prefixed hex string and then serializes
/// the list of strings as a json.
///
/// ## Panics
/// In case the serialisation to json fails.
pub fn json_serialize_bigint_list(values: &[BigInt]) -> Vec<u8> {
    json_serialize_value(
        values
            .iter()
            .map(|v| format!("0x{encoded}", encoded = hex::encode(v.to_signed_bytes_be())))
            .collect::<Vec<_>>(),
    )
}
