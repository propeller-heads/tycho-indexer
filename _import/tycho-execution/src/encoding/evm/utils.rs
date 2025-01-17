use alloy_primitives::{Address, Keccak256, U256};
use alloy_sol_types::SolValue;
use num_bigint::BigUint;
use tycho_core::Bytes;

use crate::encoding::errors::EncodingError;

/// Safely converts a `Bytes` object to an `Address` object.
///
/// Checks the length of the `Bytes` before attempting to convert, and returns an `EncodingError`
/// if not 20 bytes long.
pub fn bytes_to_address(address: &Bytes) -> Result<Address, EncodingError> {
    if address.len() == 20 {
        Ok(Address::from_slice(address))
    } else {
        Err(EncodingError::InvalidInput(format!("Invalid ERC20 token address: {:?}", address)))
    }
}

#[allow(dead_code)]
pub fn biguint_to_u256(value: &BigUint) -> U256 {
    let bytes = value.to_bytes_be();
    U256::from_be_slice(&bytes)
}

#[allow(dead_code)]
pub fn ple_encode(action_data_array: Vec<Vec<u8>>) -> Vec<u8> {
    let mut encoded_action_data: Vec<u8> = Vec::new();

    for action_data in action_data_array {
        let args = (encoded_action_data, action_data.len() as u16, action_data);
        encoded_action_data = args.abi_encode();
    }

    encoded_action_data
}

#[allow(dead_code)]
pub fn encode_input(selector: &str, mut encoded_args: Vec<u8>) -> Vec<u8> {
    let mut hasher = Keccak256::new();
    hasher.update(selector.as_bytes());
    let selector_bytes = &hasher.finalize()[..4];
    let mut call_data = selector_bytes.to_vec();
    // Remove extra prefix if present (32 bytes for dynamic data)
    // Alloy encoding is including a prefix for dynamic data indicating the offset or length
    // but at this point we don't want that
    if encoded_args.len() > 32 &&
        encoded_args[..32] ==
            [0u8; 31]
                .into_iter()
                .chain([32].to_vec())
                .collect::<Vec<u8>>()
    {
        encoded_args = encoded_args[32..].to_vec();
    }
    call_data.extend(encoded_args);
    call_data
}
