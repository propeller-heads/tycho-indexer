use std::{cmp::max, env, sync::Arc};

use alloy::{
    providers::{ProviderBuilder, RootProvider},
    transports::BoxTransport,
};
use alloy_primitives::{aliases::U24, keccak256, Address, FixedBytes, Keccak256, U256, U8};
use num_bigint::BigUint;
use tokio::runtime::{Handle, Runtime};
use tycho_common::Bytes;

use crate::encoding::{
    errors::EncodingError,
    models::{Solution, Swap},
};

/// Safely converts a `Bytes` object to an `Address` object.
///
/// Checks the length of the `Bytes` before attempting to convert, and returns an `EncodingError`
/// if not 20 bytes long.
pub fn bytes_to_address(address: &Bytes) -> Result<Address, EncodingError> {
    if address.len() == 20 {
        Ok(Address::from_slice(address))
    } else {
        Err(EncodingError::InvalidInput(format!("Invalid address: {:?}", address)))
    }
}

/// Converts a general `BigUint` to an EVM-specific `U256` value.
pub fn biguint_to_u256(value: &BigUint) -> U256 {
    let bytes = value.to_bytes_be();
    U256::from_be_slice(&bytes)
}

/// Encodes the input data for a function call to the given function selector.
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

/// Converts a decimal to a `U24` value. The percentage is a `f64` value between 0 and 1.
/// MAX_UINT24 corresponds to 100%.
pub fn percentage_to_uint24(decimal: f64) -> U24 {
    const MAX_UINT24: u32 = 16_777_215; // 2^24 - 1

    let scaled = (decimal / 1.0) * (MAX_UINT24 as f64);
    U24::from(scaled.round())
}

/// Gets the minimum amount out for a solution to pass when executed on-chain.
///
/// The minimum amount is calculated based on the expected amount and the slippage percentage, if
/// passed. If this information is not passed, the user-passed checked amount will be used.
/// If both the slippage and minimum user-passed checked amount are passed, the maximum of the two
/// will be used.
/// If neither are passed, the minimum amount will be zero.
pub fn get_min_amount_for_solution(solution: Solution) -> BigUint {
    let mut min_amount_out = solution
        .checked_amount
        .unwrap_or(BigUint::ZERO);

    if let (Some(expected_amount), Some(slippage)) =
        (solution.expected_amount.as_ref(), solution.slippage)
    {
        let bps = BigUint::from(10_000u32);
        let slippage_percent = BigUint::from((slippage * 10000.0) as u32);
        let multiplier = &bps - slippage_percent;
        let expected_amount_with_slippage = (expected_amount * &multiplier) / &bps;
        min_amount_out = max(min_amount_out, expected_amount_with_slippage);
    }
    min_amount_out
}

/// Gets the position of a token in a list of tokens.
pub fn get_token_position(tokens: Vec<Bytes>, token: Bytes) -> Result<U8, EncodingError> {
    let position = U8::from(
        tokens
            .iter()
            .position(|t| *t == token)
            .ok_or_else(|| {
                EncodingError::InvalidInput(format!("Token {:?} not found in tokens array", token))
            })?,
    );
    Ok(position)
}

/// Pads a byte slice to a fixed size array of N bytes.
pub fn pad_to_fixed_size<const N: usize>(input: &[u8]) -> Result<[u8; N], EncodingError> {
    let mut padded = [0u8; N];
    let start = N - input.len();
    padded[start..].copy_from_slice(input);
    Ok(padded)
}

/// Encodes a function selector to a fixed size array of 4 bytes.
pub fn encode_function_selector(selector: &str) -> FixedBytes<4> {
    let hash = keccak256(selector.as_bytes());
    FixedBytes::<4>::from([hash[0], hash[1], hash[2], hash[3]])
}

/// Extracts a static attribute from a swap.
pub fn get_static_attribute(swap: &Swap, attribute_name: &str) -> Result<Vec<u8>, EncodingError> {
    Ok(swap
        .component
        .static_attributes
        .get(attribute_name)
        .ok_or_else(|| {
            EncodingError::FatalError(format!("Attribute {} not found", attribute_name))
        })?
        .to_vec())
}

pub fn get_runtime() -> Result<(Handle, Option<Arc<Runtime>>), EncodingError> {
    match Handle::try_current() {
        Ok(h) => Ok((h, None)),
        Err(_) => {
            let rt = Arc::new(Runtime::new().map_err(|_| {
                EncodingError::FatalError("Failed to create a new tokio runtime".to_string())
            })?);
            Ok((rt.handle().clone(), Some(rt)))
        }
    }
}

/// Gets the client used for interacting with the EVM-compatible network.
pub async fn get_client() -> Result<Arc<RootProvider<BoxTransport>>, EncodingError> {
    dotenv::dotenv().ok();
    let eth_rpc_url = env::var("RPC_URL")
        .map_err(|_| EncodingError::FatalError("Missing RPC_URL in environment".to_string()))?;
    let client = ProviderBuilder::new()
        .on_builtin(&eth_rpc_url)
        .await
        .map_err(|_| EncodingError::FatalError("Failed to build provider".to_string()))?;
    Ok(Arc::new(client))
}

#[cfg(test)]
mod tests {
    use num_bigint::BigUint;

    use super::*;
    use crate::encoding::models::Solution;

    #[test]
    fn test_min_amount_out_small_slippage() {
        // Tests that the calculation's precision is high enough to support a slippage of 0.1%.

        let solution = Solution {
            exact_out: false,
            given_amount: BigUint::from(1000000000000000000u64),
            checked_amount: None,
            slippage: Some(0.001f64),
            expected_amount: Some(BigUint::from(1000000000000000000u64)),
            ..Default::default()
        };

        let min_amount_out = get_min_amount_for_solution(solution);
        assert_eq!(min_amount_out, BigUint::from(999000000000000000u64));
    }
}
