use std::{
    env,
    fs::OpenOptions,
    io::{BufRead, BufReader, Write},
    sync::{Arc, Mutex},
};

use alloy::{
    providers::{ProviderBuilder, RootProvider},
    transports::BoxTransport,
};
use alloy_primitives::{aliases::U24, Address, Keccak256, U256, U8};
use alloy_sol_types::SolValue;
use num_bigint::BigUint;
use once_cell::sync::Lazy;
use tokio::runtime::{Handle, Runtime};
use tycho_common::Bytes;

use crate::encoding::{errors::EncodingError, models::Swap};

/// Safely converts a `Bytes` object to an `Address` object.
///
/// Checks the length of the `Bytes` before attempting to convert, and returns an `EncodingError`
/// if not 20 bytes long.
pub fn bytes_to_address(address: &Bytes) -> Result<Address, EncodingError> {
    if address.len() == 20 {
        Ok(Address::from_slice(address))
    } else {
        Err(EncodingError::InvalidInput(format!("Invalid address: {address}",)))
    }
}

/// Converts a general `BigUint` to an EVM-specific `U256` value.
pub fn biguint_to_u256(value: &BigUint) -> U256 {
    let bytes = value.to_bytes_be();
    U256::from_be_slice(&bytes)
}

/// Converts a decimal to a `U24` value. The percentage is a `f64` value between 0 and 1.
/// MAX_UINT24 corresponds to 100%.
pub fn percentage_to_uint24(decimal: f64) -> U24 {
    const MAX_UINT24: u32 = 16_777_215; // 2^24 - 1

    let scaled = (decimal / 1.0) * (MAX_UINT24 as f64);
    U24::from(scaled.round())
}

/// Gets the position of a token in a list of tokens.
pub fn get_token_position(tokens: Vec<Bytes>, token: Bytes) -> Result<U8, EncodingError> {
    let position = U8::from(
        tokens
            .iter()
            .position(|t| *t == token)
            .ok_or_else(|| {
                EncodingError::InvalidInput(format!("Token {token} not found in tokens array"))
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

/// Extracts a static attribute from a swap.
pub fn get_static_attribute(swap: &Swap, attribute_name: &str) -> Result<Vec<u8>, EncodingError> {
    Ok(swap
        .component
        .static_attributes
        .get(attribute_name)
        .ok_or_else(|| EncodingError::FatalError(format!("Attribute {attribute_name} not found")))?
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

/// Uses prefix-length encoding to efficient encode action data.
///
/// Prefix-length encoding is a data encoding method where the beginning of a data segment
/// (the "prefix") contains information about the length of the following data.
pub fn ple_encode(action_data_array: Vec<Vec<u8>>) -> Vec<u8> {
    let mut encoded_action_data: Vec<u8> = Vec::new();

    for action_data in action_data_array {
        let args = (encoded_action_data, action_data.len() as u16, action_data);
        encoded_action_data = args.abi_encode_packed();
    }

    encoded_action_data
}

static CALLDATA_WRITE_MUTEX: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));
// Function used in tests to write calldata to a file that then is used by the corresponding
// solidity tests.
pub fn write_calldata_to_file(test_identifier: &str, hex_calldata: &str) {
    let _lock = CALLDATA_WRITE_MUTEX
        .lock()
        .expect("Couldn't acquire lock");

    let file_path = "foundry/test/assets/calldata.txt";
    let file = OpenOptions::new()
        .read(true)
        .open(file_path)
        .expect("Failed to open calldata file for reading");
    let reader = BufReader::new(file);

    let mut lines = Vec::new();
    let mut found = false;
    for line in reader.lines().map_while(Result::ok) {
        let mut parts = line.splitn(2, ':'); // split at the :
        let key = parts.next().unwrap_or("");
        if key == test_identifier {
            lines.push(format!("{test_identifier}:{hex_calldata}"));
            found = true;
        } else {
            lines.push(line);
        }
    }

    // If the test identifier wasn't found, append a new line
    if !found {
        lines.push(format!("{test_identifier}:{hex_calldata}"));
    }

    // Write the updated contents back to the file
    let mut file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(file_path)
        .expect("Failed to open calldata file for writing");

    for line in lines {
        writeln!(file, "{line}").expect("Failed to write calldata");
    }
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
