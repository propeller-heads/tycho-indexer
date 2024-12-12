use std::{
    collections::HashMap,
    env,
    fs::File,
    io::Read,
    path::{Path, PathBuf},
    str::FromStr,
    sync::{Arc, LazyLock},
};

use alloy::{
    providers::{Provider, ProviderBuilder},
    transports::RpcError,
};
use alloy_primitives::{Address, U256};
use alloy_sol_types::SolValue;

use hex::FromHex;
use mini_moka::sync::Cache;
use num_bigint::BigInt;
use revm::primitives::{Bytecode, Bytes};
use serde_json::Value;

use crate::{
    evm::{simulation::SimulationEngineError, ContractCompiler, SlotId},
    protocol::errors::{FileError, SimulationError},
};

pub(crate) fn coerce_error(
    err: &SimulationEngineError,
    pool_state: &str,
    gas_limit: Option<u64>,
) -> SimulationError {
    match err {
        // Check for revert situation (if error message starts with "0x")
        SimulationEngineError::TransactionError { ref data, ref gas_used }
            if data.starts_with("0x") =>
        {
            let reason = parse_solidity_error_message(data);
            let err = SimulationEngineError::TransactionError {
                data: format!("Revert! Reason: {}", reason),
                gas_used: *gas_used,
            };

            // Check if we are running out of gas
            if let (Some(gas_limit), Some(gas_used)) = (gas_limit, gas_used) {
                // if we used up 97% or more issue a OutOfGas error.
                let usage = *gas_used as f64 / gas_limit as f64;
                if usage >= 0.97 {
                    return SimulationError::InvalidInput(
                        format!(
                            "SimulationError: Likely out-of-gas. Used: {:.2}% of gas limit. \
                            Original error: {}. \
                            Pool state: {}",
                            usage * 100.0,
                            err,
                            pool_state,
                        ),
                        None,
                    );
                }
            }
            SimulationError::FatalError(format!(
                "Simulation reverted for unknown reason: {}",
                reason
            ))
        }
        // Check if "OutOfGas" is part of the error message
        SimulationEngineError::TransactionError { ref data, ref gas_used }
            if data.contains("OutOfGas") =>
        {
            let usage_msg = if let (Some(gas_limit), Some(gas_used)) = (gas_limit, gas_used) {
                let usage = *gas_used as f64 / gas_limit as f64;
                format!("Used: {:.2}% of gas limit. ", usage * 100.0)
            } else {
                String::new()
            };

            SimulationError::InvalidInput(
                format!(
                    "SimulationError: out-of-gas. {} Original error: {}. Pool state: {}",
                    usage_msg, data, pool_state
                ),
                None,
            )
        }
        SimulationEngineError::TransactionError { ref data, .. } => {
            SimulationError::FatalError(format!("TransactionError: {}", data))
        }
        SimulationEngineError::StorageError(message) => {
            SimulationError::RecoverableError(message.clone())
        }
        _ => SimulationError::FatalError(err.clone().to_string()), /* Otherwise return the
                                                                    * original error */
    }
}

fn parse_solidity_error_message(data: &str) -> String {
    // 10 for "0x" + 8 hex chars error signature
    if data.len() >= 10 {
        let data_bytes = match Vec::from_hex(&data[2..]) {
            Ok(bytes) => bytes,
            Err(_) => return format!("Failed to decode: {}", data),
        };

        // Check for specific error selectors:
        // Solidity Error(string) signature: 0x08c379a0
        if data_bytes.starts_with(&[0x08, 0xc3, 0x79, 0xa0]) {
            if let Ok(decoded) = String::abi_decode(&data_bytes[4..], true) {
                return decoded;
            }

            // Solidity Panic(uint256) signature: 0x4e487b71
        } else if data_bytes.starts_with(&[0x4e, 0x48, 0x7b, 0x71]) {
            if let Ok(decoded) = U256::abi_decode(&data_bytes[4..], true) {
                let panic_codes = get_solidity_panic_codes();
                return panic_codes
                    .get(&decoded.as_limbs()[0])
                    .cloned()
                    .unwrap_or_else(|| format!("Panic({})", decoded));
            }
        }

        // Try decoding as a string (old Solidity revert case)
        if let Ok(decoded) = String::abi_decode(&data_bytes, true) {
            return decoded;
        }

        // Custom error, try to decode string again with offset
        if let Ok(decoded) = String::abi_decode(&data_bytes[4..], true) {
            return decoded;
        }
    }
    // Fallback if no decoding succeeded
    format!("Failed to decode: {}", data)
}

/// Get storage slot index of a value stored at a certain key in a mapping
///
/// # Arguments
///
/// * `key`: Key in a mapping. Can be any H160 value (such as an address).
/// * `mapping_slot`: An `U256` representing the storage slot at which the mapping itself is stored.
///   See the examples for more explanation.
/// * `compiler`: The compiler with which the target contract was compiled. Solidity and Vyper
///   handle maps differently.
///
/// # Returns
///
/// An `U256` representing the  index of a storage slot where the value at the given
/// key is stored.
///
/// # Examples
///
/// If a mapping is declared as a first variable in Solidity code, its storage slot
/// is 0 (e.g. `balances` in our mocked ERC20 contract). Here's how to compute
/// a storage slot where balance of a given account is stored:
///
/// ```
/// use alloy_primitives::{U256, Address};
/// use tycho_simulation::evm::ContractCompiler;
/// use tycho_simulation::evm::protocol::vm::utils::get_storage_slot_index_at_key;
/// let address: Address = "0xC63135E4bF73F637AF616DFd64cf701866BB2628".parse().expect("Invalid address");
/// get_storage_slot_index_at_key(address, U256::from(0), ContractCompiler::Solidity);
/// ```
///
/// For nested mappings, we need to apply the function twice. An example of this is
/// `allowances` in ERC20. It is a mapping of form:
/// `HashMap<Owner, HashMap<Spender, U256>>`. In our mocked ERC20 contract, `allowances`
/// is a second variable, so it is stored at slot 1. Here's how to get a storage slot
/// where an allowance of `address_spender` to spend `address_owner`'s money is stored:
///
/// ```
/// use alloy_primitives::{U256, Address};
/// use tycho_simulation::evm::ContractCompiler;
/// use tycho_simulation::evm::protocol::vm::utils::get_storage_slot_index_at_key;
/// let address_spender: Address = "0xC63135E4bF73F637AF616DFd64cf701866BB2628".parse().expect("Invalid address");
/// let address_owner: Address = "0x6F4Feb566b0f29e2edC231aDF88Fe7e1169D7c05".parse().expect("Invalid address");
/// get_storage_slot_index_at_key(address_spender, get_storage_slot_index_at_key(address_owner, U256::from(1), ContractCompiler::Solidity), ContractCompiler::Solidity);
/// ```
///
/// # See Also
///
/// [Solidity Storage Layout documentation](https://docs.soliditylang.org/en/v0.8.13/internals/layout_in_storage.html#mappings-and-dynamic-arrays)
pub fn get_storage_slot_index_at_key(
    key: Address,
    mapping_slot: SlotId,
    compiler: ContractCompiler,
) -> SlotId {
    let mut key_bytes = key.as_slice().to_vec();
    if key_bytes.len() < 32 {
        let padding = vec![0u8; 32 - key_bytes.len()];
        key_bytes.splice(0..0, padding); // Prepend zeros to the start
    }

    let mapping_slot_bytes: [u8; 32] = mapping_slot.to_be_bytes();
    compiler.compute_map_slot(&mapping_slot_bytes, &key_bytes)
}

fn get_solidity_panic_codes() -> HashMap<u64, String> {
    let mut panic_codes = HashMap::new();
    panic_codes.insert(0, "GenericCompilerPanic".to_string());
    panic_codes.insert(1, "AssertionError".to_string());
    panic_codes.insert(17, "ArithmeticOver/Underflow".to_string());
    panic_codes.insert(18, "ZeroDivisionError".to_string());
    panic_codes.insert(33, "UnknownEnumMember".to_string());
    panic_codes.insert(34, "BadStorageByteArrayEncoding".to_string());
    panic_codes.insert(51, "EmptyArray".to_string());
    panic_codes.insert(0x32, "OutOfBounds".to_string());
    panic_codes.insert(0x41, "OutOfMemory".to_string());
    panic_codes.insert(0x51, "BadFunctionPointer".to_string());
    panic_codes
}

/// Fetches the bytecode for a specified contract address, returning an error if the address is
/// an Externally Owned Account (EOA) or if no code is associated with it.
///
/// This function checks the specified address on the blockchain, attempting to retrieve any
/// contract bytecode deployed at that address. If the address corresponds to an EOA or any
/// other address without associated bytecode, an `RpcError::EmptyResponse` error is returned.
///
/// # Parameters
/// - `address`: The address of the account or contract to query, as a string.
/// - `connection_string`: An optional RPC connection string. If not provided, the function will
///   default to the `RPC_URL` environment variable.
///
/// # Returns
/// - `Ok(Bytecode)`: The bytecode of the contract at the specified address, if present.
/// - `Err(RpcError)`: An error if the address does not have associated bytecode, if there is an
///   issue with the RPC connection, or if the address is invalid.
///
/// # Errors
/// - Returns `RpcError::InvalidRequest` if `address` is not parsable or if no RPC URL is set.
/// - Returns `RpcError::EmptyResponse` if the address has no associated bytecode (e.g., EOA).
/// - Returns `RpcError::InvalidResponse` for issues with the RPC provider response.
pub(crate) async fn get_code_for_contract(
    address: &str,
    connection_string: Option<String>,
) -> Result<Bytecode, SimulationError> {
    // Get the connection string, defaulting to the RPC_URL environment variable
    let connection_string = connection_string.or_else(|| env::var("RPC_URL").ok());

    let connection_string = match connection_string {
        Some(url) => url,
        None => {
            return Err(SimulationError::FatalError(
                "RPC_URL environment variable is not set".to_string(),
            ))
        }
    };

    // Create a provider with the URL
    let provider = ProviderBuilder::new()
        .on_builtin(&connection_string)
        .await
        .unwrap();

    let addr = Address::from_str(address).expect("Failed to parse address to get code for");

    // Call eth_getCode to get the bytecode of the contract
    match provider.get_code_at(addr).await {
        Ok(code) if code.is_empty() => {
            Err(SimulationError::FatalError("Empty code response from RPC".to_string()))
        }
        Ok(code) => {
            let bytecode = Bytecode::new_raw(Bytes::from(code.to_vec()));
            Ok(bytecode)
        }
        Err(e) => {
            println!("Error fetching code for address {}: {:?}", address, e);
            match e {
                RpcError::Transport(err) => Err(SimulationError::RecoverableError(format!(
                    "Failed to get code for contract due to internal RPC error: {:?}",
                    err
                ))),
                _ => Err(SimulationError::FatalError(format!(
                    "Failed to get code for contract. Invalid response from RPC: {:?}",
                    e
                ))),
            }
        }
    }
}

static BYTECODE_CACHE: LazyLock<Cache<Arc<String>, Bytecode>> = LazyLock::new(|| Cache::new(1_000));

pub(crate) fn get_contract_bytecode(path: &PathBuf) -> Result<Bytecode, FileError> {
    if let Some(bytecode) = BYTECODE_CACHE.get(&Arc::new(path.to_string_lossy().to_string())) {
        return Ok(bytecode);
    }

    let mut file = File::open(path).map_err(FileError::Io)?;
    let mut code = Vec::new();
    file.read_to_end(&mut code)
        .map_err(FileError::Io)?;

    let bytecode = Bytecode::new_raw(code.into()); // Construct `Bytecode` from `Vec<u8>`
    BYTECODE_CACHE.insert(Arc::new(path.to_string_lossy().to_string()), bytecode.clone());

    Ok(bytecode)
}

pub(crate) fn load_erc20_bytecode() -> Result<Bytecode, FileError> {
    let erc20_bin_path = Path::new(file!())
        .parent()
        .ok_or_else(|| {
            FileError::Structure("Failed to obtain assets directory for ERC20.bin".to_string())
        })?
        .join("assets")
        .join("ERC20.bin");

    let mut erc_20_file = File::open(&erc20_bin_path).map_err(FileError::Io)?;
    let mut erc_20_contents = Vec::new();
    erc_20_file
        .read_to_end(&mut erc_20_contents)
        .map_err(FileError::Io)?;
    let erc_20_bytecode = Bytecode::new_raw(erc_20_contents.into());
    Ok(erc_20_bytecode)
}

/// Converts a hexadecimal string into a fixed-size 32-byte array.
///
/// This function takes a string slice (e.g., a pool ID) that may or may not have
/// a `0x` prefix. It decodes the hex string into bytes, ensuring it does not exceed
/// 32 bytes in length. If the string is valid and fits within 32 bytes, the bytes
/// are copied into a `[u8; 32]` array, with right zero-padding for unused bytes.
///
/// # Arguments
///
/// * `pool_id` - A string slice representing a hexadecimal pool ID. It can optionally start with
///   the `0x` prefix.
///
/// # Returns
///
/// * `Ok([u8; 32])` - On success, returns a 32-byte array with the decoded bytes. If the input is
///   shorter than 32 bytes, the rest of the array is right padded with zeros.
/// * `Err(SimulationError)` - Returns an error if:
///     - The input string is not a valid hexadecimal string.
///     - The decoded bytes exceed 32 bytes in length.
///
/// # Example
/// ```
/// use tycho_simulation::evm::protocol::vm::utils::string_to_bytes32;
///
/// let pool_id = "0x1234abcd";
/// match string_to_bytes32(pool_id) {
///     Ok(bytes32) => println!("Bytes32: {:?}", bytes32),
///     Err(e) => eprintln!("Error: {}", e),
/// }
pub fn string_to_bytes32(pool_id: &str) -> Result<[u8; 32], SimulationError> {
    let pool_id_no_prefix =
        if let Some(stripped) = pool_id.strip_prefix("0x") { stripped } else { pool_id };
    let bytes = hex::decode(pool_id_no_prefix)
        .map_err(|e| SimulationError::FatalError(format!("Invalid hex string: {}", e)))?;
    if bytes.len() > 32 {
        return Err(SimulationError::FatalError(format!(
            "Hex string exceeds 32 bytes: length {}",
            bytes.len()
        )));
    }
    let mut array = [0u8; 32];
    array[..bytes.len()].copy_from_slice(&bytes);
    Ok(array)
}

/// Decodes a JSON-encoded list of hexadecimal strings into a `Vec<Vec<u8>>`.
///
/// This function parses a JSON array where each element is a string representing a hexadecimal
/// value. It converts each hex string into a vector of bytes (`Vec<u8>`), and aggregates them into
/// a `Vec<Vec<u8>>`.
///
/// # Arguments
///
/// * `input` - A byte slice (`&[u8]`) containing JSON-encoded data. The JSON must be a valid array
///   of hex strings.
///
/// # Returns
///
/// * `Ok(Vec<Vec<u8>>)` - On success, returns a vector of byte vectors.
/// * `Err(SimulationError)` - Returns an error if:
///     - The input is not valid JSON.
///     - The JSON is not an array.
///     - Any array element is not a string.
///     - Any string is not a valid hexadecimal string.
///
/// # Example
/// ```
/// use tycho_simulation::evm::protocol::vm::utils::json_deserialize_address_list;
///
/// let json_input = br#"["0x1234", "0xc0ffee"]"#;
/// match json_deserialize_address_list(json_input) {
///     Ok(result) => println!("Decoded: {:?}", result),
///     Err(e) => eprintln!("Error: {}", e),
/// }
/// ```
pub fn json_deserialize_address_list(input: &[u8]) -> Result<Vec<Vec<u8>>, SimulationError> {
    let json_value: Value = serde_json::from_slice(input)
        .map_err(|_| SimulationError::FatalError(format!("Invalid JSON: {:?}", input)))?;

    if let Value::Array(hex_strings) = json_value {
        let mut result = Vec::new();

        for val in hex_strings {
            if let Value::String(hexstring) = val {
                let bytes = hex::decode(hexstring.trim_start_matches("0x")).map_err(|_| {
                    SimulationError::FatalError(format!("Invalid hex string: {}", hexstring))
                })?;
                result.push(bytes);
            } else {
                return Err(SimulationError::FatalError("Array contains a non-string value".into()));
            }
        }

        Ok(result)
    } else {
        Err(SimulationError::FatalError("Input is not a JSON array".into()))
    }
}

/// Decodes a JSON-encoded list of hexadecimal strings into a `Vec<BigInt>`.
///
/// This function parses a JSON array where each element is a string representing a hexadecimal
/// value. It converts each hex string into a `BigInt` using big-endian byte interpretation, and
/// aggregates them into a `Vec<BigInt>`.
///
/// # Arguments
///
/// * `input` - A byte slice (`&[u8]`) containing JSON-encoded data. The JSON must be a valid array
///   of hex strings.
///
/// # Returns
///
/// * `Ok(Vec<BigInt>)` - On success, returns a vector of `BigInt` values.
/// * `Err(SimulationError)` - Returns an error if:
///     - The input is not valid JSON.
///     - The JSON is not an array.
///     - Any array element is not a string.
///     - Any string is not a valid hexadecimal string.
///
/// # Example
/// ```
/// use tycho_simulation::evm::protocol::vm::utils::json_deserialize_be_bigint_list;
/// use num_bigint::BigInt;
/// use tycho_simulation::evm;
/// let json_input = br#"["0x1234", "0xdeadbeef"]"#;
/// match json_deserialize_be_bigint_list(json_input) {
///     Ok(result) => println!("Decoded BigInts: {:?}", result),
///     Err(e) => eprintln!("Error: {}", e),
/// }
/// ```
pub fn json_deserialize_be_bigint_list(input: &[u8]) -> Result<Vec<BigInt>, SimulationError> {
    let json_value: Value = serde_json::from_slice(input)
        .map_err(|_| SimulationError::FatalError(format!("Invalid JSON: {:?}", input)))?;

    if let Value::Array(hex_strings) = json_value {
        let mut result = Vec::new();

        for val in hex_strings {
            if let Value::String(hexstring) = val {
                let bytes = hex::decode(hexstring.trim_start_matches("0x")).map_err(|_| {
                    SimulationError::FatalError(format!("Invalid hex string: {}", hexstring))
                })?;
                let bigint = BigInt::from_signed_bytes_be(&bytes);
                result.push(bigint);
            } else {
                return Err(SimulationError::FatalError("Array contains a non-string value".into()));
            }
        }

        Ok(result)
    } else {
        Err(SimulationError::FatalError("Input is not a JSON array".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::utils::hexstring_to_vec;
    use dotenv::dotenv;
    use hex::decode;
    use std::{fs::remove_file, io::Write};
    use tempfile::NamedTempFile;

    #[tokio::test]
    #[cfg_attr(not(feature = "network_tests"), ignore)]
    async fn test_get_code_for_address() {
        let rpc_url = env::var("ETH_RPC_URL").unwrap_or_else(|_| {
            dotenv().expect("Missing .env file");
            env::var("ETH_RPC_URL").expect("Missing ETH_RPC_URL in .env file")
        });

        let address = "0x88e6A0c2dDD26FEEb64F039a2c41296FcB3f5640";
        let result = get_code_for_contract(address, Some(rpc_url)).await;

        assert!(result.is_ok(), "Network call should not fail");

        let code = result.unwrap();
        assert!(!code.bytes().is_empty(), "Code should not be empty");
    }

    #[test]
    fn test_maybe_coerce_error_revert_no_gas_info() {
        let err = SimulationEngineError::TransactionError{
            data: "0x08c379a000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000011496e76616c6964206f7065726174696f6e000000000000000000000000000000".to_string(),
            gas_used: None
        };

        let result = coerce_error(&err, "test_pool", None);

        if let SimulationError::FatalError(msg) = result {
            assert!(msg.contains("Simulation reverted for unknown reason: Invalid operation"));
        } else {
            panic!("Expected SolidityError error");
        }
    }

    #[test]
    fn test_maybe_coerce_error_out_of_gas() {
        // Test out-of-gas situation with gas limit and gas used provided
        let err = SimulationEngineError::TransactionError{
            data: "0x08c379a000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000011496e76616c6964206f7065726174696f6e000000000000000000000000000000".to_string(),
            gas_used: Some(980)
        };

        let result = coerce_error(&err, "test_pool", Some(1000));

        if let SimulationError::InvalidInput(message, _partial_result) = result {
            assert!(message.contains("Used: 98.00% of gas limit."));
            assert!(message.contains("test_pool"));
        } else {
            panic!("Expected OutOfGas error");
        }
    }

    #[test]
    fn test_maybe_coerce_error_no_gas_limit_info() {
        // Test out-of-gas situation without gas limit info
        let err = SimulationEngineError::TransactionError {
            data: "OutOfGas".to_string(),
            gas_used: None,
        };

        let result = coerce_error(&err, "test_pool", None);

        if let SimulationError::InvalidInput(message, _partial_result) = result {
            assert!(message.contains("Original error: OutOfGas"));
            assert!(message.contains("Pool state: test_pool"));
        } else {
            panic!("Expected RetryDifferentInput error");
        }
    }

    #[test]
    fn test_maybe_coerce_error_storage_error() {
        let err = SimulationEngineError::StorageError("Storage error:".to_string());

        let result = coerce_error(&err, "test_pool", None);

        if let SimulationError::RecoverableError(message) = result {
            assert_eq!(message, "Storage error:");
        } else {
            println!("{:?}", result);
            panic!("Expected RetryLater error");
        }
    }

    #[test]
    fn test_maybe_coerce_error_no_match() {
        // Test for non-revert, non-out-of-gas, non-storage errors
        let err = SimulationEngineError::TransactionError {
            data: "Some other error".to_string(),
            gas_used: None,
        };

        let result = coerce_error(&err, "test_pool", None);

        if let SimulationError::FatalError(message) = result {
            assert_eq!(message, "TransactionError: Some other error");
        } else {
            panic!("Expected solidity error");
        }
    }

    #[test]
    fn test_parse_solidity_error_message_error_string() {
        // Test parsing Solidity Error(string) message
        let data = "0x08c379a00000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000e416d6f756e7420746f6f206c6f77000000000000000000000000000000000000";

        let result = parse_solidity_error_message(data);

        assert_eq!(result, "Amount too low");
    }

    #[test]
    fn test_parse_solidity_error_message_panic_code() {
        // Test parsing Solidity Panic(uint256) message
        let data = "0x4e487b710000000000000000000000000000000000000000000000000000000000000001";

        let result = parse_solidity_error_message(data);

        assert_eq!(result, "AssertionError");
    }

    #[test]
    fn test_parse_solidity_error_message_failed_to_decode() {
        // Test failed decoding with invalid data
        let data = "0x1234567890";

        let result = parse_solidity_error_message(data);

        assert!(result.contains("Failed to decode"));
    }

    #[test]
    fn test_get_contract_bytecode() {
        // Create a temporary file with some test data
        let mut temp_file = NamedTempFile::new().unwrap();
        let test_data = b"Test contract bytecode";
        temp_file.write_all(test_data).unwrap();
        let temp_path = temp_file.path().to_path_buf();

        // First call to get_contract_bytecode
        let result1 = get_contract_bytecode(&temp_path).unwrap();
        assert_eq!(result1, Bytecode::new_raw(test_data.into()));

        // Second call to get_contract_bytecode (should use cached data)
        // Verify that the cache was used (file is not read twice)
        remove_file(&temp_file).unwrap(); // This removes the temporary file
        let result2 = get_contract_bytecode(&temp_path).unwrap();
        assert_eq!(result2, Bytecode::new_raw(test_data.into()));
    }

    #[test]
    fn test_get_contract_bytecode_error() {
        let result = get_contract_bytecode(&PathBuf::from("non_existent_file.txt"));
        assert!(result.is_err());
    }

    #[test]
    fn test_load_erc20_bytecode() {
        let result = load_erc20_bytecode();
        assert!(result.is_ok());

        let bytecode: Bytecode = result.expect("Failed to retrieve ERC20 ABI result");

        let expected_bytes = revm::precompile::Bytes::from(decode("608060405234801561000f575f80fd5b50600436106100a6575f3560e01c8063395093511161006e578063395093511461011f57806370a082311461013257806395d89b411461015a578063a457c2d714610162578063a9059cbb14610175578063dd62ed3e14610188575f80fd5b806306fdde03146100aa578063095ea7b3146100c857806318160ddd146100eb57806323b872dd146100fd578063313ce56714610110575b5f80fd5b6100b261019b565b6040516100bf91906105b9565b60405180910390f35b6100db6100d636600461061f565b61022b565b60405190151581526020016100bf565b6002545b6040519081526020016100bf565b6100db61010b366004610647565b610244565b604051601281526020016100bf565b6100db61012d36600461061f565b610267565b6100ef610140366004610680565b6001600160a01b03165f9081526020819052604090205490565b6100b2610288565b6100db61017036600461061f565b610297565b6100db61018336600461061f565b6102f2565b6100ef6101963660046106a0565b6102ff565b6060600380546101aa906106d1565b80601f01602080910402602001604051908101604052809291908181526020018280546101d6906106d1565b80156102215780601f106101f857610100808354040283529160200191610221565b820191905f5260205f20905b81548152906001019060200180831161020457829003601f168201915b5050505050905090565b5f33610238818585610329565b60019150505b92915050565b5f336102518582856103dc565b61025c85858561043e565b506001949350505050565b5f3361023881858561027983836102ff565b6102839190610709565b610329565b6060600480546101aa906106d1565b5f33816102a482866102ff565b9050838110156102e557604051632983c0c360e21b81526001600160a01b038616600482015260248101829052604481018590526064015b60405180910390fd5b61025c8286868403610329565b5f3361023881858561043e565b6001600160a01b039182165f90815260016020908152604080832093909416825291909152205490565b6001600160a01b0383166103525760405163e602df0560e01b81525f60048201526024016102dc565b6001600160a01b03821661037b57604051634a1406b160e11b81525f60048201526024016102dc565b6001600160a01b038381165f8181526001602090815260408083209487168084529482529182902085905590518481527f8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b92591015b60405180910390a3505050565b5f6103e784846102ff565b90505f198114610438578181101561042b57604051637dc7a0d960e11b81526001600160a01b038416600482015260248101829052604481018390526064016102dc565b6104388484848403610329565b50505050565b6001600160a01b03831661046757604051634b637e8f60e11b81525f60048201526024016102dc565b6001600160a01b0382166104905760405163ec442f0560e01b81525f60048201526024016102dc565b61049b8383836104a0565b505050565b6001600160a01b0383166104ca578060025f8282546104bf9190610709565b9091555061053a9050565b6001600160a01b0383165f908152602081905260409020548181101561051c5760405163391434e360e21b81526001600160a01b038516600482015260248101829052604481018390526064016102dc565b6001600160a01b0384165f9081526020819052604090209082900390555b6001600160a01b03821661055657600280548290039055610574565b6001600160a01b0382165f9081526020819052604090208054820190555b816001600160a01b0316836001600160a01b03167fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef836040516103cf91815260200190565b5f6020808352835180828501525f5b818110156105e4578581018301518582016040015282016105c8565b505f604082860101526040601f19601f8301168501019250505092915050565b80356001600160a01b038116811461061a575f80fd5b919050565b5f8060408385031215610630575f80fd5b61063983610604565b946020939093013593505050565b5f805f60608486031215610659575f80fd5b61066284610604565b925061067060208501610604565b9150604084013590509250925092565b5f60208284031215610690575f80fd5b61069982610604565b9392505050565b5f80604083850312156106b1575f80fd5b6106ba83610604565b91506106c860208401610604565b90509250929050565b600181811c908216806106e557607f821691505b60208210810361070357634e487b7160e01b5f52602260045260245ffd5b50919050565b8082018082111561023e57634e487b7160e01b5f52601160045260245ffdfea2646970667358221220dfc123d5852c9246ea16b645b377b4436e2f778438195cc6d6c435e8c73a20e764736f6c634300081403000000000000000000000000000000000000000000000000000000000000000000").unwrap());
        let expected_bytecode = Bytecode::new_raw(expected_bytes);
        assert_eq!(bytecode, expected_bytecode);
    }

    #[test]
    fn test_hexstring_to_vec() {
        let hexstring = "0x68656c6c6f";
        let expected = vec![0x68, 0x65, 0x6c, 0x6c, 0x6f];
        let result = hexstring_to_vec(hexstring).unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_hexstring_to_vec_no_prefix() {
        let hexstring = "68656c6c6f";
        let expected = vec![0x68, 0x65, 0x6c, 0x6c, 0x6f];
        let result = hexstring_to_vec(hexstring).unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_hexstring_to_vec_invalid_characters() {
        let hexstring = "0x68656c6c6z"; // Invalid character 'z'
        let result = hexstring_to_vec(hexstring);
        assert!(result.is_err());
        if let Err(SimulationError::FatalError(msg)) = result {
            assert!(msg.contains("Invalid hex string"));
        } else {
            panic!("Expected EncodingError");
        }
    }

    #[test]
    fn test_json_deserialize_address_list() {
        let json_input = r#"["0x1234","0xabcd"]"#.as_bytes();
        let result = json_deserialize_address_list(json_input).unwrap();
        assert_eq!(result, vec![vec![0x12, 0x34], vec![0xab, 0xcd]]);
    }

    #[test]
    fn test_json_deserialize_bigint_list() {
        let json_input = r#"["0x0b1a2bc2ec500000","0x02c68af0bb140000"]"#.as_bytes();
        let result = json_deserialize_be_bigint_list(json_input).unwrap();
        assert_eq!(
            result,
            vec![BigInt::from(800000000000000000u64), BigInt::from(200000000000000000u64)]
        );
    }

    #[test]
    fn test_invalid_deserialize_address_list() {
        let json_input = r#"["invalid_hex"]"#.as_bytes();
        let result = json_deserialize_address_list(json_input);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_deserialize_bigint_list() {
        let json_input = r#"["invalid_hex"]"#.as_bytes();
        let result = json_deserialize_be_bigint_list(json_input);
        assert!(result.is_err());
    }
}
