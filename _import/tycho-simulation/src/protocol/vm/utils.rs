// TODO: remove skip for clippy dead_code check
#![allow(dead_code)]
use ethabi::{self, decode, ParamType};
use ethers::{
    abi::Abi,
    providers::{Http, Middleware, Provider, ProviderError},
    types::H160,
};
use hex::FromHex;
use mini_moka::sync::Cache;

use crate::evm_simulation::simulation::SimulationError;
use std::{
    collections::HashMap,
    env,
    fs::File,
    io::Read,
    path::Path,
    sync::{Arc, LazyLock},
};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum RpcError {
    #[error("Invalid Request: {0}")]
    InvalidRequest(String),
    #[error("Invalid Response: {0}")]
    InvalidResponse(ProviderError),
}

#[derive(Debug, Error)]
pub enum RecoverableError {
    #[error("Solidity Error: {0}")]
    SolidityError(String),
    #[error("Out of Gas: {0}. Pool state: {1}")]
    OutOfGas(String, String),
    /// Something went wrong while getting storage; might be caused by network issues
    #[error("Storage Error: {0}")]
    StorageError(String),
}

pub fn maybe_coerce_error(
    err: SimulationError,
    pool_state: &str,
    gas_limit: Option<u64>,
) -> Result<(), RecoverableError> {
    match err {
        // Check for revert situation (if error message starts with "0x")
        SimulationError::TransactionError { ref data, ref gas_used } if data.starts_with("0x") => {
            let reason = parse_solidity_error_message(data);
            let err = RecoverableError::SolidityError(format!("Revert! Reason: {}", reason));

            // Check if we are running out of gas
            if let (Some(gas_limit), Some(gas_used)) = (gas_limit, gas_used) {
                // if we used up 97% or more issue a OutOfGas error.
                let usage = *gas_used as f64 / gas_limit as f64;
                if usage >= 0.97 {
                    return Err(RecoverableError::OutOfGas(
                        format!(
                            "SimulationError: Likely out-of-gas. Used: {:.2}% of gas limit. Original error: {}",
                            usage * 100.0,
                            err
                        ),
                        pool_state.to_string(),
                    ));
                }
            }
            Err(err)
        }

        // Check if "OutOfGas" is part of the error message
        SimulationError::TransactionError { ref data, ref gas_used }
            if data.contains("OutOfGas") =>
        {
            let usage_msg = if let (Some(gas_limit), Some(gas_used)) = (gas_limit, gas_used) {
                let usage = *gas_used as f64 / gas_limit as f64;
                format!("Used: {:.2}% of gas limit. ", usage * 100.0)
            } else {
                String::new()
            };

            Err(RecoverableError::OutOfGas(
                format!("SimulationError: out-of-gas. {} Original error: {}", usage_msg, data),
                pool_state.to_string(),
            ))
        }
        SimulationError::StorageError(msg) => Err(RecoverableError::StorageError(msg)),

        // Transaction error that doesn't start with 0x or contain "OutOfGas" - re-raise the
        // original error.
        _ => Err(RecoverableError::SolidityError(err.to_string())),
    }
}

fn parse_solidity_error_message(data: &str) -> String {
    let data_bytes = match Vec::from_hex(&data[2..]) {
        Ok(bytes) => bytes,
        Err(_) => return format!("Failed to decode: {}", data),
    };

    // Check for specific error selectors:
    // Solidity Error(string) signature: 0x08c379a0
    if data_bytes.starts_with(&[0x08, 0xc3, 0x79, 0xa0]) {
        if let Ok(decoded) = decode(&[ParamType::String], &data_bytes[4..]) {
            if let Some(ethabi::Token::String(error_string)) = decoded.first() {
                return error_string.clone();
            }
        }

        // Solidity Panic(uint256) signature: 0x4e487b71
    } else if data_bytes.starts_with(&[0x4e, 0x48, 0x7b, 0x71]) {
        if let Ok(decoded) = decode(&[ParamType::Uint(256)], &data_bytes[4..]) {
            if let Some(ethabi::Token::Uint(error_code)) = decoded.first() {
                let panic_codes = get_solidity_panic_codes();
                return panic_codes
                    .get(&error_code.as_u64())
                    .cloned()
                    .unwrap_or_else(|| format!("Panic({})", error_code));
            }
        }
    }

    // Try decoding as a string (old Solidity revert case)
    if let Ok(decoded) = decode(&[ParamType::String], &data_bytes) {
        if let Some(ethabi::Token::String(error_string)) = decoded.first() {
            return error_string.clone();
        }
    }

    // Custom error, try to decode string again with offset
    if let Ok(decoded) = decode(&[ParamType::String], &data_bytes[4..]) {
        if let Some(ethabi::Token::String(error_string)) = decoded.first() {
            return error_string.clone();
        }
    }

    // Fallback if no decoding succeeded
    format!("Failed to decode: {}", data)
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

pub async fn get_code_for_address(
    address: &str,
    connection_string: Option<String>,
) -> Result<Option<Vec<u8>>, RpcError> {
    // Get the connection string, defaulting to the RPC_URL environment variable
    let connection_string = connection_string.or_else(|| env::var("RPC_URL").ok());

    let connection_string = match connection_string {
        Some(url) => url,
        None => {
            return Err(RpcError::InvalidRequest(
                "RPC_URL environment variable is not set".to_string(),
            ))
        }
    };

    // Create a provider with the URL
    let provider =
        Provider::<Http>::try_from(connection_string).expect("could not instantiate HTTP Provider");

    // Parse the address
    let addr: H160 = address
        .parse()
        .map_err(|_| RpcError::InvalidRequest(format!("Failed to parse address: {}", address)))?;

    // Call eth_getCode to get the bytecode of the contract
    match provider.get_code(addr, None).await {
        Ok(code) if code.is_empty() => Ok(None),
        Ok(code) => Ok(Some(code.to_vec())),
        Err(e) => {
            println!("Error fetching code for address {}: {:?}", address, e);
            Err(RpcError::InvalidResponse(e))
        }
    }
}

static BYTECODE_CACHE: LazyLock<Cache<Arc<String>, Vec<u8>>> = LazyLock::new(|| Cache::new(1_000));

pub fn get_contract_bytecode(path: &str) -> std::io::Result<Vec<u8>> {
    if let Some(bytecode) = BYTECODE_CACHE.get(&Arc::new(path.to_string())) {
        return Ok(bytecode.clone());
    }

    let mut file = File::open(Path::new(path))?;
    let mut code = Vec::new();

    file.read_to_end(&mut code)?;
    BYTECODE_CACHE.insert(Arc::new(path.to_string()), code.clone());

    Ok(code)
}

pub fn load_swap_abi() -> Result<Abi, std::io::Error> {
    let swap_abi_path = Path::new(file!())
        .parent()
        .unwrap()
        .join("assets")
        .join("ISwapAdapter.abi");

    let mut file = File::open(&swap_abi_path).expect("Failed to open the swap ABI file");
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .expect("Failed to read the swap ABI file");
    let abi: Abi = serde_json::from_str(&contents).expect("Swap ABI is malformed.");
    Ok(abi)
}

pub fn load_erc20_abi() -> Result<Abi, std::io::Error> {
    let erc20_abi_path = Path::new(file!())
        .parent()
        .unwrap()
        .join("assets")
        .join("ERC20.abi");

    let mut file = File::open(&erc20_abi_path).expect("Failed to open the ERC20 ABI file");
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .expect("Failed to read the ERC20 ABI file");

    let abi: Abi = serde_json::from_str(&contents).expect("ERC20 ABI is malformed.");
    Ok(abi)
}

#[cfg(test)]
mod tests {
    use dotenv::dotenv;
    use std::{fs::remove_file, io::Write};
    use tempfile::NamedTempFile;

    use super::*;

    #[tokio::test]
    #[cfg_attr(not(feature = "network_tests"), ignore)]
    async fn test_get_code_for_address() {
        let rpc_url = env::var("ETH_RPC_URL").unwrap_or_else(|_| {
            dotenv().expect("Missing .env file");
            env::var("ETH_RPC_URL").expect("Missing ETH_RPC_URL in .env file")
        });

        let address = "0x88e6A0c2dDD26FEEb64F039a2c41296FcB3f5640";
        let result = get_code_for_address(address, Some(rpc_url)).await;

        assert!(result.is_ok(), "Network call should not fail");

        let code_bytes = result.unwrap();
        match code_bytes {
            Some(bytes) => {
                assert!(!bytes.is_empty(), "Code should not be empty");
            }
            None => {
                panic!("There should be some code for the address");
            }
        }
    }

    #[test]
    fn test_maybe_coerce_error_revert_no_gas_info() {
        let err = SimulationError::TransactionError{
            data: "0x08c379a000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000011496e76616c6964206f7065726174696f6e000000000000000000000000000000".to_string(),
            gas_used: None
        };

        let result = maybe_coerce_error(err, "test_pool", None);

        assert!(result.is_err());
        if let Err(RecoverableError::SolidityError(message)) = result {
            assert!(message.contains("Revert! Reason: Invalid operation"));
        } else {
            panic!("Expected SolidityError error");
        }
    }

    #[test]
    fn test_maybe_coerce_error_out_of_gas() {
        // Test out-of-gas situation with gas limit and gas used provided
        let err = SimulationError::TransactionError{
            data: "0x08c379a000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000011496e76616c6964206f7065726174696f6e000000000000000000000000000000".to_string(),
            gas_used: Some(980)
        };

        let result = maybe_coerce_error(err, "test_pool", Some(1000));

        assert!(result.is_err());
        if let Err(RecoverableError::OutOfGas(message, pool_state)) = result {
            assert!(message.contains("Used: 98.00% of gas limit."));
            assert_eq!(pool_state, "test_pool");
        } else {
            panic!("Expected OutOfGas error");
        }
    }

    #[test]
    fn test_maybe_coerce_error_no_gas_limit_info() {
        // Test out-of-gas situation without gas limit info
        let err =
            SimulationError::TransactionError { data: "OutOfGas".to_string(), gas_used: None };

        let result = maybe_coerce_error(err, "test_pool", None);

        assert!(result.is_err());
        if let Err(RecoverableError::OutOfGas(message, pool_state)) = result {
            assert!(message.contains("Original error: OutOfGas"));
            assert_eq!(pool_state, "test_pool");
        } else {
            panic!("Expected OutOfGas error");
        }
    }

    #[test]
    fn test_maybe_coerce_error_storage_error() {
        let err = SimulationError::StorageError("Storage error:".to_string());

        let result = maybe_coerce_error(err, "test_pool", None);

        assert!(result.is_err());
        if let Err(RecoverableError::StorageError(message)) = result {
            assert_eq!(message, "Storage error:");
        } else {
            panic!("Expected storage error");
        }
    }

    #[test]
    fn test_maybe_coerce_error_no_match() {
        // Test for non-revert, non-out-of-gas, non-storage errors
        let err = SimulationError::TransactionError {
            data: "Some other error".to_string(),
            gas_used: None,
        };

        let result = maybe_coerce_error(err, "test_pool", None);

        assert!(result.is_err());
        if let Err(RecoverableError::SolidityError(message)) = result {
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
        let temp_path = temp_file.path().to_str().unwrap();

        // First call to get_contract_bytecode
        let result1 = get_contract_bytecode(temp_path).unwrap();
        assert_eq!(result1, test_data);

        // Second call to get_contract_bytecode (should use cached data)
        // Verify that the cache was used (file is not read twice)
        remove_file(&temp_file).unwrap(); // This removes the temporary file
        let result2 = get_contract_bytecode(temp_path).unwrap();
        assert_eq!(result2, test_data);
    }

    #[test]
    fn test_get_contract_bytecode_error() {
        let result = get_contract_bytecode("non_existent_file.txt");
        assert!(result.is_err());
    }

    #[test]
    fn test_load_swap_abi() {
        let result = load_swap_abi();
        assert!(result.is_ok());

        let abi: Abi = result.expect("Failed to retrieve swap ABI result");
        assert!(!abi.functions.is_empty(), "The swap ABI should contain functions.");
    }

    #[test]
    fn test_load_erc20_abi() {
        let result = load_erc20_abi();
        assert!(result.is_ok());
        let abi: Abi = result.expect("Failed to retrieve ERC20 ABI result");
        assert!(!abi.functions.is_empty(), "The ERC20 ABI should contain functions.");
    }
}
