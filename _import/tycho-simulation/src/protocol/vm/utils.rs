// TODO: remove skip for clippy dead_code check
#![allow(dead_code)]

use mini_moka::sync::Cache;
use reqwest::{blocking::Client, StatusCode};
use serde_json::json;
use std::{
    env,
    fs::File,
    io::Read,
    path::Path,
    sync::{Arc, LazyLock},
    time::Duration,
};

#[derive(Debug)]
pub enum RpcError {
    Http(reqwest::Error),
    Rpc(String, StatusCode),
    InvalidResponse(String),
}

fn exec_rpc_method(
    url: &str,
    method: &str,
    params: Vec<serde_json::Value>,
    timeout: u64,
) -> Result<serde_json::Value, RpcError> {
    let client = Client::new();
    let payload = json!({
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
        "id": 1,
    });

    let response = client
        .post(url)
        .json(&payload)
        .timeout(Duration::from_secs(timeout))
        .send()
        .map_err(RpcError::Http)?;

    if response.status().is_client_error() || response.status().is_server_error() {
        let status = response.status();
        let body = response
            .text()
            .unwrap_or_else(|_| "Unknown error".to_string());
        return Err(RpcError::Rpc(body, status));
    }

    let data: serde_json::Value = response
        .json()
        .map_err(RpcError::Http)?;

    if let Some(result) = data.get("result") {
        Ok(result.clone())
    } else if let Some(error) = data.get("error") {
        Err(RpcError::InvalidResponse(format!(
            "RPC failed to call {} with Error: {}",
            method, error
        )))
    } else {
        Ok(serde_json::Value::Null)
    }
}

pub fn get_code_for_address(
    address: &str,
    connection_string: Option<String>,
) -> Result<Option<Vec<u8>>, RpcError> {
    // Get the connection string, defaulting to the RPC_URL environment variable
    let connection_string = connection_string.or_else(|| env::var("RPC_URL").ok());

    let connection_string = match connection_string {
        Some(url) => url,
        None => {
            return Err(RpcError::InvalidResponse(
                "RPC_URL environment variable is not set".to_string(),
            ))
        }
    };

    let method = "eth_getCode";
    let params = vec![json!(address), json!("latest")];

    match exec_rpc_method(&connection_string, method, params, 240) {
        Ok(code) => {
            if let Some(code_str) = code.as_str() {
                let code_bytes = hex::decode(&code_str[2..]).map_err(|_| {
                    RpcError::InvalidResponse(format!(
                        "Failed to decode hex string for address {}",
                        address
                    ))
                })?;
                Ok(Some(code_bytes))
            } else {
                Ok(None)
            }
        }
        Err(e) => {
            println!("Error fetching code for address {}: {:?}", address, e);
            Err(e)
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

#[cfg(test)]
mod tests {
    use dotenv::dotenv;
    use std::{fs::remove_file, io::Write};
    use tempfile::NamedTempFile;

    use super::*;

    #[test]
    #[cfg_attr(not(feature = "network_tests"), ignore)]
    fn test_get_code_for_address() {
        let rpc_url = env::var("ETH_RPC_URL").unwrap_or_else(|_| {
            dotenv().expect("Missing .env file");
            env::var("ETH_RPC_URL").expect("Missing ETH_RPC_URL in .env file")
        });

        let address = "0x88e6A0c2dDD26FEEb64F039a2c41296FcB3f5640";
        let result = get_code_for_address(address, Some(rpc_url));

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
}
