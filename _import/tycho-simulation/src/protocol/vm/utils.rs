// TODO: remove skip for clippy dead_code check
#![allow(dead_code)]

use mini_moka::sync::Cache;
use std::{
    fs::File,
    io::Read,
    path::Path,
    sync::{Arc, LazyLock},
};

static BYTECODE_CACHE: LazyLock<Cache<Arc<String>, Vec<u8>>> = LazyLock::new(|| Cache::new(1_000));

fn get_contract_bytecode(path: &str) -> std::io::Result<Vec<u8>> {
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
    use super::*;
    use std::{fs::remove_file, io::Write};
    use tempfile::NamedTempFile;

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
