use std::convert::TryInto;
use std::error::Error;
use std::fmt;
use std::fmt::Display;

#[derive(Debug, Clone, PartialEq)]
pub struct DecodeError {
    pub msg: String,
}

impl DecodeError {
    fn new(msg: String) -> DecodeError {
        DecodeError { msg }
    }
}

impl Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "invalid decoding")
    }
}

impl Error for DecodeError {}

pub fn read_uint32(input: &[u8]) -> Result<u32, DecodeError> {
    if input.len() != 32 {
        return Err(DecodeError::new(format!(
            "uint32 invalid length: {}",
            input.len()
        )));
    }
    let as_array: [u8; 4] = input[28..32].try_into().unwrap();
    Ok(u32::from_be_bytes(as_array))
}

pub fn read_string_from_bytes(input: &[u8]) -> String {
    // we have to check if we have a valid utf8 representation and if we do
    // we return the value if not we return a DecodeError
    if let Some(last) = input.to_vec().iter().rev().position(|&pos| pos != 0) {
        return String::from_utf8_lossy(&input[0..input.len() - last]).to_string();
    }

    // use case when all the bytes are set to 0
    "".to_string()
}

pub fn read_string(input: &[u8]) -> Result<String, DecodeError> {
    // first 32 bytes are the offset of where to read the len the next 32 bytes is
    // the len of how many bytes we are going to read the rest is the bytes to read,
    // respective of the len and ethereum pads with 0s at the end
    if input.len() < 64 {
        return Err(DecodeError::new(format!(
            "string invalid length: {}",
            input.len()
        )));
    }

    let offset = read_uint32(&input[0..32])?;
    if offset != 32 {
        return Err(DecodeError::new(format!(
            "invalid string uint32 value: {}",
            offset
        )));
    };

    let size_to_read = read_uint32(&input[offset as usize..(offset + 32) as usize])?;
    if size_to_read == 0 {
        return Ok("".to_string());
    }

    let end: usize = (offset + 32 + size_to_read) as usize;
    Ok(String::from_utf8_lossy(&input[(offset + 32) as usize..end]).to_string())
}

/// Returns the timestamp for the start of the most recent day
pub(crate) fn get_latest_day(timestamp: i64) -> i64 {
    const SECONDS_IN_DAY: i64 = 86400_i64;
    timestamp / SECONDS_IN_DAY
}

/// Returns the timestamp for the start of the most recent hour
pub(crate) fn get_latest_hour(timestamp: i64) -> i64 {
    const SECONDS_IN_HOUR: i64 = 3600_i64;
    timestamp / SECONDS_IN_HOUR
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_token_name_32_bytes() {
        let expected_name = "Maker";
        let name_bytes: &[u8; 32] = &[
            77, 97, 107, 101, 114, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0,
        ];

        assert_eq!(expected_name, read_string_from_bytes(name_bytes));
    }

    #[test]
    fn test_read_token_symbol_32_bytes() {
        let expected_name = "MKR";
        let name_bytes: &[u8; 32] = &[
            77, 75, 82, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0,
        ];

        assert_eq!(expected_name, read_string_from_bytes(name_bytes));
    }

    #[test]
    fn test_read_string_from_bytes32_all_zeros() {
        let bytes: &[u8; 32] = &[
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ];

        assert_eq!("".to_string(), read_string_from_bytes(bytes));
    }

    #[test]
    fn test_read_string_from_bytes64_all_zeros() {
        let bytes: &[u8; 64] = &[
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0,
        ];

        assert_eq!("".to_string(), read_string_from_bytes(bytes));
    }

    #[test]
    fn test_read_string_from_bytes32_empty_bytes() {
        let bytes: &[u8; 0] = &[];

        assert_eq!("".to_string(), read_string_from_bytes(bytes));
    }

    #[test]
    fn test_read_token_symbol_64_bytes() {
        let expected_symbol = "".to_string();
        let symbol_bytes: &[u8; 64] = &[
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0,
        ];

        assert_eq!(expected_symbol, read_string(symbol_bytes).unwrap());
    }

    #[test]
    fn test_read_token_name_more_than_64_bytes() {
        let expected_name = "USD Coin";
        let name_bytes: &[u8; 96] = &[
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 8, 85, 83, 68, 32, 67, 111, 105, 110, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];

        assert_eq!(expected_name, read_string(name_bytes).unwrap())
    }

    #[test]
    fn test_read_token_symbol_more_than_64_bytes() {
        let expected_name = "USDC";
        let name_bytes: &[u8; 96] = &[
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 4, 85, 83, 68, 67, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];

        assert_eq!(expected_name, read_string(name_bytes).unwrap())
    }
}
