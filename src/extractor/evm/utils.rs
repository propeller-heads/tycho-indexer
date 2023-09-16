use ethers::types::{H160, H256, U256};

/// Decoding trait with nice contextual error messages
pub trait TryDecode: Sized {
    /// Tries to decode a literal value
    ///
    /// In case it is not successfull returns a generic `Err(String)` with an error message
    /// mentioning the target type, as well as the passed type context. This provides a more
    /// detailed error message compared to ethers-rs "Invalid data" message.
    ///
    /// The error is puprosefully kept as string so it can be casted to a more appropriate type on
    /// the caller.
    ///
    /// ## Example
    /// ```
    /// let data = [0;32].to_vec();
    /// let balance = U256::try_decode(data.as_slice(), "balance").unwrap();
    /// ```
    fn try_decode(v: &[u8], type_context: &str) -> Result<Self, String>;
}

impl TryDecode for H160 {
    fn try_decode(v: &[u8], type_context: &str) -> Result<Self, String> {
        if v.len() != 20 {
            return Err(format!("H160: Invalid {} format: 0x{}", type_context, hex::encode(v)))
        }
        // This is much simpler compared to AbiDecode::decode, the latter will do
        // some more complex parsing and required all input to be 32 bytes vs
        // from_slice simply operates on the underlying bytes directly.
        Ok(H160::from_slice(v))
    }
}

impl TryDecode for H256 {
    fn try_decode(v: &[u8], type_context: &str) -> Result<Self, String> {
        if v.len() != 32 {
            return Err(format!("H256: Invalid {} format: 0x{}", type_context, hex::encode(v)))
        }
        Ok(H256::from_slice(v))
    }
}

impl TryDecode for U256 {
    fn try_decode(v: &[u8], type_context: &str) -> Result<Self, String> {
        if v.len() != 32 {
            return Err(format!("U256: Invalid {} format: 0x{}", type_context, hex::encode(v)))
        }
        Ok(U256::from_big_endian(v))
    }
}

// Parse an address potentially zero left padding the value
pub fn pad_and_parse_h160(v: &[u8]) -> Result<H160, String> {
    if v.len() > 20 {
        return Err(format!(
            "H160: too long; expected 20, got {}, val: 0x{}",
            v.len(),
            hex::encode(v)
        ))
    }

    let mut data: [u8; 20] = [0; 20];
    let start_index = 20 - v.len();
    data[start_index..].copy_from_slice(v);

    Ok(H160::from(data))
}

/// Parses a tuple of U256 representing an slot entry
///
/// In case the value is None it will assume a value of zero.
pub fn parse_u256_slot_entry(
    raw_key: &[u8],
    raw_val: Option<&[u8]>,
) -> Result<(U256, U256), String> {
    let v =
        if let Some(val) = raw_val { U256::try_decode(val, "slot value")? } else { U256::zero() };

    let k = U256::try_decode(raw_key, "slot key")?;
    Ok((k, v))
}

// Parse a 32 bytes value potentially zero left padding the value
pub fn pad_and_parse_32bytes<T>(v: &[u8]) -> Result<T, String>
where
    T: From<[u8; 32]>,
{
    if v.len() > 32 {
        return Err(format!(
            "Byte slice too long: Expected 32, got {}, val: 0x{}",
            v.len(),
            hex::encode(v)
        ))
    }
    let mut data: [u8; 32] = [0; 32];
    let start_index = 32 - v.len();
    data[start_index..].copy_from_slice(v);

    Ok(T::from(data))
}

#[cfg(test)]
mod test {
    use super::*;
    use ethers::types::H256;
    use rstest::rstest;

    #[rstest]
    #[case::ok([0;20].to_vec(), Ok(H160::zero()))]
    #[case::err([0;1].to_vec(), Err("H160: Invalid address format: 0x00".to_owned()))]
    fn test_parse_h160(#[case] inp: Vec<u8>, #[case] exp: Result<H160, String>) {
        assert_eq!(H160::try_decode(&inp, "address"), exp);
    }

    #[rstest]
    #[case::ok([0;20].to_vec(), Ok(H160::zero()))]
    #[case::pad([0;1].to_vec(), Ok(H160::zero()))]
    #[case::err([0;21].to_vec(), Err("H160: too long; expected 20, got 21, val: 0x000000000000000000000000000000000000000000".to_owned()))]
    fn test_pad_and_parse_h160(#[case] inp: Vec<u8>, #[case] exp: Result<H160, String>) {
        assert_eq!(pad_and_parse_h160(&inp), exp);
    }

    #[rstest]
    #[case::ok([0;32].to_vec(), Some([0;32].to_vec()), Ok((U256::from(0), U256::from(0))))]
    #[case::ok_none_val([0;32].to_vec(), None, Ok((U256::from(0), U256::from(0))))]
    #[case::key_bad([0;1].to_vec(), Some([0;32].to_vec()), Err("U256: Invalid slot key format: 0x00".to_owned()))]
    #[case::val_bad([0;32].to_vec(), Some([0;1].to_vec()), Err("U256: Invalid slot value format: 0x00".to_owned()))]
    fn test_parse_u256_slot_entry(
        #[case] key: Vec<u8>,
        #[case] val: Option<Vec<u8>>,
        #[case] exp: Result<(U256, U256), String>,
    ) {
        assert_eq!(parse_u256_slot_entry(&key, val.as_deref()), exp);
    }

    #[rstest]
    #[case::ok([0;32].to_vec(), Ok(H256::zero()))]
    #[case::pad([0;1].to_vec(), Ok(H256::zero()))]
    #[case::err([0;33].to_vec(), Err("Byte slice too long: Expected 32, got 33, val: 0x000000000000000000000000000000000000000000000000000000000000000000".to_owned()))]
    fn test_pad_and_parse_bytes32(#[case] inp: Vec<u8>, #[case] exp: Result<H256, String>) {
        assert_eq!(pad_and_parse_32bytes(&inp), exp);
    }
}
