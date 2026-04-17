use anyhow::{anyhow, Result};
use substreams::scalar::BigInt;
use tycho_substreams::models::{Attribute, ChangeType};

pub fn attribute_with_bigint(name: &str, value: &BigInt, change: ChangeType) -> Attribute {
    Attribute { name: name.to_string(), value: value.to_signed_bytes_be(), change: change.into() }
}

pub fn bigint_from_hex(value: &str) -> Result<BigInt> {
    let value = value
        .strip_prefix("0x")
        .unwrap_or(value);
    let bytes = hex::decode(value).map_err(|e| anyhow!("Failed to decode hex value: {e}"))?;
    Ok(BigInt::from_unsigned_bytes_be(&bytes))
}

pub fn bigint_from_store_value(value: &[u8]) -> Result<BigInt> {
    if value.is_empty() {
        return Ok(BigInt::from(0));
    }

    let value_str =
        std::str::from_utf8(value).map_err(|e| anyhow!("Invalid UTF-8 store value: {e}"))?;
    let parsed = num_bigint::BigInt::parse_bytes(value_str.as_bytes(), 10)
        .ok_or_else(|| anyhow!("Failed to parse decimal store value: {value_str}"))?;

    Ok(BigInt::from(parsed))
}

pub fn decode_packed_uint128_pair(raw: &[u8]) -> (BigInt, BigInt) {
    let low = read_bytes(raw, 0, 16);
    let high = read_bytes(raw, 16, 16);
    (BigInt::from_unsigned_bytes_be(low), BigInt::from_unsigned_bytes_be(high))
}

pub fn read_bytes(buf: &[u8], offset: usize, number_of_bytes: usize) -> &[u8] {
    let buf_length = buf.len();
    if buf_length < number_of_bytes {
        panic!(
            "attempting to read {number_of_bytes} bytes in buffer size {buf_size}",
            buf_size = buf.len()
        )
    }

    if offset > (buf_length - 1) {
        panic!("offset {offset} exceeds buffer size {buf_size}", buf_size = buf.len())
    }

    let end = buf_length - 1 - offset;
    let start = (end + 1)
        .checked_sub(number_of_bytes)
        .unwrap_or_else(|| {
            panic!(
                "number of bytes {number_of_bytes} with offset {offset} exceeds buffer size \
{buf_size}",
                buf_size = buf.len()
            )
        });

    &buf[start..=end]
}

#[cfg(test)]
mod tests {
    use super::{decode_packed_uint128_pair, read_bytes};
    use substreams::hex;

    #[test]
    fn read_low_and_high_uint128_halves() {
        let raw = hex!("00000000000000000000000000065004000000000000002303b296dd9f3631db");
        let (low, high) = decode_packed_uint128_pair(&raw);

        assert_eq!(
            low,
            substreams::scalar::BigInt::from_unsigned_bytes_be(&hex!(
                "000000000000002303b296dd9f3631db"
            ))
        );
        assert_eq!(
            high,
            substreams::scalar::BigInt::from_unsigned_bytes_be(&hex!(
                "00000000000000000000000000065004"
            ))
        );
    }

    #[test]
    fn read_bytes_from_low_side() {
        let raw = hex!("aabbccdd");
        assert_eq!(read_bytes(&raw, 0, 2), hex!("ccdd"));
        assert_eq!(read_bytes(&raw, 2, 2), hex!("aabb"));
    }
}
