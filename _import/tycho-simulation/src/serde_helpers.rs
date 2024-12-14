/// serde functions for handling bytes as hex strings, such as [bytes::Bytes]
pub mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    /// Serialize a byte vec as a hex string with 0x prefix
    pub fn serialize<S, T>(x: T, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        T: AsRef<[u8]>,
    {
        s.serialize_str(&format!("0x{}", hex::encode(x.as_ref())))
    }

    /// Deserialize a hex string into a byte vec
    /// Accepts a hex string with optional 0x prefix
    pub fn deserialize<'de, T, D>(d: D) -> Result<T, D::Error>
    where
        D: Deserializer<'de>,
        T: From<Vec<u8>>,
    {
        let value = String::deserialize(d)?;
        if let Some(value) = value.strip_prefix("0x") {
            hex::decode(value)
        } else {
            hex::decode(&value)
        }
        .map(Into::into)
        .map_err(|e| serde::de::Error::custom(e.to_string()))
    }
}

/// serde functions for handling Option of bytes
pub mod hex_bytes_option {
    use serde::{Deserialize, Deserializer, Serializer};

    /// Serialize a byte vec as a Some hex string with 0x prefix
    pub fn serialize<S, T>(x: &Option<T>, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        T: AsRef<[u8]>,
    {
        if let Some(x) = x {
            s.serialize_str(&format!("0x{}", hex::encode(x.as_ref())))
        } else {
            s.serialize_none()
        }
    }

    /// Deserialize a hex string into a byte vec or None
    /// Accepts a hex string with optional 0x prefix
    pub fn deserialize<'de, T, D>(d: D) -> Result<Option<T>, D::Error>
    where
        D: Deserializer<'de>,
        T: From<Vec<u8>>,
    {
        let value: Option<String> = Option::deserialize(d)?;

        match value {
            Some(val) => {
                let val = if let Some(stripped) = val.strip_prefix("0x") { stripped } else { &val };
                hex::decode(val)
                    .map(Into::into)
                    .map(Some)
                    .map_err(|e| serde::de::Error::custom(e.to_string()))
            }
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};
    use serde_json;

    use super::*;

    #[derive(Debug, Serialize, Deserialize)]
    struct TestStruct {
        #[serde(with = "hex_bytes")]
        bytes: Vec<u8>,

        #[serde(with = "hex_bytes_option")]
        bytes_option: Option<Vec<u8>>,
    }

    #[test]
    fn hex_bytes_serialize_deserialize() {
        let test_struct = TestStruct { bytes: vec![0u8; 10], bytes_option: Some(vec![0u8; 10]) };

        // Serialize to JSON
        let serialized = serde_json::to_string(&test_struct).unwrap();
        assert_eq!(
            serialized,
            "{\"bytes\":\"0x00000000000000000000\",\"bytes_option\":\"0x00000000000000000000\"}"
        );

        // Deserialize from JSON
        let deserialized: TestStruct = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized.bytes, vec![0u8; 10]);
        assert_eq!(deserialized.bytes_option, Some(vec![0u8; 10]));
    }

    #[test]
    fn hex_bytes_option_none() {
        let test_struct = TestStruct { bytes: vec![0u8; 10], bytes_option: None };

        // Serialize to JSON
        let serialized = serde_json::to_string(&test_struct).unwrap();
        assert_eq!(serialized, "{\"bytes\":\"0x00000000000000000000\",\"bytes_option\":null}");

        // Deserialize from JSON
        let deserialized: TestStruct = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized.bytes, vec![0u8; 10]);
        assert_eq!(deserialized.bytes_option, None);
    }
}
