use hex::FromHexError;

fn decode_hex_with_prefix(val: &str) -> Result<Vec<u8>, FromHexError> {
    let mut stripped: String =
        if let Some(stripped) = val.strip_prefix("0x") { stripped } else { val }.into();

    // Check if the length of the string is odd
    if !stripped.len().is_multiple_of(2) {
        // If it's odd, prepend a zero
        stripped.insert(0, '0');
    }

    hex::decode(&stripped)
}

/// serde functions for handling bytes as hex strings, such as [bytes::Bytes]
pub mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    use super::decode_hex_with_prefix;

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
        decode_hex_with_prefix(&value)
            .map(Into::into)
            .map_err(|e| serde::de::Error::custom(e.to_string()))
    }
}

/// serde functions for handling Option of bytes
pub mod hex_bytes_option {
    use serde::{Deserialize, Deserializer, Serializer};

    use super::decode_hex_with_prefix;

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
            Some(val) => decode_hex_with_prefix(&val)
                .map(Into::into)
                .map(Some)
                .map_err(|e| serde::de::Error::custom(e.to_string())),
            None => Ok(None),
        }
    }
}

/// serde functions for handling HashMap with a bytes key
pub mod hex_hashmap_key {
    use std::collections::HashMap;

    use serde::{de, ser::SerializeMap, Deserialize, Deserializer, Serialize, Serializer};

    use super::decode_hex_with_prefix;
    use crate::Bytes;

    pub fn serialize<S, V>(x: &HashMap<Bytes, V>, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        V: Serialize,
    {
        let mut map = s.serialize_map(Some(x.len()))?;
        for (k, v) in x.iter() {
            map.serialize_entry(&format!("{k:#x}"), v)?;
        }
        map.end()
    }

    pub fn deserialize<'de, V, D>(d: D) -> Result<HashMap<Bytes, V>, D::Error>
    where
        D: Deserializer<'de>,
        V: Deserialize<'de>,
    {
        let interim = HashMap::<String, V>::deserialize(d)?;

        interim
            .into_iter()
            .map(|(k, v)| {
                let k = decode_hex_with_prefix(&k).map_err(|e| de::Error::custom(e.to_string()))?;
                Ok((Bytes::from(k), v))
            })
            .collect::<Result<HashMap<_, _>, _>>()
    }
}

/// serde functions for handling Vec of Bytes as hex strings
pub mod hex_bytes_vec {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use super::decode_hex_with_prefix;

    /// Serialize Vec<Vec<u8>> as a list of hex strings with 0x prefix
    pub fn serialize<S>(list: &[Vec<u8>], s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Each element to hex string
        let hex_strings: Vec<String> = list
            .iter()
            .map(|x| format!("0x{}", hex::encode(x)))
            .collect();
        hex_strings.serialize(s)
    }

    /// Deserialize a list of hex strings into Vec<Vec<u8>>
    pub fn deserialize<'de, D>(d: D) -> Result<Vec<Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let hex_strings = Vec::<String>::deserialize(d)?;
        hex_strings
            .into_iter()
            .map(|s| {
                decode_hex_with_prefix(&s).map_err(|e| serde::de::Error::custom(e.to_string()))
            })
            .collect()
    }
}

/// serde functions for handling HashMap with bytes value
pub mod hex_hashmap_value {
    use std::collections::HashMap;

    use serde::{de, ser::SerializeMap, Deserialize, Deserializer, Serialize, Serializer};

    use super::decode_hex_with_prefix;
    use crate::Bytes;

    pub fn serialize<S, K>(x: &HashMap<K, Bytes>, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        K: Serialize,
    {
        let mut map = s.serialize_map(Some(x.len()))?;
        for (k, v) in x.iter() {
            map.serialize_entry(k, &format!("{v:#x}"))?;
        }
        map.end()
    }

    pub fn deserialize<'de, K, D>(d: D) -> Result<HashMap<K, Bytes>, D::Error>
    where
        D: Deserializer<'de>,
        K: Deserialize<'de> + Eq + std::hash::Hash, // HashMap key trait bounds
    {
        let interim = HashMap::<K, String>::deserialize(d)?;

        interim
            .into_iter()
            .map(|(k, v)| {
                let v = decode_hex_with_prefix(&v).map_err(|e| de::Error::custom(e.to_string()))?;
                Ok((k, Bytes::from(v)))
            })
            .collect::<Result<HashMap<_, _>, _>>()
    }
}

/// serde functions for handling HashMap with a bytes key and value
pub mod hex_hashmap_key_value {
    use std::collections::HashMap;

    use serde::{de, ser::SerializeMap, Deserialize, Deserializer, Serializer};

    use super::decode_hex_with_prefix;
    use crate::Bytes;

    pub fn serialize<S>(x: &HashMap<Bytes, Bytes>, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = s.serialize_map(Some(x.len()))?;
        for (k, v) in x.iter() {
            map.serialize_entry(&format!("{k:#x}"), &format!("{v:#x}"))?;
        }
        map.end()
    }

    pub fn deserialize<'de, D>(d: D) -> Result<HashMap<Bytes, Bytes>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let interim = HashMap::<String, String>::deserialize(d)?;
        interim
            .into_iter()
            .map(|(k, v)| {
                let k = decode_hex_with_prefix(&k).map_err(|e| de::Error::custom(e.to_string()))?;
                let v = decode_hex_with_prefix(&v).map_err(|e| de::Error::custom(e.to_string()))?;
                Ok((k.into(), v.into()))
            })
            .collect::<Result<HashMap<_, _>, _>>()
    }
}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};

    use super::*;

    #[derive(Debug, Serialize, Deserialize)]
    struct TestStruct {
        #[serde(with = "hex_bytes")]
        bytes: Vec<u8>,

        #[serde(with = "hex_bytes_option")]
        bytes_option: Option<Vec<u8>>,

        #[serde(with = "hex_bytes_vec")]
        bytes_vec: Vec<Vec<u8>>,
    }

    #[test]
    fn hex_bytes_serialize_deserialize() {
        let test_struct = TestStruct {
            bytes: vec![0u8; 10],
            bytes_option: Some(vec![0u8; 10]),
            bytes_vec: vec![vec![0, 1, 2, 3], vec![0xFF, 0xAB]],
        };

        // Serialize to JSON
        let serialized = serde_json::to_string(&test_struct).unwrap();
        assert_eq!(
            serialized,
            "{\"bytes\":\"0x00000000000000000000\",\"bytes_option\":\"0x00000000000000000000\",\"bytes_vec\":[\"0x00010203\",\"0xffab\"]}"
        );

        // Deserialize from JSON
        let deserialized: TestStruct = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized.bytes, vec![0u8; 10]);
        assert_eq!(deserialized.bytes_option, Some(vec![0u8; 10]));
        assert_eq!(deserialized.bytes_vec, vec![vec![0, 1, 2, 3], vec![0xFF, 0xAB]]);
    }

    #[test]
    fn hex_bytes_option_none() {
        let test_struct =
            TestStruct { bytes: vec![0u8; 10], bytes_option: None, bytes_vec: vec![] };

        // Serialize to JSON
        let serialized = serde_json::to_string(&test_struct).unwrap();
        assert_eq!(
            serialized,
            "{\"bytes\":\"0x00000000000000000000\",\"bytes_option\":null,\"bytes_vec\":[]}"
        );

        // Deserialize from JSON
        let deserialized: TestStruct = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized.bytes, vec![0u8; 10]);
        assert_eq!(deserialized.bytes_option, None);
    }
}
