use std::str::FromStr;

use num_bigint::BigUint;
use serde::{self, Deserialize, Deserializer, Serializer};

fn serialize_biguint<S>(value: &BigUint, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&value.to_string())
}

fn deserialize_biguint<'de, D>(deserializer: D) -> Result<BigUint, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    BigUint::from_str(&s).map_err(serde::de::Error::custom)
}

pub mod biguint_string {
    use super::*;

    pub fn serialize<S>(value: &BigUint, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serialize_biguint(value, serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<BigUint, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_biguint(deserializer)
    }
}

pub mod biguint_string_option {
    use super::*;

    pub fn serialize<S>(value: &Option<BigUint>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(v) => serialize_biguint(v, serializer),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<BigUint>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Option::<String>::deserialize(deserializer)?
            .map(|s| BigUint::from_str(&s).map_err(serde::de::Error::custom))
            .transpose()
    }
}
