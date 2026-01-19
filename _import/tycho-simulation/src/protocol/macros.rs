/// Macro to implement error-returning Serialize/Deserialize for protocols
/// that cannot be serialized (e.g., due to VM state or external SDK dependencies).
///
/// # Examples
/// ```ignore
/// impl_non_serializable_protocol!(MyProtocolState, "error message");
///
/// ```
#[macro_export]
macro_rules! impl_non_serializable_protocol {
    ($type:ty, $msg:expr) => {
        impl serde::Serialize for $type {
            fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                Err(serde::ser::Error::custom($msg))
            }
        }

        impl<'de> serde::Deserialize<'de> for $type {
            fn deserialize<D>(_deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                Err(serde::de::Error::custom($msg))
            }
        }
    };
}
