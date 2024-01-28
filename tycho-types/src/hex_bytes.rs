use crate::serde_primitives::hex_bytes;
use ethers::types::{H160, H256, U256};
use serde::{Deserialize, Serialize};
use std::{
    borrow::Borrow,
    clone::Clone,
    fmt::{Debug, Display, Formatter, LowerHex, Result as FmtResult},
    ops::Deref,
    str::FromStr,
};
use thiserror::Error;

#[cfg(feature = "diesel")]
use diesel::{
    deserialize::{self, FromSql, FromSqlRow},
    expression::AsExpression,
    pg::Pg,
    serialize::{self, ToSql},
    sql_types::Binary,
};

/// Wrapper type around Bytes to deserialize/serialize from/to hex
#[derive(Clone, Default, PartialEq, Eq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
#[cfg_attr(feature = "diesel", derive(AsExpression, FromSqlRow,))]
#[cfg_attr(feature = "diesel", diesel(sql_type = Binary))]
pub struct Bytes(#[serde(with = "hex_bytes")] pub bytes::Bytes);

fn bytes_to_hex(b: &Bytes) -> String {
    hex::encode(b.0.as_ref())
}

impl Debug for Bytes {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "Bytes(0x{})", bytes_to_hex(self))
    }
}

impl Display for Bytes {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "0x{}", bytes_to_hex(self))
    }
}

impl LowerHex for Bytes {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "0x{}", bytes_to_hex(self))
    }
}

impl Bytes {
    /// Return bytes as [`Vec::<u8>`]
    pub fn to_vec(&self) -> Vec<u8> {
        self.as_ref().to_vec()
    }
}

impl Deref for Bytes {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &[u8] {
        self.as_ref()
    }
}

impl AsRef<[u8]> for Bytes {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl Borrow<[u8]> for Bytes {
    fn borrow(&self) -> &[u8] {
        self.as_ref()
    }
}

impl IntoIterator for Bytes {
    type Item = u8;
    type IntoIter = bytes::buf::IntoIter<bytes::Bytes>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a> IntoIterator for &'a Bytes {
    type Item = &'a u8;
    type IntoIter = core::slice::Iter<'a, u8>;

    fn into_iter(self) -> Self::IntoIter {
        self.as_ref().iter()
    }
}

impl From<&[u8]> for Bytes {
    fn from(src: &[u8]) -> Self {
        Self(bytes::Bytes::copy_from_slice(src))
    }
}

impl From<bytes::Bytes> for Bytes {
    fn from(src: bytes::Bytes) -> Self {
        Self(src)
    }
}

impl From<Bytes> for bytes::Bytes {
    fn from(src: Bytes) -> Self {
        src.0
    }
}

impl From<Vec<u8>> for Bytes {
    fn from(src: Vec<u8>) -> Self {
        Self(src.into())
    }
}

impl From<Bytes> for Vec<u8> {
    fn from(value: Bytes) -> Self {
        value.to_vec()
    }
}

impl<const N: usize> From<[u8; N]> for Bytes {
    fn from(src: [u8; N]) -> Self {
        src.to_vec().into()
    }
}

impl<'a, const N: usize> From<&'a [u8; N]> for Bytes {
    fn from(src: &'a [u8; N]) -> Self {
        src.to_vec().into()
    }
}

impl PartialEq<[u8]> for Bytes {
    fn eq(&self, other: &[u8]) -> bool {
        self.as_ref() == other
    }
}

impl PartialEq<Bytes> for [u8] {
    fn eq(&self, other: &Bytes) -> bool {
        *other == *self
    }
}

impl PartialEq<Vec<u8>> for Bytes {
    fn eq(&self, other: &Vec<u8>) -> bool {
        self.as_ref() == &other[..]
    }
}

impl PartialEq<Bytes> for Vec<u8> {
    fn eq(&self, other: &Bytes) -> bool {
        *other == *self
    }
}

impl PartialEq<bytes::Bytes> for Bytes {
    fn eq(&self, other: &bytes::Bytes) -> bool {
        other == self.as_ref()
    }
}

#[derive(Debug, Clone, Error)]
#[error("Failed to parse bytes: {0}")]
pub struct ParseBytesError(String);

impl FromStr for Bytes {
    type Err = ParseBytesError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if let Some(value) = value.strip_prefix("0x") {
            hex::decode(value)
        } else {
            hex::decode(value)
        }
        .map(Into::into)
        .map_err(|e| ParseBytesError(format!("Invalid hex: {e}")))
    }
}

impl From<&str> for Bytes {
    fn from(value: &str) -> Self {
        value.parse().unwrap()
    }
}

#[cfg(feature = "diesel")]
impl ToSql<Binary, Pg> for Bytes {
    fn to_sql<'b>(&'b self, out: &mut serialize::Output<'b, '_, Pg>) -> serialize::Result {
        let bytes_slice: &[u8] = &self.0;
        <&[u8] as ToSql<Binary, Pg>>::to_sql(&bytes_slice, &mut out.reborrow())
    }
}

#[cfg(feature = "diesel")]
impl FromSql<Binary, Pg> for Bytes {
    fn from_sql(
        bytes: <diesel::pg::Pg as diesel::backend::Backend>::RawValue<'_>,
    ) -> deserialize::Result<Self> {
        let byte_vec: Vec<u8> = <Vec<u8> as FromSql<Binary, Pg>>::from_sql(bytes)?;
        Ok(Bytes(bytes::Bytes::from(byte_vec)))
    }
}

macro_rules! impl_from_for_ethers_fixed_hash {
    ($($type:ident),+) => {
        $(impl From<$type> for Bytes {
            fn from(src: $type) -> Self {
                Self(bytes::Bytes::from(src.0.to_vec()))
            }
        }

        impl From<Bytes> for $type {
            fn from(src: Bytes) -> Self {
                let bytes = src.as_ref();
                $type::from_slice(bytes)
            }
        })*
    };
}

impl_from_for_ethers_fixed_hash!(H160, H256);

impl From<U256> for Bytes {
    fn from(src: U256) -> Self {
        let mut buf = [0u8; 32];
        src.to_big_endian(&mut buf);

        Self(bytes::Bytes::from(buf.to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use diesel::{insert_into, table, Insertable, Queryable};
    use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl, SimpleAsyncConnection};

    use super::*;

    #[test]
    fn test_from_bytes() {
        let b = bytes::Bytes::from("0123456789abcdef");
        let wrapped_b = Bytes::from(b.clone());
        let expected = Bytes(b);

        assert_eq!(wrapped_b, expected);
    }

    #[test]
    fn test_from_slice() {
        let arr = [1, 35, 69, 103, 137, 171, 205, 239];
        let b = Bytes::from(&arr);
        let expected = Bytes(bytes::Bytes::from(arr.to_vec()));

        assert_eq!(b, expected);
    }

    #[test]
    fn hex_formatting() {
        let b = Bytes::from(vec![1, 35, 69, 103, 137, 171, 205, 239]);
        let expected = String::from("0x0123456789abcdef");
        assert_eq!(format!("{b:x}"), expected);
        assert_eq!(format!("{b}"), expected);
    }

    #[test]
    fn test_from_str() {
        let b = Bytes::from_str("0x1213");
        assert!(b.is_ok());
        let b = b.unwrap();
        assert_eq!(b.as_ref(), hex::decode("1213").unwrap());

        let b = Bytes::from_str("1213");
        let b = b.unwrap();
        assert_eq!(b.as_ref(), hex::decode("1213").unwrap());
    }

    #[test]
    fn test_debug_formatting() {
        let b = Bytes::from(vec![1, 35, 69, 103, 137, 171, 205, 239]);
        assert_eq!(format!("{b:?}"), "Bytes(0x0123456789abcdef)");
        assert_eq!(format!("{b:#?}"), "Bytes(0x0123456789abcdef)");
    }

    #[test]
    fn test_to_vec() {
        let vec = vec![1, 35, 69, 103, 137, 171, 205, 239];
        let b = Bytes::from(vec.clone());

        assert_eq!(b.to_vec(), vec);
    }

    #[test]
    fn test_vec_partialeq() {
        let vec = vec![1, 35, 69, 103, 137, 171, 205, 239];
        let b = Bytes::from(vec.clone());
        assert_eq!(b, vec);
        assert_eq!(vec, b);

        let wrong_vec = vec![1, 3, 52, 137];
        assert_ne!(b, wrong_vec);
        assert_ne!(wrong_vec, b);
    }

    #[test]
    fn test_bytes_partialeq() {
        let b = bytes::Bytes::from("0123456789abcdef");
        let wrapped_b = Bytes::from(b.clone());
        assert_eq!(wrapped_b, b);

        let wrong_b = bytes::Bytes::from("0123absd");
        assert_ne!(wrong_b, b);
    }

    async fn setup_db() -> AsyncPgConnection {
        let db_url = std::env::var("DATABASE_URL").unwrap();
        let mut conn = AsyncPgConnection::establish(&db_url)
            .await
            .unwrap();
        conn.begin_test_transaction()
            .await
            .unwrap();
        conn
    }

    #[tokio::test]
    async fn test_bytes_db_round_trip() {
        table! {
            bytes_table (id) {
                id -> Int4,
                data -> Binary,
            }
        }

        #[derive(Insertable)]
        #[diesel(table_name = bytes_table)]
        struct NewByteEntry {
            data: Bytes,
        }

        #[derive(Queryable, PartialEq)]
        struct ByteEntry {
            id: i32,
            data: Bytes,
        }

        let mut conn = setup_db().await;
        let example_bytes = Bytes::from_str("0x0123456789abcdef").unwrap();

        conn.batch_execute(
            r"
            CREATE TEMPORARY TABLE bytes_table (
                id SERIAL PRIMARY KEY,
                data BYTEA NOT NULL
            );
        ",
        )
        .await
        .unwrap();

        let new_entry = NewByteEntry { data: example_bytes.clone() };

        let inserted: Vec<ByteEntry> = insert_into(bytes_table::table)
            .values(&new_entry)
            .get_results(&mut conn)
            .await
            .unwrap();

        assert_eq!(inserted[0].data, example_bytes);
    }
}
