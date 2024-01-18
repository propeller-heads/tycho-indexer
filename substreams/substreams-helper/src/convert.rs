use substreams::scalar::BigInt;
use substreams_ethereum::pb::eth::v2::BigInt as sfBigInt;

pub trait BigIntDeserializeExt {
    fn deserialize(&self) -> BigInt;
}

impl BigIntDeserializeExt for Option<sfBigInt> {
    fn deserialize(&self) -> BigInt {
        match self {
            Some(b) => return b.deserialize(),
            None => return BigInt::from(0),
        }
    }
}

impl BigIntDeserializeExt for sfBigInt {
    fn deserialize(&self) -> BigInt {
        BigInt::from_unsigned_bytes_be(self.bytes.as_slice())
    }
}

pub(crate) trait BigIntSerializeExt {
    fn serialize(&self) -> sfBigInt;
}

impl BigIntSerializeExt for BigInt {
    fn serialize(&self) -> sfBigInt {
        sfBigInt {
            bytes: self.to_bytes_be().1,
        }
    }
}
