use crate::storage::*;

#[cfg(test)]

mod abi_encodeable {
    use std::str::FromStr;

    use ethabi::Address;
    use substreams::scalar::BigInt;

    use super::*;
    use crate::hex::Hexable;

    #[test]
    fn test_abi_token() {
        struct TT<'a> {
            name: &'static str,
            abi_encodeable: Box<dyn ABIEncodeable + 'a>,
            encoded: &'static str,
        }

        let tests: Vec<TT> = vec![
            TT {
                name: "Address impl",
                abi_encodeable: Box::new(
                    Address::from_str("0xca0e8f557ea98f950029a41d74f16dd76648b1f1").unwrap(),
                ),
                encoded: "0x000000000000000000000000ca0e8f557ea98f950029a41d74f16dd76648b1f1",
            },
            TT {
                name: "BigInt impl",
                abi_encodeable: Box::new(BigInt::from(54)),
                encoded: "0x0000000000000000000000000000000000000000000000000000000000000036",
            },
        ];

        for tt in tests {
            assert_eq!(
                ethabi::encode(&[tt.abi_encodeable.abi_token()]).to_hex(),
                tt.encoded,
                "Failed at test with name: {}",
                tt.name,
            );
        }
    }

    #[test]
    fn test_abi_decode_big_int() {
        {
            let encoded =
                hex::decode("0000000000000000000000000000000000000000000000000000000000000036")
                    .unwrap();
            assert_eq!(
                BigInt::abi_decode(encoded.as_slice()).unwrap(),
                BigInt::from(54),
                "Decode Normal Number"
            );
        }

        {
            let encoded =
                hex::decode("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
                    .unwrap();
            assert_eq!(
                    BigInt::abi_decode(encoded.as_slice()).unwrap(),
                    BigInt::from_str("115792089237316195423570985008687907853269984665640564039457584007913129639935").unwrap(),
                    "Decode Max Uint256"
                );
        }
    }

    #[test]
    fn test_abi_decode_address() {
        let encoded =
            hex::decode("000000000000000000000000ca0e8f557ea98f950029a41d74f16dd76648b1f1")
                .unwrap();
        assert_eq!(
            Address::abi_decode(encoded.as_slice()).unwrap(),
            Address::from_str("0xca0e8f557ea98f950029a41d74f16dd76648b1f1").unwrap(),
            "Decode Padded Address",
        )
    }
}

mod storage {
    use std::str::FromStr;
    use Default;

    use ethabi::Address;
    use substreams::{scalar::BigInt, Hex};

    use super::*;
    use crate::hex::Hexable;

    #[test]
    fn test_mapping_address_key() {
        let m = Mapping {
            slot: BigInt::from(12),
        };
        let preimage = Hex::decode("0000000000000000000000001a13f4ca1d028320a707d99520abfefca3998b7f000000000000000000000000000000000000000000000000000000000000000c").unwrap();
        let encoded = "0x9e3150b55a3c0fe6929063dde4bd380cd1b3bd4bd4fca20b85691cb17e2880da";
        let key = Address::from_str("0x1a13f4ca1d028320a707d99520abfefca3998b7f").unwrap();

        assert_eq!(m.preimage(&key).to_hex(), preimage.to_hex());
        assert_eq!(m.storage_key(&key).to_hex(), encoded);
        assert_eq!(
            m.key_from_preimage::<Address>(preimage).unwrap().to_hex(),
            key.to_hex()
        );
    }

    #[test]
    fn test_mapping_big_int_key() {
        let m = Mapping {
            slot: BigInt::from(12),
        };
        let preimage = Hex::decode("000000000000000000000000000000000000000000000000000000000000007f000000000000000000000000000000000000000000000000000000000000000c").unwrap();
        let encoded = "0x20e322d575d78a86a3761da49565fbbf1fcb4f0a86011c98ac148d9ee6b9c682";
        let key = BigInt::from(127);

        assert_eq!(m.preimage(&key).to_hex(), preimage.to_hex());
        assert_eq!(m.storage_key(&key).to_hex(), encoded);
        assert_eq!(m.key_from_preimage::<BigInt>(preimage).unwrap(), key);
    }

    #[test]
    fn test_array_storage_key_at_index() {
        let slot = BigInt::abi_decode(
            Hex::decode("da475eaaa4acc4d88403115cf1ef7280bb115c584f5611300cb1c87775af645b")
                .unwrap()
                .as_slice(),
        )
        .unwrap();

        let a = Array::new(slot, Uint256::default());

        let key0 = "0x41dccaadfb4febf18991ec018954ef6d813a2e7099e85e7a0007d1fba7dc080c";
        let key1 = "0x41dccaadfb4febf18991ec018954ef6d813a2e7099e85e7a0007d1fba7dc080d";
        let key2 = "0x41dccaadfb4febf18991ec018954ef6d813a2e7099e85e7a0007d1fba7dc080e";
        let key3 = "0x41dccaadfb4febf18991ec018954ef6d813a2e7099e85e7a0007d1fba7dc080f";
        let key5 = "0x41dccaadfb4febf18991ec018954ef6d813a2e7099e85e7a0007d1fba7dc0811";
        let key10 = "0x41dccaadfb4febf18991ec018954ef6d813a2e7099e85e7a0007d1fba7dc0816";

        assert_eq!(a.storage_key_at_index(BigInt::from(0)).to_hex(), key0);
        assert_eq!(a.storage_key_at_index(BigInt::from(1)).to_hex(), key1);
        assert_eq!(a.storage_key_at_index(BigInt::from(2)).to_hex(), key2);
        assert_eq!(a.storage_key_at_index(BigInt::from(3)).to_hex(), key3);
        assert_eq!(a.storage_key_at_index(BigInt::from(5)).to_hex(), key5);
        assert_eq!(a.storage_key_at_index(BigInt::from(10)).to_hex(), key10);
    }
}

mod storage_layout {
    use std::str::FromStr;

    use substreams::{scalar::BigInt, Hex};

    use super::*;

    #[test]
    fn test_uint256() {
        let mut u = Uint256::default();

        let storage_val =
            Hex::decode("000000000000000000000000637e5ed300000000000008e97b4a884b8bf0b00b")
                .unwrap();
        u.decode(vec![storage_val], None).unwrap();

        assert_eq!(u.size(), SLOT_SIZE);
        assert_eq!(
            u.value,
            BigInt::from_str("568008240561031977196115359908856468935134982155").unwrap(),
        );
    }

    #[test]
    fn test_uint128() {
        let mut u = Uint128::default();

        let storage_val =
            vec![
                Hex::decode("000000000000000000000000637e5ed300000000000008e97b4a884b8bf0b00b")
                    .unwrap(),
            ];

        u.decode(storage_val.clone(), None).unwrap();
        assert_eq!(
            u.value,
            BigInt::from_str("42085907295204480692235").unwrap(),
        );

        u.decode(storage_val, Some(16)).unwrap();
        assert_eq!(u.value, BigInt::from_str("1669226195").unwrap(),);

        assert_eq!(u.size(), 16);
    }

    #[test]
    fn test_struct_simple() {
        let mut s = EvmStruct::new(BigInt::zero());
        s.add_field("balance", Uint128::default());
        s.add_field("timestamp", Uint128::default());

        let storage_val =
            Hex::decode("000000000000000000000000637e5ed300000000000008e97b4a884b8bf0b00b")
                .unwrap();

        s.decode(vec![storage_val], None).unwrap();

        let balance = s.get::<Uint128>("balance");
        let timestamp = s.get::<Uint128>("timestamp");

        assert_eq!(s.size(), SLOT_SIZE);
        assert_eq!(
            balance.value,
            BigInt::from_str("42085907295204480692235").unwrap()
        );
        assert_eq!(timestamp.value, BigInt::from_str("1669226195").unwrap());
    }

    #[test]
    fn test_struct_multislot() {
        let mut s = EvmStruct::new(BigInt::zero());
        s.add_field("balance", Uint128::default());
        s.add_field("timestamp", Uint128::default());
        s.add_field("balance2", Uint128::default());
        s.add_field("some_uin256", Uint256::default());

        let storage_val =
            Hex::decode("000000000000000000000000637e5ed300000000000008e97b4a884b8bf0b00b")
                .unwrap();
        let slots = vec![storage_val.clone(), storage_val.clone(), storage_val];

        s.decode(slots, None).unwrap();

        let balance = s.get::<Uint128>("balance");
        let ts = s.get::<Uint128>("timestamp");
        let balance2 = s.get::<Uint128>("balance2");
        let u256 = s.get::<Uint256>("some_uin256");

        assert_eq!(s.size(), SLOT_SIZE * 3);
        assert_eq!(
            balance.value,
            BigInt::from_str("42085907295204480692235").unwrap()
        );
        assert_eq!(ts.value, BigInt::from_str("1669226195").unwrap());
        assert_eq!(
            balance2.value,
            BigInt::from_str("42085907295204480692235").unwrap()
        );
        assert_eq!(
            u256.value,
            BigInt::from_str("568008240561031977196115359908856468935134982155").unwrap(),
        );
    }

    #[test]
    fn test_struct_multislot_with_big_gaps() {
        let mut s = EvmStruct::new(BigInt::zero());
        s.add_field("u128_1", Uint128::default());
        s.add_field("u256_2", Uint256::default());
        s.add_field("u128_3", Uint128::default());
        s.add_field("u256_4", Uint256::default());
        s.add_field("u128_5", Uint128::default());

        let slots = vec![
            Hex::decode("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap(),
            Hex::decode("0000000000000000000000000000000000000000000000000000000000000002")
                .unwrap(),
            Hex::decode("0000000000000000000000000000000000000000000000000000000000000003")
                .unwrap(),
            Hex::decode("0000000000000000000000000000000000000000000000000000000000000004")
                .unwrap(),
            Hex::decode("0000000000000000000000000000000000000000000000000000000000000005")
                .unwrap(),
        ];

        s.decode(slots, None).unwrap();

        let u1 = s.get::<Uint128>("u128_1");
        let u2 = s.get::<Uint256>("u256_2");
        let u3 = s.get::<Uint128>("u128_3");
        let u4 = s.get::<Uint256>("u256_4");
        let u5 = s.get::<Uint128>("u128_5");

        assert_eq!(s.size(), SLOT_SIZE * 5);
        assert_eq!(u1.value, BigInt::from(1));
        assert_eq!(u2.value, BigInt::from(2));
        assert_eq!(u3.value, BigInt::from(3));
        assert_eq!(u4.value, BigInt::from(4));
        assert_eq!(u5.value, BigInt::from(5));
    }
}
