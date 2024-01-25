use ethabi::ethereum_types::Address;

use substreams::store::{
    StoreGet, StoreGetBigDecimal, StoreGetBigInt, StoreGetInt64, StoreGetProto, StoreGetRaw,
    StoreGetString,
};

use crate::hex::Hexable;

/// HasAddresser is a trait that a few functionalities in this crate depend on.
/// Every time we need to filter something by address (events emmited by a set of addresses,
/// storage changes occurring on certain contracts, etc) you'll likely need
/// to provide a HasAddresser.
///
/// HasAddresser has been implemented already for all substreams::store's for convenience.
/// So if you know a given store module contains the list of addresses you want to filter by
/// you can pass it directly as a HasAddresser. In this case, the addresses need to be the store key
/// hex encoded as a string including the leading 0x. The value of the store is ignored.
pub trait HasAddresser {
    fn has_address(&self, key: Address) -> bool;
}

impl HasAddresser for Vec<Address> {
    fn has_address(&self, key: Address) -> bool {
        self.contains(&key)
    }
}

impl HasAddresser for StoreGetString {
    fn has_address(&self, key: Address) -> bool {
        self.get_last(key.to_hex()).is_some()
    }
}

impl<T: Default + prost::Message> HasAddresser for StoreGetProto<T> {
    fn has_address(&self, key: Address) -> bool {
        self.get_last(key.to_hex()).is_some()
    }
}

impl HasAddresser for StoreGetRaw {
    fn has_address(&self, key: Address) -> bool {
        self.get_last(key.to_hex()).is_some()
    }
}

impl HasAddresser for StoreGetBigInt {
    fn has_address(&self, key: Address) -> bool {
        self.get_last(key.to_hex()).is_some()
    }
}

impl HasAddresser for StoreGetBigDecimal {
    fn has_address(&self, key: Address) -> bool {
        self.get_last(key.to_hex()).is_some()
    }
}

impl HasAddresser for StoreGetInt64 {
    fn has_address(&self, key: Address) -> bool {
        self.get_last(key.to_hex()).is_some()
    }
}

impl HasAddresser for Address {
    fn has_address(&self, key: Address) -> bool {
        key == *self
    }
}
