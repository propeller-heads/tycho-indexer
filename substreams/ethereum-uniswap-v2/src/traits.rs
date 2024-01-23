use ethabi::ethereum_types::Address;
use substreams::store::{StoreGet, StoreGetProto};

use substreams_helper::common::HasAddresser;
use substreams_helper::hex::Hexable;

use crate::pb::tycho::evm::uniswap::v2::Pool;
use crate::store_key::StoreKey;

pub struct PoolAddresser<'a> {
    pub store: &'a StoreGetProto<Pool>,
}

impl<'a> PoolAddresser<'a> {
    fn has_address(&self, key: Address) -> bool {
        let pool = self
            .store
            .get_last(StoreKey::Pool.get_unique_pool_key(&key.to_hex()));

        pool.is_some()
    }
}

impl<'a> HasAddresser for PoolAddresser<'a> {
    fn has_address(&self, key: Address) -> bool {
        return self.has_address(key);
    }
}
