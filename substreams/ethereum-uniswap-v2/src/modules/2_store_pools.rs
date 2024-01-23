use substreams::store::{StoreNew, StoreSetIfNotExists, StoreSetIfNotExistsProto};
use std::str;
use substreams_helper::hex::Hexable;

use crate::{
    pb::tycho::evm::uniswap::v2::{Pool, Pools},
    store_key::StoreKey,
};

#[substreams::handlers::store]
pub fn store_pools(pools_created: Pools, store: StoreSetIfNotExistsProto<Pool>) {
    for pool in pools_created.pools {
        //  Use ordinal 0 because the address should be unique, so ordering doesn't matter.
        let pool_address: &str = &pool.address.to_hex();
        store.set_if_not_exists(0, StoreKey::Pool.get_unique_pool_key(pool_address), &pool);
    }
}
