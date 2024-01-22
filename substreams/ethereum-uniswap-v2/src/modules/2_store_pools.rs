use substreams::store::{StoreNew, StoreSetIfNotExists, StoreSetIfNotExistsProto};

use crate::{
    pb::uniswap::v2::{Pool, Pools},
    store_key::StoreKey,
};

#[substreams::handlers::store]
pub fn store_pools(pools_created: Pools, store: StoreSetIfNotExistsProto<Pool>) {
    for pool in pools_created.pools {
        store.set_if_not_exists(0, StoreKey::Pool.get_unique_pool_key(&pool.address), &pool);
    }
}
