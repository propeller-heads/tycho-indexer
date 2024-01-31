use std::str;

use substreams::store::{StoreNew, StoreSetIfNotExists, StoreSetIfNotExistsProto};

use crate::{
    pb::tycho::evm::{uniswap::v3::Pool, v1::SameTypeTransactionChanges},
    store_key::StoreKey,
};

#[substreams::handlers::store]
pub fn store_pools(
    pools_created: SameTypeTransactionChanges,
    store: StoreSetIfNotExistsProto<Pool>,
) {
    // Store pools. Required so the next maps can match any event to a known pool by their address

    for change in pools_created.changes {
        //  Use ordinal 0 because the address should be unique, so ordering doesn't matter.
        let pool_address: &str = &change.component_changes[0].id;
        let pool: Pool = Pool {
            address: hex::decode(pool_address.trim_start_matches("0x")).unwrap(),
            token0: change.component_changes[0].tokens[0].clone(),
            token1: change.component_changes[0].tokens[1].clone(),
            created_tx_hash: change.tx.as_ref().unwrap().hash.clone(),
        };
        store.set_if_not_exists(0, StoreKey::Pool.get_unique_pool_key(pool_address), &pool);
    }
}
