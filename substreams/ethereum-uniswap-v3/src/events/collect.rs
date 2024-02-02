use substreams_ethereum::pb::eth::v2::StorageChange;

use crate::{
    abi::pool::events::Collect,
    pb::tycho::evm::{uniswap::v3::Pool, v1::Attribute},
    storage::uniswap_v3_pool::UniswapPoolStorage,
};

use super::{BalanceDelta, EventHandlers};

impl EventHandlers for Collect {
    fn get_changed_attributes(
        &self,
        storage_changes: &[StorageChange],
        pool: &Pool,
    ) -> Vec<Attribute> {
        let storage_vec = storage_changes.to_vec();

        let pool_storage = UniswapPoolStorage::new(&storage_vec, &pool.address);

        let mut changed_attributes = pool_storage.get_changed_attributes();

        let changed_ticks = pool_storage.get_ticks_changes(&self.tick_upper, &self.tick_lower);

        changed_attributes.extend(changed_ticks);

        changed_attributes
    }

    fn get_balance_delta(&self, _pool: &Pool, _ordinal: u64) -> Vec<BalanceDelta> {
        vec![]
    }
}
