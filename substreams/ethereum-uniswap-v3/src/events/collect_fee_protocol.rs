use substreams_ethereum::pb::eth::v2::StorageChange;
use substreams_helper::storage_change::StorageChangesFilter;

use crate::{
    abi::pool::events::CollectProtocol,
    pb::tycho::evm::{uniswap::v3::Pool, v1::Attribute},
    storage::{constants::TRACKED_SLOTS, pool_storage::UniswapPoolStorage},
};

use super::{BalanceDelta, EventHandlers};

impl EventHandlers for CollectProtocol {
    fn get_changed_attributes(
        &self,
        storage_changes: &[StorageChange],
        pool_address: &[u8; 20],
    ) -> Vec<Attribute> {
        let storage_vec = storage_changes.to_vec();

        let filtered_storage_changes = storage_vec
            .filter_by_address(pool_address)
            .into_iter()
            .cloned()
            .collect();

        let pool_storage = UniswapPoolStorage::new(&filtered_storage_changes);

        pool_storage.get_changed_attributes(TRACKED_SLOTS.to_vec().iter().collect())
    }

    fn get_balance_delta(&self, _pool: &Pool, _ordinal: u64) -> Vec<BalanceDelta> {
        vec![]
    }
}
