use substreams_ethereum::pb::eth::v2::StorageChange;

use crate::{
    abi::pool::events::SetFeeProtocol,
    pb::tycho::evm::{uniswap::v3::Pool, v1::Attribute},
    storage::uniswap_v3_pool::UniswapPoolStorage,
};

use super::{BalanceDelta, EventHandlers};

impl EventHandlers for SetFeeProtocol {
    fn get_changed_attributes(
        &self,
        storage_changes: &[StorageChange],
        pool: &Pool,
    ) -> Vec<Attribute> {
        let storage_vec = storage_changes.to_vec();

        let pool_storage = UniswapPoolStorage::new(&storage_vec, &pool.address);

        pool_storage.get_changed_attributes()
    }

    fn get_balance_delta(&self, _pool: &Pool, _ordinal: usize) -> Vec<BalanceDelta> {
        vec![]
    }
}
